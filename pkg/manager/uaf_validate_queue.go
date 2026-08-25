package manager

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/prog"
)

// QueuedUAFCorpusEntry is a queued validation item together with queue metadata.
type QueuedUAFCorpusEntry struct {
	Key                  string
	Seq                  uint64
	PairKey              string
	VarNameFamilyKey     string
	CorpusRecordID       string
	Pair                 ddrd.MayUAFPair
	HistoryCount         int
	AdmissionThresholdUs int64
}

// QueuedUAFCorpusGroup groups queue items that share the same heavy corpus record.
// Pair-level status remains in race-pair-index.db, but validate can materialize the
// shared corpus record once and test all queued pairs from that state together.
type QueuedUAFCorpusGroup struct {
	CorpusRecordID       string
	QueueKeys            []string
	PairKeys             []string
	Pairs                []ddrd.MayUAFPair
	HistoryCount         int
	AdmissionThresholdUs int64
	FirstSeq             uint64
	Items                []*QueuedUAFCorpusEntry
}

// UAFValidateQueueStore is a small append-only queue used to hand validation
// work from the fuzzer process to the validate process without rescanning the
// full uaf-corpus.db file on every poll.
type UAFValidateQueueStore struct {
	mu          sync.Mutex
	db          *db.DB
	target      *prog.Target
	path        string
	lockPath    string
	localSuffix uint64
	pairIndex   *RacePairIndexStore
}

type UAFValidateQueueStats struct {
	Pending          int
	PendingFamilies  int
	WithPairKey      int
	WithCorpusRecord int
	WithHistory      int
	Malformed        int
	MaxSeq           uint64
	LatestEnqueuedAt time.Time
}

type UAFValidateQueueEnqueueResult struct {
	Key             string
	Seq             uint64
	PairKey         string
	Enqueued        bool
	RecordActivated bool
	FamilyActivated bool
}

type UAFValidateQueueAckResult struct {
	Entries           int
	CompletedFamilies int
}

type storedValidateQueueItem struct {
	PairKey              string    `json:"pair_key"`
	VarNameFamilyKey     string    `json:"varname_family_key,omitempty"`
	CorpusRecordID       string    `json:"corpus_record_id"`
	EnqueuedAt           time.Time `json:"enqueued_at"`
	HistoryCount         int       `json:"history_count,omitempty"`
	AdmissionThresholdUs int64     `json:"admission_threshold_us,omitempty"`
}

func NewUAFValidateQueueStore(workdir string, target *prog.Target) (*UAFValidateQueueStore, error) {
	path := filepath.Join(workdir, "uaf-validate-queue.db")
	pairIndex, indexErr := NewRacePairIndexStore(workdir)
	store := &UAFValidateQueueStore{
		target:    target,
		path:      path,
		lockPath:  path + ".lock",
		pairIndex: pairIndex,
	}
	err := store.reloadLatest(false)
	if err != nil && store.db == nil {
		return nil, fmt.Errorf("failed to open uaf validate queue db: %w", err)
	}
	if err == nil {
		err = indexErr
	}
	return store, err
}

func (store *UAFValidateQueueStore) Reload() error {
	if err := store.reloadLatest(false); err != nil {
		return err
	}
	if store.pairIndex != nil {
		if err := store.pairIndex.Reload(); err != nil {
			return err
		}
	}
	return nil
}

func (store *UAFValidateQueueStore) Close() error {
	if store == nil || store.db == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := acquireSharedDBFileLock(store.lockPath, true)
	if err != nil {
		return fmt.Errorf("failed to lock uaf validate queue db: %w", err)
	}
	defer lock.Close()

	err = store.db.Flush()
	if store.pairIndex != nil {
		if indexErr := store.pairIndex.Close(); err == nil {
			err = indexErr
		}
	}
	return err
}

func (store *UAFValidateQueueStore) Count() int {
	if store == nil || store.db == nil {
		return 0
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.db.Records)
}

func (store *UAFValidateQueueStore) Stats() (UAFValidateQueueStats, error) {
	var stats UAFValidateQueueStats
	if store == nil || store.db == nil {
		return stats, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	stats.Pending = len(store.db.Records)
	families := make(map[string]struct{})
	for _, rec := range store.db.Records {
		if rec.Seq > stats.MaxSeq {
			stats.MaxSeq = rec.Seq
		}
		if len(rec.Val) == 0 {
			stats.Malformed++
			continue
		}
		var item storedValidateQueueItem
		if err := json.Unmarshal(rec.Val, &item); err != nil {
			stats.Malformed++
			continue
		}
		if item.PairKey != "" {
			stats.WithPairKey++
		}
		if familyKey := store.storedItemFamilyKey(&item); familyKey != "" {
			families[familyKey] = struct{}{}
		}
		if item.CorpusRecordID != "" {
			stats.WithCorpusRecord++
		}
		if item.HistoryCount > 0 {
			stats.WithHistory++
		}
		if item.EnqueuedAt.After(stats.LatestEnqueuedAt) {
			stats.LatestEnqueuedAt = item.EnqueuedAt
		}
	}
	stats.PendingFamilies = len(families)
	return stats, nil
}

func (store *UAFValidateQueueStore) FamilyCount() (int, error) {
	if store == nil || store.db == nil {
		return 0, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	counts, err := store.pendingFamilyCountsLocked()
	return len(counts), err
}

func (store *UAFValidateQueueStore) Enqueue(entry *fuzzer.UAFCorpusEntry) (string, error) {
	if store == nil || entry == nil {
		return "", nil
	}
	var pair *ddrd.MayUAFPair
	if len(entry.Pairs) != 0 {
		pair = entry.Pairs[0]
	} else if entry.PairBasicInfo.UAFPairID() != 0 {
		pair = &entry.PairBasicInfo
	}
	if pair == nil {
		return "", nil
	}
	record := &RacePairRecord{
		PairKey:                 ddrd.RacePairKeyString(pair),
		Pair:                    *pair,
		PreferredCorpusRecordID: entry.CorpusRecordID,
		PreferredHistoryRecords: len(entry.ReplayHistory),
		AdmissionThresholdUs:    entry.AdmissionThresholdUs,
	}
	key, _, _, err := store.EnqueueRecord(record)
	return key, err
}

func (store *UAFValidateQueueStore) EnqueueRecord(record *RacePairRecord) (string, uint64, bool, error) {
	results, err := store.EnqueueRecords([]*RacePairRecord{record})
	if err != nil || len(results) == 0 {
		return "", 0, false, err
	}
	result := results[0]
	return result.Key, result.Seq, result.Enqueued, nil
}

func (store *UAFValidateQueueStore) EnqueueRecords(records []*RacePairRecord) ([]UAFValidateQueueEnqueueResult, error) {
	if store == nil || len(records) == 0 {
		return nil, nil
	}
	results := make([]UAFValidateQueueEnqueueResult, 0, len(records))
	err := store.withWriteTxn(func() error {
		familyCounts, err := store.pendingFamilyCountsLocked()
		if err != nil {
			return err
		}
		for _, record := range records {
			result, err := store.enqueueRecordLocked(record, familyCounts)
			if err != nil {
				return err
			}
			if result.Key != "" {
				results = append(results, result)
			}
		}
		return nil
	})
	if err != nil {
		return results, err
	}
	return results, nil
}

func (store *UAFValidateQueueStore) enqueueRecordLocked(record *RacePairRecord,
	familyCounts map[string]int) (UAFValidateQueueEnqueueResult, error) {
	var result UAFValidateQueueEnqueueResult
	if store == nil || record == nil || record.PairKey == "" {
		return result, nil
	}
	corpusID := record.PreferredCorpusRecordID
	if corpusID == "" && len(record.CorpusRecordIDs) != 0 {
		corpusID = record.CorpusRecordIDs[0]
	}
	if corpusID == "" {
		return result, nil
	}
	familyKey := ddrd.VarNamePairKey(&record.Pair)
	item := storedValidateQueueItem{
		PairKey:              record.PairKey,
		VarNameFamilyKey:     familyKey,
		CorpusRecordID:       corpusID,
		EnqueuedAt:           time.Now(),
		HistoryCount:         record.PreferredHistoryRecords,
		AdmissionThresholdUs: record.AdmissionThresholdUs,
	}
	data, err := json.Marshal(item)
	if err != nil {
		return result, err
	}

	key := record.PairKey
	seq := store.nextSeqLocked()
	_, familyWasPending := familyCounts[familyKey]
	_, recordAlreadyPending := store.db.Records[key]
	if existingRec, exists := store.db.Records[key]; exists {
		if len(existingRec.Val) != 0 {
			var existing storedValidateQueueItem
			if err := json.Unmarshal(existingRec.Val, &existing); err == nil {
				if existing.HistoryCount <= item.HistoryCount {
					return UAFValidateQueueEnqueueResult{
						Key:      key,
						Seq:      existingRec.Seq,
						PairKey:  record.PairKey,
						Enqueued: false,
					}, nil
				}
			}
		}
	}
	store.db.Save(key, data, seq)
	if !recordAlreadyPending && familyKey != "" {
		familyCounts[familyKey]++
	}
	return UAFValidateQueueEnqueueResult{
		Key:             key,
		Seq:             seq,
		PairKey:         record.PairKey,
		Enqueued:        true,
		RecordActivated: !recordAlreadyPending,
		FamilyActivated: familyKey != "" && !familyWasPending,
	}, nil
}

func (store *UAFValidateQueueStore) nextSeqLocked() uint64 {
	seq := uint64(time.Now().UnixNano())
	if seq <= store.localSuffix {
		seq = store.localSuffix + 1
	}
	store.localSuffix = seq
	return seq
}

func (store *UAFValidateQueueStore) EntriesSince(sinceSeq uint64) ([]*QueuedUAFCorpusEntry, uint64, error) {
	if store == nil || store.db == nil {
		return nil, sinceSeq, nil
	}

	store.mu.Lock()
	maxSeq := sinceSeq
	type queueRecord struct {
		key string
		seq uint64
		val []byte
	}
	records := make([]queueRecord, 0, len(store.db.Records))
	for key, rec := range store.db.Records {
		if rec.Seq > maxSeq {
			maxSeq = rec.Seq
		}
		if rec.Seq <= sinceSeq || len(rec.Val) == 0 {
			continue
		}
		records = append(records, queueRecord{
			key: key,
			seq: rec.Seq,
			val: rec.Val,
		})
	}
	store.mu.Unlock()

	sort.Slice(records, func(i, j int) bool {
		if records[i].seq == records[j].seq {
			return records[i].key < records[j].key
		}
		return records[i].seq < records[j].seq
	})

	items := make([]*QueuedUAFCorpusEntry, 0, len(records))
	for _, rec := range records {
		var queued storedValidateQueueItem
		if err := json.Unmarshal(rec.val, &queued); err != nil {
			return nil, maxSeq, err
		}
		if store.pairIndex == nil {
			items = append(items, &QueuedUAFCorpusEntry{
				Key:                  rec.key,
				Seq:                  rec.seq,
				PairKey:              queued.PairKey,
				VarNameFamilyKey:     store.storedItemFamilyKey(&queued),
				CorpusRecordID:       queued.CorpusRecordID,
				HistoryCount:         queued.HistoryCount,
				AdmissionThresholdUs: queued.AdmissionThresholdUs,
			})
			continue
		}
		pairRecord, err := store.pairIndex.Get(queued.PairKey)
		if err != nil {
			return nil, maxSeq, err
		}
		if pairRecord == nil {
			items = append(items, &QueuedUAFCorpusEntry{
				Key:                  rec.key,
				Seq:                  rec.seq,
				PairKey:              queued.PairKey,
				VarNameFamilyKey:     store.storedItemFamilyKey(&queued),
				CorpusRecordID:       queued.CorpusRecordID,
				AdmissionThresholdUs: queued.AdmissionThresholdUs,
			})
			continue
		}
		corpusID := queued.CorpusRecordID
		if corpusID == "" {
			corpusID = pairRecord.PreferredCorpusRecordID
		}
		historyCount := queued.HistoryCount
		if historyCount == 0 {
			historyCount = pairRecord.PreferredHistoryRecords
		}
		admissionThresholdUs := queued.AdmissionThresholdUs
		if admissionThresholdUs <= 0 {
			admissionThresholdUs = pairRecord.AdmissionThresholdUs
		}
		items = append(items, &QueuedUAFCorpusEntry{
			Key:                  rec.key,
			Seq:                  rec.seq,
			PairKey:              queued.PairKey,
			VarNameFamilyKey:     ddrd.VarNamePairKey(&pairRecord.Pair),
			CorpusRecordID:       corpusID,
			Pair:                 pairRecord.Pair,
			HistoryCount:         historyCount,
			AdmissionThresholdUs: admissionThresholdUs,
		})
	}
	return items, maxSeq, nil
}

func (store *UAFValidateQueueStore) EntriesSinceGroupedByCorpus(sinceSeq uint64) ([]*QueuedUAFCorpusGroup, uint64, error) {
	items, maxSeq, err := store.EntriesSince(sinceSeq)
	if err != nil {
		return nil, maxSeq, err
	}
	if len(items) == 0 {
		return nil, maxSeq, nil
	}

	groupsByCorpus := make(map[string]*QueuedUAFCorpusGroup)
	order := make([]string, 0, len(items))
	for _, item := range items {
		corpusID := ""
		if item != nil {
			corpusID = item.CorpusRecordID
		}
		if corpusID == "" {
			var key string
			var seq uint64
			if item != nil {
				key = item.Key
				seq = item.Seq
			}
			corpusID = fmt.Sprintf("__malformed__:%s:%d", key, seq)
		}
		group, ok := groupsByCorpus[corpusID]
		if !ok {
			group = &QueuedUAFCorpusGroup{
				CorpusRecordID: corpusID,
			}
			if item != nil {
				group.FirstSeq = item.Seq
				group.HistoryCount = item.HistoryCount
			}
			groupsByCorpus[corpusID] = group
			order = append(order, corpusID)
		}
		if item == nil {
			continue
		}
		appendQueuedGroupItem(group, item)
	}

	groups := make([]*QueuedUAFCorpusGroup, 0, len(order))
	for _, corpusID := range order {
		group := groupsByCorpus[corpusID]
		if group == nil {
			continue
		}
		groups = append(groups, group)
	}
	return groups, maxSeq, nil
}

// SplitQueuedUAFCorpusGroups bounds pair work and repeated collection for one
// corpus record. It preserves queue order and keeps each queue key in exactly
// one returned group so callers can ack completed chunks precisely.
func SplitQueuedUAFCorpusGroups(groups []*QueuedUAFCorpusGroup, maxPairs, maxTasks int) []*QueuedUAFCorpusGroup {
	if len(groups) == 0 || (maxPairs <= 0 && maxTasks <= 0) {
		return groups
	}

	result := make([]*QueuedUAFCorpusGroup, 0, len(groups))
	for _, group := range groups {
		pairCount := queuedGroupPairCount(group)
		effectiveMaxPairs := maxPairs
		if maxTasks > 0 && pairCount > 0 {
			pairsForTaskCap := (pairCount + maxTasks - 1) / maxTasks
			if effectiveMaxPairs <= 0 || pairsForTaskCap > effectiveMaxPairs {
				effectiveMaxPairs = pairsForTaskCap
			}
		}
		if group == nil || effectiveMaxPairs <= 0 || pairCount <= effectiveMaxPairs {
			result = append(result, group)
			continue
		}

		var chunk *QueuedUAFCorpusGroup
		chunkPairs := 0
		flush := func() {
			if chunk == nil || len(chunk.Items) == 0 {
				return
			}
			result = append(result, chunk)
			chunk = nil
			chunkPairs = 0
		}
		for _, item := range group.Items {
			if item == nil {
				continue
			}
			itemPairs := 0
			if item.PairKey != "" {
				itemPairs = 1
			}
			if chunk != nil && chunkPairs > 0 && itemPairs > 0 && chunkPairs+itemPairs > effectiveMaxPairs {
				flush()
			}
			if chunk == nil {
				chunk = &QueuedUAFCorpusGroup{
					CorpusRecordID: group.CorpusRecordID,
				}
			}
			appendQueuedGroupItem(chunk, item)
			chunkPairs += itemPairs
		}
		flush()
	}
	return result
}

func queuedGroupPairCount(group *QueuedUAFCorpusGroup) int {
	if group == nil {
		return 0
	}
	count := 0
	for _, item := range group.Items {
		if item != nil && item.PairKey != "" {
			count++
		}
	}
	return count
}

func appendQueuedGroupItem(group *QueuedUAFCorpusGroup, item *QueuedUAFCorpusEntry) {
	if group == nil || item == nil {
		return
	}
	group.Items = append(group.Items, item)
	group.QueueKeys = append(group.QueueKeys, item.Key)
	group.PairKeys = append(group.PairKeys, item.PairKey)
	if item.Pair.UAFPairID() != 0 {
		group.Pairs = append(group.Pairs, item.Pair)
	}
	if item.HistoryCount > group.HistoryCount {
		group.HistoryCount = item.HistoryCount
	}
	if item.AdmissionThresholdUs > group.AdmissionThresholdUs {
		group.AdmissionThresholdUs = item.AdmissionThresholdUs
	}
	if group.FirstSeq == 0 || item.Seq < group.FirstSeq {
		group.FirstSeq = item.Seq
	}
}

func (store *UAFValidateQueueStore) Ack(key string) error {
	return store.AckBatch([]string{key})
}

func (store *UAFValidateQueueStore) AckBatch(keys []string) error {
	_, err := store.AckBatchWithStats(keys)
	return err
}

func (store *UAFValidateQueueStore) AckBatchWithStats(keys []string) (UAFValidateQueueAckResult, error) {
	var result UAFValidateQueueAckResult
	if store == nil || len(keys) == 0 {
		return result, nil
	}
	err := store.withWriteTxn(func() error {
		familyCounts, err := store.pendingFamilyCountsLocked()
		if err != nil {
			return err
		}
		touchedFamilies := make(map[string]struct{})
		seen := make(map[string]struct{}, len(keys))
		for _, key := range keys {
			if key == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			rec, ok := store.db.Records[key]
			if !ok {
				continue
			}
			var item storedValidateQueueItem
			if len(rec.Val) != 0 && json.Unmarshal(rec.Val, &item) == nil {
				if familyKey := store.storedItemFamilyKey(&item); familyKey != "" {
					touchedFamilies[familyKey] = struct{}{}
					familyCounts[familyKey]--
				}
			}
			store.db.Delete(key)
			result.Entries++
		}
		for familyKey := range touchedFamilies {
			if familyCounts[familyKey] <= 0 {
				result.CompletedFamilies++
			}
		}
		return nil
	})
	return result, err
}

func (store *UAFValidateQueueStore) pendingFamilyCountsLocked() (map[string]int, error) {
	counts := make(map[string]int)
	if store == nil || store.db == nil {
		return counts, nil
	}
	for _, rec := range store.db.Records {
		if len(rec.Val) == 0 {
			continue
		}
		var item storedValidateQueueItem
		if err := json.Unmarshal(rec.Val, &item); err != nil {
			return nil, err
		}
		if familyKey := store.storedItemFamilyKey(&item); familyKey != "" {
			counts[familyKey]++
		}
	}
	return counts, nil
}

func (store *UAFValidateQueueStore) storedItemFamilyKey(item *storedValidateQueueItem) string {
	if item == nil {
		return ""
	}
	if item.VarNameFamilyKey != "" {
		return item.VarNameFamilyKey
	}
	// Legacy queue records predate family metadata. Treat each as its own
	// fallback unit so old workdirs remain processable without lock inversion.
	if item.PairKey != "" {
		return "legacy-pair:" + item.PairKey
	}
	return ""
}

func (store *UAFValidateQueueStore) reloadLatest(exclusive bool) error {
	if store == nil || store.path == "" {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	lock, err := acquireSharedDBFileLock(store.lockPath, exclusive)
	if err != nil {
		return fmt.Errorf("failed to lock uaf validate queue db: %w", err)
	}
	defer lock.Close()

	newDB, err := db.OpenNoCompact(store.path, true)
	if err != nil && newDB == nil {
		return fmt.Errorf("failed to reload uaf validate queue db: %w", err)
	}
	store.db = newDB
	return err
}

func (store *UAFValidateQueueStore) withWriteTxn(update func() error) error {
	if store == nil || store.path == "" {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	lock, err := acquireSharedDBFileLock(store.lockPath, true)
	if err != nil {
		return fmt.Errorf("failed to lock uaf validate queue db: %w", err)
	}
	defer lock.Close()

	newDB, reloadErr := db.OpenNoCompact(store.path, true)
	if reloadErr != nil && newDB == nil {
		return fmt.Errorf("failed to reload uaf validate queue db: %w", reloadErr)
	}
	store.db = newDB

	if err := update(); err != nil {
		return err
	}
	if store.db == nil {
		return nil
	}
	if err := store.db.Flush(); err != nil {
		return err
	}
	if reloadErr != nil {
		if err := store.db.Compact(); err != nil {
			return err
		}
	}
	return nil
}
