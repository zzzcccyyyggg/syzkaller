package manager

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
)

type RacePairStatus string

const (
	RacePairDiscovered RacePairStatus = "discovered"
	RacePairQueued     RacePairStatus = "queued"
	RacePairProcessing RacePairStatus = "processing"
	RacePairProcessed  RacePairStatus = "processed"
	RacePairValidated  RacePairStatus = "validated"
	RacePairInvalid    RacePairStatus = "invalid"
)

type RacePairRecord struct {
	PairKey                 string                 `json:"pair_key"`
	VarHash                 uint64                 `json:"var_hash"`
	StackHash               uint64                 `json:"stack_hash"`
	PairID                  uint64                 `json:"pair_id"`
	Pair                    ddrd.MayUAFPair        `json:"pair"`
	CorpusRecordIDs         []string               `json:"corpus_record_ids,omitempty"`
	PreferredCorpusRecordID string                 `json:"preferred_corpus_record_id,omitempty"`
	PreferredHistoryRecords int                    `json:"preferred_history_records,omitempty"`
	AdmissionThresholdUs    int64                  `json:"admission_threshold_us,omitempty"`
	Source                  int                    `json:"source,omitempty"`
	Status                  RacePairStatus         `json:"status"`
	DiscoveredAt            time.Time              `json:"discovered_at"`
	UpdatedAt               time.Time              `json:"updated_at"`
	QueuedAt                time.Time              `json:"queued_at,omitempty"`
	LastQueueSeq            uint64                 `json:"last_queue_seq,omitempty"`
	ValidateAttempts        int                    `json:"validate_attempts,omitempty"`
	ValidateSuccesses       int                    `json:"validate_successes,omitempty"`
	ValidateFailures        int                    `json:"validate_failures,omitempty"`
	LastValidatedAt         time.Time              `json:"last_validated_at,omitempty"`
	LastInvalidAt           time.Time              `json:"last_invalid_at,omitempty"`
	LastProcessedAt         time.Time              `json:"last_processed_at,omitempty"`
	Metadata                map[string]interface{} `json:"metadata,omitempty"`
}

type RacePairIndexStore struct {
	mu       sync.Mutex
	db       *db.DB
	path     string
	lockPath string
}

type RacePairIndexStats struct {
	Total       int
	Discovered  int
	Queued      int
	Processing  int
	Processed   int
	Validated   int
	Invalid     int
	Unknown     int
	Queueable   int
	WithCorpus  int
	WithHistory int
	MaxQueueSeq uint64
}

func NewRacePairIndexStore(workdir string) (*RacePairIndexStore, error) {
	path := filepath.Join(workdir, "race-pair-index.db")
	store := &RacePairIndexStore{
		path:     path,
		lockPath: path + ".lock",
	}
	err := store.reloadLatest(false)
	if err != nil && store.db == nil {
		return nil, fmt.Errorf("failed to open race pair index db: %w", err)
	}
	return store, err
}

func (store *RacePairIndexStore) Reload() error {
	return store.reloadLatest(false)
}

func (store *RacePairIndexStore) Close() error {
	if store == nil || store.db == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := acquireSharedDBFileLock(store.lockPath, true)
	if err != nil {
		return fmt.Errorf("failed to lock race pair index db: %w", err)
	}
	defer lock.Close()
	return store.db.Flush()
}

func (store *RacePairIndexStore) Count() int {
	if store == nil || store.db == nil {
		return 0
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.db.Records)
}

func (store *RacePairIndexStore) Stats() (RacePairIndexStats, error) {
	var stats RacePairIndexStats
	if store == nil || store.db == nil {
		return stats, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	stats.Total = len(store.db.Records)
	for key, rec := range store.db.Records {
		if key == "" || len(rec.Val) == 0 {
			stats.Unknown++
			continue
		}
		var record RacePairRecord
		if err := json.Unmarshal(rec.Val, &record); err != nil {
			return stats, err
		}
		switch record.Status {
		case RacePairDiscovered:
			stats.Discovered++
		case RacePairQueued:
			stats.Queued++
		case RacePairProcessing:
			stats.Processing++
		case RacePairProcessed:
			stats.Processed++
		case RacePairValidated:
			stats.Validated++
		case RacePairInvalid:
			stats.Invalid++
		default:
			stats.Unknown++
		}
		if record.PreferredCorpusRecordID != "" || len(record.CorpusRecordIDs) != 0 {
			stats.WithCorpus++
		}
		if record.PreferredHistoryRecords > 0 {
			stats.WithHistory++
		}
		if racePairRecordQueueable(&record) {
			stats.Queueable++
		}
		if record.LastQueueSeq > stats.MaxQueueSeq {
			stats.MaxQueueSeq = record.LastQueueSeq
		}
	}
	return stats, nil
}

func (store *RacePairIndexStore) ObserveEntry(entry *fuzzer.UAFCorpusEntry, corpusRecordID string) ([]*RacePairRecord, error) {
	if store == nil || entry == nil || corpusRecordID == "" {
		return nil, nil
	}
	return store.ObserveRefs([]RaceCorpusRecordRef{{ID: corpusRecordID, Entry: entry}})
}

func (store *RacePairIndexStore) ObserveRefs(refs []RaceCorpusRecordRef) ([]*RacePairRecord, error) {
	if store == nil || len(refs) == 0 {
		return nil, nil
	}
	records := make([]*RacePairRecord, 0, len(refs))
	err := store.withWriteTxn(func() error {
		now := time.Now()
		for _, ref := range refs {
			if ref.ID == "" || ref.Entry == nil {
				continue
			}
			entryRecords, err := store.observeEntryLocked(ref.Entry, ref.ID, now)
			if err != nil {
				return err
			}
			records = append(records, entryRecords...)
		}
		return nil
	})
	if err != nil {
		return records, err
	}
	return records, nil
}

func (store *RacePairIndexStore) observeEntryLocked(entry *fuzzer.UAFCorpusEntry, corpusRecordID string, now time.Time) ([]*RacePairRecord, error) {
	pairs := entry.Pairs
	if len(pairs) == 0 && entry.PairBasicInfo.UAFPairID() != 0 {
		pairs = []*ddrd.MayUAFPair{&entry.PairBasicInfo}
	}
	if len(pairs) == 0 {
		return nil, nil
	}

	records := make([]*RacePairRecord, 0, len(pairs))
	for _, pair := range pairs {
		if pair == nil {
			continue
		}
		key := ddrd.RacePairKeyFromUAFPair(pair)
		if key.IsZero() {
			continue
		}
		pairKey := key.String()
		rec, err := store.getLocked(pairKey)
		if err != nil {
			return records, err
		}
		recordChanged := false
		if rec == nil {
			pairCopy := *pair
			rec = &RacePairRecord{
				PairKey:                 pairKey,
				VarHash:                 key.VarHash,
				StackHash:               key.StackHash,
				PairID:                  pair.UAFPairID(),
				Pair:                    pairCopy,
				CorpusRecordIDs:         []string{corpusRecordID},
				PreferredCorpusRecordID: corpusRecordID,
				PreferredHistoryRecords: len(entry.ReplayHistory),
				AdmissionThresholdUs:    entry.AdmissionThresholdUs,
				Source:                  int(entry.Source),
				Status:                  RacePairDiscovered,
				DiscoveredAt:            now,
				UpdatedAt:               now,
			}
			recordChanged = true
		} else {
			if !containsString(rec.CorpusRecordIDs, corpusRecordID) {
				rec.CorpusRecordIDs = append(rec.CorpusRecordIDs, corpusRecordID)
				recordChanged = true
			}
			if shouldPreferCorpusRecord(rec.PreferredCorpusRecordID, rec.PreferredHistoryRecords,
				corpusRecordID, len(entry.ReplayHistory)) {
				rec.PreferredCorpusRecordID = corpusRecordID
				rec.PreferredHistoryRecords = len(entry.ReplayHistory)
				rec.AdmissionThresholdUs = entry.AdmissionThresholdUs
				if rec.Status == RacePairProcessed {
					rec.Status = RacePairDiscovered
				}
				recordChanged = true
			}
			if rec.AdmissionThresholdUs == 0 && rec.PreferredCorpusRecordID == corpusRecordID &&
				entry.AdmissionThresholdUs > 0 {
				rec.AdmissionThresholdUs = entry.AdmissionThresholdUs
				recordChanged = true
			}
			if rec.PairID == 0 {
				rec.PairID = pair.UAFPairID()
				recordChanged = true
			}
			if rec.Status == "" {
				rec.Status = RacePairDiscovered
				recordChanged = true
			}
			if recordChanged {
				rec.UpdatedAt = now
			}
		}
		if recordChanged {
			if err := store.saveLocked(rec); err != nil {
				return records, err
			}
		}
		records = append(records, cloneRacePairRecord(rec))
	}
	return records, nil
}

func (store *RacePairIndexStore) Get(pairKey string) (*RacePairRecord, error) {
	if store == nil || store.db == nil || pairKey == "" {
		return nil, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.getLocked(pairKey)
}

func (store *RacePairIndexStore) ShouldQueue(record *RacePairRecord) bool {
	return racePairRecordQueueable(record)
}

func (store *RacePairIndexStore) MarkQueued(pairKey string, seq uint64) error {
	return store.updateStatus(pairKey, RacePairQueued, func(rec *RacePairRecord, now time.Time) {
		rec.QueuedAt = now
		rec.LastQueueSeq = seq
	})
}

func (store *RacePairIndexStore) MarkQueuedBatch(queued map[string]uint64) error {
	if store == nil || len(queued) == 0 {
		return nil
	}
	return store.withWriteTxn(func() error {
		now := time.Now()
		for pairKey, seq := range queued {
			if pairKey == "" {
				continue
			}
			rec, err := store.getLocked(pairKey)
			if err != nil || rec == nil {
				return err
			}
			rec.Status = RacePairQueued
			rec.UpdatedAt = now
			rec.QueuedAt = now
			rec.LastQueueSeq = seq
			if err := store.saveLocked(rec); err != nil {
				return err
			}
		}
		return nil
	})
}

func (store *RacePairIndexStore) MarkProcessing(pairKey string) error {
	return store.MarkProcessingBatch([]string{pairKey})
}

func (store *RacePairIndexStore) MarkProcessingBatch(pairKeys []string) error {
	return store.updateStatusBatch(pairKeys, RacePairProcessing, false, func(rec *RacePairRecord, now time.Time) {
		rec.ValidateAttempts++
	})
}

func (store *RacePairIndexStore) MarkProcessed(pairKey string) error {
	return store.MarkProcessedBatch([]string{pairKey})
}

func (store *RacePairIndexStore) MarkProcessedBatch(pairKeys []string) error {
	return store.updateStatusBatch(pairKeys, RacePairProcessed, true, func(rec *RacePairRecord, now time.Time) {
		rec.LastProcessedAt = now
	})
}

func (store *RacePairIndexStore) MarkPairValidated(pair ddrd.MayUAFPair, _ []byte) {
	_ = store.updatePairStatus(&pair, RacePairValidated, func(rec *RacePairRecord, now time.Time) {
		rec.ValidateSuccesses++
		rec.LastValidatedAt = now
	})
}

func (store *RacePairIndexStore) MarkPairInvalid(pair ddrd.MayUAFPair) {
	_ = store.updatePairStatus(&pair, RacePairInvalid, func(rec *RacePairRecord, now time.Time) {
		rec.ValidateFailures++
		rec.LastInvalidAt = now
	})
}

func (store *RacePairIndexStore) updatePairStatus(pair *ddrd.MayUAFPair, status RacePairStatus, update func(*RacePairRecord, time.Time)) error {
	if pair == nil {
		return nil
	}
	return store.updateStatus(ddrd.RacePairKeyString(pair), status, update)
}

func (store *RacePairIndexStore) updateStatus(pairKey string, status RacePairStatus, update func(*RacePairRecord, time.Time)) error {
	return store.updateStatusBatch([]string{pairKey}, status, false, update)
}

func (store *RacePairIndexStore) updateStatusBatch(pairKeys []string, status RacePairStatus, keepFinal bool,
	update func(*RacePairRecord, time.Time)) error {
	if store == nil || len(pairKeys) == 0 {
		return nil
	}
	return store.withWriteTxn(func() error {
		now := time.Now()
		seen := make(map[string]struct{}, len(pairKeys))
		for _, pairKey := range pairKeys {
			if pairKey == "" {
				continue
			}
			if _, ok := seen[pairKey]; ok {
				continue
			}
			seen[pairKey] = struct{}{}
			rec, err := store.getLocked(pairKey)
			if err != nil || rec == nil {
				return err
			}
			if keepFinal && (rec.Status == RacePairValidated || rec.Status == RacePairInvalid) {
				continue
			}
			rec.Status = status
			rec.UpdatedAt = now
			if update != nil {
				update(rec, now)
			}
			if err := store.saveLocked(rec); err != nil {
				return err
			}
		}
		return nil
	})
}

func (store *RacePairIndexStore) getLocked(pairKey string) (*RacePairRecord, error) {
	if store == nil || store.db == nil || pairKey == "" {
		return nil, nil
	}
	rec, ok := store.db.Records[pairKey]
	if !ok || len(rec.Val) == 0 {
		return nil, nil
	}
	var decoded RacePairRecord
	if err := json.Unmarshal(rec.Val, &decoded); err != nil {
		return nil, err
	}
	return &decoded, nil
}

func (store *RacePairIndexStore) saveLocked(record *RacePairRecord) error {
	if store == nil || store.db == nil || record == nil || record.PairKey == "" {
		return nil
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	store.db.Save(record.PairKey, data, uint64(time.Now().UnixNano()))
	return nil
}

func (store *RacePairIndexStore) reloadLatest(exclusive bool) error {
	if store == nil || store.path == "" {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.reloadLatestLocked(exclusive)
}

func (store *RacePairIndexStore) reloadLatestLocked(exclusive bool) error {
	lock, err := acquireSharedDBFileLock(store.lockPath, exclusive)
	if err != nil {
		return fmt.Errorf("failed to lock race pair index db: %w", err)
	}
	defer lock.Close()

	indexDB, err := db.OpenNoCompact(store.path, true)
	if err != nil && indexDB == nil {
		return fmt.Errorf("failed to reload race pair index db: %w", err)
	}
	store.db = indexDB
	return err
}

func (store *RacePairIndexStore) withWriteTxn(update func() error) error {
	if store == nil || store.path == "" {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	lock, err := acquireSharedDBFileLock(store.lockPath, true)
	if err != nil {
		return fmt.Errorf("failed to lock race pair index db: %w", err)
	}
	defer lock.Close()

	indexDB, reloadErr := db.OpenNoCompact(store.path, true)
	if reloadErr != nil && indexDB == nil {
		return fmt.Errorf("failed to reload race pair index db: %w", reloadErr)
	}
	store.db = indexDB

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

func cloneRacePairRecord(record *RacePairRecord) *RacePairRecord {
	if record == nil {
		return nil
	}
	clone := *record
	if len(record.CorpusRecordIDs) != 0 {
		clone.CorpusRecordIDs = append([]string(nil), record.CorpusRecordIDs...)
	}
	if record.Metadata != nil {
		clone.Metadata = make(map[string]interface{}, len(record.Metadata))
		for k, v := range record.Metadata {
			clone.Metadata[k] = v
		}
	}
	return &clone
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func shouldPreferCorpusRecord(currentID string, currentHistory int, candidateID string, candidateHistory int) bool {
	if candidateID == "" {
		return false
	}
	if currentID == "" {
		return true
	}
	if candidateID == currentID {
		return false
	}
	return candidateHistory < currentHistory
}

func racePairRecordQueueable(record *RacePairRecord) bool {
	if record == nil {
		return false
	}
	switch record.Status {
	case RacePairValidated, RacePairInvalid, RacePairProcessing, RacePairProcessed:
		return false
	default:
		return record.PreferredCorpusRecordID != ""
	}
}
