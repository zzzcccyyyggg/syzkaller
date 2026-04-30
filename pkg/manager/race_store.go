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
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

type UAFCorpusStore struct {
	mu     sync.Mutex
	db     *db.DB
	target *prog.Target
	path   string
}

type RaceCorpusRecordRef struct {
	ID    string
	Seq   uint64
	Entry *fuzzer.UAFCorpusEntry
}

type UAFCorpusStoreStats struct {
	Records int
	MaxSeq  uint64
}

type storedUAFCorpusEntry struct {
	Program       []byte                 `json:"program"`
	Programs      [][]byte               `json:"programs,omitempty"`
	CallIdx       int                    `json:"call_idx"`
	Pair          ddrd.MayUAFPair        `json:"pair"`
	Pairs         []ddrd.MayUAFPair      `json:"pairs,omitempty"`
	Signals       []uint64               `json:"signals,omitempty"`
	Barrier       fuzzer.BarrierSnapshot `json:"barrier"`
	ReplayPlan    *storedReplayPlan      `json:"replay_plan,omitempty"`
	Profile       *storedPairProfile     `json:"profile,omitempty"`
	ReplayHistory []storedBarrierRecord  `json:"replay_history,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	Source        int                    `json:"source,omitempty"` // 0=fuzz, 1=timing

	// AsyncMode entries use intra-process threaded execution instead of cross-process barrier.
	AsyncMode      bool   `json:"async_mode,omitempty"`
	AsyncRaceCalls [2]int `json:"async_race_calls,omitempty"`
}

type storedReplayPlan struct {
	DelaysMicros []int64 `json:"delays_micros,omitempty"`
}

type storedPairProfile struct {
	FreeAccessName uint64 `json:"free_access_name,omitempty"`
	UseAccessName  uint64 `json:"use_access_name,omitempty"`
	FreeCallStack  uint64 `json:"free_call_stack,omitempty"`
	UseCallStack   uint64 `json:"use_call_stack,omitempty"`
}

// storedBarrierRecord represents a serialized barrier execution record for replay.
type storedBarrierRecord struct {
	Programs  [][]byte  `json:"programs"`
	Timestamp time.Time `json:"timestamp"`
	GroupID   int64     `json:"group_id"`
}

func NewUAFCorpusStore(workdir string, target *prog.Target) (*UAFCorpusStore, error) {
	path := filepath.Join(workdir, "uaf-corpus.db")
	corpusDB, err := db.Open(path, true)
	if err != nil {
		if corpusDB == nil {
			return nil, fmt.Errorf("failed to open uaf corpus db: %w", err)
		}
		log.Errorf("uaf corpus db: recovered with errors: %v", err)
	}
	// The corpus DB stores heavy replay/program payloads. Keep only keys/seqs in
	// memory; validators and fuzzers can stream materialize records by id.
	corpusDB.DiscardData()
	return &UAFCorpusStore{db: corpusDB, target: target, path: path}, nil
}

// Reload re-reads the database from disk to pick up changes made by other processes.
// This is useful for validator mode which runs in a separate process from the fuzzer.
func (store *UAFCorpusStore) Reload() error {
	if store == nil || store.path == "" {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	newDB, err := db.Open(store.path, true)
	if err != nil {
		if newDB == nil {
			return fmt.Errorf("failed to reload uaf corpus db: %w", err)
		}
		log.Errorf("uaf corpus db: reload recovered with errors: %v", err)
	}
	newDB.DiscardData()
	store.db = newDB
	return nil
}

func (store *UAFCorpusStore) Close() error {
	if store == nil || store.db == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.db.Flush()
}

func (store *UAFCorpusStore) Count() int {
	if store == nil || store.db == nil {
		return 0
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.db.Records)
}

func (store *UAFCorpusStore) Stats() UAFCorpusStoreStats {
	var stats UAFCorpusStoreStats
	if store == nil || store.db == nil {
		return stats
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	stats.Records = len(store.db.Records)
	for _, rec := range store.db.Records {
		if rec.Seq > stats.MaxSeq {
			stats.MaxSeq = rec.Seq
		}
	}
	return stats
}

// IterateEntriesBatched streams corpus entries from disk in bounded batches.
// This avoids materializing the whole database in memory at once during startup.
func (store *UAFCorpusStore) IterateEntriesBatched(batchSize int, callback func(entries []*fuzzer.UAFCorpusEntry) bool) error {
	if store == nil || store.path == "" || callback == nil {
		return nil
	}
	store.mu.Lock()
	path := store.path
	target := store.target
	store.mu.Unlock()

	reader := NewStreamingUAFCorpusReader(path, target)
	_, err := reader.IterateEntriesBatched(0, batchSize, func(entries []*fuzzer.UAFCorpusEntry, _ []uint64) bool {
		return callback(entries)
	})
	return err
}

// EntriesSince returns entries with seq greater than sinceSeq along with the max seq seen.
// This enables incremental reads of the corpus without reprocessing already-seen entries.
func (store *UAFCorpusStore) EntriesSince(sinceSeq uint64) ([]*fuzzer.UAFCorpusEntry, uint64, error) {
	if store == nil {
		return nil, sinceSeq, nil
	}
	store.mu.Lock()
	path := store.path
	target := store.target
	store.mu.Unlock()

	reader := NewStreamingUAFCorpusReader(path, target)
	entries := make([]*fuzzer.UAFCorpusEntry, 0)
	maxSeq, err := reader.IterateEntries(sinceSeq, func(entry *fuzzer.UAFCorpusEntry, _ uint64) bool {
		entries = append(entries, entry)
		return true
	})
	if err != nil {
		return nil, sinceSeq, err
	}
	// Sort entries: prioritize entries with ReplayHistory, then by Timestamp.
	// This ensures that when multiple entries have the same signature/key,
	// the one with history is processed first (and others are deduplicated away).
	sort.Slice(entries, func(i, j int) bool {
		iHasHistory := len(entries[i].ReplayHistory) > 0
		jHasHistory := len(entries[j].ReplayHistory) > 0
		if iHasHistory != jHasHistory {
			// Entry with history comes first
			return iHasHistory
		}
		// Same history status: sort by timestamp (older first)
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})
	return entries, maxSeq, nil
}

func (store *UAFCorpusStore) Add(entries []*fuzzer.UAFCorpusEntry) (int, error) {
	refs, err := store.AddWithRefs(entries)
	return len(refs), err
}

func (store *UAFCorpusStore) AddWithRefs(entries []*fuzzer.UAFCorpusEntry) ([]RaceCorpusRecordRef, error) {
	if store == nil || store.db == nil || len(entries) == 0 {
		return nil, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	refs := make([]RaceCorpusRecordRef, 0, len(entries))
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		data, err := serializeUAFCorpusEntry(entry)
		if err != nil {
			return refs, err
		}
		key := entry.CorpusRecordID
		if key == "" {
			key = hash.String("race-corpus-record-v2", data)
		}
		seq := uint64(time.Now().UnixNano())
		if !entry.Timestamp.IsZero() {
			seq = uint64(entry.Timestamp.UnixNano())
		}
		entry.CorpusRecordID = key
		if _, exists := store.db.Records[key]; !exists {
			store.db.Save(key, data, seq)
		}
		refs = append(refs, RaceCorpusRecordRef{
			ID:    key,
			Seq:   seq,
			Entry: entry,
		})
	}
	if len(refs) == 0 {
		return nil, nil
	}
	return refs, store.db.Flush()
}

func serializeUAFCorpusEntry(entry *fuzzer.UAFCorpusEntry) ([]byte, error) {
	stored := storedUAFCorpusEntry{
		CallIdx:        entry.CallIdx,
		Barrier:        entry.Barrier,
		Timestamp:      entry.Timestamp,
		Source:         int(entry.Source),
		AsyncMode:      entry.AsyncMode,
		AsyncRaceCalls: entry.AsyncRaceCalls,
	}
	if entry.Prog != nil && (len(entry.Programs) == 0 || entry.AsyncMode) {
		stored.Program = entry.Prog.Serialize()
	}
	if len(entry.Programs) != 0 {
		stored.Programs = serializeProgramGroup(entry.Programs)
	}
	if !entry.ReplayPlan.IsZero() {
		stored.ReplayPlan = &storedReplayPlan{
			DelaysMicros: append([]int64(nil), entry.ReplayPlan.DelaysMicros...),
		}
	}
	// Serialize replay history
	if len(entry.ReplayHistory) != 0 {
		stored.ReplayHistory = serializeReplayHistory(entry.ReplayHistory)
		// Debug logging disabled for production
		// log.Logf(0, "[history] race_store: serializing entry with %d history records", len(entry.ReplayHistory))
	}
	return json.Marshal(stored)
}

func serializeReplayHistory(history []*fuzzer.BarrierExecutionRecord) []storedBarrierRecord {
	if len(history) == 0 {
		return nil
	}
	result := make([]storedBarrierRecord, 0, len(history))
	for _, rec := range history {
		if rec == nil {
			continue
		}
		stored := storedBarrierRecord{
			Timestamp: rec.Timestamp,
			GroupID:   rec.GroupID,
		}
		if len(rec.Programs) != 0 {
			stored.Programs = serializeProgramGroup(rec.Programs)
		}
		result = append(result, stored)
	}
	return result
}

func (store *UAFCorpusStore) Entries() ([]*fuzzer.UAFCorpusEntry, error) {
	if store == nil {
		return nil, nil
	}
	store.mu.Lock()
	path := store.path
	target := store.target
	store.mu.Unlock()

	reader := NewStreamingUAFCorpusReader(path, target)
	entries, _, err := reader.LoadEntriesWithProgress(0, nil)
	if err != nil {
		return nil, err
	}
	// Sort entries: prioritize entries with ReplayHistory, then by Timestamp.
	// This ensures that when multiple entries have the same signature/key,
	// the one with history is processed first (and others are deduplicated away).
	sort.Slice(entries, func(i, j int) bool {
		iHasHistory := len(entries[i].ReplayHistory) > 0
		jHasHistory := len(entries[j].ReplayHistory) > 0
		if iHasHistory != jHasHistory {
			// Entry with history comes first
			return iHasHistory
		}
		// Same history status: sort by timestamp (older first)
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})
	return entries, nil
}

func (store *UAFCorpusStore) deserialize(data []byte) (*fuzzer.UAFCorpusEntry, error) {
	var stored storedUAFCorpusEntry
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}
	entry := &fuzzer.UAFCorpusEntry{
		CallIdx:        stored.CallIdx,
		PairBasicInfo:  stored.Pair,
		Signals:        sliceToSignal(stored.Signals),
		Barrier:        stored.Barrier,
		Timestamp:      stored.Timestamp,
		Source:         fuzzer.PairSource(stored.Source),
		AsyncMode:      stored.AsyncMode,
		AsyncRaceCalls: stored.AsyncRaceCalls,
	}
	if len(stored.Pairs) != 0 {
		entry.Pairs = make([]*ddrd.MayUAFPair, 0, len(stored.Pairs))
		for i := range stored.Pairs {
			pair := stored.Pairs[i]
			copyPair := pair
			entry.Pairs = append(entry.Pairs, &copyPair)
		}
	} else if !isZeroMayUAFPair(stored.Pair) {
		pairCopy := stored.Pair
		entry.Pairs = []*ddrd.MayUAFPair{&pairCopy}
	}
	if len(entry.Pairs) != 0 {
		entry.PairBasicInfo = *entry.Pairs[0]
	}
	if store.target != nil && len(stored.Program) != 0 {
		progObj, err := store.target.Deserialize(stored.Program, prog.NonStrict)
		if err != nil {
			return nil, err
		}
		entry.Prog = progObj
	}
	if store.target != nil && len(stored.Programs) != 0 {
		group, err := store.deserializeProgramGroup(stored.Programs)
		if err != nil {
			return nil, err
		}
		entry.Programs = group
		if !entry.AsyncMode {
			entry.Prog = nil
		}
	}
	if stored.ReplayPlan != nil {
		entry.ReplayPlan = fuzzer.UAFCorpusReplayPlan{
			DelaysMicros: append([]int64(nil), stored.ReplayPlan.DelaysMicros...),
		}
	}
	if stored.Profile != nil {
		entry.Profile = fuzzer.UAFPairProfile{
			FreeAccessName: stored.Profile.FreeAccessName,
			UseAccessName:  stored.Profile.UseAccessName,
			FreeCallStack:  stored.Profile.FreeCallStack,
			UseCallStack:   stored.Profile.UseCallStack,
		}
	} else {
		// Fall back to the pair metadata if an explicit profile was not persisted.
		entry.Profile = fuzzer.UAFPairProfile{
			FreeAccessName: stored.Pair.FreeAccessName,
			UseAccessName:  stored.Pair.UseAccessName,
			FreeCallStack:  stored.Pair.FreeCallStack,
			UseCallStack:   stored.Pair.UseCallStack,
		}
	}
	// Deserialize replay history
	if len(stored.ReplayHistory) != 0 {
		// Debug logging disabled for production
		// log.Logf(0, "[history] race_store: deserializing entry with %d stored history records", len(stored.ReplayHistory))
		history, err := store.deserializeReplayHistory(stored.ReplayHistory)
		if err != nil {
			log.Logf(0, "warning: failed to deserialize replay history: %v", err)
			// Continue without history - not fatal
		} else {
			entry.ReplayHistory = history
			// Debug logging disabled for production
			// log.Logf(0, "[history] race_store: deserialized %d history records", len(history))
		}
	}
	return entry, nil
}

func (store *UAFCorpusStore) deserializeReplayHistory(records []storedBarrierRecord) ([]*fuzzer.BarrierExecutionRecord, error) {
	if len(records) == 0 || store.target == nil {
		return nil, nil
	}
	result := make([]*fuzzer.BarrierExecutionRecord, 0, len(records))
	for _, rec := range records {
		entry := &fuzzer.BarrierExecutionRecord{
			Timestamp: rec.Timestamp,
			GroupID:   rec.GroupID,
		}
		if len(rec.Programs) != 0 {
			programs, err := store.deserializeProgramGroup(rec.Programs)
			if err != nil {
				return nil, fmt.Errorf("deserialize replay history programs: %w", err)
			}
			entry.Programs = programs
		}
		result = append(result, entry)
	}
	return result, nil
}

func isZeroMayUAFPair(pair ddrd.MayUAFPair) bool {
	return pair.FreeAccessName == 0 && pair.UseAccessName == 0 &&
		pair.FreeCallStack == 0 && pair.UseCallStack == 0
}

func attachPairToEntry(entry *fuzzer.UAFCorpusEntry, pair *ddrd.MayUAFPair) {
	if entry == nil || pair == nil || pair.UAFPairID() == 0 {
		return
	}
	pairCopy := *pair
	entry.PairBasicInfo = pairCopy
	entry.Pairs = []*ddrd.MayUAFPair{&pairCopy}
	entry.Signals = ddrd.FromUAFPairs(entry.Pairs, ddrd.UAFSignalPrioHigh)
	entry.Profile = fuzzer.UAFPairProfile{
		FreeAccessName: pair.FreeAccessName,
		UseAccessName:  pair.UseAccessName,
		FreeCallStack:  pair.FreeCallStack,
		UseCallStack:   pair.UseCallStack,
	}
	entry.ValidatePairKey = ddrd.RacePairKeyString(pair)
}

func sliceToSignal(values []uint64) ddrd.UAFSignal {
	if len(values) == 0 {
		return nil
	}
	signal := make(ddrd.UAFSignal, len(values))
	for _, val := range values {
		signal[val] = struct{}{}
	}
	return signal
}

func serializeProgramGroup(programs []*prog.Prog) [][]byte {
	if len(programs) == 0 {
		return nil
	}
	serialized := make([][]byte, len(programs))
	for i, p := range programs {
		if p == nil {
			continue
		}
		serialized[i] = p.Serialize()
	}
	return serialized
}

func (store *UAFCorpusStore) deserializeProgramGroup(data [][]byte) ([]*prog.Prog, error) {
	if len(data) == 0 {
		return nil, nil
	}
	group := make([]*prog.Prog, len(data))
	for i, blob := range data {
		if len(blob) == 0 {
			continue
		}
		progObj, err := store.target.Deserialize(blob, prog.NonStrict)
		if err != nil {
			return nil, fmt.Errorf("deserialize barrier program %d: %w", i, err)
		}
		group[i] = progObj
	}
	return group, nil
}
