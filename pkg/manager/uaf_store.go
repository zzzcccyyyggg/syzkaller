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
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

type UAFCorpusStore struct {
	mu     sync.Mutex
	db     *db.DB
	target *prog.Target
}

type storedUAFCorpusEntry struct {
	Program    []byte                 `json:"program"`
	Programs   [][]byte               `json:"programs,omitempty"`
	CallIdx    int                    `json:"call_idx"`
	Pair       ddrd.MayUAFPair        `json:"pair"`
	Pairs      []ddrd.MayUAFPair      `json:"pairs,omitempty"`
	Signals    []uint64               `json:"signals,omitempty"`
	Barrier    fuzzer.BarrierSnapshot `json:"barrier"`
	ReplayPlan *storedReplayPlan      `json:"replay_plan,omitempty"`
	Profile    *storedPairProfile     `json:"profile,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
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

func NewUAFCorpusStore(workdir string, target *prog.Target) (*UAFCorpusStore, error) {
	path := filepath.Join(workdir, "uaf-corpus.db")
	corpusDB, err := db.Open(path, true)
	if err != nil {
		if corpusDB == nil {
			return nil, fmt.Errorf("failed to open uaf corpus db: %w", err)
		}
		log.Errorf("uaf corpus db: recovered with errors: %v", err)
	}
	return &UAFCorpusStore{db: corpusDB, target: target}, nil
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

// EntriesSince returns entries with seq greater than sinceSeq along with the max seq seen.
// This enables incremental reads of the corpus without reprocessing already-seen entries.
func (store *UAFCorpusStore) EntriesSince(sinceSeq uint64) ([]*fuzzer.UAFCorpusEntry, uint64, error) {
	if store == nil || store.db == nil {
		return nil, sinceSeq, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	maxSeq := sinceSeq
	entries := make([]*fuzzer.UAFCorpusEntry, 0)
	for _, rec := range store.db.Records {
		if rec.Seq <= sinceSeq {
			continue
		}
		if len(rec.Val) == 0 {
			continue
		}
		if rec.Seq > maxSeq {
			maxSeq = rec.Seq
		}
		entry, err := store.deserialize(rec.Val)
		if err != nil {
			log.Errorf("failed to deserialize uaf corpus entry: %v", err)
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})
	return entries, maxSeq, nil
}

func (store *UAFCorpusStore) Add(entries []*fuzzer.UAFCorpusEntry) (int, error) {
	if store == nil || store.db == nil || len(entries) == 0 {
		return 0, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	added := 0
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		id := entry.PairID()
		if id == 0 {
			continue
		}
		key := fmt.Sprintf("%016x", id)
		if _, exists := store.db.Records[key]; exists {
			continue
		}
		data, err := serializeUAFCorpusEntry(entry)
		if err != nil {
			return added, err
		}
		seq := uint64(entry.Timestamp.UnixNano())
		store.db.Save(key, data, seq)
		added++
	}
	if added == 0 {
		return 0, nil
	}
	return added, store.db.Flush()
}

func serializeUAFCorpusEntry(entry *fuzzer.UAFCorpusEntry) ([]byte, error) {
	stored := storedUAFCorpusEntry{
		CallIdx:   entry.CallIdx,
		Pair:      entry.PairBasicInfo,
		Signals:   entry.SignalsSlice(),
		Barrier:   entry.Barrier,
		Timestamp: entry.Timestamp,
	}
	if len(entry.Pairs) != 0 {
		stored.Pairs = make([]ddrd.MayUAFPair, 0, len(entry.Pairs))
		for _, pair := range entry.Pairs {
			if pair == nil {
				continue
			}
			stored.Pairs = append(stored.Pairs, *pair)
		}
	}
	if entry.Prog != nil {
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
	if !entry.Profile.IsZero() {
		stored.Profile = &storedPairProfile{
			FreeAccessName: entry.Profile.FreeAccessName,
			UseAccessName:  entry.Profile.UseAccessName,
			FreeCallStack:  entry.Profile.FreeCallStack,
			UseCallStack:   entry.Profile.UseCallStack,
		}
	}
	return json.Marshal(stored)
}

func (store *UAFCorpusStore) Entries() ([]*fuzzer.UAFCorpusEntry, error) {
	if store == nil || store.db == nil {
		return nil, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entries := make([]*fuzzer.UAFCorpusEntry, 0, len(store.db.Records))
	for _, rec := range store.db.Records {
		if len(rec.Val) == 0 {
			continue
		}
		entry, err := store.deserialize(rec.Val)
		if err != nil {
			log.Errorf("failed to deserialize uaf corpus entry: %v", err)
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
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
		CallIdx:       stored.CallIdx,
		PairBasicInfo: stored.Pair,
		Signals:       sliceToSignal(stored.Signals),
		Barrier:       stored.Barrier,
		Timestamp:     stored.Timestamp,
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
	return entry, nil
}

func isZeroMayUAFPair(pair ddrd.MayUAFPair) bool {
	return pair.FreeAccessName == 0 && pair.UseAccessName == 0 &&
		pair.FreeCallStack == 0 && pair.UseCallStack == 0
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
