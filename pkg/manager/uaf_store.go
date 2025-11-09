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
	Program   []byte                 `json:"program"`
	CallIdx   int                    `json:"call_idx"`
	Pair      ddrd.MayUAFPair        `json:"pair"`
	Signals   []uint64               `json:"signals,omitempty"`
	Barrier   fuzzer.BarrierSnapshot `json:"barrier"`
	Timestamp time.Time              `json:"timestamp"`
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
	if entry.Prog != nil {
		stored.Program = entry.Prog.Serialize()
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
	if store.target != nil && len(stored.Program) != 0 {
		progObj, err := store.target.Deserialize(stored.Program, prog.NonStrict)
		if err != nil {
			return nil, err
		}
		entry.Prog = progObj
	}
	return entry, nil
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
