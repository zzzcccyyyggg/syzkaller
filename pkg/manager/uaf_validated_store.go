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
)

type UAFValidationOutcome string

const (
	OutcomeUnknown   UAFValidationOutcome = "unknown"
	OutcomeConfirmed UAFValidationOutcome = "confirmed"
	OutcomeFailed    UAFValidationOutcome = "failed"
)

type UAFValidationEntry struct {
	Profile     fuzzer.UAFPairProfile
	Barrier     fuzzer.BarrierSnapshot
	ReplayPlan  fuzzer.UAFCorpusReplayPlan
	Outcome     UAFValidationOutcome
	Attempts    int
	LastAttempt time.Time
	Notes       string
	RepeatCount int
	StablePairs []ddrd.MayUAFPair
	LastPairs   []ddrd.MayUAFPair
}

type UAFValidatedStore struct {
	mu sync.Mutex
	db *db.DB
}

type storedUAFValidationEntry struct {
	Profile     storedPairProfile      `json:"profile"`
	Barrier     fuzzer.BarrierSnapshot `json:"barrier"`
	ReplayPlan  *storedReplayPlan      `json:"replay_plan,omitempty"`
	Outcome     UAFValidationOutcome   `json:"outcome"`
	Attempts    int                    `json:"attempts"`
	Timestamp   time.Time              `json:"timestamp"`
	Notes       string                 `json:"notes,omitempty"`
	RepeatCount int                    `json:"repeat_count,omitempty"`
	StablePairs []storedUAFPair        `json:"stable_pairs,omitempty"`
	LastPairs   []storedUAFPair        `json:"last_pairs,omitempty"`
}

type storedUAFPair struct {
	FreeAccessName uint64 `json:"free_access_name"`
	UseAccessName  uint64 `json:"use_access_name"`
	FreeCallStack  uint64 `json:"free_call_stack"`
	UseCallStack   uint64 `json:"use_call_stack"`
	Signal         uint64 `json:"signal"`
	TimeDiff       uint64 `json:"time_diff"`
	FreeSN         int32  `json:"free_sn"`
	UseSN          int32  `json:"use_sn"`
	LockType       uint32 `json:"lock_type"`
	UseAccessType  uint32 `json:"use_access_type"`
}

func NewUAFValidatedStore(workdir string) (*UAFValidatedStore, error) {
	path := filepath.Join(workdir, "uaf-validated.db")
	storeDB, err := db.Open(path, true)
	if err != nil {
		if storeDB == nil {
			return nil, fmt.Errorf("failed to open uaf validated db: %w", err)
		}
	}
	return &UAFValidatedStore{db: storeDB}, nil
}

func (store *UAFValidatedStore) Close() error {
	if store == nil || store.db == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.db.Flush()
}

func (store *UAFValidatedStore) key(profile fuzzer.UAFPairProfile) string {
	return fmt.Sprintf("%016x-%016x-%016x-%016x",
		profile.FreeAccessName,
		profile.UseAccessName,
		profile.FreeCallStack,
		profile.UseCallStack,
	)
}

func (store *UAFValidatedStore) Upsert(entry *UAFValidationEntry) error {
	if store == nil || store.db == nil || entry == nil {
		return nil
	}
	if entry.Outcome == "" {
		entry.Outcome = OutcomeUnknown
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := store.key(entry.Profile)
	blob, err := serializeUAFValidationEntry(entry)
	if err != nil {
		return err
	}
	seq := uint64(entry.LastAttempt.UnixNano())
	store.db.Save(key, blob, seq)
	return store.db.Flush()
}

func (store *UAFValidatedStore) Entries() ([]*UAFValidationEntry, error) {
	if store == nil || store.db == nil {
		return nil, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entries := make([]*UAFValidationEntry, 0, len(store.db.Records))
	for _, rec := range store.db.Records {
		if len(rec.Val) == 0 {
			continue
		}
		entry, err := deserializeUAFValidationEntry(rec.Val)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].LastAttempt.Before(entries[j].LastAttempt)
	})
	return entries, nil
}

func serializeUAFValidationEntry(entry *UAFValidationEntry) ([]byte, error) {
	stored := storedUAFValidationEntry{
		Profile: storedPairProfile{
			FreeAccessName: entry.Profile.FreeAccessName,
			UseAccessName:  entry.Profile.UseAccessName,
			FreeCallStack:  entry.Profile.FreeCallStack,
			UseCallStack:   entry.Profile.UseCallStack,
		},
		Barrier:     entry.Barrier,
		Outcome:     entry.Outcome,
		Attempts:    entry.Attempts,
		Timestamp:   entry.LastAttempt,
		Notes:       entry.Notes,
		RepeatCount: entry.RepeatCount,
	}
	if !entry.ReplayPlan.IsZero() {
		stored.ReplayPlan = &storedReplayPlan{
			DelaysMicros: append([]int64(nil), entry.ReplayPlan.DelaysMicros...),
		}
	}
	if len(entry.StablePairs) != 0 {
		stored.StablePairs = convertPairsToStored(entry.StablePairs)
	}
	if len(entry.LastPairs) != 0 {
		stored.LastPairs = convertPairsToStored(entry.LastPairs)
	}
	return json.Marshal(stored)
}

func deserializeUAFValidationEntry(data []byte) (*UAFValidationEntry, error) {
	var stored storedUAFValidationEntry
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}
	entry := &UAFValidationEntry{
		Profile: fuzzer.UAFPairProfile{
			FreeAccessName: stored.Profile.FreeAccessName,
			UseAccessName:  stored.Profile.UseAccessName,
			FreeCallStack:  stored.Profile.FreeCallStack,
			UseCallStack:   stored.Profile.UseCallStack,
		},
		Barrier:     stored.Barrier,
		Outcome:     stored.Outcome,
		Attempts:    stored.Attempts,
		LastAttempt: stored.Timestamp,
		Notes:       stored.Notes,
		RepeatCount: stored.RepeatCount,
	}
	if stored.ReplayPlan != nil {
		entry.ReplayPlan = fuzzer.UAFCorpusReplayPlan{
			DelaysMicros: append([]int64(nil), stored.ReplayPlan.DelaysMicros...),
		}
	}
	if len(stored.StablePairs) != 0 {
		entry.StablePairs = convertPairsFromStored(stored.StablePairs)
	}
	if len(stored.LastPairs) != 0 {
		entry.LastPairs = convertPairsFromStored(stored.LastPairs)
	}
	return entry, nil
}

func convertPairsToStored(pairs []ddrd.MayUAFPair) []storedUAFPair {
	if len(pairs) == 0 {
		return nil
	}
	stored := make([]storedUAFPair, 0, len(pairs))
	for _, pair := range pairs {
		stored = append(stored, storedUAFPair{
			FreeAccessName: pair.FreeAccessName,
			UseAccessName:  pair.UseAccessName,
			FreeCallStack:  pair.FreeCallStack,
			UseCallStack:   pair.UseCallStack,
			Signal:         pair.Signal,
			TimeDiff:       pair.TimeDiff,
			FreeSN:         pair.FreeSN,
			UseSN:          pair.UseSN,
			LockType:       pair.LockType,
			UseAccessType:  pair.UseAccessType,
		})
	}
	return stored
}

func convertPairsFromStored(stored []storedUAFPair) []ddrd.MayUAFPair {
	if len(stored) == 0 {
		return nil
	}
	pairs := make([]ddrd.MayUAFPair, 0, len(stored))
	for _, entry := range stored {
		pairs = append(pairs, ddrd.MayUAFPair{
			FreeAccessName: entry.FreeAccessName,
			UseAccessName:  entry.UseAccessName,
			FreeCallStack:  entry.FreeCallStack,
			UseCallStack:   entry.UseCallStack,
			Signal:         entry.Signal,
			TimeDiff:       entry.TimeDiff,
			FreeSN:         entry.FreeSN,
			UseSN:          entry.UseSN,
			LockType:       entry.LockType,
			UseAccessType:  entry.UseAccessType,
		})
	}
	return pairs
}
