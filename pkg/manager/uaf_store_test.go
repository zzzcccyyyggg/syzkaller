package manager

import (
	"math/rand"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/prog"
)

func TestUAFCorpusStoreProgramsAndPlan(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}

	store, err := NewUAFCorpusStore(t.TempDir(), target)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("failed to close store: %v", cerr)
		}
	})

	ct := target.DefaultChoiceTable()
	progMain := target.Generate(rand.NewSource(1), 2, ct)
	progAlt := target.Generate(rand.NewSource(2), 2, ct)

	signal := uint64(0xdeadbeef)
	primary := &ddrd.MayUAFPair{
		Signal:         signal,
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
	}
	secondary := &ddrd.MayUAFPair{
		Signal:         signal + 1,
		FreeAccessName: 0x11,
		UseAccessName:  0x21,
		FreeCallStack:  0x31,
		UseCallStack:   0x41,
	}
	pairs := []*ddrd.MayUAFPair{primary, secondary}
	entry := &fuzzer.UAFCorpusEntry{
		Prog:          progMain.Clone(),
		Programs:      []*prog.Prog{progMain.Clone(), progAlt.Clone()},
		PairBasicInfo: *primary,
		Pairs:         pairs,
		Signals:       ddrd.FromUAFPairs(pairs, ddrd.UAFSignalPrioHigh),
		Barrier:       fuzzer.BarrierSnapshot{Participants: 0x3, ProcList: []int{0, 1}},
		ReplayPlan: fuzzer.UAFCorpusReplayPlan{
			DelaysMicros: []int64{1500, 2500},
		},
		Timestamp: time.Unix(0, 1234),
	}

	refs, err := store.AddWithRefs([]*fuzzer.UAFCorpusEntry{entry})
	if err != nil {
		t.Fatalf("AddWithRefs failed: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("unexpected add count %d", len(refs))
	}

	loaded, err := store.Entries()
	if err != nil {
		t.Fatalf("Entries failed: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("unexpected entry count %d", len(loaded))
	}

	got := loaded[0]
	if got.Prog != nil {
		t.Fatalf("expected primary program to be omitted when barrier programs are persisted")
	}
	if len(got.Programs) != 2 {
		t.Fatalf("expected 2 barrier programs, got %d", len(got.Programs))
	}
	for idx, expect := range entry.Programs {
		if expect == nil {
			if got.Programs[idx] != nil {
				t.Fatalf("expected nil program at %d", idx)
			}
			continue
		}
		if got.Programs[idx] == nil {
			t.Fatalf("missing program at %d", idx)
		}
		want := expect.Serialize()
		have := got.Programs[idx].Serialize()
		if string(want) != string(have) {
			t.Fatalf("program %d mismatch", idx)
		}
	}
	if len(got.ReplayPlan.DelaysMicros) != len(entry.ReplayPlan.DelaysMicros) {
		t.Fatalf("replay plan length mismatch: got %d want %d", len(got.ReplayPlan.DelaysMicros), len(entry.ReplayPlan.DelaysMicros))
	}
	for i, delay := range entry.ReplayPlan.DelaysMicros {
		if got.ReplayPlan.DelaysMicros[i] != delay {
			t.Fatalf("delay[%d]=%d want %d", i, got.ReplayPlan.DelaysMicros[i], delay)
		}
	}
	if len(got.Pairs) != 0 {
		t.Fatalf("heavy corpus records must not carry pair details, got %d pairs", len(got.Pairs))
	}
	if !got.Profile.IsZero() {
		t.Fatalf("heavy corpus records must not carry pair profile: %+v", got.Profile)
	}
	reader := NewStreamingUAFCorpusReader(store.path, target)
	materialized, _, err := reader.LoadEntryByKey(refs[0].ID, primary)
	if err != nil {
		t.Fatalf("LoadEntryByKey failed: %v", err)
	}
	if materialized == nil {
		t.Fatalf("materialized entry is nil")
	}
	if len(materialized.Pairs) != 1 || materialized.Pairs[0] == nil || *materialized.Pairs[0] != *primary {
		t.Fatalf("materialized pair mismatch: got=%+v want=%+v", materialized.Pairs, primary)
	}
	if materialized.Profile.FreeAccessName != entry.PairBasicInfo.FreeAccessName {
		t.Fatalf("free access mismatch: got %x want %x", materialized.Profile.FreeAccessName, entry.PairBasicInfo.FreeAccessName)
	}
}

func TestUAFCorpusStoreIterateEntriesBatched(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}

	store, err := NewUAFCorpusStore(t.TempDir(), target)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("failed to close store: %v", cerr)
		}
	})

	ct := target.DefaultChoiceTable()
	var entries []*fuzzer.UAFCorpusEntry
	for i := 0; i < 5; i++ {
		p := target.Generate(rand.NewSource(int64(i+1)), 2, ct)
		pair := &ddrd.MayUAFPair{
			Signal:         uint64(0x100 + i),
			FreeAccessName: uint64(0x10 + i),
			UseAccessName:  uint64(0x20 + i),
			FreeCallStack:  uint64(0x30 + i),
			UseCallStack:   uint64(0x40 + i),
		}
		entries = append(entries, &fuzzer.UAFCorpusEntry{
			Prog:          p.Clone(),
			Programs:      []*prog.Prog{p.Clone()},
			PairBasicInfo: *pair,
			Pairs:         []*ddrd.MayUAFPair{pair},
			Timestamp:     time.Unix(0, int64(i+1)),
		})
	}

	added, err := store.Add(entries)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if added != len(entries) {
		t.Fatalf("unexpected add count %d", added)
	}

	var batchSizes []int
	var total int
	err = store.IterateEntriesBatched(2, func(batch []*fuzzer.UAFCorpusEntry) bool {
		batchSizes = append(batchSizes, len(batch))
		total += len(batch)
		return true
	})
	if err != nil {
		t.Fatalf("IterateEntriesBatched failed: %v", err)
	}
	if total != len(entries) {
		t.Fatalf("iterated %d entries, want %d", total, len(entries))
	}
	if len(batchSizes) != 3 || batchSizes[0] != 2 || batchSizes[1] != 2 || batchSizes[2] != 1 {
		t.Fatalf("unexpected batch sizes: %v", batchSizes)
	}
}

func TestUAFCorpusStoreReloadDiscardsHeavyValues(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}

	store, err := NewUAFCorpusStore(t.TempDir(), target)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("failed to close store: %v", cerr)
		}
	})

	pair := &ddrd.MayUAFPair{
		Signal:         0x200,
		FreeAccessName: 0x21,
		UseAccessName:  0x22,
		FreeCallStack:  0x23,
		UseCallStack:   0x24,
	}
	entry := &fuzzer.UAFCorpusEntry{
		PairBasicInfo: *pair,
		Pairs:         []*ddrd.MayUAFPair{pair},
		ReplayHistory: []*fuzzer.BarrierExecutionRecord{
			{Timestamp: time.Unix(0, 10), GroupID: 1},
			{Timestamp: time.Unix(0, 11), GroupID: 2},
		},
		Timestamp: time.Unix(0, 123),
	}

	refs, err := store.AddWithRefs([]*fuzzer.UAFCorpusEntry{entry})
	if err != nil {
		t.Fatalf("AddWithRefs failed: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("unexpected ref count %d", len(refs))
	}

	rec, ok := store.db.Records[refs[0].ID]
	if !ok {
		t.Fatalf("missing record %q", refs[0].ID)
	}
	if len(rec.Val) != 0 {
		t.Fatalf("expected heavy value to be discarded after add, got %d bytes", len(rec.Val))
	}

	if err := store.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	rec, ok = store.db.Records[refs[0].ID]
	if !ok {
		t.Fatalf("missing record %q after reload", refs[0].ID)
	}
	if len(rec.Val) != 0 {
		t.Fatalf("expected heavy value to stay discarded after reload, got %d bytes", len(rec.Val))
	}

	reader := NewStreamingUAFCorpusReader(store.path, target)
	materialized, _, err := reader.LoadEntryByKey(refs[0].ID, pair)
	if err != nil {
		t.Fatalf("LoadEntryByKey failed: %v", err)
	}
	if materialized == nil {
		t.Fatalf("materialized entry is nil")
	}
	if len(materialized.ReplayHistory) != len(entry.ReplayHistory) {
		t.Fatalf("history length mismatch after reload: got %d want %d", len(materialized.ReplayHistory), len(entry.ReplayHistory))
	}
}
