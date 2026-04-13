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

	added, err := store.Add([]*fuzzer.UAFCorpusEntry{entry})
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if added != 1 {
		t.Fatalf("unexpected add count %d", added)
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
	if len(got.Pairs) != len(entry.Pairs) {
		t.Fatalf("pairs length mismatch: got %d want %d", len(got.Pairs), len(entry.Pairs))
	}
	for i, want := range entry.Pairs {
		gotPair := got.Pairs[i]
		if gotPair == nil {
			t.Fatalf("missing pair at %d", i)
		}
		if *gotPair != *want {
			t.Fatalf("pair %d mismatch: got=%+v want=%+v", i, *gotPair, *want)
		}
	}
	if got.Profile.FreeAccessName != entry.PairBasicInfo.FreeAccessName {
		t.Fatalf("free access mismatch: got %x want %x", got.Profile.FreeAccessName, entry.PairBasicInfo.FreeAccessName)
	}
	if got.Profile.UseAccessName != entry.PairBasicInfo.UseAccessName {
		t.Fatalf("use access mismatch: got %x want %x", got.Profile.UseAccessName, entry.PairBasicInfo.UseAccessName)
	}
	if got.Profile.FreeCallStack != entry.PairBasicInfo.FreeCallStack {
		t.Fatalf("free callstack mismatch: got %x want %x", got.Profile.FreeCallStack, entry.PairBasicInfo.FreeCallStack)
	}
	if got.Profile.UseCallStack != entry.PairBasicInfo.UseCallStack {
		t.Fatalf("use callstack mismatch: got %x want %x", got.Profile.UseCallStack, entry.PairBasicInfo.UseCallStack)
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
