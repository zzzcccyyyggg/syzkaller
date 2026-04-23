package fuzzer

import (
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/prog"
)

func testMayUAFPair(freeName, useName, freeStack, useStack uint64) *ddrd.MayUAFPair {
	return &ddrd.MayUAFPair{
		FreeAccessName: freeName,
		UseAccessName:  useName,
		FreeCallStack:  freeStack,
		UseCallStack:   useStack,
	}
}

func TestUAFCorpusAddSeedPreservesVarnameAndStackTracking(t *testing.T) {
	uc := newUAFCorpus(2)
	varID := varnamePairID(0x10, 0x20)

	entry1 := &UAFCorpusEntry{
		Pairs: []*ddrd.MayUAFPair{
			testMayUAFPair(0x10, 0x20, 0x100, 0x200),
		},
		ReplayHistory: []*BarrierExecutionRecord{{Timestamp: time.Now()}},
	}
	uc.addSeed("seed1", entry1, SourceFuzz)
	if got := len(uc.seeds); got != 1 {
		t.Fatalf("got %d seeds, want 1", got)
	}
	if !uc.seeds["seed1"].HasReplayHistory {
		t.Fatalf("expected replay history metadata to be preserved")
	}
	if got := uc.varnameStackCounts[varID]; got != 1 {
		t.Fatalf("got stack count %d, want 1", got)
	}
	if got := len(uc.pairs); got != 1 {
		t.Fatalf("got %d unique pairs, want 1", got)
	}

	entry2 := &UAFCorpusEntry{
		Pairs: []*ddrd.MayUAFPair{
			testMayUAFPair(0x10, 0x20, 0x300, 0x400),
		},
	}
	uc.addSeed("seed2", entry2, SourceFuzz)
	if got := uc.varnameStackCounts[varID]; got != 2 {
		t.Fatalf("got stack count %d after new stack, want 2", got)
	}
	if got := len(uc.pairs); got != 2 {
		t.Fatalf("got %d unique pairs after new stack, want 2", got)
	}

	entry3 := &UAFCorpusEntry{
		Pairs: []*ddrd.MayUAFPair{
			testMayUAFPair(0x10, 0x20, 0x300, 0x400),
		},
	}
	uc.addSeed("seed3", entry3, SourceFuzz)
	if got := uc.varnameStackCounts[varID]; got != 2 {
		t.Fatalf("duplicate stack changed count to %d, want 2", got)
	}
	if got := len(uc.pairs); got != 2 {
		t.Fatalf("duplicate stack changed pair count to %d, want 2", got)
	}

	entry4 := &UAFCorpusEntry{
		Pairs: []*ddrd.MayUAFPair{
			testMayUAFPair(0x10, 0x20, 0x500, 0x600),
		},
	}
	uc.addSeed("seed4", entry4, SourceFuzz)
	if got := uc.varnameStackCounts[varID]; got != 2 {
		t.Fatalf("stack limit changed count to %d, want 2", got)
	}
	if got := len(uc.pairs); got != 2 {
		t.Fatalf("stack limit changed pair count to %d, want 2", got)
	}
}

func TestEnqueueSeedFallsBackToBarrierPrograms(t *testing.T) {
	target, err := getTestTarget()
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("syz_test_fuzzer1()\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}

	u := &uafMode{
		fuzzer: &Fuzzer{Config: &Config{}},
		queue:  &queue.PlainQueue{},
	}
	seed := &barrierSeed{
		entry: &UAFCorpusEntry{
			Programs: []*prog.Prog{p},
		},
	}

	u.enqueueSeed(seed)
	req := u.queue.Next()
	if req == nil || req.Prog == nil {
		t.Fatal("expected seed enqueue to fall back to first barrier program")
	}
	if seed.entry != nil {
		t.Fatal("expected non-syncable seed entry to be released after enqueue")
	}
}

func TestPendingEntriesCompactsSyncedSeeds(t *testing.T) {
	entry := &UAFCorpusEntry{
		Pairs: []*ddrd.MayUAFPair{
			testMayUAFPair(0x10, 0x20, 0x100, 0x200),
		},
	}
	u := &uafMode{
		entries: map[string]*barrierSeed{
			"seed": {
				entry:    entry,
				syncable: true,
				synced:   false,
			},
		},
	}

	pending := u.pendingEntries()
	if len(pending) != 1 {
		t.Fatalf("got %d pending entries, want 1", len(pending))
	}
	if pending[0] == entry {
		t.Fatal("expected pending entry to be cloned")
	}
	seed := u.entries["seed"]
	if !seed.synced {
		t.Fatal("expected seed to be marked synced")
	}
	if seed.entry != nil {
		t.Fatal("expected synced seed entry to be released")
	}
}

func TestTryPersistSeedMarksSynced(t *testing.T) {
	called := 0
	u := &uafMode{
		fuzzer: &Fuzzer{
			Config: &Config{
				PersistUAFCorpusEntry: func(entry *UAFCorpusEntry) error {
					called++
					if entry == nil || entry.PairID() == 0 {
						t.Fatal("expected non-nil entry with pair id")
					}
					return nil
				},
			},
		},
	}
	seed := &barrierSeed{
		entry: &UAFCorpusEntry{
			PairBasicInfo: *testMayUAFPair(0x10, 0x20, 0x100, 0x200),
		},
		syncable: true,
	}

	u.tryPersistSeed(seed)
	if called != 1 {
		t.Fatalf("persist callback called %d times, want 1", called)
	}
	if !seed.synced {
		t.Fatal("expected seed to be marked synced after successful persist")
	}
}

func TestIsThreadBarrierRequestUsesExplicitMarker(t *testing.T) {
	req := &queue.Request{
		ExecOpts: flatrpc.ExecOpts{
			ExecFlags: flatrpc.ExecFlagThreaded,
		},
	}
	if isThreadBarrierRequest(req) {
		t.Fatal("plain threaded execution must not be treated as thread-barrier")
	}

	req.ThreadBarrier = true
	if !isThreadBarrierRequest(req) {
		t.Fatal("explicit thread-barrier marker should be honored")
	}
}

func TestTimingExplorationCandidatesUseUAFCorpusNewness(t *testing.T) {
	u := &uafMode{
		corpus: newUAFCorpus(10),
	}

	pairA1 := testMayUAFPair(0x10, 0x20, 0x100, 0x200)
	pairA2 := testMayUAFPair(0x10, 0x20, 0x300, 0x400)
	pairB := testMayUAFPair(0x30, 0x40, 0x500, 0x600)

	candidates := u.timingExplorationCandidates([]*ddrd.MayUAFPair{pairA1, pairA2, pairB})
	if len(candidates) != 2 {
		t.Fatalf("got %d candidates for fresh corpus, want 2", len(candidates))
	}

	entry := &UAFCorpusEntry{
		Pairs: []*ddrd.MayUAFPair{pairA1},
	}
	u.corpus.addSeed("seed-a", entry, SourceFuzz)

	candidates = u.timingExplorationCandidates([]*ddrd.MayUAFPair{pairA1, pairA2, pairB})
	if len(candidates) != 1 {
		t.Fatalf("got %d candidates after existing varname pair, want 1", len(candidates))
	}
	if candidates[0].FreeAccessName != pairB.FreeAccessName || candidates[0].UseAccessName != pairB.UseAccessName {
		t.Fatal("expected only unseen varname pair to remain eligible for timing exploration")
	}
}
