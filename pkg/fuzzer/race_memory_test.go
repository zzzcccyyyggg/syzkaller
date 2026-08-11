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

func TestNewUAFModeCanDisableHistoryBuffer(t *testing.T) {
	enabled := newUAFMode(&Fuzzer{Config: &Config{ModeUAF: true}})
	if enabled == nil || enabled.historyBuffer == nil {
		t.Fatal("expected default UAF mode to keep replay history enabled")
	}

	disabled := newUAFMode(&Fuzzer{Config: &Config{
		ModeUAF:           true,
		DisableUAFHistory: true,
	}})
	if disabled == nil {
		t.Fatal("expected UAF mode to initialize")
	}
	if disabled.historyBuffer != nil {
		t.Fatal("expected replay history buffer to be disabled")
	}
	if disabled.corpus == nil || disabled.entries == nil || disabled.pairs == nil {
		t.Fatal("expected race corpus bookkeeping to remain enabled")
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

func TestEnqueueSeedPreparesRestoredBarrierForRaceCollection(t *testing.T) {
	target, err := getTestTarget()
	if err != nil {
		t.Fatal(err)
	}
	p1, err := target.Deserialize([]byte("syz_test_fuzzer1()\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := target.Deserialize([]byte("syz_test_fuzzer1()\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}

	u := &uafMode{
		fuzzer: &Fuzzer{Config: &Config{
			ModeUAF:               true,
			BarrierMode:           true,
			BarrierMask:           0x3,
			NormalThresholdMicros: 2500,
		}},
		queue: &queue.PlainQueue{},
	}
	seed := &barrierSeed{
		entry: &UAFCorpusEntry{
			Programs: []*prog.Prog{p1, p2},
			Barrier:  BarrierSnapshot{Participants: 0x3},
		},
		execOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		synced:   true,
	}

	u.enqueueSeed(seed)
	req := u.queue.Next()
	if req == nil {
		t.Fatal("expected restored seed to be enqueued")
	}
	if !req.Barrier || len(req.BarrierPrograms) != 2 {
		t.Fatalf("queued request barrier=%v programs=%d, want barrier with 2 programs",
			req.Barrier, len(req.BarrierPrograms))
	}
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectDdrdUaf == 0 {
		t.Fatal("restored barrier seed must collect DDRD UAF pairs")
	}
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectDdrdRace != 0 {
		t.Fatal("restored UAF barrier seed must not use race-only collection")
	}
	if req.TimingThresholdUs != 2500 {
		t.Fatalf("queued timing threshold = %d, want 2500", req.TimingThresholdUs)
	}
}

func TestHandleDiscoveredBarrierPairsBypassesSoloFilterByDefault(t *testing.T) {
	target, err := getTestTarget()
	if err != nil {
		t.Fatal(err)
	}
	p1, err := target.Deserialize([]byte("syz_test_fuzzer1()\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := target.Deserialize([]byte("syz_test_fuzzer1()\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}

	req := &queue.Request{
		Prog:     p1,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
	}
	req.SetBarrier(0x3)
	if err := req.SetBarrierPrograms([]*prog.Prog{p1, p2}); err != nil {
		t.Fatal(err)
	}

	persisted := 0
	fuzzer := &Fuzzer{
		Config: &Config{
			NormalThresholdMicros: 2500,
			PersistUAFCorpusEntry: func(entry *UAFCorpusEntry) error {
				persisted++
				if entry == nil || entry.PairID() == 0 {
					t.Fatal("expected persisted entry with pair id")
				}
				if len(entry.Programs) != 2 {
					t.Fatalf("persisted entry has %d programs, want 2", len(entry.Programs))
				}
				if entry.Source != SourceFuzz {
					t.Fatalf("persisted source = %v, want SourceFuzz", entry.Source)
				}
				return nil
			},
		},
		target: target,
	}
	u := &uafMode{
		fuzzer:  fuzzer,
		queue:   &queue.PlainQueue{},
		entries: make(map[string]*barrierSeed),
		corpus:  newUAFCorpus(10),
		pairs:   make(map[uint64]struct{}),
	}
	fuzzer.uaf = u

	fuzzer.handleDiscoveredBarrierPairs(req, &queue.Result{
		Executor:         queue.ExecutorID{VM: 1},
		BarrierGroupID:   42,
		BarrierGroupSize: 2,
	}, []*ddrd.MayUAFPair{
		testMayUAFPair(0x10, 0x20, 0x100, 0x200),
	}, SourceFuzz)

	if persisted != 0 {
		t.Fatalf("persist callback called %d times, want 0; persistence should be batched", persisted)
	}
	if got := len(u.entries); got != 1 {
		t.Fatalf("got %d UAF entries, want 1", got)
	}
	pending := fuzzer.PendingUAFCorpusEntries()
	if len(pending) != 1 {
		t.Fatalf("got %d pending entries, want 1", len(pending))
	}
	if pending[0].PairID() == 0 {
		t.Fatal("expected pending entry with pair id")
	}
	if len(pending[0].Programs) != 2 {
		t.Fatalf("pending entry has %d programs, want 2", len(pending[0].Programs))
	}
	if pending[0].Source != SourceFuzz {
		t.Fatalf("pending source = %v, want SourceFuzz", pending[0].Source)
	}
	if got := u.corpus.GetVarNamePairCount(0x10, 0x20); got != 1 {
		t.Fatalf("got varname pair count %d, want 1", got)
	}
	queued := u.queue.Next()
	if queued == nil {
		t.Fatal("expected direct path to enqueue a validation request")
	}
	if !queued.Barrier || len(queued.BarrierPrograms) != 2 {
		t.Fatalf("queued request barrier=%v programs=%d, want barrier with 2 programs",
			queued.Barrier, len(queued.BarrierPrograms))
	}
	if queued.TimingThresholdUs != 2500 {
		t.Fatalf("queued timing threshold = %d, want 2500", queued.TimingThresholdUs)
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
