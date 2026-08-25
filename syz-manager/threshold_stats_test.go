package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	managerpkg "github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
)

func TestWriteThresholdValidatorQueueStatsUsesPairRecords(t *testing.T) {
	workdir := t.TempDir()
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}
	queue, err := managerpkg.NewUAFValidateQueueStore(workdir, target)
	if err != nil {
		t.Fatalf("failed to create validation queue: %v", err)
	}
	t.Cleanup(func() {
		if err := queue.Close(); err != nil {
			t.Fatalf("failed to close validation queue: %v", err)
		}
	})

	records := []*managerpkg.RacePairRecord{
		{PairKey: "pair-a", PreferredCorpusRecordID: "corpus-a"},
		{PairKey: "pair-b", PreferredCorpusRecordID: "corpus-b"},
	}
	results, err := queue.EnqueueRecords(records)
	if err != nil {
		t.Fatalf("failed to enqueue records: %v", err)
	}
	if len(results) != len(records) {
		t.Fatalf("enqueued %d records, want %d", len(results), len(records))
	}

	mgr := &Manager{
		uafValidateQueue: queue,
		uafSharedWorkdir: workdir,
	}
	mgr.thresholdConsumedPairs.Store(3)
	mgr.writeThresholdValidatorQueueStats(time.Now().Add(-time.Minute), 1)

	state, err := ddrd.ReadThresholdState(workdir)
	if err != nil {
		t.Fatalf("failed to read threshold state: %v", err)
	}
	got := state.Validator
	if got.CounterUnit != ddrd.ThresholdCounterUnitQueuePair {
		t.Fatalf("counter unit = %q, want %q", got.CounterUnit, ddrd.ThresholdCounterUnitQueuePair)
	}
	if got.PendingCount != 2 || got.ProcessedCount != 3 || got.SuccessCount != 1 {
		t.Fatalf("unexpected validator stats: %+v", got)
	}
}

func TestThresholdPairStatsCountStartedAndExcludeProcessing(t *testing.T) {
	workdir := t.TempDir()
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}
	pairIndex, err := managerpkg.NewRacePairIndexStore(workdir)
	if err != nil {
		t.Fatalf("failed to create pair index: %v", err)
	}
	queue, err := managerpkg.NewUAFValidateQueueStore(workdir, target)
	if err != nil {
		t.Fatalf("failed to create validation queue: %v", err)
	}
	t.Cleanup(func() {
		_ = queue.Close()
		_ = pairIndex.Close()
	})

	makeEntry := func(free, use, freeStack, useStack uint64) *fuzzer.UAFCorpusEntry {
		pair := ddrd.MayUAFPair{
			FreeAccessName: free, UseAccessName: use,
			FreeCallStack: freeStack, UseCallStack: useStack,
		}
		return &fuzzer.UAFCorpusEntry{PairBasicInfo: pair, Pairs: []*ddrd.MayUAFPair{&pair}}
	}
	var records []*managerpkg.RacePairRecord
	for i, entry := range []*fuzzer.UAFCorpusEntry{
		makeEntry(0x10, 0x20, 0x30, 0x40),
		makeEntry(0x11, 0x21, 0x31, 0x41),
	} {
		observed, err := pairIndex.ObserveEntry(entry, fmt.Sprintf("corpus-%d", i))
		if err != nil || len(observed) != 1 {
			t.Fatalf("ObserveEntry %d = %d records, %v", i, len(observed), err)
		}
		records = append(records, observed[0])
	}
	results, err := queue.EnqueueRecords(records)
	if err != nil || len(results) != 2 {
		t.Fatalf("EnqueueRecords = %d results, %v", len(results), err)
	}
	queued := make(map[string]uint64)
	for _, result := range results {
		queued[result.PairKey] = result.Seq
	}
	if err := pairIndex.MarkQueuedBatch(queued); err != nil {
		t.Fatalf("MarkQueuedBatch failed: %v", err)
	}

	mgr := &Manager{
		cfg:              &mgrconfig.Config{},
		uafValidateQueue: queue,
		uafPairIndex:     pairIndex,
		uafSharedWorkdir: workdir,
	}
	started := &fuzzer.UAFCorpusEntry{
		ValidateQueueKeys: []string{results[0].Key},
		ValidatePairKeys:  []string{results[0].PairKey},
	}
	mgr.recordThresholdValidationTaskStarted(started)
	mgr.recordThresholdValidationTaskStarted(started)
	mgr.writeThresholdValidatorQueueStats(time.Now().Add(-time.Minute), 0)

	state, err := ddrd.ReadThresholdState(workdir)
	if err != nil {
		t.Fatalf("failed to read threshold state: %v", err)
	}
	if got := state.Validator; got.PendingCount != 1 || got.ProcessedCount != 1 {
		t.Fatalf("started accounting = %+v, want pending=1 processed=1", got)
	}
}

func TestWriteThresholdValidatorQueueStatsUsesVarNameFamilies(t *testing.T) {
	workdir := t.TempDir()
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}
	queue, err := managerpkg.NewUAFValidateQueueStore(workdir, target)
	if err != nil {
		t.Fatalf("failed to create validation queue: %v", err)
	}
	t.Cleanup(func() {
		if err := queue.Close(); err != nil {
			t.Fatalf("failed to close validation queue: %v", err)
		}
	})

	pairA := ddrd.MayUAFPair{FreeAccessName: 0x10, UseAccessName: 0x20, FreeCallStack: 0x30, UseCallStack: 0x40}
	pairB := ddrd.MayUAFPair{FreeAccessName: 0x10, UseAccessName: 0x20, FreeCallStack: 0x31, UseCallStack: 0x41}
	records := []*managerpkg.RacePairRecord{
		{PairKey: ddrd.RacePairKeyString(&pairA), Pair: pairA, PreferredCorpusRecordID: "corpus-a"},
		{PairKey: ddrd.RacePairKeyString(&pairB), Pair: pairB, PreferredCorpusRecordID: "corpus-b"},
	}
	if _, err := queue.EnqueueRecords(records); err != nil {
		t.Fatalf("failed to enqueue records: %v", err)
	}

	mgr := &Manager{
		cfg: &mgrconfig.Config{Experimental: mgrconfig.Experimental{
			DynamicThresholdCounterUnit: ddrd.ThresholdCounterUnitQueueFamily,
		}},
		uafValidateQueue: queue,
		uafSharedWorkdir: workdir,
	}
	mgr.thresholdConsumedFamilies.Store(3)
	mgr.writeThresholdValidatorQueueStats(time.Now().Add(-time.Minute), 1)

	state, err := ddrd.ReadThresholdState(workdir)
	if err != nil {
		t.Fatalf("failed to read threshold state: %v", err)
	}
	got := state.Validator
	if got.CounterUnit != ddrd.ThresholdCounterUnitQueueFamily {
		t.Fatalf("counter unit = %q, want %q", got.CounterUnit, ddrd.ThresholdCounterUnitQueueFamily)
	}
	if got.PendingCount != 1 || got.ProcessedCount != 3 || got.SuccessCount != 1 {
		t.Fatalf("unexpected validator stats: %+v", got)
	}
}

func TestFilterValidationGroupPairsUsesQueuedPairsAsPG(t *testing.T) {
	original := &ddrd.MayUAFPair{
		FreeAccessName: 0x10, UseAccessName: 0x20,
		FreeCallStack: 0x30, UseCallStack: 0x40,
		TimeDiff: 500_000,
	}
	unrelated := &ddrd.MayUAFPair{
		FreeAccessName: 0x50, UseAccessName: 0x60,
		FreeCallStack: 0x70, UseCallStack: 0x80,
	}
	entry := &fuzzer.UAFCorpusEntry{Pairs: []*ddrd.MayUAFPair{unrelated}}
	group := &managerpkg.QueuedUAFCorpusGroup{Pairs: []ddrd.MayUAFPair{*original}}

	filterValidationGroupPairs(entry, group)
	if len(entry.Pairs) != 1 || entry.Pairs[0] == nil {
		t.Fatalf("materialized P_G=%v, want one queued pair", entry.Pairs)
	}
	if got := entry.Pairs[0]; got.FreeAccessName != original.FreeAccessName ||
		got.UseAccessName != original.UseAccessName ||
		got.FreeCallStack != original.FreeCallStack || got.UseCallStack != original.UseCallStack ||
		got.TimeDiff != original.TimeDiff {
		t.Fatalf("materialized pair=%+v, want %+v", got, original)
	}
	if entry.PairBasicInfo != *original {
		t.Fatalf("primary pair=%+v, want %+v", entry.PairBasicInfo, *original)
	}
}
