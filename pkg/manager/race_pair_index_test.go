package manager

import (
	"sync"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
)

func TestRacePairIndexStoreTracksPairStateByHash(t *testing.T) {
	store, err := NewRacePairIndexStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create pair index: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("failed to close pair index: %v", cerr)
		}
	})

	pair := &ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
	}
	entry := &fuzzer.UAFCorpusEntry{
		PairBasicInfo: *pair,
		Pairs:         []*ddrd.MayUAFPair{pair},
		Timestamp:     time.Unix(0, 1),
	}

	records, err := store.ObserveEntry(entry, "corpus-a")
	if err != nil {
		t.Fatalf("ObserveEntry failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	key := ddrd.RacePairKeyString(pair)
	if records[0].PairKey != key {
		t.Fatalf("pair key mismatch: got %q want %q", records[0].PairKey, key)
	}
	if !store.ShouldQueue(records[0]) {
		t.Fatalf("newly discovered pair should be queueable")
	}

	if err := store.MarkQueued(key, 123); err != nil {
		t.Fatalf("MarkQueued failed: %v", err)
	}
	queued, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if queued.Status != RacePairQueued || queued.LastQueueSeq != 123 {
		t.Fatalf("queued state mismatch: %+v", queued)
	}

	store.MarkPairValidated(*pair, []byte("validated"))
	validated, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get validated failed: %v", err)
	}
	if validated.Status != RacePairValidated || validated.ValidateSuccesses != 1 {
		t.Fatalf("validated state mismatch: %+v", validated)
	}
	if store.ShouldQueue(validated) {
		t.Fatalf("validated pair must not be queueable")
	}

	stats, err := store.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if stats.Total != 1 || stats.Validated != 1 || stats.Queueable != 0 || stats.WithCorpus != 1 {
		t.Fatalf("unexpected stats after validation: %+v", stats)
	}
}

func TestRacePairIndexStoreReloadPreventsStateRegression(t *testing.T) {
	workdir := t.TempDir()

	fuzzStore, err := NewRacePairIndexStore(workdir)
	if err != nil {
		t.Fatalf("failed to create fuzz-side pair index: %v", err)
	}
	t.Cleanup(func() {
		if cerr := fuzzStore.Close(); cerr != nil {
			t.Fatalf("failed to close fuzz-side pair index: %v", cerr)
		}
	})

	validateStore, err := NewRacePairIndexStore(workdir)
	if err != nil {
		t.Fatalf("failed to create validate-side pair index: %v", err)
	}
	t.Cleanup(func() {
		if cerr := validateStore.Close(); cerr != nil {
			t.Fatalf("failed to close validate-side pair index: %v", cerr)
		}
	})

	pair := &ddrd.MayUAFPair{
		FreeAccessName: 0x50,
		UseAccessName:  0x60,
		FreeCallStack:  0x70,
		UseCallStack:   0x80,
	}
	longHistory := []*fuzzer.BarrierExecutionRecord{
		{Timestamp: time.Unix(0, 10), GroupID: 1},
		{Timestamp: time.Unix(0, 11), GroupID: 2},
	}
	shortHistory := []*fuzzer.BarrierExecutionRecord{
		{Timestamp: time.Unix(0, 10), GroupID: 1},
	}
	entry := &fuzzer.UAFCorpusEntry{
		PairBasicInfo: *pair,
		Pairs:         []*ddrd.MayUAFPair{pair},
		ReplayHistory: longHistory,
		Timestamp:     time.Unix(0, 1),
	}

	records, err := fuzzStore.ObserveEntry(entry, "corpus-a")
	if err != nil {
		t.Fatalf("ObserveEntry failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("ObserveEntry returned %d records, want 1", len(records))
	}
	key := records[0].PairKey

	if err := fuzzStore.MarkQueued(key, 111); err != nil {
		t.Fatalf("MarkQueued failed: %v", err)
	}
	if err := validateStore.MarkProcessing(key); err != nil {
		t.Fatalf("MarkProcessing failed: %v", err)
	}

	seenAgain, err := fuzzStore.ObserveEntry(entry, "corpus-a")
	if err != nil {
		t.Fatalf("second ObserveEntry failed: %v", err)
	}
	if len(seenAgain) != 1 {
		t.Fatalf("second ObserveEntry returned %d records, want 1", len(seenAgain))
	}
	if seenAgain[0].Status != RacePairProcessing {
		t.Fatalf("status regressed after validate-side update: got %q want %q", seenAgain[0].Status, RacePairProcessing)
	}
	if fuzzStore.ShouldQueue(seenAgain[0]) {
		t.Fatalf("processing pair must not be queueable")
	}

	if err := validateStore.MarkProcessed(key); err != nil {
		t.Fatalf("MarkProcessed failed: %v", err)
	}

	cheaperEntry := &fuzzer.UAFCorpusEntry{
		PairBasicInfo: *pair,
		Pairs:         []*ddrd.MayUAFPair{pair},
		ReplayHistory: shortHistory,
		Timestamp:     time.Unix(0, 2),
	}
	reopened, err := fuzzStore.ObserveEntry(cheaperEntry, "corpus-b")
	if err != nil {
		t.Fatalf("ObserveEntry with cheaper history failed: %v", err)
	}
	if len(reopened) != 1 {
		t.Fatalf("ObserveEntry with cheaper history returned %d records, want 1", len(reopened))
	}
	if reopened[0].Status != RacePairDiscovered {
		t.Fatalf("processed pair should reopen on cheaper history: got %q want %q", reopened[0].Status, RacePairDiscovered)
	}
	if reopened[0].PreferredCorpusRecordID != "corpus-b" {
		t.Fatalf("preferred corpus mismatch: got %q want %q", reopened[0].PreferredCorpusRecordID, "corpus-b")
	}
	if reopened[0].PreferredHistoryRecords != len(shortHistory) {
		t.Fatalf("preferred history mismatch: got %d want %d", reopened[0].PreferredHistoryRecords, len(shortHistory))
	}
	if !fuzzStore.ShouldQueue(reopened[0]) {
		t.Fatalf("reopened pair should be queueable")
	}

	restartedStore, err := NewRacePairIndexStore(workdir)
	if err != nil {
		t.Fatalf("failed to reopen pair index: %v", err)
	}
	t.Cleanup(func() {
		if cerr := restartedStore.Close(); cerr != nil {
			t.Fatalf("failed to close reopened pair index: %v", cerr)
		}
	})

	persisted, err := restartedStore.Get(key)
	if err != nil {
		t.Fatalf("Get after restart failed: %v", err)
	}
	if persisted == nil {
		t.Fatalf("persisted record is nil")
	}
	if persisted.Status != RacePairDiscovered {
		t.Fatalf("persisted status mismatch: got %q want %q", persisted.Status, RacePairDiscovered)
	}
	if len(persisted.CorpusRecordIDs) != 2 {
		t.Fatalf("persisted corpus refs mismatch: got %d want 2", len(persisted.CorpusRecordIDs))
	}
	stats, err := restartedStore.Stats()
	if err != nil {
		t.Fatalf("Stats after restart failed: %v", err)
	}
	if stats.Total != 1 || stats.Discovered != 1 || stats.Queueable != 1 || stats.WithHistory != 1 {
		t.Fatalf("unexpected stats after restart: %+v", stats)
	}
}

func TestRacePairIndexStoreConcurrentWritersPreservePreferredRecord(t *testing.T) {
	workdir := t.TempDir()

	writerA, err := NewRacePairIndexStore(workdir)
	if err != nil {
		t.Fatalf("failed to create writerA pair index: %v", err)
	}
	t.Cleanup(func() {
		if cerr := writerA.Close(); cerr != nil {
			t.Fatalf("failed to close writerA pair index: %v", cerr)
		}
	})

	writerB, err := NewRacePairIndexStore(workdir)
	if err != nil {
		t.Fatalf("failed to create writerB pair index: %v", err)
	}
	t.Cleanup(func() {
		if cerr := writerB.Close(); cerr != nil {
			t.Fatalf("failed to close writerB pair index: %v", cerr)
		}
	})

	pair := &ddrd.MayUAFPair{
		FreeAccessName: 0x150,
		UseAccessName:  0x160,
		FreeCallStack:  0x170,
		UseCallStack:   0x180,
	}
	longEntry := &fuzzer.UAFCorpusEntry{
		PairBasicInfo: *pair,
		Pairs:         []*ddrd.MayUAFPair{pair},
		ReplayHistory: []*fuzzer.BarrierExecutionRecord{
			{Timestamp: time.Unix(0, 10), GroupID: 1},
			{Timestamp: time.Unix(0, 11), GroupID: 2},
		},
		Timestamp: time.Unix(0, 1),
	}
	shortEntry := &fuzzer.UAFCorpusEntry{
		PairBasicInfo: *pair,
		Pairs:         []*ddrd.MayUAFPair{pair},
		ReplayHistory: []*fuzzer.BarrierExecutionRecord{
			{Timestamp: time.Unix(0, 10), GroupID: 1},
		},
		Timestamp: time.Unix(0, 2),
	}

	records, err := writerA.ObserveEntry(longEntry, "corpus-a")
	if err != nil {
		t.Fatalf("failed to seed pair index: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("seed ObserveEntry returned %d records, want 1", len(records))
	}
	key := records[0].PairKey

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 40; i++ {
			if err := writerA.MarkQueued(key, uint64(1000+i)); err != nil {
				t.Errorf("writerA MarkQueued failed at iter %d: %v", i, err)
				return
			}
			if i == 20 {
				if _, err := writerA.ObserveEntry(shortEntry, "corpus-b"); err != nil {
					t.Errorf("writerA ObserveEntry(short) failed: %v", err)
					return
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 40; i++ {
			if err := writerB.MarkProcessing(key); err != nil {
				t.Errorf("writerB MarkProcessing failed at iter %d: %v", i, err)
				return
			}
			if err := writerB.MarkProcessed(key); err != nil {
				t.Errorf("writerB MarkProcessed failed at iter %d: %v", i, err)
				return
			}
		}
	}()

	close(start)
	wg.Wait()

	reloaded, err := NewRacePairIndexStore(workdir)
	if err != nil {
		t.Fatalf("failed to reopen pair index after concurrent writers: %v", err)
	}
	t.Cleanup(func() {
		if cerr := reloaded.Close(); cerr != nil {
			t.Fatalf("failed to close reloaded pair index: %v", cerr)
		}
	})

	record, err := reloaded.Get(key)
	if err != nil {
		t.Fatalf("Get after concurrent writers failed: %v", err)
	}
	if record == nil {
		t.Fatalf("record disappeared after concurrent writers")
	}
	if record.PreferredCorpusRecordID != "corpus-b" {
		t.Fatalf("preferred corpus mismatch: got %q want %q", record.PreferredCorpusRecordID, "corpus-b")
	}
	if record.PreferredHistoryRecords != len(shortEntry.ReplayHistory) {
		t.Fatalf("preferred history mismatch: got %d want %d", record.PreferredHistoryRecords, len(shortEntry.ReplayHistory))
	}
	if len(record.CorpusRecordIDs) != 2 {
		t.Fatalf("expected both corpus refs to persist, got %d", len(record.CorpusRecordIDs))
	}
	if record.LastQueueSeq == 0 {
		t.Fatalf("expected queue seq to survive concurrent writers")
	}
	if record.ValidateAttempts == 0 {
		t.Fatalf("expected validate attempts to survive concurrent writers")
	}
	stats, err := reloaded.Stats()
	if err != nil {
		t.Fatalf("Stats after concurrent writers failed: %v", err)
	}
	if stats.Total != 1 || stats.WithCorpus != 1 || stats.WithHistory != 1 {
		t.Fatalf("unexpected stats after concurrent writers: %+v", stats)
	}
}
