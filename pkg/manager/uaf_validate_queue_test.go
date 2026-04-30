package manager

import (
	"sync"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/prog"
)

func TestUAFValidateQueueStoreRoundTrip(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}

	store, err := NewUAFValidateQueueStore(t.TempDir(), target)
	if err != nil {
		t.Fatalf("failed to create queue store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("failed to close queue store: %v", cerr)
		}
	})

	entry1 := testQueueEntry(0x10, 0x20, 0x30, 0x40, time.Unix(0, 1))
	entry2 := testQueueEntry(0x11, 0x21, 0x31, 0x41, time.Unix(0, 2))
	record1 := observeQueueEntry(t, store, entry1, "record-1")
	record2 := observeQueueEntry(t, store, entry2, "record-2")

	key1, _, _, err := store.EnqueueRecord(record1)
	if err != nil {
		t.Fatalf("enqueue entry1 failed: %v", err)
	}
	key2, _, _, err := store.EnqueueRecord(record2)
	if err != nil {
		t.Fatalf("enqueue entry2 failed: %v", err)
	}
	if key1 == key2 {
		t.Fatalf("queue keys should be unique: %q", key1)
	}

	items, maxSeq, err := store.EntriesSince(0)
	if err != nil {
		t.Fatalf("EntriesSince failed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("unexpected queue item count %d", len(items))
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if stats.Pending != 2 || stats.WithPairKey != 2 || stats.WithCorpusRecord != 2 {
		t.Fatalf("unexpected queue stats: %+v", stats)
	}
	for _, item := range items {
		if item == nil {
			t.Fatalf("unexpected nil queue item: %#v", item)
		}
		if item.PairKey == "" {
			t.Fatalf("expected queue item to carry pair key")
		}
		if item.CorpusRecordID == "" {
			t.Fatalf("expected queue item to carry corpus record id")
		}
	}

	if err := store.Ack(key1); err != nil {
		t.Fatalf("Ack failed: %v", err)
	}
	if err := store.Ack(key2); err != nil {
		t.Fatalf("Ack failed: %v", err)
	}

	items, _, err = store.EntriesSince(0)
	if err != nil {
		t.Fatalf("EntriesSince after ack failed: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected empty queue after ack, got %d items", len(items))
	}
	stats, err = store.Stats()
	if err != nil {
		t.Fatalf("Stats after ack failed: %v", err)
	}
	if stats.Pending != 0 {
		t.Fatalf("expected empty queue stats after ack, got %+v", stats)
	}

	entry3 := testQueueEntry(0x12, 0x22, 0x32, 0x42, time.Unix(0, 3))
	record3 := observeQueueEntry(t, store, entry3, "record-3")
	key3, _, _, err := store.EnqueueRecord(record3)
	if err != nil {
		t.Fatalf("enqueue entry3 failed: %v", err)
	}
	items, _, err = store.EntriesSince(maxSeq)
	if err != nil {
		t.Fatalf("incremental EntriesSince failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 incremental item, got %d", len(items))
	}
	if items[0].Key != key3 {
		t.Fatalf("unexpected incremental key %q, want %q", items[0].Key, key3)
	}
}

func TestUAFValidateQueueStoreDeduplicatesByPairID(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}

	store, err := NewUAFValidateQueueStore(t.TempDir(), target)
	if err != nil {
		t.Fatalf("failed to create queue store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("failed to close queue store: %v", cerr)
		}
	})

	entry1 := testQueueEntry(0x10, 0x20, 0x30, 0x40, time.Unix(0, 1))
	entry2 := testQueueEntry(0x10, 0x20, 0x30, 0x40, time.Unix(0, 2))
	record1 := observeQueueEntry(t, store, entry1, "record-1")
	record2 := observeQueueEntry(t, store, entry2, "record-2")

	key1, _, _, err := store.EnqueueRecord(record1)
	if err != nil {
		t.Fatalf("enqueue entry1 failed: %v", err)
	}
	key2, _, _, err := store.EnqueueRecord(record2)
	if err != nil {
		t.Fatalf("enqueue entry2 failed: %v", err)
	}
	if key1 != key2 {
		t.Fatalf("queue keys should match for duplicate pair ids: %q vs %q", key1, key2)
	}

	items, _, err := store.EntriesSince(0)
	if err != nil {
		t.Fatalf("EntriesSince failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 queue item after dedupe, got %d", len(items))
	}
}

func TestUAFValidateQueueStorePrefersEntryWithReplayHistory(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}

	store, err := NewUAFValidateQueueStore(t.TempDir(), target)
	if err != nil {
		t.Fatalf("failed to create queue store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("failed to close queue store: %v", cerr)
		}
	})

	withoutHistory := testQueueEntry(0x50, 0x60, 0x70, 0x80, time.Unix(0, 1))
	withHistory := testQueueEntry(0x50, 0x60, 0x70, 0x80, time.Unix(0, 2))
	withHistory.ReplayHistory = []*fuzzer.BarrierExecutionRecord{
		{Timestamp: time.Unix(0, 3), GroupID: 1},
		{Timestamp: time.Unix(0, 4), GroupID: 2},
	}

	recordWithout := observeQueueEntry(t, store, withoutHistory, "record-without")
	recordWith := observeQueueEntry(t, store, withHistory, "record-with")

	if _, _, _, err := store.EnqueueRecord(recordWithout); err != nil {
		t.Fatalf("enqueue withoutHistory failed: %v", err)
	}
	if _, _, _, err := store.EnqueueRecord(recordWith); err != nil {
		t.Fatalf("enqueue withHistory failed: %v", err)
	}
	if _, _, _, err := store.EnqueueRecord(recordWithout); err != nil {
		t.Fatalf("re-enqueue withoutHistory failed: %v", err)
	}

	items, _, err := store.EntriesSince(0)
	if err != nil {
		t.Fatalf("EntriesSince failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 queue item after replay-history replacement, got %d", len(items))
	}
	if got := items[0].HistoryCount; got != 2 {
		t.Fatalf("expected queue item to keep richer replay-history reference, got %d records", got)
	}
	if items[0].CorpusRecordID != "record-with" {
		t.Fatalf("expected queue item to point at richer corpus record, got %q", items[0].CorpusRecordID)
	}
}

func TestUAFValidateQueueStoreReloadKeepsLatestReplacementAndAck(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}
	workdir := t.TempDir()

	producer, err := NewUAFValidateQueueStore(workdir, target)
	if err != nil {
		t.Fatalf("failed to create producer queue store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := producer.Close(); cerr != nil {
			t.Fatalf("failed to close producer queue store: %v", cerr)
		}
	})

	consumer, err := NewUAFValidateQueueStore(workdir, target)
	if err != nil {
		t.Fatalf("failed to create consumer queue store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := consumer.Close(); cerr != nil {
			t.Fatalf("failed to close consumer queue store: %v", cerr)
		}
	})

	short := testQueueEntry(0x90, 0xa0, 0xb0, 0xc0, time.Unix(0, 1))
	long := testQueueEntry(0x90, 0xa0, 0xb0, 0xc0, time.Unix(0, 2))
	long.ReplayHistory = []*fuzzer.BarrierExecutionRecord{
		{Timestamp: time.Unix(0, 3), GroupID: 1},
		{Timestamp: time.Unix(0, 4), GroupID: 2},
	}

	shortRecord := observeQueueEntry(t, producer, short, "record-short")
	key, shortSeq, enqueued, err := producer.EnqueueRecord(shortRecord)
	if err != nil {
		t.Fatalf("enqueue short record failed: %v", err)
	}
	if !enqueued {
		t.Fatalf("short record should enqueue")
	}

	longRecord := observeQueueEntry(t, consumer, long, "record-long")
	longKey, longSeq, enqueued, err := consumer.EnqueueRecord(longRecord)
	if err != nil {
		t.Fatalf("enqueue long record failed: %v", err)
	}
	if !enqueued {
		t.Fatalf("long record should replace queued reference")
	}
	if longKey != key {
		t.Fatalf("queue key changed across replacement: got %q want %q", longKey, key)
	}
	if longSeq <= shortSeq {
		t.Fatalf("replacement seq should advance: short=%d long=%d", shortSeq, longSeq)
	}

	restartedStore, err := NewUAFValidateQueueStore(workdir, target)
	if err != nil {
		t.Fatalf("failed to reopen queue store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := restartedStore.Close(); cerr != nil {
			t.Fatalf("failed to close reopened queue store: %v", cerr)
		}
	})

	items, _, err := restartedStore.EntriesSince(0)
	if err != nil {
		t.Fatalf("EntriesSince after restart failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 queue item after restart, got %d", len(items))
	}
	if items[0].CorpusRecordID != "record-long" {
		t.Fatalf("expected replacement corpus ref after restart, got %q", items[0].CorpusRecordID)
	}
	if items[0].HistoryCount != len(long.ReplayHistory) {
		t.Fatalf("expected replacement history count %d, got %d", len(long.ReplayHistory), items[0].HistoryCount)
	}

	if err := consumer.Ack(key); err != nil {
		t.Fatalf("Ack from consumer failed: %v", err)
	}

	afterAck, err := NewUAFValidateQueueStore(workdir, target)
	if err != nil {
		t.Fatalf("failed to reopen queue store after ack: %v", err)
	}
	t.Cleanup(func() {
		if cerr := afterAck.Close(); cerr != nil {
			t.Fatalf("failed to close post-ack queue store: %v", cerr)
		}
	})

	items, _, err = afterAck.EntriesSince(0)
	if err != nil {
		t.Fatalf("EntriesSince after ack restart failed: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected empty queue after ack restart, got %d items", len(items))
	}
	stats, err := afterAck.Stats()
	if err != nil {
		t.Fatalf("Stats after ack restart failed: %v", err)
	}
	if stats.Pending != 0 {
		t.Fatalf("expected empty queue stats after ack restart, got %+v", stats)
	}
}

func TestUAFValidateQueueStoreConcurrentEnqueuePreservesRicherReference(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}
	workdir := t.TempDir()

	producer, err := NewUAFValidateQueueStore(workdir, target)
	if err != nil {
		t.Fatalf("failed to create producer queue store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := producer.Close(); cerr != nil {
			t.Fatalf("failed to close producer queue store: %v", cerr)
		}
	})

	consumer, err := NewUAFValidateQueueStore(workdir, target)
	if err != nil {
		t.Fatalf("failed to create consumer queue store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := consumer.Close(); cerr != nil {
			t.Fatalf("failed to close consumer queue store: %v", cerr)
		}
	})

	short := testQueueEntry(0xd0, 0xe0, 0xf0, 0x100, time.Unix(0, 1))
	long := testQueueEntry(0xd0, 0xe0, 0xf0, 0x100, time.Unix(0, 2))
	long.ReplayHistory = []*fuzzer.BarrierExecutionRecord{
		{Timestamp: time.Unix(0, 3), GroupID: 1},
		{Timestamp: time.Unix(0, 4), GroupID: 2},
		{Timestamp: time.Unix(0, 5), GroupID: 3},
	}

	shortRecord := observeQueueEntry(t, producer, short, "record-short")
	longRecord := observeQueueEntry(t, consumer, long, "record-long")

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 40; i++ {
			if _, _, _, err := producer.EnqueueRecord(shortRecord); err != nil {
				t.Errorf("producer enqueue failed at iter %d: %v", i, err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 40; i++ {
			if _, _, _, err := consumer.EnqueueRecord(longRecord); err != nil {
				t.Errorf("consumer enqueue failed at iter %d: %v", i, err)
				return
			}
		}
	}()

	close(start)
	wg.Wait()

	restarted, err := NewUAFValidateQueueStore(workdir, target)
	if err != nil {
		t.Fatalf("failed to reopen queue store after concurrent enqueues: %v", err)
	}
	t.Cleanup(func() {
		if cerr := restarted.Close(); cerr != nil {
			t.Fatalf("failed to close restarted queue store: %v", cerr)
		}
	})

	items, _, err := restarted.EntriesSince(0)
	if err != nil {
		t.Fatalf("EntriesSince after concurrent enqueues failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 queue item after concurrent enqueues, got %d", len(items))
	}
	if items[0].CorpusRecordID != "record-long" {
		t.Fatalf("expected richer corpus ref to survive, got %q", items[0].CorpusRecordID)
	}
	if items[0].HistoryCount != len(long.ReplayHistory) {
		t.Fatalf("expected richer history count %d, got %d", len(long.ReplayHistory), items[0].HistoryCount)
	}

	if err := restarted.Ack(items[0].Key); err != nil {
		t.Fatalf("Ack after concurrent enqueues failed: %v", err)
	}

	finalStore, err := NewUAFValidateQueueStore(workdir, target)
	if err != nil {
		t.Fatalf("failed to reopen queue store after ack: %v", err)
	}
	t.Cleanup(func() {
		if cerr := finalStore.Close(); cerr != nil {
			t.Fatalf("failed to close final queue store: %v", cerr)
		}
	})

	finalItems, _, err := finalStore.EntriesSince(0)
	if err != nil {
		t.Fatalf("EntriesSince after final ack failed: %v", err)
	}
	if len(finalItems) != 0 {
		t.Fatalf("expected queue to be empty after final ack, got %d items", len(finalItems))
	}
}

func observeQueueEntry(t *testing.T, store *UAFValidateQueueStore, entry *fuzzer.UAFCorpusEntry, corpusRecordID string) *RacePairRecord {
	t.Helper()
	entry.CorpusRecordID = corpusRecordID
	records, err := store.pairIndex.ObserveEntry(entry, corpusRecordID)
	if err != nil {
		t.Fatalf("ObserveEntry failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("ObserveEntry returned %d records, want 1", len(records))
	}
	return records[0]
}

func testQueueEntry(freeName, useName, freeStack, useStack uint64, ts time.Time) *fuzzer.UAFCorpusEntry {
	pair := ddrd.MayUAFPair{
		Signal:         freeName + useName,
		FreeAccessName: freeName,
		UseAccessName:  useName,
		FreeCallStack:  freeStack,
		UseCallStack:   useStack,
	}
	return &fuzzer.UAFCorpusEntry{
		PairBasicInfo: pair,
		Pairs:         []*ddrd.MayUAFPair{&pair},
		Timestamp:     ts,
	}
}
