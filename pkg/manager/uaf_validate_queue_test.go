package manager

import (
	"fmt"
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

func TestUAFValidateQueueStorePrefersEntryWithShorterReplayHistory(t *testing.T) {
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

	shortHistory := testQueueEntry(0x50, 0x60, 0x70, 0x80, time.Unix(0, 1))
	longHistory := testQueueEntry(0x50, 0x60, 0x70, 0x80, time.Unix(0, 2))
	longHistory.ReplayHistory = []*fuzzer.BarrierExecutionRecord{
		{Timestamp: time.Unix(0, 3), GroupID: 1},
		{Timestamp: time.Unix(0, 4), GroupID: 2},
	}

	recordShort := observeQueueEntry(t, store, shortHistory, "record-short")
	recordLong := observeQueueEntry(t, store, longHistory, "record-long")

	if _, _, _, err := store.EnqueueRecord(recordLong); err != nil {
		t.Fatalf("enqueue longHistory failed: %v", err)
	}
	if _, _, _, err := store.EnqueueRecord(recordShort); err != nil {
		t.Fatalf("enqueue shortHistory failed: %v", err)
	}
	if _, _, _, err := store.EnqueueRecord(recordLong); err != nil {
		t.Fatalf("re-enqueue longHistory failed: %v", err)
	}

	items, _, err := store.EntriesSince(0)
	if err != nil {
		t.Fatalf("EntriesSince failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 queue item after replay-history replacement, got %d", len(items))
	}
	if got := items[0].HistoryCount; got != 0 {
		t.Fatalf("expected queue item to keep shorter replay-history reference, got %d records", got)
	}
	if items[0].CorpusRecordID != "record-short" {
		t.Fatalf("expected queue item to point at shorter corpus record, got %q", items[0].CorpusRecordID)
	}
}

func TestUAFValidateQueueStoreReloadKeepsShorterReplacementAndAck(t *testing.T) {
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

	longRecord := observeQueueEntry(t, producer, long, "record-long")
	key, longSeq, enqueued, err := producer.EnqueueRecord(longRecord)
	if err != nil {
		t.Fatalf("enqueue long record failed: %v", err)
	}
	if !enqueued {
		t.Fatalf("long record should enqueue")
	}

	shortRecord := observeQueueEntry(t, consumer, short, "record-short")
	shortKey, shortSeq, enqueued, err := consumer.EnqueueRecord(shortRecord)
	if err != nil {
		t.Fatalf("enqueue short record failed: %v", err)
	}
	if !enqueued {
		t.Fatalf("short record should replace queued reference")
	}
	if shortKey != key {
		t.Fatalf("queue key changed across replacement: got %q want %q", shortKey, key)
	}
	if shortSeq <= longSeq {
		t.Fatalf("replacement seq should advance: long=%d short=%d", longSeq, shortSeq)
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
	if items[0].CorpusRecordID != "record-short" {
		t.Fatalf("expected replacement corpus ref after restart, got %q", items[0].CorpusRecordID)
	}
	if items[0].HistoryCount != len(short.ReplayHistory) {
		t.Fatalf("expected replacement history count %d, got %d", len(short.ReplayHistory), items[0].HistoryCount)
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

func TestUAFValidateQueueStoreConcurrentEnqueuePreservesShorterReference(t *testing.T) {
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
	if items[0].CorpusRecordID != "record-short" {
		t.Fatalf("expected shorter corpus ref to survive, got %q", items[0].CorpusRecordID)
	}
	if items[0].HistoryCount != len(short.ReplayHistory) {
		t.Fatalf("expected shorter history count %d, got %d", len(short.ReplayHistory), items[0].HistoryCount)
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

func TestUAFValidateQueueStoreGroupsEntriesByCorpusRecord(t *testing.T) {
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

	pairA := &ddrd.MayUAFPair{Signal: 1, FreeAccessName: 0x10, UseAccessName: 0x20, FreeCallStack: 0x30, UseCallStack: 0x40}
	pairB := &ddrd.MayUAFPair{Signal: 2, FreeAccessName: 0x11, UseAccessName: 0x21, FreeCallStack: 0x31, UseCallStack: 0x41}
	entry := &fuzzer.UAFCorpusEntry{
		PairBasicInfo: *pairA,
		Pairs:         []*ddrd.MayUAFPair{pairA, pairB},
		ReplayHistory: []*fuzzer.BarrierExecutionRecord{{Timestamp: time.Unix(0, 1), GroupID: 1}},
		Timestamp:     time.Unix(0, 1),
	}

	records, err := store.pairIndex.ObserveEntry(entry, "record-shared")
	if err != nil {
		t.Fatalf("ObserveEntry failed: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("ObserveEntry returned %d records, want 2", len(records))
	}
	for _, record := range records {
		if _, _, _, err := store.EnqueueRecord(record); err != nil {
			t.Fatalf("EnqueueRecord failed for %s: %v", record.PairKey, err)
		}
	}

	groups, _, err := store.EntriesSinceGroupedByCorpus(0)
	if err != nil {
		t.Fatalf("EntriesSinceGroupedByCorpus failed: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 grouped corpus entry, got %d", len(groups))
	}
	group := groups[0]
	if group.CorpusRecordID != "record-shared" {
		t.Fatalf("unexpected corpus record id %q", group.CorpusRecordID)
	}
	if len(group.PairKeys) != 2 || len(group.QueueKeys) != 2 || len(group.Pairs) != 2 {
		t.Fatalf("unexpected grouped payload: pair_keys=%d queue_keys=%d pairs=%d",
			len(group.PairKeys), len(group.QueueKeys), len(group.Pairs))
	}
	if group.HistoryCount != len(entry.ReplayHistory) {
		t.Fatalf("unexpected grouped history count %d", group.HistoryCount)
	}
}

func TestSplitQueuedUAFCorpusGroupsByPairLimit(t *testing.T) {
	group := &QueuedUAFCorpusGroup{CorpusRecordID: "record-shared"}
	for i := 0; i < 5; i++ {
		pair := ddrd.MayUAFPair{
			Signal:         uint64(i + 1),
			FreeAccessName: uint64(0x10 + i),
			UseAccessName:  uint64(0x20 + i),
			FreeCallStack:  uint64(0x30 + i),
			UseCallStack:   uint64(0x40 + i),
		}
		appendQueuedGroupItem(group, &QueuedUAFCorpusEntry{
			Key:            fmt.Sprintf("queue-%d", i),
			Seq:            uint64(i + 1),
			PairKey:        fmt.Sprintf("pair-%d", i),
			CorpusRecordID: "record-shared",
			Pair:           pair,
			HistoryCount:   i + 1,
		})
	}

	chunks := SplitQueuedUAFCorpusGroups([]*QueuedUAFCorpusGroup{group}, 2)
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}
	wantSizes := []int{2, 2, 1}
	wantFirstSeqs := []uint64{1, 3, 5}
	var gotQueueKeys []string
	for i, chunk := range chunks {
		if chunk.CorpusRecordID != "record-shared" {
			t.Fatalf("chunk %d corpus id = %q", i, chunk.CorpusRecordID)
		}
		if len(chunk.PairKeys) != wantSizes[i] || len(chunk.QueueKeys) != wantSizes[i] || len(chunk.Pairs) != wantSizes[i] {
			t.Fatalf("chunk %d sizes pair_keys=%d queue_keys=%d pairs=%d, want %d",
				i, len(chunk.PairKeys), len(chunk.QueueKeys), len(chunk.Pairs), wantSizes[i])
		}
		if chunk.FirstSeq != wantFirstSeqs[i] {
			t.Fatalf("chunk %d first seq = %d, want %d", i, chunk.FirstSeq, wantFirstSeqs[i])
		}
		gotQueueKeys = append(gotQueueKeys, chunk.QueueKeys...)
	}
	for i, key := range gotQueueKeys {
		want := fmt.Sprintf("queue-%d", i)
		if key != want {
			t.Fatalf("queue key %d = %q, want %q", i, key, want)
		}
	}
}

func TestUAFValidateQueueStoreBatchEnqueue(t *testing.T) {
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

	entryA := testQueueEntry(0x10, 0x20, 0x30, 0x40, time.Unix(0, 1))
	entryB := testQueueEntry(0x11, 0x21, 0x31, 0x41, time.Unix(0, 2))
	records, err := store.pairIndex.ObserveRefs([]RaceCorpusRecordRef{
		{ID: "record-a", Entry: entryA},
		{ID: "record-b", Entry: entryB},
	})
	if err != nil {
		t.Fatalf("ObserveRefs failed: %v", err)
	}
	results, err := store.EnqueueRecords(records)
	if err != nil {
		t.Fatalf("EnqueueRecords failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("EnqueueRecords returned %d results, want 2", len(results))
	}
	for _, result := range results {
		if !result.Enqueued || result.Key == "" || result.PairKey == "" || result.Seq == 0 {
			t.Fatalf("unexpected enqueue result: %+v", result)
		}
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if stats.Pending != 2 || stats.WithPairKey != 2 || stats.WithCorpusRecord != 2 {
		t.Fatalf("unexpected queue stats: %+v", stats)
	}
}

func TestUAFValidateQueueStoreAckBatch(t *testing.T) {
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

	entryA := testQueueEntry(0x30, 0x40, 0x50, 0x60, time.Unix(0, 1))
	entryB := testQueueEntry(0x31, 0x41, 0x51, 0x61, time.Unix(0, 2))
	recordA := observeQueueEntry(t, store, entryA, "record-a")
	recordB := observeQueueEntry(t, store, entryB, "record-b")
	keyA, _, _, err := store.EnqueueRecord(recordA)
	if err != nil {
		t.Fatalf("EnqueueRecord A failed: %v", err)
	}
	keyB, _, _, err := store.EnqueueRecord(recordB)
	if err != nil {
		t.Fatalf("EnqueueRecord B failed: %v", err)
	}

	if err := store.AckBatch([]string{keyA, keyB, keyA, ""}); err != nil {
		t.Fatalf("AckBatch failed: %v", err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if stats.Pending != 0 {
		t.Fatalf("pending after AckBatch = %d, want 0", stats.Pending)
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
