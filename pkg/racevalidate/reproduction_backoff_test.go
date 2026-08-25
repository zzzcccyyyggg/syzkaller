package uafvalidate

import (
	"testing"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
)

func TestReproductionBackoffProbabilityIsSoftAndBounded(t *testing.T) {
	stats := &ReproductionBackoffStats{}
	for misses := 0; misses <= collectionMissFreeAttempts; misses++ {
		stats.ConsecutiveMisses = misses
		if got := stats.DeferProbability(); got != 0 {
			t.Fatalf("misses=%d probability=%f, want 0", misses, got)
		}
	}
	stats.ConsecutiveMisses = 3
	if got := stats.DeferProbability(); got != 0.2 {
		t.Fatalf("third miss probability=%f, want 0.2", got)
	}
	stats.ConsecutiveMisses = 100
	if got := stats.DeferProbability(); got != collectionMissMaxDefer {
		t.Fatalf("probability=%f, want cap %f", got, collectionMissMaxDefer)
	}
}

func TestReproductionBackoffSharesCanonicalFamilyAndResetsOnHit(t *testing.T) {
	store := NewReproductionBackoffStore(nil)
	pair := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
	}
	entry := &fuzzer.UAFCorpusEntry{PairBasicInfo: pair, Pairs: []*ddrd.MayUAFPair{&pair}}
	for range 3 {
		store.RecordCollection(entry, nil)
	}

	reversed := pair
	reversed.FreeAccessName, reversed.UseAccessName = pair.UseAccessName, pair.FreeAccessName
	reversed.FreeCallStack, reversed.UseCallStack = 0x50, 0x60
	reversedEntry := &fuzzer.UAFCorpusEntry{PairBasicInfo: reversed, Pairs: []*ddrd.MayUAFPair{&reversed}}
	deferred, probability := store.ShouldDeferEntry(reversedEntry, func() float64 { return 0.1 })
	if !deferred || probability != 0.2 {
		t.Fatalf("canonical family defer=%t probability=%f, want true/0.2", deferred, probability)
	}

	store.RecordCollection(entry, []StablePairWithDelays{{Pair: pair}})
	deferred, probability = store.ShouldDeferEntry(entry, func() float64 { return 0 })
	if deferred || probability != 0 {
		t.Fatalf("hit did not reset backoff: defer=%t probability=%f", deferred, probability)
	}
}

func TestReproductionBackoffCustomAggressiveConfig(t *testing.T) {
	config := normalizeReproductionBackoffConfig(ReproductionBackoffConfig{
		FreeAttempts: 1,
		Weight:       0.95,
		MaxDefer:     0.9,
	})
	stats := &ReproductionBackoffStats{ConsecutiveMisses: 1}
	if got := stats.deferProbability(config); got != 0 {
		t.Fatalf("first miss probability=%f, want 0", got)
	}
	stats.ConsecutiveMisses = 2
	if got := stats.deferProbability(config); got < 0.487 || got > 0.488 {
		t.Fatalf("second miss probability=%f, want about 0.487", got)
	}
	stats.ConsecutiveMisses = 100
	if got := stats.deferProbability(config); got != 0.9 {
		t.Fatalf("probability=%f, want cap 0.9", got)
	}
}
