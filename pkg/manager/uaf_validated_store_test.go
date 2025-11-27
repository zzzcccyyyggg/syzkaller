package manager

import (
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
)

func TestUAFValidatedStoreRoundTrip(t *testing.T) {
	store, err := NewUAFValidatedStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Fatalf("failed to close store: %v", cerr)
		}
	})

	entry := &UAFValidationEntry{
		Profile: fuzzer.UAFPairProfile{
			FreeAccessName: 0x11,
			UseAccessName:  0x22,
			FreeCallStack:  0x33,
			UseCallStack:   0x44,
		},
		Barrier: fuzzer.BarrierSnapshot{Participants: 0x3},
		ReplayPlan: fuzzer.UAFCorpusReplayPlan{
			DelaysMicros: []int64{1, 2, 3},
		},
		Outcome:     OutcomeConfirmed,
		Attempts:    5,
		LastAttempt: time.Unix(0, 42),
		Notes:       "ok",
		RepeatCount: 3,
		StablePairs: []ddrd.MayUAFPair{{FreeAccessName: 1, UseAccessName: 2}},
		LastPairs:   []ddrd.MayUAFPair{{FreeAccessName: 3, UseAccessName: 4}},
	}

	if err := store.Upsert(entry); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}

	records, err := store.Entries()
	if err != nil {
		t.Fatalf("Entries failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	got := records[0]
	if got.Outcome != OutcomeConfirmed {
		t.Fatalf("unexpected outcome %q", got.Outcome)
	}
	if got.Attempts != entry.Attempts {
		t.Fatalf("unexpected attempts %d", got.Attempts)
	}
	if got.LastAttempt != entry.LastAttempt {
		t.Fatalf("timestamp mismatch got=%v want=%v", got.LastAttempt, entry.LastAttempt)
	}
	if len(got.ReplayPlan.DelaysMicros) != len(entry.ReplayPlan.DelaysMicros) {
		t.Fatalf("replay plan size mismatch")
	}
	for i, v := range entry.ReplayPlan.DelaysMicros {
		if got.ReplayPlan.DelaysMicros[i] != v {
			t.Fatalf("delay[%d] mismatch", i)
		}
	}
	if got.Profile != entry.Profile {
		t.Fatalf("profile mismatch: got=%+v want=%+v", got.Profile, entry.Profile)
	}
	if got.Notes != entry.Notes {
		t.Fatalf("notes mismatch")
	}
	if got.RepeatCount != entry.RepeatCount {
		t.Fatalf("repeat count mismatch got=%d want=%d", got.RepeatCount, entry.RepeatCount)
	}
	if len(got.StablePairs) != len(entry.StablePairs) {
		t.Fatalf("stable pairs length mismatch")
	}
	if len(got.StablePairs) != 0 && got.StablePairs[0] != entry.StablePairs[0] {
		t.Fatalf("stable pair mismatch got=%+v want=%+v", got.StablePairs[0], entry.StablePairs[0])
	}
	if len(got.LastPairs) != len(entry.LastPairs) {
		t.Fatalf("last pairs length mismatch")
	}
	if len(got.LastPairs) != 0 && got.LastPairs[0] != entry.LastPairs[0] {
		t.Fatalf("last pair mismatch got=%+v want=%+v", got.LastPairs[0], entry.LastPairs[0])
	}
}
