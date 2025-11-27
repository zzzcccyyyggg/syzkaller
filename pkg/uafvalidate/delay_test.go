package uafvalidate

import (
	"math"
	"testing"

	"github.com/google/syzkaller/pkg/fuzzer"
)

func TestDelayManagerBuildDelays(t *testing.T) {
	dm := NewDelayManager(4, 1)
	entry := &fuzzer.UAFCorpusEntry{
		Barrier: fuzzer.BarrierSnapshot{Participants: 0x7},
		ReplayPlan: fuzzer.UAFCorpusReplayPlan{
			DelaysMicros: []int64{10, 20},
		},
	}
	got := dm.BuildDelays(entry)
	if len(got) != 3 {
		t.Fatalf("expected 3 delays, got %d", len(got))
	}
	if got[0] != 10 || got[1] != 20 {
		t.Fatalf("unexpected prefix %v", got[:2])
	}
	if got[2] != 20 {
		t.Fatalf("expected padding with last value, got %v", got[2])
	}
}

func TestDelayClamp(t *testing.T) {
	if clampDelay(math.MaxInt64) != math.MaxInt32 {
		t.Fatalf("max clamp failed")
	}
	if clampDelay(-math.MaxInt64) != -math.MaxInt32 {
		t.Fatalf("min clamp failed")
	}
}
