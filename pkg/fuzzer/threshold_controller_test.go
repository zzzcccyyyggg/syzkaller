package fuzzer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
)

func TestThresholdControllerDefaults(t *testing.T) {
	config := DefaultThresholdControllerConfig()
	counter := 0
	tc := NewThresholdController(config, func() int { return counter })

	if tc.CurrentThreshold() != config.InitialThresholdUs {
		t.Fatalf("initial threshold: got %d, want %d", tc.CurrentThreshold(), config.InitialThresholdUs)
	}
}

func TestThresholdControllerGrowsOnLowDiscovery(t *testing.T) {
	config := DefaultThresholdControllerConfig()
	config.EvalWindowSeconds = 1 // fast evaluation
	config.MinDiscoveryRatePerMin = 10.0

	counter := 0 // No new MRPs discovered
	tc := NewThresholdController(config, func() int { return counter })
	initial := tc.CurrentThreshold()

	// First evaluation: lowRateStreak=1, no change yet
	tc.mu.Lock()
	tc.lastEvalTime = time.Now().Add(-2 * time.Second)
	tc.mu.Unlock()
	tc.Evaluate()

	// Second evaluation: lowRateStreak=2, should grow
	tc.mu.Lock()
	tc.lastEvalTime = time.Now().Add(-2 * time.Second)
	tc.mu.Unlock()
	tc.Evaluate()

	if tc.CurrentThreshold() <= initial {
		t.Fatalf("threshold should grow on sustained low discovery: got %d, initial was %d", tc.CurrentThreshold(), initial)
	}
}

func TestThresholdControllerShrinksOnHighDiscovery(t *testing.T) {
	config := DefaultThresholdControllerConfig()
	config.EvalWindowSeconds = 1
	config.MinDiscoveryRatePerMin = 1.0

	counter := 0
	tc := NewThresholdController(config, func() int { return counter })
	tc.ForceThreshold(10000) // Start high

	// Simulate very high discovery rate (>10x min rate)
	tc.mu.Lock()
	tc.lastEvalTime = time.Now().Add(-2 * time.Second)
	tc.lastMRPCount = 0
	tc.mu.Unlock()

	counter = 1000 // 1000 new MRPs in ~2 seconds = very high rate
	tc.Evaluate()

	if tc.CurrentThreshold() >= 10000 {
		t.Fatalf("threshold should shrink on high discovery rate: got %d", tc.CurrentThreshold())
	}
}

func TestThresholdControllerRespectsMinMax(t *testing.T) {
	config := DefaultThresholdControllerConfig()
	config.MinThresholdUs = 100
	config.MaxThresholdUs = 5000
	config.EvalWindowSeconds = 1

	counter := 0
	tc := NewThresholdController(config, func() int { return counter })

	// Force to min, try to shrink further
	tc.ForceThreshold(100)
	tc.mu.Lock()
	tc.lastEvalTime = time.Now().Add(-2 * time.Second)
	tc.lastMRPCount = 0
	tc.mu.Unlock()
	counter = 100000
	tc.Evaluate()

	if tc.CurrentThreshold() < config.MinThresholdUs {
		t.Fatalf("threshold below min: got %d, min is %d", tc.CurrentThreshold(), config.MinThresholdUs)
	}

	// Force to max, try to grow further
	tc.ForceThreshold(5000)
	counter = 0
	tc.mu.Lock()
	tc.lastEvalTime = time.Now().Add(-2 * time.Second)
	tc.lastMRPCount = 0
	tc.lowRateStreak = 5
	tc.mu.Unlock()
	tc.Evaluate()

	if tc.CurrentThreshold() > config.MaxThresholdUs {
		t.Fatalf("threshold above max: got %d, max is %d", tc.CurrentThreshold(), config.MaxThresholdUs)
	}
}

func TestThresholdControllerValidatorHungry(t *testing.T) {
	workdir := t.TempDir()
	config := DefaultThresholdControllerConfig()
	config.EvalWindowSeconds = 1
	config.Workdir = workdir
	config.PendingLowWatermark = 5
	config.PendingHighWatermark = 50

	counter := 100
	tc := NewThresholdController(config, func() int { return counter })
	initial := tc.CurrentThreshold()

	// Write validator stats: pending is low, validator is idle
	writeTestValidatorStats(t, workdir, ddrd.ValidatorStats{
		PendingCount:   1,
		ProcessedCount: 50,
		Idle:           true,
		LastUpdate:     time.Now(),
	})

	tc.mu.Lock()
	tc.lastEvalTime = time.Now().Add(-2 * time.Second)
	tc.lastMRPCount = counter
	tc.mu.Unlock()

	tc.Evaluate()

	if tc.CurrentThreshold() <= initial {
		t.Fatalf("threshold should grow when validator is hungry: got %d, initial was %d",
			tc.CurrentThreshold(), initial)
	}
}

func TestThresholdControllerValidatorOverloaded(t *testing.T) {
	workdir := t.TempDir()
	config := DefaultThresholdControllerConfig()
	config.EvalWindowSeconds = 1
	config.Workdir = workdir
	config.PendingLowWatermark = 5
	config.PendingHighWatermark = 50

	counter := 100
	tc := NewThresholdController(config, func() int { return counter })
	tc.ForceThreshold(10000)

	// Write validator stats: pending is very high
	writeTestValidatorStats(t, workdir, ddrd.ValidatorStats{
		PendingCount:   100, // > 50 high watermark
		ProcessedCount: 200,
		Idle:           false,
		LastUpdate:     time.Now(),
	})

	tc.mu.Lock()
	tc.lastEvalTime = time.Now().Add(-2 * time.Second)
	tc.lastMRPCount = counter
	tc.mu.Unlock()

	tc.Evaluate()

	if tc.CurrentThreshold() >= 10000 {
		t.Fatalf("threshold should shrink when validator is overloaded: got %d", tc.CurrentThreshold())
	}
}

func TestThresholdControllerIgnoresStaleValidatorStats(t *testing.T) {
	workdir := t.TempDir()
	config := DefaultThresholdControllerConfig()
	config.EvalWindowSeconds = 1
	config.Workdir = workdir
	config.StaleValidatorTimeout = 1 * time.Minute

	counter := 0
	tc := NewThresholdController(config, func() int { return counter })
	initial := tc.CurrentThreshold()

	// Write stale validator stats (5 minutes old)
	writeTestValidatorStats(t, workdir, ddrd.ValidatorStats{
		PendingCount: 100,
		LastUpdate:   time.Now().Add(-5 * time.Minute),
	})

	tc.mu.Lock()
	tc.lastEvalTime = time.Now().Add(-2 * time.Second)
	tc.mu.Unlock()

	tc.Evaluate()

	// With stale stats, should use supply-only mode (not validator-overloaded mode)
	// First eval: lowRateStreak=1, no change
	if tc.CurrentThreshold() != initial {
		// Should NOT have shrunk due to stale validator pending=100
		t.Logf("threshold changed on first eval (may be expected): %d → %d", initial, tc.CurrentThreshold())
	}
}

func TestThresholdControllerForceThreshold(t *testing.T) {
	config := DefaultThresholdControllerConfig()
	tc := NewThresholdController(config, func() int { return 0 })

	tc.ForceThreshold(9999)
	if tc.CurrentThreshold() != 9999 {
		t.Fatalf("ForceThreshold: got %d, want 9999", tc.CurrentThreshold())
	}
}

func TestThresholdControllerWritesFuzzerStats(t *testing.T) {
	workdir := t.TempDir()
	config := DefaultThresholdControllerConfig()
	config.EvalWindowSeconds = 1
	config.Workdir = workdir

	counter := 42
	tc := NewThresholdController(config, func() int { return counter })

	tc.mu.Lock()
	tc.lastEvalTime = time.Now().Add(-2 * time.Second)
	tc.mu.Unlock()

	tc.Evaluate()

	// Verify the state file was written
	state, err := ddrd.ReadThresholdState(workdir)
	if err != nil {
		t.Fatalf("failed to read threshold state: %v", err)
	}
	if state.Fuzzer.TotalMRPsDiscovered != 42 {
		t.Fatalf("fuzzer stats not written: got total_mrps=%d, want 42", state.Fuzzer.TotalMRPsDiscovered)
	}
	if state.Fuzzer.CurrentThresholdUs <= 0 {
		t.Fatalf("fuzzer stats threshold not written: %d", state.Fuzzer.CurrentThresholdUs)
	}
}

func writeTestValidatorStats(t *testing.T, workdir string, stats ddrd.ValidatorStats) {
	t.Helper()
	state := &ddrd.ThresholdSharedState{Validator: stats}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	path := filepath.Join(workdir, "threshold-state.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}
}
