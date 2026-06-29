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

func TestThresholdControllerZeroConfigUsesDefaultEvalWindow(t *testing.T) {
	tc := NewThresholdController(ThresholdControllerConfig{}, func() int { return 0 })

	if tc.config.EvalWindowSeconds != 30 {
		t.Fatalf("default eval window: got %d, want 30", tc.config.EvalWindowSeconds)
	}
}

func TestThresholdControllerPaperDefaults(t *testing.T) {
	config := DefaultThresholdControllerConfig()

	if config.EvalWindowSeconds != 30 {
		t.Fatalf("EvalWindowSeconds: got %d, want 30", config.EvalWindowSeconds)
	}
	if config.WorkloadLowWatermark != 10 {
		t.Fatalf("WorkloadLowWatermark: got %v, want 10", config.WorkloadLowWatermark)
	}
	if config.WorkloadHighWatermark != 40 {
		t.Fatalf("WorkloadHighWatermark: got %v, want 40", config.WorkloadHighWatermark)
	}
	if config.SmoothingFactor != 0.8 {
		t.Fatalf("SmoothingFactor: got %v, want 0.8", config.SmoothingFactor)
	}
	if config.WorkloadEpsilon != 1 {
		t.Fatalf("WorkloadEpsilon: got %v, want 1", config.WorkloadEpsilon)
	}
	if config.TighteningFactor != 0.5 {
		t.Fatalf("TighteningFactor: got %v, want 0.5", config.TighteningFactor)
	}
	if config.RelaxationStepFraction != 0.05 {
		t.Fatalf("RelaxationStepFraction: got %v, want 0.05", config.RelaxationStepFraction)
	}
}

func TestThresholdControllerGrowsWhenQueueEmpty(t *testing.T) {
	config := DefaultThresholdControllerConfig()
	config.EvalWindowSeconds = 1
	config.MinThresholdUs = 500
	config.MaxThresholdUs = 10500
	config.InitialThresholdUs = 2500

	counter := 0
	tc := NewThresholdController(config, func() int { return counter })
	initial := tc.CurrentThreshold()

	// Paper Algorithm 1 grows when Q = 0.
	tc.mu.Lock()
	tc.lastEvalTime = time.Now().Add(-2 * time.Second)
	tc.mu.Unlock()
	tc.Evaluate()

	want := initial + 500 // 0.05 * (10500 - 500)
	if tc.CurrentThreshold() != want {
		t.Fatalf("threshold should grow additively when queue is empty: got %d, want %d", tc.CurrentThreshold(), want)
	}
}

func TestThresholdControllerRespectsMinMax(t *testing.T) {
	workdir := t.TempDir()
	config := DefaultThresholdControllerConfig()
	config.MinThresholdUs = 100
	config.MaxThresholdUs = 5000
	config.EvalWindowSeconds = 1
	config.Workdir = workdir

	counter := 0
	tc := NewThresholdController(config, func() int { return counter })

	// Force to min, try to shrink further
	tc.ForceThreshold(100)
	tc.mu.Lock()
	tc.lastEvalTime = time.Now().Add(-2 * time.Second)
	tc.mu.Unlock()
	counter = 100000
	writeTestValidatorStats(t, workdir, ddrd.ValidatorStats{
		PendingCount: 100,
		LastUpdate:   time.Now(),
	})
	tc.Evaluate()

	if tc.CurrentThreshold() < config.MinThresholdUs {
		t.Fatalf("threshold below min: got %d, min is %d", tc.CurrentThreshold(), config.MinThresholdUs)
	}

	// Force to max, try to grow further
	tc.ForceThreshold(5000)
	writeTestValidatorStats(t, workdir, ddrd.ValidatorStats{
		PendingCount: 0,
		LastUpdate:   time.Now(),
	})
	tc.mu.Lock()
	tc.lastEvalTime = time.Now().Add(-2 * time.Second)
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
	tc.mu.Unlock()
	tc.Evaluate()

	if tc.CurrentThreshold() <= initial {
		t.Fatalf("threshold should grow when validator workload is low: got %d, initial was %d",
			tc.CurrentThreshold(), initial)
	}
}

func TestThresholdControllerValidatorOverloaded(t *testing.T) {
	workdir := t.TempDir()
	config := DefaultThresholdControllerConfig()
	config.EvalWindowSeconds = 1
	config.Workdir = workdir

	counter := 100
	tc := NewThresholdController(config, func() int { return counter })
	tc.ForceThreshold(10000)

	// Write validator stats: pending implies W > Whigh.
	writeTestValidatorStats(t, workdir, ddrd.ValidatorStats{
		PendingCount: 100,
		Idle:         false,
		LastUpdate:   time.Now(),
	})

	tc.mu.Lock()
	tc.lastEvalTime = time.Now().Add(-2 * time.Second)
	tc.mu.Unlock()
	counter = 1000
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

	// Stale stats should not trigger the overload branch. With no fresh Q/C
	// observation, Algorithm 1 sees Q=0 and may grow, but it must not shrink.
	if tc.CurrentThreshold() < initial {
		t.Fatalf("threshold should not shrink from stale validator stats: got %d, initial was %d",
			tc.CurrentThreshold(), initial)
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
