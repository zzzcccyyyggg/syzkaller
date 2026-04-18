package fuzzer

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/stat"
)

// ThresholdControllerConfig holds parameters for the dynamic threshold controller.
type ThresholdControllerConfig struct {
	// InitialThresholdUs is the starting threshold value (microseconds).
	// Default: 1000 (1ms).
	InitialThresholdUs int64

	// MinThresholdUs is the lower bound of threshold (microseconds).
	// Default: 50 (50μs). Below this, MRP discovery is extremely rare.
	MinThresholdUs int64

	// MaxThresholdUs is the upper bound of threshold (microseconds).
	// Default: 50000 (50ms). Above this, most MRPs are low quality.
	MaxThresholdUs int64

	// EvalWindowSeconds is how often the controller evaluates and adjusts.
	// Default: 60 seconds.
	EvalWindowSeconds int

	// PendingLowWatermark: if validator pending count is below this,
	// the validator is hungry — increase threshold.
	// Default: 5.
	PendingLowWatermark int

	// PendingHighWatermark: if validator pending count is above this,
	// the validator is overloaded — decrease threshold.
	// Default: 50.
	PendingHighWatermark int

	// GrowFactor: multiplicative increase factor when validator is hungry.
	// Default: 1.5.
	GrowFactor float64

	// ShrinkFactor: multiplicative decrease factor when validator is overloaded.
	// Default: 0.6.
	ShrinkFactor float64

	// MinDiscoveryRatePerMin: if MRP discovery rate drops below this for >2 windows,
	// force threshold increase. Default: 1.0 (at least 1 new MRP/min).
	MinDiscoveryRatePerMin float64

	// StaleValidatorTimeout: if validator stats haven't been updated for this long,
	// assume validator is not running and use supply-only mode.
	// Default: 3 minutes.
	StaleValidatorTimeout time.Duration

	// Workdir for shared state file.
	Workdir string
}

// DefaultThresholdControllerConfig returns sensible defaults.
func DefaultThresholdControllerConfig() ThresholdControllerConfig {
	return ThresholdControllerConfig{
		InitialThresholdUs:     1000,    // 1ms
		MinThresholdUs:         50,      // 50μs
		MaxThresholdUs:         50000,   // 50ms
		EvalWindowSeconds:      60,      // 1 minute
		PendingLowWatermark:    5,
		PendingHighWatermark:   50,
		GrowFactor:             1.5,
		ShrinkFactor:           0.6,
		MinDiscoveryRatePerMin: 1.0,
		StaleValidatorTimeout:  3 * time.Minute,
	}
}

// ThresholdController dynamically adjusts the MRP time threshold to balance
// fuzzing discovery rate and validation consumption rate.
//
// Core idea: time threshold τ controls the quality/quantity tradeoff of MRPs.
//   - Small τ → fewer, higher-quality MRPs (closer to real races)
//   - Large τ → more, lower-quality MRPs (many won't be confirmed)
//
// The controller monitors:
//   - Fuzzer side: MRP discovery rate (new unique MRPs per minute)
//   - Validator side: pending queue depth and processing rate
//
// It adjusts τ to keep the validator neither starved nor overwhelmed.
type ThresholdController struct {
	config ThresholdControllerConfig
	mu     sync.Mutex

	// currentThreshold is the active threshold in microseconds.
	// Accessed atomically for fast reads from hot path.
	currentThreshold atomic.Int64

	// Tracking state
	lastEvalTime     time.Time
	lastMRPCount     int       // Total MRP count at last evaluation
	lowRateStreak    int       // Consecutive windows with low discovery rate
	prevDiscoveryRate float64  // Previous window's discovery rate

	// MRP count provider (from ddrd.Store or uafCorpus)
	mrpCountFunc func() int

	// Stats
	statThreshold    *stat.Val
	statDiscoveryRate *stat.Val
	statAdjustments  *stat.Val
}

// NewThresholdController creates and returns a new dynamic threshold controller.
func NewThresholdController(config ThresholdControllerConfig, mrpCountFunc func() int) *ThresholdController {
	if config.InitialThresholdUs <= 0 {
		config.InitialThresholdUs = 1000
	}
	if config.MinThresholdUs <= 0 {
		config.MinThresholdUs = 50
	}
	if config.MaxThresholdUs <= config.MinThresholdUs {
		config.MaxThresholdUs = 50000
	}
	if config.EvalWindowSeconds <= 0 {
		config.EvalWindowSeconds = 60
	}
	if config.PendingLowWatermark <= 0 {
		config.PendingLowWatermark = 5
	}
	if config.PendingHighWatermark <= config.PendingLowWatermark {
		config.PendingHighWatermark = config.PendingLowWatermark * 10
	}
	if config.GrowFactor <= 1.0 {
		config.GrowFactor = 1.5
	}
	if config.ShrinkFactor <= 0 || config.ShrinkFactor >= 1.0 {
		config.ShrinkFactor = 0.6
	}
	if config.MinDiscoveryRatePerMin <= 0 {
		config.MinDiscoveryRatePerMin = 1.0
	}
	if config.StaleValidatorTimeout <= 0 {
		config.StaleValidatorTimeout = 3 * time.Minute
	}

	tc := &ThresholdController{
		config:       config,
		mrpCountFunc: mrpCountFunc,
		lastEvalTime: time.Now(),
	}
	tc.currentThreshold.Store(config.InitialThresholdUs)

	tc.statThreshold = stat.New("dynamic threshold (μs)", "Current dynamic MRP time threshold",
		stat.Console, stat.Graph("threshold"), func() int {
			return int(tc.currentThreshold.Load())
		})
	tc.statAdjustments = stat.New("threshold adjustments", "Total threshold adjustments made",
		stat.Console, stat.NoGraph)

	return tc
}

// CurrentThreshold returns the current dynamic threshold in microseconds.
// This is lock-free and safe to call from the hot execution path.
func (tc *ThresholdController) CurrentThreshold() int64 {
	return tc.currentThreshold.Load()
}

// Evaluate performs one evaluation cycle. Call this periodically (e.g., every EvalWindowSeconds).
// It reads the current MRP discovery rate and validator state, then adjusts the threshold.
func (tc *ThresholdController) Evaluate() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tc.lastEvalTime)
	if elapsed < time.Duration(tc.config.EvalWindowSeconds/2)*time.Second {
		return // Too soon since last evaluation
	}

	// 1. Compute MRP discovery rate
	currentMRPCount := 0
	if tc.mrpCountFunc != nil {
		currentMRPCount = tc.mrpCountFunc()
	}
	newMRPs := currentMRPCount - tc.lastMRPCount
	elapsedMinutes := elapsed.Minutes()
	if elapsedMinutes < 0.01 {
		elapsedMinutes = 0.01
	}
	discoveryRate := float64(newMRPs) / elapsedMinutes

	// 2. Read validator stats if available
	var validatorStats *ddrd.ValidatorStats
	if tc.config.Workdir != "" {
		state, err := ddrd.ReadThresholdState(tc.config.Workdir)
		if err == nil && !state.Validator.LastUpdate.IsZero() {
			staleness := now.Sub(state.Validator.LastUpdate)
			if staleness < tc.config.StaleValidatorTimeout {
				validatorStats = &state.Validator
			}
		}
	}

	// 3. Determine adjustment
	oldThreshold := tc.currentThreshold.Load()
	newThreshold := oldThreshold
	reason := "stable"

	if validatorStats != nil {
		// Validator is alive: use supply-demand balancing
		pending := validatorStats.PendingCount

		if pending < tc.config.PendingLowWatermark {
			if validatorStats.Idle {
				// Validator has nothing to do, aggressively increase
				newThreshold = int64(float64(oldThreshold) * tc.config.GrowFactor * 1.2)
				reason = "validator-idle-grow"
			} else {
				newThreshold = int64(float64(oldThreshold) * tc.config.GrowFactor)
				reason = "validator-hungry-grow"
			}
		} else if pending > tc.config.PendingHighWatermark {
			newThreshold = int64(float64(oldThreshold) * tc.config.ShrinkFactor)
			reason = "validator-overloaded-shrink"
		}
		// Between watermarks: check discovery rate
		if discoveryRate < tc.config.MinDiscoveryRatePerMin && pending < tc.config.PendingHighWatermark {
			tc.lowRateStreak++
			if tc.lowRateStreak >= 2 {
				// Sustained low discovery: increase threshold
				newThreshold = int64(float64(oldThreshold) * tc.config.GrowFactor)
				reason = "low-discovery-rate-grow"
			}
		} else {
			tc.lowRateStreak = 0
		}
	} else {
		// No validator stats: supply-only mode
		// Adjust based on discovery rate alone
		if discoveryRate < tc.config.MinDiscoveryRatePerMin {
			tc.lowRateStreak++
			if tc.lowRateStreak >= 2 {
				newThreshold = int64(float64(oldThreshold) * tc.config.GrowFactor)
				reason = "no-validator-low-rate-grow"
			}
		} else if discoveryRate > tc.config.MinDiscoveryRatePerMin*10 {
			// Very high discovery rate: might be generating low-quality MRPs
			newThreshold = int64(float64(oldThreshold) * tc.config.ShrinkFactor)
			reason = "no-validator-high-rate-shrink"
			tc.lowRateStreak = 0
		} else {
			tc.lowRateStreak = 0
		}
	}

	// 4. Clamp threshold
	if newThreshold < tc.config.MinThresholdUs {
		newThreshold = tc.config.MinThresholdUs
	}
	if newThreshold > tc.config.MaxThresholdUs {
		newThreshold = tc.config.MaxThresholdUs
	}

	// 5. Apply
	if newThreshold != oldThreshold {
		tc.currentThreshold.Store(newThreshold)
		if tc.statAdjustments != nil {
			tc.statAdjustments.Add(1)
		}
		log.Logf(0, "[THRESHOLD] adjusted: %dμs → %dμs (reason=%s, discovery_rate=%.1f/min, new_mrps=%d, "+
			"elapsed=%.0fs, validator=%v)",
			oldThreshold, newThreshold, reason, discoveryRate, newMRPs, elapsed.Seconds(),
			validatorStats != nil)
	} else {
		log.Logf(1, "[THRESHOLD] stable at %dμs (discovery_rate=%.1f/min, new_mrps=%d)",
			oldThreshold, discoveryRate, newMRPs)
	}

	// 6. Write fuzzer stats to shared state
	if tc.config.Workdir != "" {
		_ = ddrd.WriteFuzzerStats(tc.config.Workdir, ddrd.FuzzerStats{
			CurrentThresholdUs:   newThreshold,
			MRPDiscoveryRatePerM: discoveryRate,
			TotalMRPsDiscovered:  currentMRPCount,
			LastUpdate:           now,
		})
	}

	// Update tracking
	tc.lastEvalTime = now
	tc.lastMRPCount = currentMRPCount
	tc.prevDiscoveryRate = discoveryRate
}

// Run starts the periodic evaluation loop. Call in a goroutine.
// Stops when the done channel is closed.
func (tc *ThresholdController) Run(done <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(tc.config.EvalWindowSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			tc.Evaluate()
		}
	}
}

// ForceThreshold manually sets the threshold (for testing or override).
func (tc *ThresholdController) ForceThreshold(us int64) {
	tc.currentThreshold.Store(us)
}
