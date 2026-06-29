package fuzzer

import (
	"math"
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
	// Paper default: 30 seconds.
	EvalWindowSeconds int

	// WorkloadLowWatermark is the paper Wlow watermark.
	// Paper default: 10.
	WorkloadLowWatermark float64

	// WorkloadHighWatermark is the paper Whigh watermark.
	// Paper default: 40.
	WorkloadHighWatermark float64

	// SmoothingFactor is rho for the producer/consumer EWMAs.
	// Paper default: 0.8.
	SmoothingFactor float64

	// WorkloadEpsilon prevents division by zero in W = Q / max(Cbar, epsilon).
	// Paper default: 1.
	WorkloadEpsilon float64

	// RelaxationStepFraction is delta_tau as a fraction of (tau_max - tau_min).
	// Paper default: 0.05.
	RelaxationStepFraction float64

	// TighteningFactor is gamma_shrink for multiplicative threshold tightening.
	// Paper default: 0.5.
	TighteningFactor float64

	// StaleValidatorTimeout: if validator stats haven't been updated for this long,
	// treat the observable scheduling queue as empty.
	// Default: 3 minutes.
	StaleValidatorTimeout time.Duration

	// Workdir for shared state file.
	Workdir string
}

// DefaultThresholdControllerConfig returns sensible defaults.
func DefaultThresholdControllerConfig() ThresholdControllerConfig {
	return ThresholdControllerConfig{
		InitialThresholdUs:     1000,  // 1ms
		MinThresholdUs:         50,    // 50μs
		MaxThresholdUs:         50000, // 50ms
		EvalWindowSeconds:      30,
		WorkloadLowWatermark:   10,
		WorkloadHighWatermark:  40,
		SmoothingFactor:        0.8,
		WorkloadEpsilon:        1,
		RelaxationStepFraction: 0.05,
		TighteningFactor:       0.5,
		StaleValidatorTimeout:  3 * time.Minute,
	}
}

// ThresholdController dynamically adjusts the MRP time threshold to balance
// fuzzing discovery rate and validation consumption rate.
// It implements the paper's backpressure controller: at each control interval it
// observes newly produced MRPs P, consumed MRPs C, pending MRPs Q, maintains EWMA
// producer/consumer rates Pbar/Cbar, and adjusts tau from W = Q/max(Cbar, eps).
//
// Core idea: time threshold τ controls the quality/quantity tradeoff of MRPs.
//   - Small τ → fewer, higher-quality MRPs (closer to real races)
//   - Large τ → more, lower-quality MRPs (many won't be confirmed)
//
// The controller adjusts τ to keep the validator neither starved nor overwhelmed.
type ThresholdController struct {
	config ThresholdControllerConfig
	mu     sync.Mutex

	// currentThreshold is the active threshold in microseconds.
	// Accessed atomically for fast reads from hot path.
	currentThreshold atomic.Int64

	// Tracking state for Algorithm 1.
	lastEvalTime      time.Time
	lastMRPCount      int
	lastConsumedCount int
	producedEWMA      float64
	consumedEWMA      float64

	// MRP count provider (from ddrd.Store or uafCorpus)
	mrpCountFunc func() int

	// Stats
	statThreshold     *stat.Val
	statDiscoveryRate *stat.Val
	statAdjustments   *stat.Val
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
		config.EvalWindowSeconds = 30
	}
	if config.WorkloadLowWatermark <= 0 {
		config.WorkloadLowWatermark = 10
	}
	if config.WorkloadHighWatermark <= config.WorkloadLowWatermark {
		config.WorkloadHighWatermark = 40
		if config.WorkloadHighWatermark <= config.WorkloadLowWatermark {
			config.WorkloadHighWatermark = config.WorkloadLowWatermark * 4
		}
	}
	if config.SmoothingFactor < 0 || config.SmoothingFactor >= 1 {
		config.SmoothingFactor = 0.8
	}
	if config.WorkloadEpsilon <= 0 {
		config.WorkloadEpsilon = 1
	}
	if config.RelaxationStepFraction <= 0 {
		config.RelaxationStepFraction = 0.05
	}
	if config.TighteningFactor <= 0 || config.TighteningFactor >= 1 {
		config.TighteningFactor = 0.5
	}
	if config.StaleValidatorTimeout <= 0 {
		config.StaleValidatorTimeout = 3 * time.Minute
	}

	initialMRPCount := 0
	if mrpCountFunc != nil {
		initialMRPCount = mrpCountFunc()
	}
	tc := &ThresholdController{
		config:       config,
		mrpCountFunc: mrpCountFunc,
		lastEvalTime: time.Now(),
		lastMRPCount: initialMRPCount,
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
// It implements Algorithm 1 from the paper.
func (tc *ThresholdController) Evaluate() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tc.lastEvalTime)
	if elapsed < time.Duration(tc.config.EvalWindowSeconds/2)*time.Second {
		return // Too soon since last evaluation
	}

	// 1. Compute newly produced MRPs P for this control interval.
	currentMRPCount := 0
	if tc.mrpCountFunc != nil {
		currentMRPCount = tc.mrpCountFunc()
	}
	produced := currentMRPCount - tc.lastMRPCount
	if produced < 0 {
		// Counter reset across process restarts.
		produced = currentMRPCount
	}
	elapsedMinutes := elapsed.Minutes()
	if elapsedMinutes < 0.01 {
		elapsedMinutes = 0.01
	}
	discoveryRate := float64(produced) / elapsedMinutes

	// 2. Read validator stats and compute consumed MRPs C plus pending MRPs Q.
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

	consumed := 0
	pending := 0
	if validatorStats != nil {
		consumed = validatorStats.ProcessedCount - tc.lastConsumedCount
		if consumed < 0 {
			// Validator counter reset across process restarts.
			consumed = validatorStats.ProcessedCount
		}
		pending = validatorStats.PendingCount
	}

	// 3. Update EWMA producer/consumer counts and compute workload W.
	rho := tc.config.SmoothingFactor
	tc.producedEWMA = rho*tc.producedEWMA + (1-rho)*float64(produced)
	tc.consumedEWMA = rho*tc.consumedEWMA + (1-rho)*float64(consumed)
	workload := float64(pending) / math.Max(tc.consumedEWMA, tc.config.WorkloadEpsilon)

	// 4. Determine threshold adjustment using the paper conditions.
	oldThreshold := tc.currentThreshold.Load()
	newThreshold := oldThreshold
	reason := "stable"

	switch {
	case workload > tc.config.WorkloadHighWatermark && tc.producedEWMA >= tc.consumedEWMA:
		newThreshold = int64(float64(oldThreshold) * tc.config.TighteningFactor)
		reason = "paper-backpressure-shrink"
	case pending == 0 || (workload < tc.config.WorkloadLowWatermark && tc.producedEWMA <= tc.consumedEWMA):
		newThreshold = oldThreshold + tc.relaxationStep()
		reason = "paper-backpressure-grow"
	}

	// 5. Clamp threshold.
	if newThreshold < tc.config.MinThresholdUs {
		newThreshold = tc.config.MinThresholdUs
	}
	if newThreshold > tc.config.MaxThresholdUs {
		newThreshold = tc.config.MaxThresholdUs
	}

	// 6. Apply.
	if newThreshold != oldThreshold {
		tc.currentThreshold.Store(newThreshold)
		if tc.statAdjustments != nil {
			tc.statAdjustments.Add(1)
		}
		log.Logf(0, "[THRESHOLD] adjusted: %dμs → %dμs (reason=%s, P=%d, C=%d, Q=%d, "+
			"Pbar=%.2f, Cbar=%.2f, W=%.2f, discovery_rate=%.1f/min, elapsed=%.0fs, validator=%v)",
			oldThreshold, newThreshold, reason, produced, consumed, pending,
			tc.producedEWMA, tc.consumedEWMA, workload, discoveryRate, elapsed.Seconds(), validatorStats != nil)
	} else {
		log.Logf(1, "[THRESHOLD] stable at %dμs (P=%d, C=%d, Q=%d, Pbar=%.2f, Cbar=%.2f, W=%.2f, discovery_rate=%.1f/min)",
			oldThreshold, produced, consumed, pending, tc.producedEWMA, tc.consumedEWMA, workload, discoveryRate)
	}

	// 7. Write fuzzer stats to shared state.
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
	if validatorStats != nil {
		tc.lastConsumedCount = validatorStats.ProcessedCount
	}
}

func (tc *ThresholdController) relaxationStep() int64 {
	step := int64(math.Ceil(float64(tc.config.MaxThresholdUs-tc.config.MinThresholdUs) * tc.config.RelaxationStepFraction))
	if step < 1 {
		step = 1
	}
	return step
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
