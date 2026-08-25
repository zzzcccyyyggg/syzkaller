package uafvalidate

import (
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
)

type ValidationEntryRef struct {
	QueueKey       string
	QueueSeq       uint64
	PairKey        string
	CorpusRecordID string
	Pair           ddrd.MayUAFPair
	HistoryCount   int
}

type ValidationEntryResolver interface {
	ResolveValidationEntry(ref *ValidationEntryRef) (*fuzzer.UAFCorpusEntry, error)
}

type PairStatusSink interface {
	MarkPairValidated(pair ddrd.MayUAFPair, data []byte)
	MarkPairInvalid(pair ddrd.MayUAFPair)
}

const (
	TargetMatchModeSNFallback  = "sn-fallback"
	TargetMatchModeStrictSN    = "strict-sn"
	TargetMatchModeSNRange     = "sn-range"
	TargetMatchModeSNOnly      = "sn-only"
	TargetMatchModeSNRangeOnly = "sn-range-only"
	TargetMatchModeSiteOnly    = "site-only"
	TargetMatchModeStackOnly   = "stack-only"

	TargetDelaySideBoth = "both"
	TargetDelaySideUse  = "use"
	TargetDelaySideFree = "free"
	TargetDelaySideNone = "none"

	TargetDelayModeSleep       = "sleep"
	TargetDelayModeNonblocking = "nonblocking"

	OriginMatchModeExact          = "exact"
	OriginMatchModeVarName        = "varname"
	OriginMatchModePrimaryVarName = "primary-varname"
)

func NormalizeTargetMatchMode(mode string) string {
	switch mode {
	case "", TargetMatchModeSNFallback:
		return TargetMatchModeSNFallback
	case TargetMatchModeStrictSN, TargetMatchModeSNRange, TargetMatchModeSNOnly,
		TargetMatchModeSNRangeOnly, TargetMatchModeSiteOnly, TargetMatchModeStackOnly:
		return mode
	default:
		return mode
	}
}

func NormalizeTargetDelaySide(side string) string {
	switch side {
	case "", TargetDelaySideBoth:
		return TargetDelaySideBoth
	case TargetDelaySideUse, TargetDelaySideFree, TargetDelaySideNone:
		return side
	default:
		return side
	}
}

func TargetDelaySideID(side string) int32 {
	switch NormalizeTargetDelaySide(side) {
	case TargetDelaySideUse:
		return 1
	case TargetDelaySideFree:
		return 2
	case TargetDelaySideNone:
		return 3
	default:
		return 0
	}
}

func NormalizeTargetDelayMode(mode string) string {
	switch mode {
	case "", TargetDelayModeSleep:
		return TargetDelayModeSleep
	case TargetDelayModeNonblocking:
		return mode
	default:
		return mode
	}
}

func TargetDelayModeID(mode string) int32 {
	switch NormalizeTargetDelayMode(mode) {
	case TargetDelayModeNonblocking:
		return 1
	default:
		return 0
	}
}

// Config captures high level knobs for the validation stage.
type Config struct {
	MaxConcurrent    int
	DelayRetryBudget int
	ExecutionTimeout time.Duration
	MaxBatchTimeout  time.Duration
	Debug            bool
	RepeatCount      int
	// StablePairMinOccurrences overrides the collection majority threshold.
	// Zero derives a majority threshold from RepeatCount.
	StablePairMinOccurrences int
	// VerifyRepeatTimes specifies how many times to repeat each pair during verification phase.
	// Defaults to 10 if unset or zero.
	VerifyRepeatTimes int
	Workdir           string
	// TargetVarNamePair specifies a specific VarName pair to debug.
	// Format: "freeAccessName-useAccessName" (hex, e.g. "610067002c7c8254-235d4d37a0583ad1")
	// When set, only entries containing this VarName pair are validated,
	// and all skip logic (invalid/validated/backoff) is bypassed.
	TargetVarNamePair string
	// TargetCorpusKey specifies a specific corpus entry key to validate.
	// Format: "sig0-sig1-sig2-sig3" (hex, e.g. "d9daa1d91920e5d5-...")
	// When set, only this specific entry is loaded and validated.
	TargetCorpusKey string
	// DisableAsyncSplit disables the async call splitting during verification phase.
	// By default (false), each program pair (2 programs) is expanded to 4 programs
	// by duplicating each with async calls marked, maximizing race triggering.
	// When enabled (true), programs are used as-is without async splitting.
	DisableAsyncSplit bool
	// DisableCollectionDelay disables start_delay during the collection phase (finding stable pairs).
	// When enabled (true), programs run without artificial delays during collection,
	// allowing natural timing to determine which pairs are stable.
	// Delays are only applied during the verification phase.
	DisableCollectionDelay bool
	// CollectionThresholdFloorUs widens replay collection without changing the
	// fuzz-time admission threshold or verification-delay normalization. Zero
	// preserves admission-linked collection.
	CollectionThresholdFloorUs int64
	// DisableVerifyDelay disables start_delay during the verification phase.
	// When enabled (true), verification runs without barrier start delays,
	// relying only on access_delay (kernel udelay) to create race windows.
	DisableVerifyDelay bool
	// DisableAccessDelay disables the kernel-side target access delay during verification.
	// When enabled, the target pair is still installed, but its TimeDiff is zeroed before
	// being sent to the executor.
	DisableAccessDelay bool
	// VerifyAccessDelayMinUs floors the kernel-side target access delay during verification.
	// It keeps the original barrier start delay intact and only widens the watchpoint window.
	VerifyAccessDelayMinUs int64
	// VerifyAccessDelayMultiplier scales the observed gap for strict/range
	// attempts before floors and caps are applied.
	VerifyAccessDelayMultiplier int64
	// VerifyAccessDelayNormalizeToThreshold scales strict/range attempts by the
	// observed-delay/admission-threshold ratio.
	VerifyAccessDelayNormalizeToThreshold bool
	// VerifyAccessDelayTargetUs is the strict/range delay at the threshold boundary.
	VerifyAccessDelayTargetUs int64
	// VerifyAccessDelayMaxUs caps normalized strict/range delay. Zero means no cap.
	VerifyAccessDelayMaxUs int64
	// VerifyStackAccessDelayUs fixes stack-only delay when non-zero.
	VerifyStackAccessDelayUs int64
	// VerifyStackAccessDelayMultiplier scales the observed gap for stack-only
	// attempts and takes precedence over the fixed stack-only delay.
	VerifyStackAccessDelayMultiplier int64
	// VerifyStackAccessDelayMinUs overrides the floor for stack-only attempts. Zero
	// preserves VerifyAccessDelayMinUs for all target-match modes.
	VerifyStackAccessDelayMinUs int64
	// TargetMatchMode controls how the target UAF access is matched in the kernel.
	// "sn-fallback" first tries exact SN/TID/stack matching, then bounded
	// stack+SN-range matching, then falls back to stack-only on misses.
	// "strict-sn" requires SN/TID/stack matching. "sn-range" matches
	// VarName+stack with SN falling into a configured interval and ignores TID.
	// "sn-only" and "sn-range-only" keep SN constraints but ignore stack/TID;
	// they are useful when call stacks drift but sequence positions are stable.
	// "stack-only" matches VarName+stack but ignores SN/TID.
	// "site-only" clears stack/SN/TID in the target request and is kept as an explicit
	// diagnostic mode for kernels that support VarName-only matching.
	TargetMatchMode string
	// SNFallbackRange controls the half-window used by target_match_mode=sn-fallback/sn-range.
	// A value of N matches runtime sequence numbers in [SN-N, SN+N]. Zero disables
	// the range layer, so sn-fallback becomes strict-sn -> stack-only.
	SNFallbackRange int
	// TargetDelaySide controls which matched target side receives the kernel access
	// delay during verification. "both" preserves legacy behavior; "use"/"free"
	// reduce timing perturbation by keeping the other side observable but undelayed.
	TargetDelaySide string
	// TargetDelayMode controls how a matched target access applies its delay.
	// "sleep" preserves the legacy pre-access udelay. "nonblocking" arms a
	// persistent watchpoint window and lets the matched access continue.
	TargetDelayMode string
	// WildcardTargetTID clears target TID constraints while preserving VarName, stack,
	// and SN constraints. This is useful for testing whether executor thread-id drift
	// causes otherwise stable SN-directed pairs to miss.
	WildcardTargetTID bool
	// VerifyDelaySweep enables progressive start_delay sweep during verification.
	// When enabled, multiple verify requests are generated with different delays,
	// from 0 to VerifyDelayMaxUs using an exponential curve.
	VerifyDelaySweep bool
	// VerifyDelaySteps specifies how many delay steps to try during sweep.
	// Each step uses a different delay value. Defaults to 10 if unset or zero.
	VerifyDelaySteps int
	// VerifyDelayMaxUs is the maximum start_delay in microseconds for delay sweep.
	// Defaults to 800 if unset or zero.
	VerifyDelayMaxUs int64
	// VerifyDelayPower controls the exponential curve steepness.
	// Higher values = slower start, faster end. Defaults to 2.0.
	// delay(i) = maxDelay * (i/n)^power
	VerifyDelayPower float64
	// EnableReplay enables replay of execution history before validation.
	// When enabled, the saved barrier execution history from fuzzing is replayed
	// to reconstruct the system state before testing each entry.
	EnableReplay bool
	// ReplayCollectPairs controls whether to collect race pairs during replay.
	// When false (default), replay runs in barrier mode but skips race pair collection
	// to reduce overhead. When true, pairs are collected during replay as well.
	ReplayCollectPairs bool
	// VerifyCollectPairs collects DDRD pairs during verification for diagnostics.
	// Observed target pairs are logged separately and are not counted as validated
	// unless the kernel also reports a matching DATARACE crash.
	VerifyCollectPairs bool
	// MaxReplayHistory limits how many saved history records are replayed per validation attempt.
	// When positive, the most recent N records are used. Zero means no limit.
	MaxReplayHistory int

	// EnableVarNameScheduling enables VarName-based round-robin scheduling.
	// When enabled, entries are grouped by their VarName pairs and scheduled
	// in a round-robin fashion, prioritizing VarName pairs with fewer entries.
	EnableVarNameScheduling bool
	// MaxConcurrentPerVarName limits active tasks sharing a canonical VarName
	// family. Waiting tasks remain queued. Zero disables the cap.
	MaxConcurrentPerVarName int
	// EnableCollectionMissBackoff applies soft task-level deferral based on
	// repeated failures to reproduce a stable VarName family during collection.
	EnableCollectionMissBackoff bool
	CollectionMissFreeAttempts  int
	CollectionMissWeight        float64
	CollectionMissMaxDefer      float64

	// PriorityLowHistory prioritizes entries with fewer replay history records.
	// Entries are sorted by ascending history count within each scheduling group.
	PriorityLowHistory                     bool
	EnableThresholdAwareValidationPriority bool
	ThresholdPriorityInitialUs             int64
	CurrentThresholdUs                     func() int64

	// RequireOriginMatch controls whether stable pairs must exist in the original corpus pairs.
	// When false (default), any runtime-discovered pair meeting the stability threshold is accepted.
	// When true, only pairs that also exist in entry.Pairs are considered stable.
	RequireOriginMatch bool
	// OriginMatchMode controls how RequireOriginMatch compares runtime pairs to entry.Pairs.
	// "exact" requires VarName+stack equality. "varname" only requires the original VarName pair.
	// "primary-varname" only uses the entry's primary pair VarName as the origin.
	OriginMatchMode string
	// MaxStablePairsPerOrigin limits how many runtime stable stack variants are verified for
	// each original origin match key. Zero means no limit.
	MaxStablePairsPerOrigin int
	// MaxStablePairsPerEntry limits total stable pairs verified for one corpus entry.
	// Zero means no limit.
	MaxStablePairsPerEntry int
	// CollectionOnly stops after the replay+collection phase and does not run the
	// target-pair verification phase. This is intended for sensitivity probes that
	// measure how many pairs the current program group can expose without history.
	CollectionOnly bool

	// DisableBackoffSkip disables probabilistic validation backoff skip logic.
	// When enabled (true), entries and pairs are never skipped based on the
	// historical backoff score,
	// allowing all entries to be validated regardless of historical failure rates.
	// This is useful when you want to retry entries that were previously skipped.
	DisableBackoffSkip bool

	// ContinueAfterBackoff controls whether to continue testing backoff-skipped entries after the
	// initial backoff-guided validation pass completes. When enabled, entries that were skipped
	// by the backoff heuristic (shouldSkipEntry) are re-enqueued with backoff skip disabled, allowing
	// all pairs to be tested. This is useful for modules with few pairs where backoff skipping
	// causes validation to finish too quickly during long experiments (e.g., 24h runs).
	ContinueAfterBackoff bool

	// EnableHistoryMinimization enables replay history minimization after successful validation.
	// When enabled, after a pair is validated, the system will try to find the minimum
	// subset of history records required to reproduce the race condition.
	// This makes the reproducer smaller and easier to analyze.
	EnableHistoryMinimization bool

	// MinimizationMaxAttempts limits the number of execution attempts per minimization step.
	// Each subset of history is tested this many times to account for race non-determinism.
	// Higher values increase reliability but slow down minimization. Defaults to 3.
	MinimizationMaxAttempts int

	// MinimizationStrategy specifies the algorithm to use for history minimization.
	// Supported values:
	// - "binary" (default): Binary search - fast but may not find optimal minimum
	// - "greedy": Greedy removal - slower but finds better minimum
	// - "hybrid": Binary first, then greedy refinement
	MinimizationStrategy string

	EntryResolver  ValidationEntryResolver
	PairStatusSink PairStatusSink
	// TaskStarted is called once when a validation worker takes ownership of a
	// task, before materialization and VM acquisition.
	TaskStarted func(*fuzzer.UAFCorpusEntry)
}

func (cfg Config) withDefaults() Config {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 1
	}
	if cfg.DelayRetryBudget <= 0 {
		cfg.DelayRetryBudget = 1
	}
	if cfg.ExecutionTimeout <= 0 {
		cfg.ExecutionTimeout = 90 * time.Second
	}
	if cfg.RepeatCount <= 0 {
		cfg.RepeatCount = 1
	}
	if cfg.VerifyRepeatTimes <= 0 {
		cfg.VerifyRepeatTimes = 10
	}
	cfg.TargetMatchMode = NormalizeTargetMatchMode(cfg.TargetMatchMode)
	cfg.TargetDelaySide = NormalizeTargetDelaySide(cfg.TargetDelaySide)
	cfg.TargetDelayMode = NormalizeTargetDelayMode(cfg.TargetDelayMode)
	if cfg.VerifyDelaySteps <= 0 {
		cfg.VerifyDelaySteps = 10
	}
	if cfg.VerifyDelayMaxUs <= 0 {
		cfg.VerifyDelayMaxUs = 800
	}
	if cfg.VerifyDelayPower <= 0 {
		cfg.VerifyDelayPower = 2.0
	}
	if cfg.MinimizationMaxAttempts <= 0 {
		cfg.MinimizationMaxAttempts = 3
	}
	if cfg.MinimizationStrategy == "" {
		cfg.MinimizationStrategy = "binary"
	}
	backoff := normalizeReproductionBackoffConfig(ReproductionBackoffConfig{
		FreeAttempts: cfg.CollectionMissFreeAttempts,
		Weight:       cfg.CollectionMissWeight,
		MaxDefer:     cfg.CollectionMissMaxDefer,
	})
	cfg.CollectionMissFreeAttempts = backoff.FreeAttempts
	cfg.CollectionMissWeight = backoff.Weight
	cfg.CollectionMissMaxDefer = backoff.MaxDefer
	return cfg
}
