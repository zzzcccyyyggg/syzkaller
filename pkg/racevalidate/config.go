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

// Config captures high level knobs for the validation stage.
type Config struct {
	MaxConcurrent    int
	DelayRetryBudget int
	ExecutionTimeout time.Duration
	Debug            bool
	RepeatCount      int
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
	// DisableVerifyDelay disables start_delay during the verification phase.
	// When enabled (true), verification runs without barrier start delays,
	// relying only on access_delay (kernel udelay) to create race windows.
	DisableVerifyDelay bool
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

	// EnableVarNameScheduling enables VarName-based round-robin scheduling.
	// When enabled, entries are grouped by their VarName pairs and scheduled
	// in a round-robin fashion, prioritizing VarName pairs with fewer entries.
	EnableVarNameScheduling bool

	// PriorityLowHistory prioritizes entries with fewer replay history records.
	// Entries are sorted by ascending history count within each scheduling group.
	PriorityLowHistory bool

	// RequireOriginMatch controls whether stable pairs must exist in the original corpus pairs.
	// When false (default), any runtime-discovered pair meeting the stability threshold is accepted.
	// When true, only pairs that also exist in entry.Pairs are considered stable.
	RequireOriginMatch bool

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
	return cfg
}
