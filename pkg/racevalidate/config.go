package uafvalidate

import "time"

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
	// and all skip logic (invalid/validated/HB) is bypassed.
	TargetVarNamePair string
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
	// VerifyDelaySweep enables progressive start_delay sweep during verification.
	// When enabled, start_delay increases from 0 to VerifyDelayMaxUs across repetitions
	// using an exponential curve (slow start, fast end).
	VerifyDelaySweep bool
	// VerifyDelayMaxUs is the maximum start_delay in microseconds for delay sweep.
	// Defaults to 800 if unset or zero.
	VerifyDelayMaxUs int64
	// VerifyDelayPower controls the exponential curve steepness.
	// Higher values = slower start, faster end. Defaults to 2.0.
	// delay(i) = maxDelay * (i/n)^power
	VerifyDelayPower float64
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
	if cfg.VerifyDelayMaxUs <= 0 {
		cfg.VerifyDelayMaxUs = 800
	}
	if cfg.VerifyDelayPower <= 0 {
		cfg.VerifyDelayPower = 2.0
	}
	return cfg
}
