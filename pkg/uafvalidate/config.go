package uafvalidate

import "time"

// Config captures high level knobs for the validation stage.
type Config struct {
	MaxConcurrent    int
	DelayRetryBudget int
	ExecutionTimeout time.Duration
	Debug            bool
	RepeatCount      int
	Workdir          string
	// TargetVarNamePair specifies a specific VarName pair to debug.
	// Format: "freeAccessName-useAccessName" (hex, e.g. "610067002c7c8254-235d4d37a0583ad1")
	// When set, only entries containing this VarName pair are validated,
	// and all skip logic (invalid/validated/HB) is bypassed.
	TargetVarNamePair string
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
	return cfg
}
