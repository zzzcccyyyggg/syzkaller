package uafvalidate

import (
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
)

// Config captures high level knobs for the validation stage.
type Config struct {
	MaxConcurrent    int
	DelayRetryBudget int
	ExecutionTimeout time.Duration
	Debug            bool
	RepeatCount      int
	Workdir          string
	// ThresholdCtrl is an optional shared threshold controller.
	// If nil, a new one will be created from Workdir.
	ThresholdCtrl *ddrd.ThresholdController
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
