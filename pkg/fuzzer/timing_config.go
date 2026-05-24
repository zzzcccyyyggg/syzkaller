// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package fuzzer provides timing exploration configuration.
//
// Dual Queue Architecture:
//
// 1. Pair Discovery Queue:
//    - Uses NORMAL threshold to find may-race pairs
//    - Random partner selection (no intelligent selection)
//    - Only NEW VarName pairs are considered high-quality
//    - High-quality program pairs are sent to Timing Exploration Queue
//
// 2. Timing Exploration Queue:
//    - Uses WIDENED threshold to capture more potential pairs
//    - Explores ALL potential pairs in high-quality program pairs
//    - Deduplicates by (VarName1, VarName2, Stack1, Stack2) quadruple
//    - Optionally uses syscall-local delays or barrier start-delay resampling

package fuzzer

// ============================================================================
// Timing Exploration Configuration
// ============================================================================

// TimingExplorationConfig holds configuration for the dual-queue system.
type TimingExplorationConfig struct {
	// ======== Pair Discovery Queue ========
	// Uses NORMAL threshold, random partners
	// Only NEW VarName pairs → Timing Queue

	// EnablePairDiscovery enables the pair discovery queue
	EnablePairDiscovery bool

	// UseRandomPartner disables intelligent partner selection
	UseRandomPartner bool

	// ======== Timing Exploration Queue ========
	// Uses WIDENED threshold, explores all pairs in high-quality programs
	// Deduplicates by (VarName + Stack) quadruple

	// EnableTimingExploration enables the timing exploration queue
	EnableTimingExploration bool

	// TimingExplorationQueueSize is the max number of high-quality program pairs
	TimingExplorationQueueSize int

	// WidenedThresholdMicros is the widened timing window for exploration (microseconds)
	// This captures may-may pairs that normal threshold would miss
	WidenedThresholdMicros int64

	// ======== Delay Mutation Parameters ========

	// Delay range for syz_delay() insertions (microseconds)
	DelayMinMicros int64
	DelayMaxMicros int64

	// MaxDelaysPerProgram limits syz_delay() calls per program
	MaxDelaysPerProgram int

	// ======== Exploration Strategy ========

	// TimingMutationStrategy: "random", "targeted", "binary_search", "timediff", "start_delay"
	// - random: random delay insertions at any position
	// - targeted: focus delays around Free/Use syscalls
	// - binary_search: iteratively refine delays based on previous results
	// - start_delay: do not mutate programs; shift barrier participant launch time
	TimingMutationStrategy string

	// MaxAttemptsPerPair is max timing attempts per unique (VarName+Stack) pair
	MaxAttemptsPerPair int

	// MaxCorpusCountPerVarName: if a VarName pair already has this many entries
	// in the corpus, skip timing exploration for it to avoid wasting resources
	// on common pairs. 0 means no limit.
	MaxCorpusCountPerVarName int

	// SuccessThreshold: trigger rate above this is considered successful
	SuccessThreshold float64

	// ======== Execution Parameters ========

	// TimingExplorationRatio is the fraction of executions dedicated to timing exploration
	// e.g., 0.1 means 10% of executions are timing explorations
	TimingExplorationRatio float64

	// ExecutionsPerAttempt is how many times to execute a delay plan to measure trigger rate
	ExecutionsPerAttempt int
}

// DefaultTimingExplorationConfig returns sensible defaults.
func DefaultTimingExplorationConfig() TimingExplorationConfig {
	return TimingExplorationConfig{
		// Pair Discovery Queue
		EnablePairDiscovery: true,
		UseRandomPartner:    true,

		// Timing Exploration Queue
		EnableTimingExploration:    false,
		TimingExplorationQueueSize: 500,
		WidenedThresholdMicros:     500000, // 500ms widened window

		// Delay parameters
		DelayMinMicros: 10,     // 10 microseconds
		DelayMaxMicros: 200000, // 200 milliseconds

		// Limits
		MaxDelaysPerProgram: 5,

		// Strategy
		TimingMutationStrategy:   "targeted",
		MaxAttemptsPerPair:       20,
		MaxCorpusCountPerVarName: 0,   // 0 = no limit (default)
		SuccessThreshold:         0.1, // 10% trigger rate = success

		// Execution
		TimingExplorationRatio: 0.1, // 10% of executions
		ExecutionsPerAttempt:   5,   // 5 executions per delay plan
	}
}

// Validate checks the configuration for invalid values and applies defaults.
func (c *TimingExplorationConfig) Validate() {
	if c.TimingExplorationQueueSize <= 0 {
		c.TimingExplorationQueueSize = 500
	}
	if c.WidenedThresholdMicros <= 0 {
		c.WidenedThresholdMicros = 500000
	}
	if c.DelayMinMicros <= 0 {
		c.DelayMinMicros = 10
	}
	if c.DelayMaxMicros <= c.DelayMinMicros {
		c.DelayMaxMicros = 200000
	}
	if c.MaxDelaysPerProgram <= 0 {
		c.MaxDelaysPerProgram = 5
	}
	if c.TimingMutationStrategy == "" {
		c.TimingMutationStrategy = "targeted"
	}
	if c.MaxAttemptsPerPair <= 0 {
		c.MaxAttemptsPerPair = 20
	}
	if c.SuccessThreshold <= 0 || c.SuccessThreshold > 1.0 {
		c.SuccessThreshold = 0.1
	}
	if c.TimingExplorationRatio <= 0 || c.TimingExplorationRatio > 1.0 {
		c.TimingExplorationRatio = 0.1
	}
	if c.ExecutionsPerAttempt <= 0 {
		c.ExecutionsPerAttempt = 5
	}
}

func isStartDelayTimingStrategy(strategy string) bool {
	return strategy == "start_delay" || strategy == "launch_jitter"
}
