// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// ============================================================================
// PairCooldown - Prevents repeated execution of exhausted (main, partner) pairs
// ============================================================================
// Uses a three-tier scoring system based on discovery type:
// - New VarName pair discovered → reset failure score to 0
// - Only new stack discovered → add NewStackPenalty (default: 1)
// - Nothing discovered → add NoDiscoveryPenalty (default: 2)
//
// When failure score reaches CooldownThreshold (default: 20), the pair enters
// cooldown and receives a penalty in partner selection.
// ============================================================================

const (
	// DefaultCooldownThreshold is the failure score threshold before cooldown
	DefaultCooldownThreshold = 20
	// DefaultNewStackPenalty is the penalty for discovering only new stacks
	DefaultNewStackPenalty = 1
	// DefaultNoDiscoveryPenalty is the penalty for discovering nothing new
	DefaultNoDiscoveryPenalty = 2
	// DefaultCooldownDuration is how many partner selections to skip after entering cooldown
	DefaultCooldownDuration = 200
	// DefaultMaxPairEntries prevents unbounded growth of the pair tracking map
	DefaultMaxPairEntries = 50000
)

// PairState tracks the state of a (main, partner) pair.
type PairState struct {
	FailureScore      int // Accumulated failure score (reset on new VarName pair)
	CooldownRemaining int // Remaining partner selections to skip (0 = not in cooldown)
	TotalSuccesses    int // Total number of successful executions (found new VarName pairs)
	TotalNewStacks    int // Total number of executions that found new stacks (but not new VarName pairs)
	TotalFailures     int // Total number of executions that found nothing new
}

// PairCooldown manages cooldown state for (main, partner) pairs.
type PairCooldown struct {
	mu sync.RWMutex

	// (mainSig, partnerSig) -> PairState
	pairs map[string]*PairState

	// Configuration
	cooldownThreshold  int
	newStackPenalty    int
	noDiscoveryPenalty int
	cooldownDuration   int
	maxEntries         int

	// Statistics
	totalCooldowns    int
	activeCooldowns   int
	cooldownPenalties int
}

// PairCooldownConfig holds configuration for PairCooldown.
type PairCooldownConfig struct {
	CooldownThreshold  int // Failure score threshold to enter cooldown (default: 20)
	NewStackPenalty    int // Failure score penalty for new stack only (default: 1)
	NoDiscoveryPenalty int // Failure score penalty for no discovery (default: 2)
	CooldownDuration   int // How many partner selections to skip (default: 200)
	MaxEntries         int // Maximum pair entries to track (default: 50000)
}

// DefaultPairCooldownConfig returns the default configuration.
func DefaultPairCooldownConfig() PairCooldownConfig {
	return PairCooldownConfig{
		CooldownThreshold:  DefaultCooldownThreshold,
		NewStackPenalty:    DefaultNewStackPenalty,
		NoDiscoveryPenalty: DefaultNoDiscoveryPenalty,
		CooldownDuration:   DefaultCooldownDuration,
		MaxEntries:         DefaultMaxPairEntries,
	}
}

// NewPairCooldown creates a new PairCooldown manager with default config.
func NewPairCooldown() *PairCooldown {
	return NewPairCooldownWithConfig(DefaultPairCooldownConfig())
}

// NewPairCooldownWithConfig creates a new PairCooldown manager with custom config.
func NewPairCooldownWithConfig(cfg PairCooldownConfig) *PairCooldown {
	if cfg.CooldownThreshold <= 0 {
		cfg.CooldownThreshold = DefaultCooldownThreshold
	}
	if cfg.NewStackPenalty <= 0 {
		cfg.NewStackPenalty = DefaultNewStackPenalty
	}
	if cfg.NoDiscoveryPenalty <= 0 {
		cfg.NoDiscoveryPenalty = DefaultNoDiscoveryPenalty
	}
	if cfg.CooldownDuration <= 0 {
		cfg.CooldownDuration = DefaultCooldownDuration
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxPairEntries
	}
	return &PairCooldown{
		pairs:              make(map[string]*PairState),
		cooldownThreshold:  cfg.CooldownThreshold,
		newStackPenalty:    cfg.NewStackPenalty,
		noDiscoveryPenalty: cfg.NoDiscoveryPenalty,
		cooldownDuration:   cfg.CooldownDuration,
		maxEntries:         cfg.MaxEntries,
	}
}

// cooldownPairKey generates a unique key for a (main, partner) pair.
func cooldownPairKey(mainSig, partnerSig string) string {
	return mainSig + "|" + partnerSig
}

// RecordExecution records an execution result for a (main, partner) pair.
// Uses three-tier penalty system:
// - newVarNamePairCount > 0: reset failure score to 0 (highest value discovery)
// - newStackCount > 0 (but no new VarName pairs): add NewStackPenalty (medium value)
// - nothing new: add NoDiscoveryPenalty (true failure)
func (pc *PairCooldown) RecordExecution(main, partner *prog.Prog, newVarNamePairCount, newStackCount int) {
	if main == nil || partner == nil {
		return
	}

	mainSig := progSignature(main)
	partnerSig := progSignature(partner)
	key := cooldownPairKey(mainSig, partnerSig)

	pc.mu.Lock()
	defer pc.mu.Unlock()

	state := pc.pairs[key]
	if state == nil {
		// Check if we need to evict old entries
		if len(pc.pairs) >= pc.maxEntries {
			pc.evictOldEntries()
		}
		state = &PairState{}
		pc.pairs[key] = state
	}

	if newVarNamePairCount > 0 {
		// Highest value: new VarName pair discovered
		// Reset failure score and exit cooldown
		state.FailureScore = 0
		state.CooldownRemaining = 0
		state.TotalSuccesses++
	} else if newStackCount > 0 {
		// Medium value: new stack for existing VarName pair
		// Apply smaller penalty
		state.FailureScore += pc.newStackPenalty
		state.TotalNewStacks++
	} else {
		// No discovery: true failure
		// Apply larger penalty
		state.FailureScore += pc.noDiscoveryPenalty
		state.TotalFailures++
	}

	// Check if we should enter cooldown
	if state.FailureScore >= pc.cooldownThreshold && state.CooldownRemaining == 0 {
		state.CooldownRemaining = pc.cooldownDuration
		pc.totalCooldowns++
		pc.activeCooldowns++
		log.Logf(0, "[PAIR-COOLDOWN] pair entered cooldown: score=%d threshold=%d duration=%d total_cooldowns=%d",
			state.FailureScore, pc.cooldownThreshold, pc.cooldownDuration, pc.totalCooldowns)
	}
}

// GetPenalty returns a penalty multiplier for a (main, partner) pair.
// Returns 1.0 for normal pairs, 0.01 for pairs in cooldown.
func (pc *PairCooldown) GetPenalty(main, partner *prog.Prog) float64 {
	if main == nil || partner == nil {
		return 1.0
	}

	mainSig := progSignature(main)
	partnerSig := progSignature(partner)
	key := cooldownPairKey(mainSig, partnerSig)

	pc.mu.RLock()
	defer pc.mu.RUnlock()

	state := pc.pairs[key]
	if state == nil || state.CooldownRemaining == 0 {
		return 1.0
	}

	// Pair is in cooldown - apply heavy penalty
	pc.cooldownPenalties++
	return 0.01
}

// DecrementCooldowns should be called periodically (e.g., every partner selection)
// to decrement cooldown counters.
func (pc *PairCooldown) DecrementCooldowns() {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	for _, state := range pc.pairs {
		if state.CooldownRemaining > 0 {
			state.CooldownRemaining--
			if state.CooldownRemaining == 0 {
				pc.activeCooldowns--
			}
		}
	}
}

// evictOldEntries removes the oldest entries when the map is full.
// Called with lock held.
func (pc *PairCooldown) evictOldEntries() {
	// Simple strategy: remove entries with 0 cooldown and lowest total count
	toRemove := len(pc.pairs) / 4 // Remove 25%
	removed := 0

	for key, state := range pc.pairs {
		if state.CooldownRemaining == 0 && state.TotalSuccesses == 0 {
			delete(pc.pairs, key)
			removed++
			if removed >= toRemove {
				break
			}
		}
	}
}

// GetStats returns statistics about the cooldown system.
func (pc *PairCooldown) GetStats() (pairCount, totalCooldowns, activeCooldowns int) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return len(pc.pairs), pc.totalCooldowns, pc.activeCooldowns
}
