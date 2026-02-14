// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sync"

	"github.com/google/syzkaller/pkg/ddrd"
)

// PairStats contains statistics about a specific pair.
type PairStats struct {
	// VarName level stats
	VarNameCorpusCount int // Number of different stacks for this VarName pair in corpus

	// Stack level stats (VarName + Stack quadruple)
	TimingAttempts int     // Number of timing exploration attempts
	TimingBestRate float64 // Best trigger rate achieved

	// Flags
	IsInCorpus bool // Whether this exact (VarName+Stack) pair is already in corpus
}

// PairEvaluatorConfig holds configuration for pair evaluation.
type PairEvaluatorConfig struct {
	// MaxCorpusCountPerVarName: skip if VarName pair has this many corpus entries
	// 0 means no limit
	MaxCorpusCountPerVarName int

	// MaxTimingAttemptsPerPair: max timing attempts per (VarName+Stack) pair
	// 0 means no limit
	MaxTimingAttemptsPerPair int

	// MaxStacksPerVarName: max stacks to save per VarName pair
	// 0 means no limit
	MaxStacksPerVarName int
}

// PairEvaluator provides unified pair evaluation for timing exploration and corpus saving.
type PairEvaluator struct {
	mu sync.RWMutex

	config PairEvaluatorConfig

	// Corpus count checker: returns the number of corpus entries for a VarName pair
	corpusCounter func(freeAccessName, useAccessName uint64) int

	// Pair registry for timing attempts tracking
	pairRegistry *VarNamePairRegistry

	// Stats
	statsExploreSkippedByCorpus int
	statsExploreSkippedByAttempts int
	statsSaveSkippedByCorpus    int
	statsSaveSkippedByLimit     int
}

// NewPairEvaluator creates a new PairEvaluator.
func NewPairEvaluator(config PairEvaluatorConfig, pairRegistry *VarNamePairRegistry) *PairEvaluator {
	return &PairEvaluator{
		config:       config,
		pairRegistry: pairRegistry,
	}
}

// SetCorpusCounter sets the callback to check corpus VarName pair count.
func (pe *PairEvaluator) SetCorpusCounter(counter func(freeAccessName, useAccessName uint64) int) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.corpusCounter = counter
}

// GetStats returns statistics for a pair.
func (pe *PairEvaluator) GetStats(pair *ddrd.MayUAFPair) PairStats {
	if pe == nil || pair == nil {
		return PairStats{}
	}

	stats := PairStats{}

	// Get VarName corpus count
	pe.mu.RLock()
	counter := pe.corpusCounter
	pe.mu.RUnlock()

	if counter != nil {
		stats.VarNameCorpusCount = counter(pair.FreeAccessName, pair.UseAccessName)
	}

	// Get timing stats from registry
	if pe.pairRegistry != nil {
		stats.TimingAttempts = pe.pairRegistry.GetTimingAttemptCount(pair)
		stats.TimingBestRate = pe.pairRegistry.GetTimingBestRate(pair)
	}

	return stats
}

// ShouldExplore returns true if the pair is worth exploring with timing mutations.
// This is used for Phase 1 (discovery) and Phase 2 (validation) filtering.
func (pe *PairEvaluator) ShouldExplore(pair *ddrd.MayUAFPair) bool {
	if pe == nil || pair == nil {
		return false
	}

	// Check 1: Corpus count limit for VarName pair
	if pe.config.MaxCorpusCountPerVarName > 0 {
		pe.mu.RLock()
		counter := pe.corpusCounter
		pe.mu.RUnlock()

		if counter != nil {
			count := counter(pair.FreeAccessName, pair.UseAccessName)
			if count >= pe.config.MaxCorpusCountPerVarName {
				pe.mu.Lock()
				pe.statsExploreSkippedByCorpus++
				pe.mu.Unlock()
				return false
			}
		}
	}

	// Check 2: Timing attempts limit for (VarName+Stack) pair
	if pe.config.MaxTimingAttemptsPerPair > 0 && pe.pairRegistry != nil {
		attempts := pe.pairRegistry.GetTimingAttemptCount(pair)
		if attempts >= pe.config.MaxTimingAttemptsPerPair {
			pe.mu.Lock()
			pe.statsExploreSkippedByAttempts++
			pe.mu.Unlock()
			return false
		}
	}

	return true
}

// ShouldSave returns true if the pair is worth saving to corpus.
// This is used after Phase 2 validation to filter candidates before saving.
func (pe *PairEvaluator) ShouldSave(pair *ddrd.MayUAFPair) bool {
	if pe == nil || pair == nil {
		return false
	}

	// Check 1: Corpus count limit for VarName pair
	if pe.config.MaxCorpusCountPerVarName > 0 {
		pe.mu.RLock()
		counter := pe.corpusCounter
		pe.mu.RUnlock()

		if counter != nil {
			count := counter(pair.FreeAccessName, pair.UseAccessName)
			if count >= pe.config.MaxCorpusCountPerVarName {
				pe.mu.Lock()
				pe.statsSaveSkippedByCorpus++
				pe.mu.Unlock()
				return false
			}
		}
	}

	// Check 2: MaxStacksPerVarName limit
	// Note: This is also enforced in uafCorpus.addSeed, but checking here
	// allows us to skip processing early
	if pe.config.MaxStacksPerVarName > 0 {
		pe.mu.RLock()
		counter := pe.corpusCounter
		pe.mu.RUnlock()

		if counter != nil {
			count := counter(pair.FreeAccessName, pair.UseAccessName)
			if count >= pe.config.MaxStacksPerVarName {
				pe.mu.Lock()
				pe.statsSaveSkippedByLimit++
				pe.mu.Unlock()
				return false
			}
		}
	}

	return true
}

// FilterCandidates filters a list of candidate pairs, keeping only those worth saving.
// Returns the filtered list and the number of pairs that were filtered out.
func (pe *PairEvaluator) FilterCandidates(pairs []*ddrd.MayUAFPair) ([]*ddrd.MayUAFPair, int) {
	if pe == nil || len(pairs) == 0 {
		return pairs, 0
	}

	filtered := make([]*ddrd.MayUAFPair, 0, len(pairs))
	skipped := 0

	for _, pair := range pairs {
		if pe.ShouldSave(pair) {
			filtered = append(filtered, pair)
		} else {
			skipped++
		}
	}

	return filtered, skipped
}

// GetEvaluatorStats returns internal statistics.
func (pe *PairEvaluator) GetEvaluatorStats() (exploreSkippedByCorpus, exploreSkippedByAttempts, saveSkippedByCorpus, saveSkippedByLimit int) {
	if pe == nil {
		return 0, 0, 0, 0
	}
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.statsExploreSkippedByCorpus, pe.statsExploreSkippedByAttempts,
		pe.statsSaveSkippedByCorpus, pe.statsSaveSkippedByLimit
}
