// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package uafvalidate

import (
	"context"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// HistoryMinimizer attempts to find the minimum subset of replay history
// records required to reproduce a race condition.
type HistoryMinimizerRunner func(ctx context.Context, entry *fuzzer.UAFCorpusEntry) (*ExecutionResult, error)

type HistoryMinimizer struct {
	runAttempt HistoryMinimizerRunner
	cfg        Config
	entry      *fuzzer.UAFCorpusEntry

	// Statistics
	totalAttempts   int
	successAttempts int
}

// MinimizationResult contains the result of history minimization.
type MinimizationResult struct {
	// MinimalHistory is the smallest subset of history that can reproduce the race.
	// If minimization failed, this is nil.
	MinimalHistory []*fuzzer.BarrierExecutionRecord

	// OriginalCount is the number of records in the original history.
	OriginalCount int

	// MinimalCount is the number of records in the minimal history.
	MinimalCount int

	// TotalAttempts is the total number of execution attempts during minimization.
	TotalAttempts int

	// Success indicates whether minimization found a working subset.
	Success bool

	// Error contains any error that occurred during minimization.
	Error error
}

// NewHistoryMinimizer creates a new minimizer.
func NewHistoryMinimizer(runAttempt HistoryMinimizerRunner, cfg Config, entry *fuzzer.UAFCorpusEntry) *HistoryMinimizer {
	return &HistoryMinimizer{
		runAttempt: runAttempt,
		cfg:        cfg,
		entry:      entry,
	}
}

// Minimize attempts to find the minimum history subset.
// Returns the minimization result.
func (m *HistoryMinimizer) Minimize(ctx context.Context) *MinimizationResult {
	result := &MinimizationResult{
		OriginalCount: len(m.entry.ReplayHistory),
	}

	if len(m.entry.ReplayHistory) == 0 {
		log.Logf(0, "minimize: no history to minimize")
		result.Success = true
		result.MinimalCount = 0
		return result
	}

	log.Logf(0, "minimize: starting with %d history records, strategy=%s",
		len(m.entry.ReplayHistory), m.cfg.MinimizationStrategy)

	var minHistory []*fuzzer.BarrierExecutionRecord
	var err error

	switch m.cfg.MinimizationStrategy {
	case "greedy":
		minHistory, err = m.greedyMinimize(ctx)
	case "hybrid":
		minHistory, err = m.hybridMinimize(ctx)
	default: // "binary"
		minHistory, err = m.binaryMinimize(ctx)
	}

	result.TotalAttempts = m.totalAttempts
	if err != nil {
		result.Error = err
		log.Logf(0, "minimize: failed with error: %v", err)
		return result
	}

	result.MinimalHistory = minHistory
	result.MinimalCount = len(minHistory)
	result.Success = true

	reduction := 0.0
	if result.OriginalCount > 0 {
		reduction = 100.0 * (1 - float64(result.MinimalCount)/float64(result.OriginalCount))
	}
	log.Logf(0, "minimize: success! reduced from %d to %d records (%.1f%% reduction), attempts=%d",
		result.OriginalCount, result.MinimalCount, reduction, result.TotalAttempts)

	return result
}

// binaryMinimize uses binary search to find a minimal history subset.
// Algorithm:
// 1. Try with first half of history
// 2. If it works, recurse on first half
// 3. If not, try second half
// 4. If neither half works, the full history is needed
func (m *HistoryMinimizer) binaryMinimize(ctx context.Context) ([]*fuzzer.BarrierExecutionRecord, error) {
	history := m.entry.ReplayHistory
	return m.binaryMinimizeRecursive(ctx, history, 0)
}

func (m *HistoryMinimizer) binaryMinimizeRecursive(ctx context.Context, history []*fuzzer.BarrierExecutionRecord, depth int) ([]*fuzzer.BarrierExecutionRecord, error) {
	if len(history) <= 1 {
		// Base case: can't reduce further
		return history, nil
	}

	mid := len(history) / 2
	firstHalf := history[:mid]
	secondHalf := history[mid:]

	log.Logf(1, "minimize: depth=%d trying first half (%d records)", depth, len(firstHalf))

	// Try first half
	if m.canTrigger(ctx, firstHalf) {
		// First half works, recurse
		return m.binaryMinimizeRecursive(ctx, firstHalf, depth+1)
	}

	log.Logf(1, "minimize: depth=%d first half failed, trying second half (%d records)", depth, len(secondHalf))

	// Try second half
	if m.canTrigger(ctx, secondHalf) {
		// Second half works, recurse
		return m.binaryMinimizeRecursive(ctx, secondHalf, depth+1)
	}

	log.Logf(1, "minimize: depth=%d neither half works, keeping full (%d records)", depth, len(history))

	// Neither half works, need full history
	return history, nil
}

// greedyMinimize removes one record at a time and checks if the race still triggers.
// This is slower but finds a better minimum.
func (m *HistoryMinimizer) greedyMinimize(ctx context.Context) ([]*fuzzer.BarrierExecutionRecord, error) {
	// Start with full history
	current := make([]*fuzzer.BarrierExecutionRecord, len(m.entry.ReplayHistory))
	copy(current, m.entry.ReplayHistory)

	for {
		improved := false
		// Try removing each record
		for i := 0; i < len(current); i++ {
			select {
			case <-ctx.Done():
				return current, ctx.Err()
			default:
			}

			// Create subset without record i
			subset := make([]*fuzzer.BarrierExecutionRecord, 0, len(current)-1)
			subset = append(subset, current[:i]...)
			subset = append(subset, current[i+1:]...)

			log.Logf(2, "minimize: greedy trying without record %d (%d remaining)", i, len(subset))

			if m.canTrigger(ctx, subset) {
				// Can trigger without this record, remove it permanently
				log.Logf(1, "minimize: greedy removed record %d, %d remaining", i, len(subset))
				current = subset
				improved = true
				break // Restart from beginning since indices changed
			}
		}

		if !improved {
			// No more records can be removed
			break
		}
	}

	return current, nil
}

// hybridMinimize first uses binary search, then refines with greedy.
func (m *HistoryMinimizer) hybridMinimize(ctx context.Context) ([]*fuzzer.BarrierExecutionRecord, error) {
	// Phase 1: Binary search for quick reduction
	log.Logf(0, "minimize: hybrid phase 1 - binary search")
	binaryResult, err := m.binaryMinimize(ctx)
	if err != nil {
		return nil, err
	}

	log.Logf(0, "minimize: hybrid phase 1 complete, reduced to %d records", len(binaryResult))

	// Phase 2: Greedy refinement
	log.Logf(0, "minimize: hybrid phase 2 - greedy refinement")

	// Temporarily replace entry's history with binary result for greedy phase
	originalHistory := m.entry.ReplayHistory
	m.entry.ReplayHistory = binaryResult
	defer func() { m.entry.ReplayHistory = originalHistory }()

	return m.greedyMinimize(ctx)
}

// canTrigger tests if the race can be triggered with the given history subset.
// It makes multiple attempts to account for race non-determinism.
func (m *HistoryMinimizer) canTrigger(ctx context.Context, history []*fuzzer.BarrierExecutionRecord) bool {
	if m.runAttempt == nil {
		log.Logf(0, "minimize: no attempt runner configured")
		return false
	}

	for attempt := 0; attempt < m.cfg.MinimizationMaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		m.totalAttempts++

		// Create a modified entry with the subset of history
		testEntry := m.cloneEntryWithHistory(history)

		execCtx, cancel := context.WithTimeout(ctx, m.cfg.ExecutionTimeout)
		result, err := m.runAttempt(execCtx, testEntry)
		cancel()

		if err != nil {
			log.Logf(2, "minimize: attempt %d error: %v", attempt, err)
			continue
		}

		if result.TriggeredCount > 0 {
			m.successAttempts++
			log.Logf(2, "minimize: attempt %d triggered! history_size=%d", attempt, len(history))
			return true
		}
	}

	return false
}

// cloneEntryWithHistory creates a copy of the entry with a different history.
func (m *HistoryMinimizer) cloneEntryWithHistory(history []*fuzzer.BarrierExecutionRecord) *fuzzer.UAFCorpusEntry {
	clone := &fuzzer.UAFCorpusEntry{
		CallIdx:       m.entry.CallIdx,
		PairBasicInfo: m.entry.PairBasicInfo,
		Signals:       m.entry.Signals,
		Barrier:       m.entry.Barrier,
		ReplayPlan:    m.entry.ReplayPlan,
		Profile:       m.entry.Profile,
		Timestamp:     time.Now(),
		Kind:          m.entry.Kind,
	}

	// Clone programs
	if m.entry.Prog != nil {
		clone.Prog = m.entry.Prog.Clone()
	}
	if len(m.entry.Programs) > 0 {
		clone.Programs = make([]*prog.Prog, len(m.entry.Programs))
		for i, p := range m.entry.Programs {
			if p != nil {
				clone.Programs[i] = p.Clone()
			}
		}
	}

	// Clone pairs
	if len(m.entry.Pairs) > 0 {
		clone.Pairs = make([]*ddrd.MayUAFPair, len(m.entry.Pairs))
		for i, p := range m.entry.Pairs {
			if p != nil {
				pCopy := *p
				clone.Pairs[i] = &pCopy
			}
		}
	}

	// Use the provided history subset
	clone.ReplayHistory = history

	return clone
}
