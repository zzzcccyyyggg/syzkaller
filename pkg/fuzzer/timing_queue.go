// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package fuzzer provides timing exploration queue implementation.
//
// The timing exploration queue receives high-quality program pairs
// (those that discovered NEW VarName pairs) and explores them with:
// - WIDENED timing threshold to capture more potential pairs
// - Delay mutation to optimize race triggering
// - Deduplication by (VarName + Stack) quadruple (via VarNamePairRegistry)

package fuzzer

import (
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/prog"
)

// ============================================================================
// Timing Exploration Queue
// ============================================================================

// HighQualityProgramPair represents a program pair that discovered a new VarName pair.
// These are "high-quality" because they've proven to trigger races.
// The pair is stored in the timing exploration queue for further optimization.
type HighQualityProgramPair struct {
	// The programs that discovered the race
	Prog1 *prog.Prog
	Prog2 *prog.Prog

	// The VarName pair that made this high-quality (for reference)
	VarNamePairID uint64

	// Original pair info (Free/Use syscall indices, etc.)
	OriginalPair *ddrd.MayUAFPair

	// Exploration state
	ExplorationCount int       // How many times this program pair has been explored
	DiscoveredAt     time.Time // When this pair was discovered
	LastExploredAt   time.Time // Last exploration time

	// Pairs found during widened-threshold exploration
	// These are candidates for timing optimization
	PendingPairs []*ddrd.MayUAFPair
}

// TimingExplorationQueue manages high-quality program pairs for timing exploration.
// It uses VarNamePairRegistry for deduplication (no duplicate storage).
type TimingExplorationQueue struct {
	mu sync.RWMutex

	// Queue of high-quality program pairs (Phase 1: discovery)
	entries []*HighQualityProgramPair

	// Queue of validation jobs (Phase 2: apply delays, use normal threshold)
	validationQueue []*ValidationJob

	// VarName pairs already in queue (to avoid duplicate entries)
	inQueue map[uint64]bool

	// Configuration
	config TimingExplorationConfig

	// Statistics
	totalEnqueued   int
	totalExplored   int
	totalPairsFound int
	totalValidated  int
}

// ValidationJob represents a Phase 2 validation job.
type ValidationJob struct {
	Prog1          *prog.Prog
	Prog2          *prog.Prog
	TargetPair     *ddrd.MayUAFPair
	CandidatePairs []*ddrd.MayUAFPair
	EnqueuedAt     time.Time
}

// NewTimingExplorationQueue creates a new timing exploration queue.
func NewTimingExplorationQueue(config TimingExplorationConfig) *TimingExplorationQueue {
	config.Validate()
	return &TimingExplorationQueue{
		entries:         make([]*HighQualityProgramPair, 0),
		validationQueue: make([]*ValidationJob, 0),
		inQueue:         make(map[uint64]bool),
		config:          config,
	}
}

// EnqueueHighQualityPair adds a program pair that discovered a new VarName pair.
// Returns true if enqueued, false if duplicate or queue full.
func (q *TimingExplorationQueue) EnqueueHighQualityPair(
	prog1, prog2 *prog.Prog,
	discoveredPair *ddrd.MayUAFPair,
) bool {
	if discoveredPair == nil || prog1 == nil {
		return false
	}

	varNamePairID := varNamePairID(discoveredPair.FreeAccessName, discoveredPair.UseAccessName)

	q.mu.Lock()
	defer q.mu.Unlock()

	// Check for duplicates (same VarName pair already in queue)
	if q.inQueue[varNamePairID] {
		return false
	}

	// Check queue size limit
	if len(q.entries) >= q.config.TimingExplorationQueueSize {
		return false
	}

	// Clone programs to avoid mutation issues
	clonedProg1 := prog1.Clone()
	var clonedProg2 *prog.Prog
	if prog2 != nil {
		clonedProg2 = prog2.Clone()
	}

	entry := &HighQualityProgramPair{
		Prog1:            clonedProg1,
		Prog2:            clonedProg2,
		VarNamePairID:    varNamePairID,
		OriginalPair:     discoveredPair,
		DiscoveredAt:     time.Now(),
		ExplorationCount: 0,
		PendingPairs:     make([]*ddrd.MayUAFPair, 0),
	}

	q.entries = append(q.entries, entry)
	q.inQueue[varNamePairID] = true
	q.totalEnqueued++

	return true
}

// DequeueForExploration returns the next program pair for exploration.
// Returns nil if queue is empty.
func (q *TimingExplorationQueue) DequeueForExploration() *HighQualityProgramPair {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.entries) == 0 {
		return nil
	}

	// FIFO: take from front
	entry := q.entries[0]
	q.entries = q.entries[1:]

	entry.ExplorationCount++
	entry.LastExploredAt = time.Now()
	q.totalExplored++

	return entry
}

// RequeueForMoreExploration puts a program pair back for more exploration.
// Called when there are still unexplored pairs in this program pair.
func (q *TimingExplorationQueue) RequeueForMoreExploration(entry *HighQualityProgramPair) {
	if entry == nil {
		return
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	// Add back to end of queue
	q.entries = append(q.entries, entry)
}

// MarkExplorationComplete removes a program pair from the queue tracking.
// Called when all pairs in this program pair have been explored.
func (q *TimingExplorationQueue) MarkExplorationComplete(entry *HighQualityProgramPair) {
	if entry == nil {
		return
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	delete(q.inQueue, entry.VarNamePairID)
}

// AddPendingPairs adds pairs found during widened-threshold exploration.
func (q *TimingExplorationQueue) AddPendingPairs(entry *HighQualityProgramPair, pairs []*ddrd.MayUAFPair) {
	if entry == nil {
		return
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	entry.PendingPairs = append(entry.PendingPairs, pairs...)
	q.totalPairsFound += len(pairs)
}

// GetNextPendingPair returns the next pair to optimize from an entry.
// Returns nil if no more pending pairs.
func (q *TimingExplorationQueue) GetNextPendingPair(entry *HighQualityProgramPair) *ddrd.MayUAFPair {
	if entry == nil || len(entry.PendingPairs) == 0 {
		return nil
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	pair := entry.PendingPairs[0]
	entry.PendingPairs = entry.PendingPairs[1:]
	return pair
}

// HasPendingPairs returns true if the entry has more pairs to explore.
func (q *TimingExplorationQueue) HasPendingPairs(entry *HighQualityProgramPair) bool {
	if entry == nil {
		return false
	}

	q.mu.RLock()
	defer q.mu.RUnlock()

	return len(entry.PendingPairs) > 0
}

// Size returns current queue size.
func (q *TimingExplorationQueue) Size() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.entries)
}

// IsEmpty returns true if the queue is empty.
func (q *TimingExplorationQueue) IsEmpty() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.entries) == 0
}

// GetStats returns queue statistics.
func (q *TimingExplorationQueue) GetStats() (enqueued, explored, pairsFound, currentSize int) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.totalEnqueued, q.totalExplored, q.totalPairsFound, len(q.entries)
}

// PendingCounts returns the current queue depths for discovery and validation.
func (q *TimingExplorationQueue) PendingCounts() (exploration, validation int) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.entries), len(q.validationQueue)
}

// Clear removes all entries from the queue.
func (q *TimingExplorationQueue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.entries = make([]*HighQualityProgramPair, 0)
	q.validationQueue = make([]*ValidationJob, 0)
	q.inQueue = make(map[uint64]bool)
}

// EnqueueForValidation adds a program pair for Phase 2 validation.
// Phase 2 uses normal threshold with delays to confirm the pair.
func (q *TimingExplorationQueue) EnqueueForValidation(
	prog1, prog2 *prog.Prog,
	targetPair *ddrd.MayUAFPair,
	candidatePairs []*ddrd.MayUAFPair,
) {
	if prog1 == nil || targetPair == nil {
		return
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	job := &ValidationJob{
		Prog1:          prog1.Clone(),
		TargetPair:     targetPair,
		CandidatePairs: candidatePairs,
		EnqueuedAt:     time.Now(),
	}
	if prog2 != nil {
		job.Prog2 = prog2.Clone()
	}

	q.validationQueue = append(q.validationQueue, job)
}

// DequeueValidationJob returns the next validation job (Phase 2).
// Returns nil if no validation jobs are pending.
func (q *TimingExplorationQueue) DequeueValidationJob() *ValidationJob {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.validationQueue) == 0 {
		return nil
	}

	job := q.validationQueue[0]
	q.validationQueue = q.validationQueue[1:]
	q.totalValidated++

	return job
}

// HasValidationJobs returns true if there are Phase 2 validation jobs pending.
func (q *TimingExplorationQueue) HasValidationJobs() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.validationQueue) > 0
}
