// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package fuzzer provides timing scheduling for the dual-queue exploration architecture.
//
// The TimingScheduler coordinates two queues:
// 1. Pair Discovery Queue: Random pairing, normal threshold, discovers NEW VarName pairs
// 2. Timing Exploration Queue: Widened threshold, delay mutation, deduplicates by (VarName+Stack) quadruple
//
// Flow:
// Pair Discovery finds new VarName pairs → enqueue to Timing Exploration → apply delays → try to trigger race

package fuzzer

import (
	"math/rand"
	"sync"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/prog"
)

// ============================================================================
// Timing Exploration Job
// ============================================================================

// TimingExplorationJob represents a job for timing exploration.
type TimingExplorationJob struct {
	// The program pair to execute (with syz_delay mutations applied)
	Prog1 *prog.Prog
	Prog2 *prog.Prog

	// The original programs before delay mutation (for saving to corpus)
	OriginalProg1 *prog.Prog
	OriginalProg2 *prog.Prog

	// The target pair info
	TargetPair *ddrd.MayUAFPair

	// VarName pair ID for tracking
	VarNamePairID uint64

	// The delay plan applied
	DelayPlan DelayPlan

	// Number of attempts so far
	AttemptNumber int

	// CandidatePairs holds pairs discovered in Phase 1, to be validated in Phase 2
	CandidatePairs []*ddrd.MayUAFPair
}

// TimingExplorationResult represents the result of a timing exploration job.
type TimingExplorationResult struct {
	Job *TimingExplorationJob

	// Whether this job triggered any new pairs
	TriggeredNewPairs bool

	// New pairs found (deduplicated by VarName+Stack quadruple)
	NewPairs []*ddrd.MayUAFPair

	// Best success rate observed
	SuccessRate float64
}

// ============================================================================
// Timing Scheduler
// ============================================================================

// TimingScheduler coordinates the dual-queue exploration architecture.
type TimingScheduler struct {
	mu sync.Mutex

	target *prog.Target
	config TimingExplorationConfig

	// The exploration queue (from Pair Discovery)
	explorationQueue *TimingExplorationQueue

	// The VarName pair registry (for deduplication and tracking)
	pairRegistry *VarNamePairRegistry

	// The timing mutator
	mutator *TimingMutator

	// Corpus count checker: returns the number of corpus entries for a VarName pair
	// This is set after construction via SetCorpusCountChecker
	corpusCountChecker func(freeAccessName, useAccessName uint64) int

	// Random source
	rnd *rand.Rand

	// Stats
	stats TimingSchedulerStats
}

// TimingSchedulerStats tracks timing exploration statistics.
type TimingSchedulerStats struct {
	TotalJobsGenerated      int
	TotalJobsCompleted      int
	TotalNewVarNamePairs    int // NEW VarName pairs discovered
	TotalNewStackQuads      int // New (VarName+Stack) quadruples
	TotalRacesTriggered     int // Actual races triggered
	TimingExplorationHits   int // Timing exploration that found new stacks
	TimingExplorationMisses int
}

// NewTimingScheduler creates a new timing scheduler.
func NewTimingScheduler(
	target *prog.Target,
	config TimingExplorationConfig,
	pairRegistry *VarNamePairRegistry,
	rnd *rand.Rand,
) *TimingScheduler {
	config.Validate()

	return &TimingScheduler{
		target:           target,
		config:           config,
		explorationQueue: NewTimingExplorationQueue(config),
		pairRegistry:     pairRegistry,
		mutator:          NewTimingMutator(target, config),
		rnd:              rnd,
	}
}

// SetCorpusCountChecker sets the callback to check corpus VarName pair count.
// This must be called after construction to enable corpus-based filtering.
func (ts *TimingScheduler) SetCorpusCountChecker(checker func(freeAccessName, useAccessName uint64) int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.corpusCountChecker = checker
}

// shouldSkipByCorpusCount returns true if the VarName pair should be skipped
// because it already has enough entries in the corpus.
func (ts *TimingScheduler) shouldSkipByCorpusCount(pair *ddrd.MayUAFPair) bool {
	if pair == nil || ts.config.MaxCorpusCountPerVarName <= 0 {
		return false // No limit configured
	}
	if ts.corpusCountChecker == nil {
		return false // No checker set
	}
	count := ts.corpusCountChecker(pair.FreeAccessName, pair.UseAccessName)
	return count >= ts.config.MaxCorpusCountPerVarName
}

// ============================================================================
// Pair Discovery Interface
// ============================================================================

// OnNewVarNamePairDiscovered is called when Pair Discovery finds a NEW VarName pair.
// It enqueues the program pair for Timing Exploration.
func (ts *TimingScheduler) OnNewVarNamePairDiscovered(
	prog1, prog2 *prog.Prog,
	pair *ddrd.MayUAFPair,
) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Skip if this VarName pair already has enough corpus entries
	if ts.shouldSkipByCorpusCount(pair) {
		return
	}

	// Enqueue for timing exploration
	ts.explorationQueue.EnqueueHighQualityPair(prog1, prog2, pair)
	ts.stats.TotalNewVarNamePairs++
}

// OnStackQuadrupleDiscovered is called when a new (VarName+Stack) quadruple is found.
// This could come from either Pair Discovery or Timing Exploration.
func (ts *TimingScheduler) OnStackQuadrupleDiscovered(pair *ddrd.MayUAFPair) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.stats.TotalNewStackQuads++
}

// OnRaceTriggered is called when an actual race is triggered (may-race threshold).
func (ts *TimingScheduler) OnRaceTriggered(pair *ddrd.MayUAFPair) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.stats.TotalRacesTriggered++
}

// ============================================================================
// Timing Exploration Interface
// ============================================================================

// HasPendingJobs returns true if there are jobs waiting for exploration.
func (ts *TimingScheduler) HasPendingJobs() bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	return !ts.explorationQueue.IsEmpty() || ts.explorationQueue.HasValidationJobs()
}

// GetNextJob returns the next timing exploration job.
// Priority: Phase 2 validation jobs first, then Phase 1 discovery jobs.
// Returns nil if no jobs are available.
func (ts *TimingScheduler) GetNextJob() *TimingExplorationJob {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Priority 1: Check for Phase 2 validation jobs
	// Keep trying until we get a valid job or exhaust the validation queue
	for {
		validationJob := ts.explorationQueue.DequeueValidationJob()
		if validationJob == nil {
			break // No more validation jobs
		}
		if job := ts.createValidationJob(validationJob); job != nil {
			return job
		}
		// This validation job was skipped (e.g., timing attempts exhausted)
		// Continue to check next validation job
	}

	// Priority 2: Phase 1 discovery jobs
	return ts.createDiscoveryJob()
}

// createValidationJob creates a Phase 2 validation job with delays.
// NOTE: Phase 2 (validation) does NOT check ShouldAttemptTiming because
// Phase 1 already discovered valuable candidates. We want to validate
// them regardless of the target pair's attempt count.
func (ts *TimingScheduler) createValidationJob(vj *ValidationJob) *TimingExplorationJob {
	if vj == nil || vj.TargetPair == nil {
		return nil
	}

	targetPair := vj.TargetPair

	// Phase 2 validation: DO NOT check ShouldAttemptTiming
	// Phase 1 already found candidates, we must validate them

	// Generate delay plan for validation
	delayPlan := ts.mutator.GenerateDelayPlan(targetPair, nil, ts.rnd)

	// Apply delay plan to programs (insert syz_delay calls)
	mutatedProg1, mutatedProg2 := ts.mutator.ApplyDelayPlan(
		vj.Prog1, vj.Prog2, delayPlan,
	)

	attemptNum := ts.pairRegistry.GetTimingAttemptCount(targetPair)
	ts.stats.TotalJobsGenerated++

	return &TimingExplorationJob{
		Prog1:          mutatedProg1,
		Prog2:          mutatedProg2,
		OriginalProg1:  vj.Prog1,
		OriginalProg2:  vj.Prog2,
		TargetPair:     targetPair,
		VarNamePairID:  varNamePairID(targetPair.FreeAccessName, targetPair.UseAccessName),
		DelayPlan:      delayPlan, // Phase 2 has delays
		AttemptNumber:  attemptNum + 1,
		CandidatePairs: vj.CandidatePairs, // Pass candidate pairs from Phase 1
	}
}

// createDiscoveryJob creates a Phase 1 discovery job (no delays, widened threshold).
func (ts *TimingScheduler) createDiscoveryJob() *TimingExplorationJob {
	// Try to get a program pair from the queue
	hqPair := ts.explorationQueue.DequeueForExploration()
	if hqPair == nil {
		return nil
	}

	// Get the target pair
	targetPair := hqPair.OriginalPair
	if targetPair == nil {
		targetPair = ts.explorationQueue.GetNextPendingPair(hqPair)
	}
	if targetPair == nil {
		return nil
	}

	// Check corpus count: skip if this VarName pair already has enough entries
	if ts.shouldSkipByCorpusCount(targetPair) {
		return nil
	}

	// Check if we should attempt more timing exploration for this pair
	if !ts.pairRegistry.ShouldAttemptTiming(targetPair) {
		return nil
	}

	attemptNum := ts.pairRegistry.GetTimingAttemptCount(targetPair)
	ts.stats.TotalJobsGenerated++

	// Phase 1: NO delays - just widened threshold to discover candidates
	return &TimingExplorationJob{
		Prog1:         hqPair.Prog1, // Use original programs, no mutation
		Prog2:         hqPair.Prog2,
		OriginalProg1: hqPair.Prog1,
		OriginalProg2: hqPair.Prog2,
		TargetPair:    targetPair,
		VarNamePairID: hqPair.VarNamePairID,
		DelayPlan:     nil, // Phase 1: no delays
		AttemptNumber: attemptNum + 1,
	}
}

// OnJobCompleted is called when a timing exploration job finishes.
func (ts *TimingScheduler) OnJobCompleted(result *TimingExplorationResult) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if result == nil || result.Job == nil {
		return
	}

	job := result.Job

	// Record the attempt
	ts.pairRegistry.RecordTimingAttempt(job.TargetPair, result.SuccessRate)

	// Update stats
	ts.stats.TotalJobsCompleted++
	if result.TriggeredNewPairs {
		ts.stats.TimingExplorationHits++
	} else {
		ts.stats.TimingExplorationMisses++
	}
}

// EnqueueForValidation enqueues a program pair for Phase 2 validation.
// Called when Phase 1 (widened discovery) finds candidate pairs.
// Phase 2 will apply delays and use normal threshold to validate.
func (ts *TimingScheduler) EnqueueForValidation(
	prog1, prog2 *prog.Prog,
	targetPair *ddrd.MayUAFPair,
	candidatePairs []*ddrd.MayUAFPair,
) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if prog1 == nil || prog2 == nil || targetPair == nil {
		return
	}

	// Enqueue as high priority for validation
	ts.explorationQueue.EnqueueForValidation(prog1, prog2, targetPair, candidatePairs)
}

// ============================================================================
// Stats and Configuration
// ============================================================================

// GetStats returns a copy of the current stats.
func (ts *TimingScheduler) GetStats() TimingSchedulerStats {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.stats
}

// GetConfig returns the current configuration.
func (ts *TimingScheduler) GetConfig() TimingExplorationConfig {
	return ts.config
}

// Config returns the current configuration (alias for GetConfig).
func (ts *TimingScheduler) Config() TimingExplorationConfig {
	return ts.config
}

// RecordJobExecution records that a job was executed.
// Note: TotalJobsGenerated is already incremented in createValidationJob/createDiscoveryJob,
// so we do NOT increment it here to avoid double counting.
func (ts *TimingScheduler) RecordJobExecution(job *TimingExplorationJob) {
	if job == nil {
		return
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	// Intentionally not incrementing TotalJobsGenerated here.
	// It is incremented at creation time in createValidationJob/createDiscoveryJob.
}

// GetQueueStats returns the exploration queue stats.
func (ts *TimingScheduler) GetQueueStats() (enqueued, explored, pairsFound, currentSize int) {
	return ts.explorationQueue.GetStats()
}

// GetPendingJobCounts returns the current queue depths for discovery and validation.
func (ts *TimingScheduler) GetPendingJobCounts() (exploration, validation int) {
	return ts.explorationQueue.PendingCounts()
}

// ============================================================================
// Integration Helpers
// ============================================================================

// ShouldDoTimingExploration returns true if timing exploration should be performed.
// Uses the configured probability.
func (ts *TimingScheduler) ShouldDoTimingExploration() bool {
	if !ts.HasPendingJobs() {
		return false
	}
	return ts.rnd.Float64() < ts.config.TimingExplorationRatio
}

// IsNewVarNamePair checks if a pair represents a new VarName combination.
// Used by Pair Discovery to decide what to enqueue.
func (ts *TimingScheduler) IsNewVarNamePair(pair *ddrd.MayUAFPair) bool {
	if pair == nil || ts.pairRegistry == nil {
		return false
	}
	isNew, _, _ := ts.pairRegistry.CheckNewness(pair)
	return isNew
}
