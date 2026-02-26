// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	uafvalidate "github.com/google/syzkaller/pkg/racevalidate"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

// ============================================================================
// Race Validation Types
// ============================================================================

// ReproLevel indicates how reproducible a data race is.
type ReproLevel int

const (
	// ReproNone means the race was not reproduced.
	ReproNone ReproLevel = iota
	// ReproProg means the race can be triggered by replaying the syzlang program
	// (detected via DDRD framework, no kernel crash required).
	ReproProg
	// ReproCrash means the race triggered a real kernel crash (KASAN/KCSAN).
	// The crash is forwarded to CrashReproLoop for C reproducer generation.
	ReproCrash
)

func (l ReproLevel) String() string {
	switch l {
	case ReproNone:
		return "none"
	case ReproProg:
		return "prog"
	case ReproCrash:
		return "crash"
	default:
		return fmt.Sprintf("unknown(%d)", int(l))
	}
}

// RaceReproTask represents a validated timing pair that should be reproduced on a VM.
// Created by Phase 2 success → forwarded to RaceValidateLoop.
type RaceReproTask struct {
	// The original barrier programs (before delay insertion).
	Prog1 *prog.Prog
	Prog2 *prog.Prog

	// The merged program with syz_delay injected (ready to execute).
	MergedProg *prog.Prog

	// Target pair info (VarName pair that was validated).
	FreeAccessName uint64
	UseAccessName  uint64

	// VarName pair ID for deduplication.
	VarNamePairID uint64

	// The delay plan that was used in Phase 2 validation.
	DelayPlan []DelayInsertion

	// Candidate pairs discovered during Phase 1/2.
	CandidatePairCount int

	// RepeatBudget is how many times to execute this program on the VM.
	// Each execution attempts to trigger a kernel crash or stable DDRD detection.
	RepeatBudget int

	// ReplayHistory carries the execution history leading up to this pair's validation.
	// Used to replay system state before each collection/verification attempt.
	ReplayHistory []*fuzzer.BarrierExecutionRecord
}

// DelayInsertion mirrors fuzzer.DelayInsertion for cross-package use.
type DelayInsertion struct {
	ProgIdx     int
	BeforeCall  int
	DelayMicros int64
}

// TaskID returns a unique identifier for this task (for deduplication).
func (t *RaceReproTask) TaskID() string {
	return fmt.Sprintf("race_%x_%x", t.FreeAccessName, t.UseAccessName)
}

// RaceReproResult holds the outcome of a race reproduction attempt.
type RaceReproResult struct {
	Task *RaceReproTask

	// Whether the race was reproduced at any level.
	Reproduced bool

	// The reproduction level achieved.
	ReproLevel ReproLevel

	// The program that can reproduce the race (if ReproLevel >= ReproProg).
	// This is the merged program with delays that triggered the race.
	ProgRepro *prog.Prog

	// If a kernel crash was triggered, this holds the crash info.
	// The crash is also forwarded to CrashReproLoop for C reproducer.
	Crash *Crash

	// How many attempts were made before success (or budget exhaustion).
	Attempts int

	// How many times out of Attempts the DDRD pair was detected.
	// Used to compute stability: DetectionCount/Attempts.
	DetectionCount int
}

// StabilityRate returns the fraction of attempts that detected the target pair.
func (r *RaceReproResult) StabilityRate() float64 {
	if r.Attempts == 0 {
		return 0
	}
	return float64(r.DetectionCount) / float64(r.Attempts)
}

// ============================================================================
// RaceValidateLoop — wraps StageManager for online validation
// ============================================================================

// RaceReproManagerView is the interface that Manager must implement
// for RaceValidateLoop to function.
type RaceReproManagerView interface {
	// ResizeRaceReproPool adjusts the VM pool reservation for race validation.
	ResizeRaceReproPool(size int)
}

// RaceReproLoop manages the queue of validated timing pairs awaiting
// validation on VMs. It wraps StageManager from pkg/racevalidate
// to reuse the full barrier/fork-barrier execution pipeline.
type RaceReproLoop struct {
	statPending    *stat.Val
	statValidating *stat.Val
	statValidated  *stat.Val

	mgr      RaceReproManagerView
	raceVMs  int

	mu        sync.Mutex
	seenTasks map[string]bool // taskID → seen (for dedup before Enqueue)
	stage     *uafvalidate.StageManager
}

// NewRaceReproLoop creates a new RaceRepoLoop backed by StageManager.
// raceVMs: how many VMs are dedicated to race validation.
// factory: ExecutorFactory that creates VMs for validation (provided by Manager).
// rrCfg: user-facing RaceReproConfig from mgrconfig (can be nil for defaults).
func NewRaceReproLoop(mgr RaceReproManagerView, raceVMs int, factory uafvalidate.ExecutorFactory, rrCfg *mgrconfig.RaceReproConfig) *RaceReproLoop {
	if raceVMs <= 0 {
		raceVMs = 0
	}

	// Build StageManager config from user-facing RaceReproConfig.
	// Defaults match the offline validate pipeline behavior.
	cfg := uafvalidate.Config{
		MaxConcurrent:     max(raceVMs, 1),
		RepeatCount:       5,
		VerifyRepeatTimes: 10,
		ExecutionTimeout:  90 * time.Second,
		ForkBarrierMode:   false, // Per-entry: entry.ForkBarrier decides fork vs multi-proc barrier
		DisableHBSkip:     true,  // Already validated in Phase 2
		// Replay enabled by default — replay execution history for system state warmup
		EnableReplay:           true,
		DisableCollectionDelay: false,
		DisableVerifyDelay:     false,
		VerifyDelayMultiplier:  2.0,
		VerifyDelaySweep:       false,
		VerifyDelaySteps:       5,
		VerifyDelayMaxUs:       1000,
		VerifyDelayPower:       2.0,
	}

	// Override from user config if provided.
	if rrCfg != nil {
		if rrCfg.RepeatCount > 0 {
			cfg.RepeatCount = rrCfg.RepeatCount
		}
		if rrCfg.VerifyRepeatTimes > 0 {
			cfg.VerifyRepeatTimes = rrCfg.VerifyRepeatTimes
		}
		if rrCfg.EnableReplay != nil {
			cfg.EnableReplay = *rrCfg.EnableReplay
		}
		cfg.ReplayCollectPairs = rrCfg.ReplayCollectPairs
		cfg.DisableCollectionDelay = rrCfg.DisableCollectionDelay
		cfg.DisableVerifyDelay = rrCfg.DisableVerifyDelay
		cfg.EnableHistoryMinimization = rrCfg.EnableHistoryMinimization
		if rrCfg.DelaySweep {
			cfg.VerifyDelaySweep = true
			cfg.VerifyDelayMultiplier = 0 // Sweep takes priority when explicitly enabled
		}
		if rrCfg.DelaySweepSteps > 0 {
			cfg.VerifyDelaySteps = rrCfg.DelaySweepSteps
		}
		if rrCfg.DelayMaxUs > 0 {
			cfg.VerifyDelayMaxUs = rrCfg.DelayMaxUs
		}
	}

	var stage *uafvalidate.StageManager
	if factory != nil && raceVMs > 0 {
		stage = uafvalidate.NewStageManager(cfg, factory)
	}

	ret := &RaceReproLoop{
		mgr:       mgr,
		raceVMs:   raceVMs,
		seenTasks: map[string]bool{},
		stage:     stage,
	}
	ret.statPending = stat.New("race_repro_pending",
		"Number of pending race validation tasks",
		stat.Console, stat.NoGraph, func() int {
			if ret.stage == nil {
				return 0
			}
			return ret.stage.PendingCount()
		})
	ret.statValidating = stat.New("race_reproducing",
		"Number of race pairs being validated",
		stat.Console, stat.NoGraph, func() int {
			if ret.stage == nil {
				return 0
			}
			return ret.stage.PendingCount()
		})
	ret.statValidated = stat.New("race_reproduced",
		"Number of race validations completed",
		stat.Console, stat.NoGraph, func() int {
			if ret.stage == nil {
				return 0
			}
			return ret.stage.SeenCount()
		})
	return ret
}

// Enqueue converts a RaceReproTask into a UAFCorpusEntry and submits it
// to the StageManager for validation using the full barrier/DDRD pipeline.
func (r *RaceReproLoop) Enqueue(task *RaceReproTask) {
	if task == nil || r.stage == nil || r.raceVMs <= 0 {
		return
	}

	r.mu.Lock()
	taskID := task.TaskID()
	if r.seenTasks[taskID] {
		r.mu.Unlock()
		log.Logf(1, "[RACE-VALIDATE] Enqueue skipped (already seen): %s", taskID)
		return
	}
	r.seenTasks[taskID] = true
	r.mu.Unlock()

	// Build a UAFCorpusEntry from the RaceReproTask.
	// This is the same structure that normal fuzzing creates when discovering pairs.
	entry := taskToUAFCorpusEntry(task)
	if entry == nil {
		log.Logf(0, "[RACE-VALIDATE] Enqueue failed: could not build UAFCorpusEntry for %s", taskID)
		return
	}

	log.Logf(0, "[RACE-VALIDATE] Enqueued %s (free=0x%x use=0x%x progs=%d merged=%v)",
		taskID, task.FreeAccessName, task.UseAccessName,
		len(entry.Programs), entry.MergedProg != nil)

	r.stage.Enqueue(entry)
}

// Loop starts the StageManager.Run() and result consumer.
// It runs until ctx is cancelled. Does NOT call Close() on StageManager
// so that new entries can be enqueued at any time during fuzzing.
func (r *RaceReproLoop) Loop(ctx context.Context) {
	if r.stage == nil || r.raceVMs <= 0 {
		log.Logf(0, "[RACE-VALIDATE] Loop not started: no VMs allocated")
		return
	}
	defer log.Logf(0, "[RACE-VALIDATE] Loop terminated")

	// Reserve VMs from dispatcher pool BEFORE starting workers.
	// Without this, pool.Run() in the executor factory will block forever
	// because no VMs are reserved for the "run" category.
	r.mgr.ResizeRaceReproPool(r.raceVMs)
	defer r.mgr.ResizeRaceReproPool(0) // Release reservation on exit

	log.Logf(0, "[RACE-VALIDATE] Starting race validation loop (%d VMs)", r.raceVMs)

	// Consume results from StageManager in a separate goroutine.
	go func() {
		for res := range r.stage.Results() {
			r.handleResult(res)
		}
	}()

	// Run StageManager workers — blocks until context cancelled.
	// When ctx is cancelled, we Shutdown the stage to unblock workers.
	go func() {
		<-ctx.Done()
		r.stage.Shutdown()
	}()

	r.stage.Run(ctx)
}

// handleResult processes a ValidationResult from StageManager.
func (r *RaceReproLoop) handleResult(res *uafvalidate.ValidationResult) {
	if res == nil {
		return
	}
	entry := res.Entry
	pairDesc := "unknown"
	if entry != nil {
		pairDesc = fmt.Sprintf("free=0x%x use=0x%x", entry.PairBasicInfo.FreeAccessName, entry.PairBasicInfo.UseAccessName)
	}

	if res.CrashTitle != "" {
		log.Logf(0, "[RACE-VALIDATE-RESULT] CRASH: pair=%s attempt=%d/%d title=%q",
			pairDesc, res.Attempt, res.RepeatTotal, res.CrashTitle)
	} else if res.Success {
		log.Logf(0, "[RACE-VALIDATE-RESULT] SUCCESS: pair=%s attempt=%d/%d stable_pairs=%d",
			pairDesc, res.Attempt, res.RepeatTotal, len(res.StablePairs))
	} else if res.Err != nil {
		log.Logf(1, "[RACE-VALIDATE-RESULT] ERROR: pair=%s err=%v",
			pairDesc, res.Err)
	} else {
		log.Logf(1, "[RACE-VALIDATE-RESULT] pair=%s attempt=%d/%d pairs_found=%d",
			pairDesc, res.Attempt, res.RepeatTotal, len(res.Pairs))
	}
}

// Empty returns true if there are no running or pending tasks.
func (r *RaceReproLoop) Empty() bool {
	if r.stage == nil {
		return true
	}
	return !r.stage.HasPending()
}

// Stats returns summary statistics.
func (r *RaceReproLoop) Stats() (pending, validating, seen int) {
	if r.stage == nil {
		return 0, 0, 0
	}
	return r.stage.PendingCount(), r.stage.PendingCount(), r.stage.SeenCount()
}

// taskToUAFCorpusEntry converts a RaceReproTask (from Phase 2) into
// a UAFCorpusEntry suitable for StageManager.Enqueue().
func taskToUAFCorpusEntry(task *RaceReproTask) *fuzzer.UAFCorpusEntry {
	if task == nil {
		return nil
	}

	// Build the primary pair info.
	primaryPair := &ddrd.MayUAFPair{
		FreeAccessName: task.FreeAccessName,
		UseAccessName:  task.UseAccessName,
	}

	// Build programs list.
	var programs []*prog.Prog
	if task.Prog1 != nil {
		programs = append(programs, task.Prog1.Clone())
	}
	if task.Prog2 != nil {
		programs = append(programs, task.Prog2.Clone())
	}

	// Build barrier snapshot (2 procs, mask 0x3).
	barrier := fuzzer.BarrierSnapshot{
		Participants: 0x3,
		GroupSize:    2,
		ProcList:     []int{0, 1},
	}

	// Build replay plan from delay plan.
	var delaysMicros []int64
	for _, d := range task.DelayPlan {
		delaysMicros = append(delaysMicros, d.DelayMicros)
	}

	entry := &fuzzer.UAFCorpusEntry{
		CallIdx:       -1,
		Pairs:         []*ddrd.MayUAFPair{primaryPair},
		PairBasicInfo: *primaryPair,
		Barrier:       barrier,
		ReplayPlan:    fuzzer.UAFCorpusReplayPlan{DelaysMicros: delaysMicros},
		Profile: fuzzer.UAFPairProfile{
			FreeAccessName: task.FreeAccessName,
			UseAccessName:  task.UseAccessName,
		},
		Timestamp: time.Now(),
		Source:    fuzzer.SourceTiming,
		Programs:  programs,
	}

	// Set merged program if available.
	// ForkBarrier is determined by whether a MergedProg exists:
	// - MergedProg present → fork-barrier execution (programs merged, fork() for shared fd)
	// - MergedProg absent  → multi-proc barrier execution (separate procs, RPC barrier sync)
	if task.MergedProg != nil {
		entry.MergedProg = task.MergedProg.Clone()
		entry.ForkBarrier = true
	} else {
		entry.ForkBarrier = false
	}

	// Pass through execution history for replay.
	// This allows StageManager to replay system state before each validation attempt,
	// matching the full offline validate pipeline behavior.
	if len(task.ReplayHistory) > 0 {
		entry.ReplayHistory = make([]*fuzzer.BarrierExecutionRecord, len(task.ReplayHistory))
		for i, rec := range task.ReplayHistory {
			if rec != nil {
				entry.ReplayHistory[i] = rec.Clone()
			}
		}
	}

	return entry
}

// FmtRaceReproStatus formats a human-readable status string for dispatcher info.
func FmtRaceReproStatus(taskID string, attempt, budget, detections int) string {
	return fmt.Sprintf("race-validate: %s [%d/%d det=%d]", taskID, attempt, budget, detections)
}
