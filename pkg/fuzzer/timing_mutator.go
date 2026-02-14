// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package fuzzer provides timing mutation for race optimization.
//
// This module inserts syz_delay() calls into programs to explore
// timing windows. The goal is to transform may-may pairs (captured
// with widened threshold) into may pairs (triggerable races).
//
// Strategies:
// - random: random delay insertions at any position
// - targeted: focus delays around Free/Use syscalls
// - binary_search: iteratively refine delays based on previous results

package fuzzer

import (
	"math/rand"
	"sort"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/prog"
)

// ============================================================================
// Delay Insertion Plan
// ============================================================================

// DelayInsertion describes where and how long to delay.
type DelayInsertion struct {
	ProgIdx     int   // Which program (0 or 1)
	BeforeCall  int   // Insert delay before this syscall index
	DelayMicros int64 // Delay duration in microseconds
}

// DelayPlan is a list of delay insertions to apply.
type DelayPlan []DelayInsertion

// Clone creates a copy of the delay plan.
func (p DelayPlan) Clone() DelayPlan {
	if p == nil {
		return nil
	}
	clone := make(DelayPlan, len(p))
	copy(clone, p)
	return clone
}

// ============================================================================
// Timing Mutator
// ============================================================================

// TimingMutator handles insertion of delay syscalls into programs.
type TimingMutator struct {
	target *prog.Target
	config TimingExplorationConfig

	// Cached syz_delay syscall metadata
	delaySyscall *prog.Syscall
}

// NewTimingMutator creates a new timing mutator.
func NewTimingMutator(target *prog.Target, config TimingExplorationConfig) *TimingMutator {
	config.Validate()
	tm := &TimingMutator{
		target: target,
		config: config,
	}

	// Find syz_delay syscall
	for _, s := range target.Syscalls {
		if s.Name == "syz_delay" {
			tm.delaySyscall = s
			break
		}
	}

	return tm
}

// HasDelaySyscall returns true if syz_delay is available in the target.
func (tm *TimingMutator) HasDelaySyscall() bool {
	return tm.delaySyscall != nil
}

// ============================================================================
// Delay Plan Generation
// ============================================================================

// GenerateDelayPlan creates a delay plan targeting a specific pair.
// Uses the configured strategy and optionally refines from an existing plan.
func (tm *TimingMutator) GenerateDelayPlan(
	pair *ddrd.MayUAFPair,
	existingBestPlan DelayPlan,
	rnd *rand.Rand,
) DelayPlan {
	if tm.delaySyscall == nil || pair == nil {
		return nil
	}

	switch tm.config.TimingMutationStrategy {
	case "timediff":
		// Use actual time difference from pair to calculate optimal delay
		return tm.generateTimeDiffBasedPlan(pair, existingBestPlan, rnd)
	case "targeted":
		return tm.generateTargetedPlan(pair, existingBestPlan, rnd)
	case "binary_search":
		return tm.generateBinarySearchPlan(pair, existingBestPlan, rnd)
	case "random":
		return tm.generateRandomPlan(pair, rnd)
	default:
		// Default to timediff-based strategy for best results
		return tm.generateTimeDiffBasedPlan(pair, existingBestPlan, rnd)
	}
}

// generateTimeDiffBasedPlan uses the actual time difference between accesses
// to calculate the optimal delay needed to make them collide.
//
// IMPORTANT: In MayUAFPair, the naming is misleading for data race pairs:
//   - "use_xxx" fields correspond to the FIRST access (earlier in time)
//   - "free_xxx" fields correspond to the SECOND access (later in time)
//   - This ordering is set in access_context_analyze_race_pairs():
//     if (a->access_time <= b->access_time) { first=a; second=b; }
//
// Strategy: Delay the FIRST (earlier) access by ~TimeDiff so both accesses
// happen at approximately the same time.
func (tm *TimingMutator) generateTimeDiffBasedPlan(
	pair *ddrd.MayUAFPair,
	existingBestPlan DelayPlan,
	rnd *rand.Rand,
) DelayPlan {
	plan := make(DelayPlan, 0)

	// In MayUAFPair:
	// - UseCallIdx/UseProgIdx = FIRST access (earlier, from pair->first)
	// - FreeCallIdx/FreeProgIdx = SECOND access (later, from pair->second)
	firstProgIdx := int(pair.UseProgIdx)
	secondProgIdx := int(pair.FreeProgIdx)
	firstCallIdx := int(pair.UseCallIdx)
	secondCallIdx := int(pair.FreeCallIdx)

	// TimeDiff is in nanoseconds, convert to microseconds for delay
	// TimeDiff = second.access_time - first.access_time (since first is earlier)
	timeDiffNs := int64(pair.TimeDiff)
	timeDiffMicros := timeDiffNs / 1000

	// Add jitter: 50%-150% of calculated delay for exploration
	jitterMultiplier := 0.5 + rnd.Float64() // 0.5 to 1.5

	if timeDiffMicros < tm.config.DelayMinMicros {
		// Time difference is very small, they're already close
		// Add small random delays to explore the boundary
		smallDelay := tm.config.DelayMinMicros + rnd.Int63n(tm.config.DelayMinMicros*10)

		// Randomly choose which side to delay
		if rnd.Float64() < 0.5 {
			plan = append(plan, DelayInsertion{
				ProgIdx:     firstProgIdx,
				BeforeCall:  firstCallIdx,
				DelayMicros: smallDelay,
			})
		} else {
			plan = append(plan, DelayInsertion{
				ProgIdx:     secondProgIdx,
				BeforeCall:  secondCallIdx,
				DelayMicros: smallDelay,
			})
		}
		return plan
	}

	// Clamp delay to valid range
	calculatedDelay := int64(float64(timeDiffMicros) * jitterMultiplier)
	if calculatedDelay < tm.config.DelayMinMicros {
		calculatedDelay = tm.config.DelayMinMicros
	}
	if calculatedDelay > tm.config.DelayMaxMicros {
		calculatedDelay = tm.config.DelayMaxMicros
	}

	// The FIRST access happened earlier, so we delay it to let SECOND catch up
	// This should make both accesses happen at approximately the same time
	if firstCallIdx >= 0 && firstProgIdx >= 0 {
		plan = append(plan, DelayInsertion{
			ProgIdx:     firstProgIdx,
			BeforeCall:  firstCallIdx,
			DelayMicros: calculatedDelay,
		})
	}

	// Optionally add a secondary delay for fine-tuning (30% chance)
	// Delay after FIRST to create a wider window for SECOND to access
	if rnd.Float64() < 0.3 && firstCallIdx >= 0 {
		afterFirstDelay := tm.config.DelayMinMicros + rnd.Int63n(calculatedDelay/2+1)
		plan = append(plan, DelayInsertion{
			ProgIdx:     firstProgIdx,
			BeforeCall:  firstCallIdx + 1,
			DelayMicros: afterFirstDelay,
		})
	}

	// Limit to max delays
	if len(plan) > tm.config.MaxDelaysPerProgram {
		plan = plan[:tm.config.MaxDelaysPerProgram]
	}

	return plan
}

// generateTargetedPlan focuses delays around the racing syscalls.
// IMPORTANT: In MayUAFPair for data race pairs:
// - "use_xxx" = FIRST access (earlier in time)
// - "free_xxx" = SECOND access (later in time)
func (tm *TimingMutator) generateTargetedPlan(
	pair *ddrd.MayUAFPair,
	existingBestPlan DelayPlan,
	rnd *rand.Rand,
) DelayPlan {
	plan := make(DelayPlan, 0)
	delayRange := tm.config.DelayMaxMicros - tm.config.DelayMinMicros

	// Rename for clarity: first=earlier, second=later
	firstProgIdx := int(pair.UseProgIdx)
	secondProgIdx := int(pair.FreeProgIdx)
	firstCallIdx := int(pair.UseCallIdx)
	secondCallIdx := int(pair.FreeCallIdx)

	// Strategy: Insert delays to control relative timing
	// The goal is to make both accesses happen at the same time

	// Option 1: Delay before FIRST (slow down first, let second catch up)
	if rnd.Float64() < 0.5 && firstCallIdx >= 0 {
		delay := tm.config.DelayMinMicros + rnd.Int63n(delayRange)
		plan = append(plan, DelayInsertion{
			ProgIdx:     firstProgIdx,
			BeforeCall:  firstCallIdx,
			DelayMicros: delay,
		})
	}

	// Option 2: Delay before SECOND (slow down second, let first get ahead)
	if rnd.Float64() < 0.5 && secondCallIdx >= 0 {
		delay := tm.config.DelayMinMicros + rnd.Int63n(delayRange)
		plan = append(plan, DelayInsertion{
			ProgIdx:     secondProgIdx,
			BeforeCall:  secondCallIdx,
			DelayMicros: delay,
		})
	}

	// Option 3: Delay after FIRST (give time for second to access)
	if rnd.Float64() < 0.3 && firstCallIdx >= 0 {
		delay := tm.config.DelayMinMicros + rnd.Int63n(delayRange)
		plan = append(plan, DelayInsertion{
			ProgIdx:     firstProgIdx,
			BeforeCall:  firstCallIdx + 1, // After first
			DelayMicros: delay,
		})
	}

	// Ensure at least one delay
	if len(plan) == 0 {
		if firstCallIdx >= 0 {
			plan = append(plan, DelayInsertion{
				ProgIdx:     firstProgIdx,
				BeforeCall:  firstCallIdx,
				DelayMicros: tm.config.DelayMinMicros + rnd.Int63n(delayRange),
			})
		} else if secondCallIdx >= 0 {
			plan = append(plan, DelayInsertion{
				ProgIdx:     secondProgIdx,
				BeforeCall:  secondCallIdx,
				DelayMicros: tm.config.DelayMinMicros + rnd.Int63n(delayRange),
			})
		}
	}

	// Limit to max delays
	if len(plan) > tm.config.MaxDelaysPerProgram {
		plan = plan[:tm.config.MaxDelaysPerProgram]
	}

	return plan
}

// generateBinarySearchPlan refines an existing best plan.
func (tm *TimingMutator) generateBinarySearchPlan(
	pair *ddrd.MayUAFPair,
	existingBestPlan DelayPlan,
	rnd *rand.Rand,
) DelayPlan {
	if len(existingBestPlan) == 0 {
		// No existing plan, start with targeted
		return tm.generateTargetedPlan(pair, nil, rnd)
	}

	// Modify existing plan by adjusting delays ±50%
	plan := existingBestPlan.Clone()

	for i := range plan {
		// Random adjustment: 0.5x to 1.5x
		multiplier := 0.5 + rnd.Float64()
		plan[i].DelayMicros = int64(float64(plan[i].DelayMicros) * multiplier)

		// Clamp to valid range
		if plan[i].DelayMicros < tm.config.DelayMinMicros {
			plan[i].DelayMicros = tm.config.DelayMinMicros
		}
		if plan[i].DelayMicros > tm.config.DelayMaxMicros {
			plan[i].DelayMicros = tm.config.DelayMaxMicros
		}
	}

	// Occasionally add or remove a delay
	if rnd.Float64() < 0.2 && len(plan) > 1 {
		// Remove a random delay
		idx := rnd.Intn(len(plan))
		plan = append(plan[:idx], plan[idx+1:]...)
	} else if rnd.Float64() < 0.2 && len(plan) < tm.config.MaxDelaysPerProgram {
		// Add a new delay using targeted strategy
		newPlan := tm.generateTargetedPlan(pair, nil, rnd)
		if len(newPlan) > 0 {
			plan = append(plan, newPlan[0])
		}
	}

	return plan
}

// generateRandomPlan creates random delay insertions.
func (tm *TimingMutator) generateRandomPlan(
	pair *ddrd.MayUAFPair,
	rnd *rand.Rand,
) DelayPlan {
	plan := make(DelayPlan, 0)
	numDelays := 1 + rnd.Intn(tm.config.MaxDelaysPerProgram)
	delayRange := tm.config.DelayMaxMicros - tm.config.DelayMinMicros

	for i := 0; i < numDelays; i++ {
		progIdx := rnd.Intn(2)
		beforeCall := rnd.Intn(10) // Assume max 10 relevant calls

		plan = append(plan, DelayInsertion{
			ProgIdx:     progIdx,
			BeforeCall:  beforeCall,
			DelayMicros: tm.config.DelayMinMicros + rnd.Int63n(delayRange),
		})
	}

	return plan
}

// ============================================================================
// Delay Plan Application
// ============================================================================

// ApplyDelayPlan inserts syz_delay() calls into programs according to the plan.
// Returns cloned programs with delays inserted.
func (tm *TimingMutator) ApplyDelayPlan(
	prog1, prog2 *prog.Prog,
	plan DelayPlan,
) (*prog.Prog, *prog.Prog) {
	if tm.delaySyscall == nil || len(plan) == 0 {
		return prog1.Clone(), cloneOrNil(prog2)
	}

	// Clone programs
	newProg1 := prog1.Clone()
	var newProg2 *prog.Prog
	if prog2 != nil {
		newProg2 = prog2.Clone()
	}

	// Group insertions by program and sort by BeforeCall descending
	// (insert from end to start so indices remain valid)
	prog0Insertions := make([]DelayInsertion, 0)
	prog1Insertions := make([]DelayInsertion, 0)

	for _, ins := range plan {
		if ins.ProgIdx == 0 {
			prog0Insertions = append(prog0Insertions, ins)
		} else if newProg2 != nil {
			prog1Insertions = append(prog1Insertions, ins)
		}
	}

	// Sort descending by BeforeCall
	sort.Slice(prog0Insertions, func(i, j int) bool {
		return prog0Insertions[i].BeforeCall > prog0Insertions[j].BeforeCall
	})
	sort.Slice(prog1Insertions, func(i, j int) bool {
		return prog1Insertions[i].BeforeCall > prog1Insertions[j].BeforeCall
	})

	// Apply to prog1 (index 0)
	for _, ins := range prog0Insertions {
		if ins.BeforeCall >= 0 && ins.BeforeCall <= len(newProg1.Calls) {
			delayCall := tm.createDelayCall(ins.DelayMicros)
			if delayCall != nil {
				tm.insertCallAt(newProg1, ins.BeforeCall, delayCall)
			}
		}
	}

	// Apply to prog2 (index 1)
	if newProg2 != nil {
		for _, ins := range prog1Insertions {
			if ins.BeforeCall >= 0 && ins.BeforeCall <= len(newProg2.Calls) {
				delayCall := tm.createDelayCall(ins.DelayMicros)
				if delayCall != nil {
					tm.insertCallAt(newProg2, ins.BeforeCall, delayCall)
				}
			}
		}
	}

	return newProg1, newProg2
}

// createDelayCall creates a syz_delay(microseconds) call.
func (tm *TimingMutator) createDelayCall(microseconds int64) *prog.Call {
	if tm.delaySyscall == nil || len(tm.delaySyscall.Args) == 0 {
		return nil
	}

	// Create the call with the delay argument
	call := &prog.Call{
		Meta: tm.delaySyscall,
		Args: []prog.Arg{
			prog.MakeConstArg(tm.delaySyscall.Args[0].Type, prog.DirIn, uint64(microseconds)),
		},
	}

	// Add return value if the syscall has one
	if tm.delaySyscall.Ret != nil {
		call.Ret = prog.MakeReturnArg(tm.delaySyscall.Ret)
	}

	return call
}

// insertCallAt inserts a call at the specified index.
func (tm *TimingMutator) insertCallAt(p *prog.Prog, idx int, call *prog.Call) {
	if idx > len(p.Calls) {
		idx = len(p.Calls)
	}
	if idx < 0 {
		idx = 0
	}

	// Expand calls slice
	p.Calls = append(p.Calls, nil)
	copy(p.Calls[idx+1:], p.Calls[idx:])
	p.Calls[idx] = call
}

// cloneOrNil clones a program or returns nil if input is nil.
func cloneOrNil(p *prog.Prog) *prog.Prog {
	if p == nil {
		return nil
	}
	return p.Clone()
}

// ============================================================================
// Utility Functions
// ============================================================================

// GetDelayCallCount returns the number of syz_delay calls in a program.
func (tm *TimingMutator) GetDelayCallCount(p *prog.Prog) int {
	if p == nil || tm.delaySyscall == nil {
		return 0
	}

	count := 0
	for _, call := range p.Calls {
		if call.Meta == tm.delaySyscall {
			count++
		}
	}
	return count
}

// RemoveDelays removes all syz_delay calls from a program.
// Returns a cloned program without delays.
func (tm *TimingMutator) RemoveDelays(p *prog.Prog) *prog.Prog {
	if p == nil {
		return nil
	}

	cloned := p.Clone()
	if tm.delaySyscall == nil {
		return cloned
	}

	// Filter out syz_delay calls
	newCalls := make([]*prog.Call, 0, len(cloned.Calls))
	for _, call := range cloned.Calls {
		if call.Meta != tm.delaySyscall {
			newCalls = append(newCalls, call)
		}
	}
	cloned.Calls = newCalls

	return cloned
}
