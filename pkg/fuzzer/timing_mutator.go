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

	// Fork-barrier fallback: In fork-barrier mode, the executor loses child
	// processes' syscall context (via _exit(0)), so CallIdx and ProgIdx are
	// reported as -1. When this happens, generate delays using heuristic
	// positions within the two child program ranges (ProgIdx 0 and 1).
	needsForkFallback := (firstCallIdx < 0 || firstProgIdx < 0) &&
		(secondCallIdx < 0 || secondProgIdx < 0)
	if needsForkFallback {
		return tm.generateForkFallbackPlan(pair, timeDiffMicros, jitterMultiplier, rnd)
	}

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

// generateForkFallbackPlan creates a delay plan when the executor reports
// CallIdx/ProgIdx as -1 (fork-barrier mode). This happens because forked
// children's syscall_context history is lost on _exit(0).
//
// Strategy: Since we don't know which specific syscalls raced, we insert
// delays at heuristic positions within the two child program ranges.
// The goal is to shift relative timing between child 0 and child 1.
func (tm *TimingMutator) generateForkFallbackPlan(
	pair *ddrd.MayUAFPair,
	timeDiffMicros int64,
	jitterMultiplier float64,
	rnd *rand.Rand,
) DelayPlan {
	plan := make(DelayPlan, 0)

	// Calculate delay amount
	var delayMicros int64
	if timeDiffMicros < tm.config.DelayMinMicros {
		// Small time difference — use random delay for exploration
		delayMicros = tm.config.DelayMinMicros + rnd.Int63n(tm.config.DelayMinMicros*10)
	} else {
		delayMicros = int64(float64(timeDiffMicros) * jitterMultiplier)
		if delayMicros < tm.config.DelayMinMicros {
			delayMicros = tm.config.DelayMinMicros
		}
		if delayMicros > tm.config.DelayMaxMicros {
			delayMicros = tm.config.DelayMaxMicros
		}
	}

	// We know there are 2 children (ProgIdx 0 and 1).
	// Three strategies, chosen randomly:
	//  (a) 40%: Delay child 0 start → child 1 runs first
	//  (b) 40%: Delay child 1 start → child 0 runs first
	//  (c) 20%: Delay both at random offsets for wider exploration
	r := rnd.Float64()
	if r < 0.4 {
		// Delay child 0 at its first call
		plan = append(plan, DelayInsertion{
			ProgIdx:     0,
			BeforeCall:  0,
			DelayMicros: delayMicros,
		})
	} else if r < 0.8 {
		// Delay child 1 at its first call
		plan = append(plan, DelayInsertion{
			ProgIdx:     1,
			BeforeCall:  0,
			DelayMicros: delayMicros,
		})
	} else {
		// Delay both at random positions
		plan = append(plan, DelayInsertion{
			ProgIdx:     0,
			BeforeCall:  rnd.Intn(3), // early position in child 0
			DelayMicros: delayMicros / 2,
		})
		plan = append(plan, DelayInsertion{
			ProgIdx:     1,
			BeforeCall:  rnd.Intn(3), // early position in child 1
			DelayMicros: delayMicros,
		})
	}

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

// ApplyDelayPlanToMerged inserts syz_delay calls directly into a fork-barrier
// merged program. The delay plan's (ProgIdx, BeforeCall) are translated to
// merged-program call indices using the ForkPoint.Children ranges.
// This avoids re-merging and guarantees the same fd layout as the original merge.
func (tm *TimingMutator) ApplyDelayPlanToMerged(
	merged *prog.Prog,
	plan DelayPlan,
) *prog.Prog {
	if merged == nil {
		return nil
	}
	if tm.delaySyscall == nil || len(plan) == 0 || merged.ForkPoint == nil {
		return merged.Clone()
	}

	result := merged.Clone()
	origFP := merged.ForkPoint
	origCallCount := len(merged.Calls)

	// Remove existing syz_delay from merged program first, so Phase 2 does not
	// accumulate stale delays from previous runs/corpus programs.
	removedPrefix := tm.removeExistingDelaysAndFixForkPoint(result)
	fp := result.ForkPoint

	// Translate plan entries to merged call indices.
	// Priority:
	//  1) If BeforeCall looks like a global merged index (falls into any child
	//     range), use it directly.
	//  2) Otherwise, treat BeforeCall as child-relative and use ProgIdx range.
	type mergedIns struct {
		idx         int
		delayMicros int64
	}
	var insertions []mergedIns
	for _, d := range plan {
		mi := -1

		if d.BeforeCall >= 0 && d.BeforeCall <= origCallCount {
			if isIndexInAnyChildRange(origFP, d.BeforeCall) {
				// Translate from original merged index to post-cleanup index.
				mi = d.BeforeCall - removedPrefix[d.BeforeCall]
			}
		}

		if mi < 0 {
			if d.ProgIdx < 0 || d.ProgIdx >= len(fp.Children) {
				continue
			}
			child := fp.Children[d.ProgIdx]
			mi = child.StartIndex + d.BeforeCall
			if mi < child.StartIndex {
				mi = child.StartIndex
			}
			if mi > child.EndIndex {
				mi = child.EndIndex
			}
		}
		insertions = append(insertions, mergedIns{idx: mi, delayMicros: d.DelayMicros})
	}

	// Sort descending so that inserting from the end preserves earlier indices.
	sort.Slice(insertions, func(i, j int) bool {
		return insertions[i].idx > insertions[j].idx
	})

	for _, ins := range insertions {
		delayCall := tm.createDelayCall(ins.delayMicros)
		if delayCall == nil {
			continue
		}
		tm.insertCallAt(result, ins.idx, delayCall)

		// Update ForkPoint indices to account for the inserted call.
		if ins.idx < fp.SetupCalls {
			fp.SetupCalls++
		}
		for ci := range fp.Children {
			if fp.Children[ci].StartIndex > ins.idx {
				fp.Children[ci].StartIndex++
			}
			if fp.Children[ci].EndIndex > ins.idx {
				fp.Children[ci].EndIndex++
			}
		}
	}

	return result
}

// SanitizeMergedForTiming returns a cloned merged program with all existing
// syz_delay calls removed and ForkPoint boundaries remapped accordingly.
// Use this before Phase 1 enqueue so discovery/validation share the same base.
func (tm *TimingMutator) SanitizeMergedForTiming(merged *prog.Prog) *prog.Prog {
	if merged == nil {
		return nil
	}
	result := merged.Clone()
	if tm == nil || tm.delaySyscall == nil || result.ForkPoint == nil {
		return result
	}
	tm.removeExistingDelaysAndFixForkPoint(result)
	return result
}

func isIndexInAnyChildRange(fp *prog.ForkPoint, idx int) bool {
	if fp == nil || idx < 0 {
		return false
	}
	for _, child := range fp.Children {
		if idx >= child.StartIndex && idx <= child.EndIndex {
			return true
		}
	}
	return false
}

// removeExistingDelaysAndFixForkPoint removes all syz_delay calls from a
// merged program and rewrites ForkPoint boundaries accordingly.
// Returns removedPrefix where removedPrefix[i] is the number of removed delays
// among original call indices [0, i).
func (tm *TimingMutator) removeExistingDelaysAndFixForkPoint(p *prog.Prog) []int {
	oldCount := len(p.Calls)
	removedPrefix := make([]int, oldCount+1)
	if oldCount == 0 || p.ForkPoint == nil || tm.delaySyscall == nil {
		return removedPrefix
	}

	newCalls := make([]*prog.Call, 0, oldCount)
	for i, c := range p.Calls {
		removedPrefix[i+1] = removedPrefix[i]
		if c != nil && c.Meta != nil && c.Meta.Name == tm.delaySyscall.Name {
			removedPrefix[i+1]++
			continue
		}
		newCalls = append(newCalls, c)
	}

	if len(newCalls) == oldCount {
		return removedPrefix
	}
	p.Calls = newCalls

	fp := p.ForkPoint
	fp.SetupCalls -= removedPrefix[fp.SetupCalls]
	for i := range fp.Children {
		start := fp.Children[i].StartIndex
		end := fp.Children[i].EndIndex
		fp.Children[i].StartIndex = start - removedPrefix[start]
		fp.Children[i].EndIndex = end - removedPrefix[end]
	}

	return removedPrefix
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
