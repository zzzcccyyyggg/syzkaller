// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

// MergeForForkBarrier merges multiple independent programs into a single fork-barrier program.
//
// The merged program has the following structure:
//   - Setup phase: resource-creating calls extracted from the programs. These are executed
//     by the parent process before fork(). The child processes inherit the parent's fd table,
//     so they share the same kernel objects (struct file, inode, etc.).
//   - Fork point: marks where the executor should fork() N child processes.
//   - Child phases: each child executes its own portion of syscalls using the inherited fds.
//
// Parameters:
//   - programs: independent programs to merge (typically 2 for barrier execution).
//   - delays: per-child start delays in microseconds. Can be nil (no delays).
//
// Returns the merged program, or nil if merging is not possible (e.g., no shared resources).
func MergeForForkBarrier(programs []*Prog, delays []int64) *Prog {
	if len(programs) < 2 {
		return nil
	}
	target := programs[0].Target
	for _, p := range programs[1:] {
		if p == nil || p.Target != target {
			return nil
		}
	}

	// Step 1: Identify setup calls from the first program.
	// Setup calls are those whose return value (ResultArg) is used by subsequent calls.
	// These are typically resource-creating syscalls: open, socket, pipe, etc.
	setupCalls, childCalls0 := extractSetupCalls(programs[0])

	// Step 2: Build the merged program.
	// Clone all calls to avoid modifying the originals.
	newargs := make(map[*ResultArg]*ResultArg)
	var allCalls []*Call

	// Clone setup calls.
	for _, c := range setupCalls {
		cloned := cloneCall(c, newargs)
		allCalls = append(allCalls, cloned)
	}
	numSetup := len(allCalls)

	// Clone child 0's remaining calls (from program 0).
	child0Start := len(allCalls)
	for _, c := range childCalls0 {
		cloned := cloneCall(c, newargs)
		allCalls = append(allCalls, cloned)
	}
	child0End := len(allCalls)

	// Clone child 1's calls (from program 1).
	// We need to rewrite resource references from program 1 to point to setup results.
	child1Start := len(allCalls)
	child1Calls := rewriteAndClone(programs[0], setupCalls, programs[1], newargs)
	allCalls = append(allCalls, child1Calls...)
	child1End := len(allCalls)

	// If we have no setup calls and no meaningful children, merging is not useful.
	if numSetup == 0 && child0End-child0Start == 0 && child1End-child1Start == 0 {
		return nil
	}

	// Build children descriptors.
	children := make([]ForkChild, len(programs))
	if len(delays) < len(programs) {
		delays = make([]int64, len(programs))
	}

	children[0] = ForkChild{
		StartIndex: child0Start,
		EndIndex:   child0End,
		DelayUs:    delays[0],
	}
	children[1] = ForkChild{
		StartIndex: child1Start,
		EndIndex:   child1End,
		DelayUs:    delays[1],
	}

	merged := &Prog{
		Target: target,
		Calls:  allCalls,
		ForkPoint: &ForkPoint{
			SetupCalls: numSetup,
			Children:   children,
		},
	}
	if debug {
		fmt.Printf("[FORK-BARRIER-MERGE] setup=%d children=%d totalCalls=%d child0=[%d,%d) child1=[%d,%d) delays=[%d,%d]\n",
			numSetup, len(children), len(allCalls),
			child0Start, child0End, child1Start, child1End,
			delays[0], delays[1])
	}
	return merged
}

// extractSetupCalls separates a program's calls into:
//   - setup: calls whose return value (ResultArg) is referenced by later calls in the same program.
//   - remaining: all other calls.
//
// The setup calls are resource creators (open, socket, etc.) whose fds need to be
// inherited by child processes via fork().
func extractSetupCalls(p *Prog) (setup, remaining []*Call) {
	if p == nil || len(p.Calls) == 0 {
		return nil, nil
	}

	// Build a set of calls whose return values are used by other calls.
	usedRets := make(map[*Call]bool)
	for _, c := range p.Calls {
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			if res, ok := arg.(*ResultArg); ok && res.Res != nil {
				// Find which call produces res.Res.
				for _, producer := range p.Calls {
					if producer.Ret == res.Res {
						usedRets[producer] = true
						break
					}
				}
			}
		})
	}

	for _, c := range p.Calls {
		if usedRets[c] {
			setup = append(setup, c)
		} else {
			remaining = append(remaining, c)
		}
	}
	return setup, remaining
}

// rewriteAndClone clones program src's calls and rewrites resource references
// to point to the setup phase results from setupProg.
//
// The idea: if src has an open("./file0") that returns fd, and setupProg also
// has open("./file0") in its setup calls, then src's calls that use fd should
// instead reference the setup call's result (so the child inherits the parent's fd).
//
// The matching key is (Syscall.Name, ResourceType.TypeName). When two programs both
// have the same syscall producing the same resource type, we unify: prog2's call is
// skipped and its consumers reference the setup phase's fd instead.
//
// The matching itself is the safety mechanism: same syscall name + same resource type
// guarantees the calls are semantically compatible. The VALUE of unification is
// precisely for creating shared kernel objects between children — this is the
// whole point of fork-barrier for UAF detection (close+use on the same fd).
//
// For generic syscalls (open with random filename, socket with random params),
// unification is the MOST valuable: without it, the two children operate on
// completely unrelated objects and no UAF can occur.
//
// For specialized syscalls (openat$null, socket$inet_tcp), unification is less
// critical since both children would create equivalent objects anyway, but it
// still ensures they share the exact same struct file/socket for UAF triggering.
func rewriteAndClone(setupProg *Prog, setupCalls []*Call, src *Prog, newargs map[*ResultArg]*ResultArg) []*Call {
	if src == nil || len(src.Calls) == 0 {
		return nil
	}

	// Build an ordered mapping from (syscall name, resource type) → list of setup ResultArgs.
	// Using a list (not single value) so that multiple fds of the same type are mapped
	// in order: prog2's Nth open$foo → prog1's Nth open$foo.
	type resKey struct {
		callName string
		resType  string
	}
	setupResultsList := make(map[resKey][]*ResultArg)
	for _, c := range setupCalls {
		if c.Ret == nil || len(c.Ret.uses) == 0 {
			continue
		}
		if rt, ok := c.Ret.Type().(*ResourceType); ok {
			key := resKey{callName: c.Meta.Name, resType: rt.TypeName}
			// Use the cloned version if it exists in newargs
			if cloned, ok := newargs[c.Ret]; ok {
				setupResultsList[key] = append(setupResultsList[key], cloned)
			} else {
				setupResultsList[key] = append(setupResultsList[key], c.Ret)
			}
		}
	}

	// Track how many times each key has been consumed for ordered matching.
	setupConsumed := make(map[resKey]int)

	// Identify resource-producing calls in src that can be replaced by setup results.
	// Always unify when there's a key match: the matching key (syscall Name + resource
	// TypeName) already ensures semantic compatibility. Unification forces both children
	// to share the same kernel object, which is essential for UAF detection (close+use).
	replaceable := make(map[*ResultArg]*ResultArg) // src's ResultArg → setup's ResultArg
	var skipCalls []*Call                          // calls in src to skip (replaced by setup)
	for _, c := range src.Calls {
		if c.Ret == nil || len(c.Ret.uses) == 0 {
			continue
		}
		if rt, ok := c.Ret.Type().(*ResourceType); ok {
			key := resKey{callName: c.Meta.Name, resType: rt.TypeName}
			list := setupResultsList[key]
			idx := setupConsumed[key]
			if idx < len(list) {
				// Always unify: the resKey match guarantees compatible syscalls.
				// This is the core mechanism for UAF detection — sharing the same
				// kernel object between children so close+use triggers UAF.
				replaceable[c.Ret] = list[idx]
				skipCalls = append(skipCalls, c)
				if debug {
					fmt.Printf("[FORK-MERGE] UNIFIED %s (resType=%s)\n",
						c.Meta.Name, rt.TypeName)
				}
				setupConsumed[key] = idx + 1
			}
		}
	}

	skipSet := make(map[*Call]bool)
	for _, c := range skipCalls {
		skipSet[c] = true
	}

	// Wire up the replacement mapping in newargs so that cloneCall rewrites references.
	for srcRet, setupRet := range replaceable {
		newargs[srcRet] = setupRet
	}

	// Clone non-skipped calls from src.
	var result []*Call
	for _, c := range src.Calls {
		if skipSet[c] {
			continue
		}
		cloned := cloneCall(c, newargs)
		result = append(result, cloned)
	}
	return result
}

// SetForkDelays updates the per-child delays of a fork-barrier program.
// This is used by the validation framework to sweep delay parameters.
func (p *Prog) SetForkDelays(delays []int64) {
	if p == nil || p.ForkPoint == nil {
		return
	}
	for i := 0; i < len(p.ForkPoint.Children) && i < len(delays); i++ {
		p.ForkPoint.Children[i].DelayUs = delays[i]
	}
}

// IsForkBarrier returns true if this program uses the fork-barrier execution model.
func (p *Prog) IsForkBarrier() bool {
	return p != nil && p.ForkPoint != nil
}
