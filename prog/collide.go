// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Contains prog transformations that intend to trigger more races.

package prog

import (
	"fmt"
	"math/rand"
)

// The executor has no more than 32 threads that are used both for async calls and for calls
// that timed out. If we just ignore that limit, we could end up generating programs that
// would force the executor to fail and thus stall the fuzzing process.
// As an educated guess, let's use no more than 24 async calls to let executor handle everything.
const maxAsyncPerProg = 24

// Ensures that if an async call produces a resource, then
// it is distanced from a call consuming the resource at least
// by one non-async call.
// This does not give 100% guarantee that the async call finishes
// by that time, but hopefully this is enough for most cases.
func AssignRandomAsync(origProg *Prog, rand *rand.Rand) *Prog {
	var unassigned map[*ResultArg]bool
	leftAsync := maxAsyncPerProg
	prog := origProg.Clone()
	for i := len(prog.Calls) - 1; i >= 0 && leftAsync > 0; i-- {
		call := prog.Calls[i]
		producesUnassigned := false
		consumes := make(map[*ResultArg]bool)
		ForeachArg(call, func(arg Arg, ctx *ArgCtx) {
			res, ok := arg.(*ResultArg)
			if !ok {
				return
			}
			if res.Dir() != DirIn && unassigned[res] {
				// If this call is made async, at least one of the resources
				// will be empty when it's needed.
				producesUnassigned = true
			}
			if res.Dir() != DirOut {
				consumes[res.Res] = true
			}
		})
		// Make async with a 66% chance (but never the last call).
		if !producesUnassigned && i+1 != len(prog.Calls) && rand.Intn(3) != 0 {
			call.Props.Async = true
			for res := range consumes {
				unassigned[res] = true
			}
			leftAsync--
		} else {
			call.Props.Async = false
			unassigned = consumes
		}
	}

	return prog
}

// AssignMaxAsync is like AssignRandomAsync but assigns async with 100% probability
// (instead of 66%) to all eligible calls. This is useful for validation where we want
// to maximize the chance of triggering races.
func AssignMaxAsync(origProg *Prog) *Prog {
	var unassigned map[*ResultArg]bool
	leftAsync := maxAsyncPerProg
	prog := origProg.Clone()
	for i := len(prog.Calls) - 1; i >= 0 && leftAsync > 0; i-- {
		call := prog.Calls[i]
		producesUnassigned := false
		consumes := make(map[*ResultArg]bool)
		ForeachArg(call, func(arg Arg, ctx *ArgCtx) {
			res, ok := arg.(*ResultArg)
			if !ok {
				return
			}
			if res.Dir() != DirIn && unassigned[res] {
				// If this call is made async, at least one of the resources
				// will be empty when it's needed.
				producesUnassigned = true
			}
			if res.Dir() != DirOut {
				consumes[res.Res] = true
			}
		})
		// Always assign async if eligible (100% instead of 66%).
		// Never make the last call async.
		if !producesUnassigned && i+1 != len(prog.Calls) {
			call.Props.Async = true
			for res := range consumes {
				unassigned[res] = true
			}
			leftAsync--
		} else {
			call.Props.Async = false
			unassigned = consumes
		}
	}
	return prog
}

var rerunSteps = []int{32, 64}

func AssignRandomRerun(prog *Prog, rand *rand.Rand) {
	for i := 0; i+1 < len(prog.Calls); i++ {
		if !prog.Calls[i].Props.Async || rand.Intn(4) != 0 {
			continue
		}
		// We assign rerun to consecutive pairs of calls, where the first call is async.
		// TODO: consider assigning rerun also to non-collided progs.
		rerun := rerunSteps[rand.Intn(len(rerunSteps))]
		prog.Calls[i].Props.Rerun = rerun
		prog.Calls[i+1].Props.Rerun = rerun
		i++
	}
}

// We append prog to itself, but let the second part only reference resource from the first one.
// Then we execute all the duplicated calls simultaneously.
// This somehow resembles the way the previous collide mode was implemented - a program was executed
// normally and then one more time again, while keeping resource values from the first execution and
// not waiting until every other call finishes.
func DoubleExecCollide(origProg *Prog, rand *rand.Rand) (*Prog, error) {
	if len(origProg.Calls)*2 > MaxCalls {
		return nil, fmt.Errorf("the prog is too big for the DoubleExecCollide transformation")
	}
	prog := origProg.Clone()
	dupCalls := cloneCalls(prog.Calls, nil)
	leftAsync := maxAsyncPerProg
	for _, c := range dupCalls {
		if leftAsync == 0 {
			break
		}
		c.Props.Async = true
		leftAsync--
	}
	prog.Calls = append(prog.Calls, dupCalls...)
	return prog, nil
}

// SplitAsyncCalls creates a pair of programs for concurrent execution:
// - prog1: the original program (clone)
// - prog2: a clone with async-capable calls marked async
//
// This allows barrier execution with two copies of the program running concurrently,
// where prog2 has async calls that may execute in parallel within the same proc.
// Returns (prog1, prog2). If the program has async-capable calls, prog2 will be
// a clone with those calls marked async. Otherwise prog2 will be nil.
func SplitAsyncCalls(origProg *Prog) (prog1, prog2 *Prog) {
	if origProg == nil || len(origProg.Calls) < 2 {
		return origProg.Clone(), nil
	}

	// Check if there are any calls that can be made async
	hasAsyncCapable := false
	var unassigned map[*ResultArg]bool
	leftAsync := maxAsyncPerProg

	for i := len(origProg.Calls) - 1; i >= 0 && leftAsync > 0; i-- {
		call := origProg.Calls[i]
		producesUnassigned := false
		consumes := make(map[*ResultArg]bool)
		ForeachArg(call, func(arg Arg, ctx *ArgCtx) {
			res, ok := arg.(*ResultArg)
			if !ok {
				return
			}
			if res.Dir() != DirIn && unassigned[res] {
				producesUnassigned = true
			}
			if res.Dir() != DirOut {
				consumes[res.Res] = true
			}
		})
		// Never make the last call async
		if !producesUnassigned && i+1 != len(origProg.Calls) {
			hasAsyncCapable = true
			for res := range consumes {
				unassigned[res] = true
			}
			leftAsync--
		} else {
			unassigned = consumes
		}
	}

	// If no calls can be async, just return original
	if !hasAsyncCapable {
		return origProg.Clone(), nil
	}

	// Return original program and a clone with async calls applied
	prog1 = origProg.Clone()
	prog2 = AssignMaxAsync(origProg)

	return prog1, prog2
}

// DupCallCollide duplicates some of the calls in the program and marks them async.
// This should hopefully trigger races in a more granular way than DoubleExecCollide.
func DupCallCollide(origProg *Prog, rand *rand.Rand) (*Prog, error) {
	if len(origProg.Calls) < 2 {
		// For 1-call programs the behavior is similar to DoubleExecCollide.
		return nil, fmt.Errorf("the prog is too small for the transformation")
	}
	// By default let's duplicate 1/3 calls in the original program (but at least one).
	insert := max(len(origProg.Calls)/3, 1)
	insert = min(insert, maxAsyncPerProg)
	insert = min(insert, MaxCalls-len(origProg.Calls))
	if insert == 0 {
		return nil, fmt.Errorf("no calls could be duplicated")
	}
	duplicate := map[int]bool{}
	for _, pos := range rand.Perm(len(origProg.Calls))[:insert] {
		duplicate[pos] = true
	}
	prog := origProg.Clone()
	var retCalls []*Call
	for i, c := range prog.Calls {
		if duplicate[i] {
			dupCall := cloneCall(c, nil)
			dupCall.Props.Async = true
			retCalls = append(retCalls, dupCall)
		}
		retCalls = append(retCalls, c)
	}
	prog.Calls = retCalls
	return prog, nil
}

// MergePrograms concatenates the calls of two programs into a single program.
// The resulting program uses prog1's target. Both programs must share the same target.
func MergePrograms(prog1, prog2 *Prog) *Prog {
	merged := &Prog{
		Target:   prog1.Target,
		Comments: append(append([]string{}, prog1.Comments...), prog2.Comments...),
	}
	// Use a shared newargs map so inter-call ResultArg references are properly
	// remapped to the cloned results within the merged program.
	newargs := make(map[*ResultArg]*ResultArg)
	for _, c := range prog1.Calls {
		merged.Calls = append(merged.Calls, cloneCall(c, newargs))
	}
	for _, c := range prog2.Calls {
		merged.Calls = append(merged.Calls, cloneCall(c, newargs))
	}
	return merged
}
