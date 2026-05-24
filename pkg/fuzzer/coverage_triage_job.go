// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// ============================================================================
// Coverage Triage Job for UAF Mode (Pair-Level)
//
// This job handles new coverage discovery in UAF mode at the pair level:
//   1. When barrier execution discovers new coverage, this job is triggered
//   2. Execute prog1 solo → collect prog1's coverage
//   3. Execute prog2 solo → collect prog2's coverage
//   4. Determine which program(s) contributed the new coverage
//   5. Boost Bandit scores for programs that brought new coverage
//   6. Give the pair more mutation and execution opportunities
// ============================================================================

type coverageTriageJob struct {
	exec     queue.Executor
	prog1    *prog.Prog
	prog2    *prog.Prog
	newCover cover.Cover // new coverage discovered from barrier execution
	req      *queue.Request
	res      *queue.Result
	fuzzer   *Fuzzer
	info     *JobInfo
}

func (job *coverageTriageJob) run(fuzzer *Fuzzer) {
	log.Logf(1, "[COV-TRIAGE] run() starting: prog1=%d calls, prog2=%d calls, newCover=%d PCs",
		len(job.prog1.Calls), len(job.prog2.Calls), len(job.newCover))

	// Execute solo runs to collect individual program coverage
	prog1Cover := job.executeSoloCoverage(job.prog1, "prog1")
	prog2Cover := job.executeSoloCoverage(job.prog2, "prog2")

	// Determine which program(s) contributed the new coverage
	prog1Contributed := job.checkCoverageContribution(job.newCover, prog1Cover)
	prog2Contributed := job.checkCoverageContribution(job.newCover, prog2Cover)

	log.Logf(1, "[COV-TRIAGE] solo phases done: prog1Cover=%d PCs (contributed=%v), prog2Cover=%d PCs (contributed=%v)",
		len(prog1Cover), prog1Contributed, len(prog2Cover), prog2Contributed)

	// Boost Bandit scores for programs that brought new coverage
	job.boostProgramsWithNewCoverage(prog1Contributed, prog2Contributed)

	// Give this pair more mutation opportunities (increase its priority)
	job.boostPairPriority(prog1Contributed, prog2Contributed)

	job.info.Execs.Add(2) // Two solo executions
	log.Logf(1, "[COV-TRIAGE] run() completed: prog1Contributed=%v, prog2Contributed=%v",
		prog1Contributed, prog2Contributed)
}

// executeSoloCoverage runs a single program and collects its coverage.
// Note: IsSoloExecution=true ensures Threaded flag is NOT added, so program runs single-threaded.
func (job *coverageTriageJob) executeSoloCoverage(p *prog.Prog, name string) cover.Cover {
	req := &queue.Request{
		Prog: p.Clone(),
		ExecOpts: flatrpc.ExecOpts{
			// Solo execution: only collect cover, no Threaded flag
			ExecFlags: flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagDedupCover,
		},
		IsSoloExecution: true, // Prevents Threaded flag from being merged
	}

	log.Logf(3, "[COV-TRIAGE] executeSoloCoverage starting: prog=%s", name)
	result := job.fuzzer.executeWithFlags(job.exec, req, 0)
	if result == nil || result.Info == nil {
		log.Logf(2, "[COV-TRIAGE] %s: result is nil or has no info", name)
		return nil
	}

	// Collect all coverage from the execution
	var cov cover.Cover
	for _, call := range result.Info.Calls {
		if call != nil && len(call.Cover) > 0 {
			cov.Merge(call.Cover)
		}
	}
	if result.Info.Extra != nil && len(result.Info.Extra.Cover) > 0 {
		cov.Merge(result.Info.Extra.Cover)
	}

	log.Logf(2, "[COV-TRIAGE] %s: collected %d PCs", name, len(cov))
	return cov
}

// checkCoverageContribution checks if a program's coverage contains the new coverage.
// Returns true if at least some of the new coverage comes from this program.
func (job *coverageTriageJob) checkCoverageContribution(newCover, progCover cover.Cover) bool {
	if len(newCover) == 0 || len(progCover) == 0 {
		return false
	}

	// Check if any of the new PCs are in the program's coverage
	matchCount := 0
	for pc := range newCover {
		if _, exists := progCover[pc]; exists {
			matchCount++
		}
	}

	// Consider as contributed if at least 10% of new coverage matches
	// or at least 1 PC matches (for small new coverage sets)
	threshold := len(newCover) / 10
	if threshold < 1 {
		threshold = 1
	}

	contributed := matchCount >= threshold
	if contributed {
		log.Logf(2, "[COV-TRIAGE] coverage contribution: %d/%d PCs matched (threshold=%d)",
			matchCount, len(newCover), threshold)
	}

	return contributed
}

// boostProgramsWithNewCoverage is a no-op after M2 Bandit removal.
// Kept as stub for potential future use.
func (job *coverageTriageJob) boostProgramsWithNewCoverage(prog1Contributed, prog2Contributed bool) {
	// M2 Bandit removed — no boost needed
}

// boostPairPriority gives the pair more mutation opportunities.
// This is done by adding more entries to the UAF corpus with higher priority.
func (job *coverageTriageJob) boostPairPriority(prog1Contributed, prog2Contributed bool) {
	if job.fuzzer.uaf == nil || job.fuzzer.raceGroup == nil {
		return
	}

	// If either program contributed new coverage, mark this pair as "high yield"
	if !prog1Contributed && !prog2Contributed {
		return
	}

	// Record high-yield interaction in affinity table
	// This will increase the chance of selecting this syscall combination again
	job.recordHighYieldInteraction()

	// If the pair brought new coverage, it's likely a good pair for future fuzzing
	// The soloFilterJob already handles adding pairs to the corpus,
	// so here we just boost the Bandit weights
	log.Logf(1, "[COV-TRIAGE] pair marked as high-yield for future fuzzing")
}

// recordHighYieldInteraction records a successful interaction between the two programs.
func (job *coverageTriageJob) recordHighYieldInteraction() {
	if job.fuzzer.raceGroup == nil || job.prog1 == nil || job.prog2 == nil {
		return
	}

	// Skip if affinity table is disabled by configuration.
	if job.fuzzer.raceGroup.affinityTable == nil {
		return
	}

	// Extract syscall names from both programs and record interaction
	for _, call1 := range job.prog1.Calls {
		if call1 == nil || call1.Meta == nil {
			continue
		}
		for _, call2 := range job.prog2.Calls {
			if call2 == nil || call2.Meta == nil {
				continue
			}
			// Create syscall signatures and record the interaction
			sig1 := SyscallSignature{Name: call1.Meta.Name}
			sig2 := SyscallSignature{Name: call2.Meta.Name}
			// Record with raceCount=1 to indicate successful interaction
			job.fuzzer.raceGroup.affinityTable.RecordInteraction(sig1, sig2, 1)
		}
	}
}

func (job *coverageTriageJob) Execs() *JobInfo {
	return job.info
}

func (job *coverageTriageJob) Priority() int {
	// High priority since coverage discovery is important
	return 10
}
