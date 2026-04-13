// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type job interface {
	run(fuzzer *Fuzzer)
}

type jobIntrospector interface {
	getInfo() *JobInfo
}

type JobInfo struct {
	Name  string
	Calls []string
	Type  string
	Execs atomic.Int32

	syncBuffer
}

func (ji *JobInfo) ID() string {
	return fmt.Sprintf("%p", ji)
}

func genProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	p := fuzzer.target.Generate(rnd,
		fuzzer.RecommendedCalls(),
		fuzzer.ChoiceTable())
	req := &queue.Request{
		Prog:     p,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecGenerate,
	}
	// fuzzer.applyBarrier(req)
	return req
}

func mutateProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	// Random corpus selection (M2 Thompson Sampling removed — caused over-exploitation)
	p := fuzzer.Config.Corpus.ChooseProgram(rnd)

	if p == nil {
		return nil
	}

	// Standard mutation (M3 prefix-preserving mutation removed)
	newP := p.Clone()
	newP.Mutate(rnd,
		prog.RecommendedCalls,
		fuzzer.ChoiceTable(),
		fuzzer.Config.NoMutateCalls,
		fuzzer.Config.Corpus.Programs(),
	)

	req := &queue.Request{
		Prog:     newP,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecFuzz,
	}
	// fuzzer.applyBarrier(req)
	return req
}

// triageJob are programs for which we noticed potential new coverage during
// first execution. But we are not sure yet if the coverage is real or not.
// During triage we understand if these programs in fact give new coverage,
// and if yes, minimize them and add to corpus.
type triageJob struct {
	p        *prog.Prog
	executor queue.ExecutorID
	flags    ProgFlags
	fuzzer   *Fuzzer
	queue    queue.Executor
	// Set of calls that gave potential new coverage.
	calls map[int]*triageCall

	info *JobInfo
}

type triageCall struct {
	errno     int32
	newSignal signal.Signal

	// Filled after deflake:
	signals         [deflakeNeedRuns]signal.Signal
	stableSignal    signal.Signal
	newStableSignal signal.Signal
	cover           cover.Cover
	rawCover        []uint64
}

// As demonstrated in #4639, programs reproduce with a very high, but not 100% probability.
// The triage algorithm must tolerate this, so let's pick the signal that is common
// to 3 out of 5 runs.
// By binomial distribution, a program that reproduces 80% of time will pass deflake()
// with a 94% probability. If it reproduces 90% of time, it passes in 99% of cases.
//
// During corpus triage we are more permissive and require only 2/6 to produce new stable signal.
// Such parameters make 80% flakiness to pass 99% of time, and even 60% flakiness passes 96% of time.
// First, we don't need to be strict during corpus triage since the program has already passed
// the stricter check when it was added to the corpus. So we can do fewer runs during triage,
// and finish it sooner. If the program does not produce any stable signal any more, just flakes,
// (if the kernel code was changed, or configs disabled), then it still should be phased out
// of the corpus eventually.
// Second, even if small percent of programs are dropped from the corpus due to flaky signal,
// later after several restarts we will add them to the corpus again, and it will create lots
// of duplicate work for minimization/hints/smash/fault injection. For example, a program with
// 60% flakiness has 68% chance to pass 3/5 criteria, but it's also likely to be dropped from
// the corpus if we use the same 3/5 criteria during triage. With a large corpus this effect
// can cause re-addition of thousands of programs to the corpus, and hundreds of thousands
// of runs for the additional work. With 2/6 criteria, a program with 60% flakiness has
// 96% chance to be kept in the corpus after retriage.
const (
	deflakeNeedRuns         = 3
	deflakeMaxRuns          = 5
	deflakeNeedCorpusRuns   = 2
	deflakeMinCorpusRuns    = 4
	deflakeMaxCorpusRuns    = 6
	deflakeTotalCorpusRuns  = 20
	deflakeNeedSnapshotRuns = 2
)

func (job *triageJob) execute(req *queue.Request, flags ProgFlags) *queue.Result {
	defer job.info.Execs.Add(1)
	req.Important = true // All triage executions are important.
	// job.fuzzer.applyBarrier(req)
	return job.fuzzer.executeWithFlags(job.queue, req, flags)
}

func (job *triageJob) run(fuzzer *Fuzzer) {
	fuzzer.statNewInputs.Add(1)
	job.fuzzer = fuzzer
	job.info.Logf("\n%s", job.p.Serialize())
	for call, info := range job.calls {
		job.info.Logf("call #%d [%s]: |new signal|=%d%s",
			call, job.p.CallName(call), info.newSignal.Len(), signalPreview(info.newSignal))
	}

	// Compute input coverage and non-flaky signal for minimization.
	stop := job.deflake(job.execute)
	if stop {
		return
	}
	var wg sync.WaitGroup
	for call, info := range job.calls {
		wg.Add(1)
		go func() {
			job.handleCall(call, info)
			wg.Done()
		}()
	}
	wg.Wait()
}

func (job *triageJob) handleCall(call int, info *triageCall) {
	if info.newStableSignal.Empty() {
		return
	}

	p := job.p
	if job.flags&ProgMinimized == 0 {
		p, call = job.minimize(call, info)
		if p == nil {
			return
		}
	}
	callName := p.CallName(call)
	if !job.fuzzer.Config.NewInputFilter(callName) {
		return
	}
	if job.flags&ProgSmashed == 0 {
		// Skip smash/hints/faultinject in UAF mode to avoid interfering with
		// barrier synchronization and reduce unnecessary execution overhead.
		if !job.fuzzer.Config.ModeUAF {
			job.fuzzer.startJob(job.fuzzer.statJobsSmash, &smashJob{
				exec: job.fuzzer.smashQueue,
				p:    p.Clone(),
				info: &JobInfo{
					Name:  p.String(),
					Type:  "smash",
					Calls: []string{p.CallName(call)},
				},
			})
			if job.fuzzer.Config.Comparisons && call >= 0 {
				job.fuzzer.startJob(job.fuzzer.statJobsHints, &hintsJob{
					exec: job.fuzzer.smashQueue,
					p:    p.Clone(),
					call: call,
					info: &JobInfo{
						Name:  p.String(),
						Type:  "hints",
						Calls: []string{p.CallName(call)},
					},
				})
			}
			if job.fuzzer.Config.FaultInjection && call >= 0 {
				job.fuzzer.startJob(job.fuzzer.statJobsFaultInjection, &faultInjectionJob{
					exec: job.fuzzer.smashQueue,
					p:    p.Clone(),
					call: call,
				})
			}
		}
	}
	job.fuzzer.Logf(2, "added new input for %v to the corpus: %s", callName, p)
	input := corpus.NewInput{
		Prog:     p,
		Call:     call,
		Signal:   info.stableSignal,
		Cover:    info.cover.Serialize(),
		RawCover: info.rawCover,
	}
	job.fuzzer.Config.Corpus.Save(input)

	// Update namespace index when new programs are added to corpus
	if job.fuzzer.raceGroup != nil {
		job.fuzzer.raceGroup.UpdateNamespaceIndex(p)
	}
}

func (job *triageJob) deflake(exec func(*queue.Request, ProgFlags) *queue.Result) (stop bool) {
	job.info.Logf("deflake started")
	avoid := []queue.ExecutorID{job.executor}
	needRuns := deflakeNeedCorpusRuns
	if job.fuzzer.Config.Snapshot {
		needRuns = deflakeNeedSnapshotRuns
	} else if job.flags&ProgFromCorpus == 0 {
		needRuns = deflakeNeedRuns
	}
	prevTotalNewSignal := 0
	for run := 1; ; run++ {
		totalNewSignal := 0
		indices := make([]int, 0, len(job.calls))
		for call, info := range job.calls {
			indices = append(indices, call)
			totalNewSignal += len(info.newSignal)
		}
		if job.stopDeflake(run, needRuns, prevTotalNewSignal == totalNewSignal) {
			break
		}
		prevTotalNewSignal = totalNewSignal
		result := exec(&queue.Request{
			Prog:            job.p,
			ExecOpts:        setFlags(flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal),
			ReturnAllSignal: indices,
			Avoid:           avoid,
			Stat:            job.fuzzer.statExecTriage,
		}, progInTriage)
		// log.Logf(0, "deflake stopped after %d runs", run)
		if result.Stop() {
			// log.Logf(0, "deflake stopped after %d runs", run)
			return true
		}
		// log.Logf(0, "deflake stopped after %d runs2", run)
		avoid = append(avoid, result.Executor)
		if result.Info == nil {
			continue // the program has failed
		}
		deflakeCall := func(call int, res *flatrpc.CallInfo) {
			info := job.calls[call]
			if info == nil {
				job.fuzzer.triageProgCall(job.p, res, call, &job.calls)
				info = job.calls[call]
			}
			if info == nil || res == nil {
				return
			}
			if len(info.rawCover) == 0 && job.fuzzer.Config.FetchRawCover {
				info.rawCover = res.Cover
			}
			// Since the signal is frequently flaky, we may get some new new max signal.
			// Merge it into the new signal we are chasing.
			// Most likely we won't conclude it's stable signal b/c we already have at least one
			// initial run w/o this signal, so if we exit after needRuns runs,
			// it won't be stable. However, it's still possible if we do more than needRuns runs.
			// But also we already observed it and we know it's flaky, so at least doing
			// cover.addRawMaxSignal for it looks useful.
			prio := signalPrio(job.p, res, call)
			newMaxSignal := job.fuzzer.Cover.addRawMaxSignal(res.Signal, prio)
			info.newSignal.Merge(newMaxSignal)
			info.cover.Merge(res.Cover)
			thisSignal := signal.FromRaw(res.Signal, prio)
			for j := needRuns - 1; j > 0; j-- {
				intersect := info.signals[j-1].Intersection(thisSignal)
				info.signals[j].Merge(intersect)
			}
			info.signals[0].Merge(thisSignal)
		}
		for i, callInfo := range result.Info.Calls {
			deflakeCall(i, callInfo)
		}
		deflakeCall(-1, result.Info.Extra)
	}
	job.info.Logf("deflake complete")
	for call, info := range job.calls {
		info.stableSignal = info.signals[needRuns-1]
		info.newStableSignal = info.newSignal.Intersection(info.stableSignal)
		job.info.Logf("call #%d [%s]: |stable signal|=%d, |new stable signal|=%d%s",
			call, job.p.CallName(call), info.stableSignal.Len(), info.newStableSignal.Len(),
			signalPreview(info.newStableSignal))
	}
	return false
}

func (job *triageJob) stopDeflake(run, needRuns int, noNewSignal bool) bool {
	if job.fuzzer.Config.Snapshot {
		return run >= needRuns+1
	}
	haveSignal := true
	for _, call := range job.calls {
		if !call.newSignal.IntersectsWith(call.signals[needRuns-1]) {
			haveSignal = false
		}
	}
	if job.flags&ProgFromCorpus == 0 {
		// For fuzzing programs we stop if we already have the right deflaked signal for all calls,
		// or there's no chance to get coverage common to needRuns for all calls.
		if run >= deflakeMaxRuns {
			return true
		}
		noChance := true
		for _, call := range job.calls {
			if left := deflakeMaxRuns - run; left >= needRuns ||
				call.newSignal.IntersectsWith(call.signals[needRuns-left-1]) {
				noChance = false
			}
		}
		if haveSignal || noChance {
			return true
		}
	} else if run >= deflakeTotalCorpusRuns ||
		noNewSignal && (run >= deflakeMaxCorpusRuns || run >= deflakeMinCorpusRuns && haveSignal) {
		// For programs from the corpus we use a different condition b/c we want to extract
		// as much flaky signal from them as possible. They have large coverage and run
		// in the beginning, gathering flaky signal on them allows to grow max signal quickly
		// and avoid lots of useless executions later. Any bit of flaky coverage discovered
		// later will lead to triage, and if we are unlucky to conclude it's stable also
		// to minimization+smash+hints (potentially thousands of runs).
		// So we run them at least 5 times, or while we are still getting any new signal.
		return true
	}
	return false
}

func (job *triageJob) minimize(call int, info *triageCall) (*prog.Prog, int) {
	job.info.Logf("[call #%d] minimize started", call)
	minimizeAttempts := 3
	if job.fuzzer.Config.Snapshot {
		minimizeAttempts = 2
	}
	stop := false
	mode := prog.MinimizeCorpus
	if job.fuzzer.Config.PatchTest {
		mode = prog.MinimizeCallsOnly
	}
	p, call := prog.Minimize(job.p, call, mode, func(p1 *prog.Prog, call1 int) bool {
		if stop {
			return false
		}
		var mergedSignal signal.Signal
		for i := 0; i < minimizeAttempts; i++ {
			result := job.execute(&queue.Request{
				Prog:            p1,
				ExecOpts:        setFlags(flatrpc.ExecFlagCollectSignal),
				ReturnAllSignal: []int{call1},
				Stat:            job.fuzzer.statExecMinimize,
			}, 0)
			if result.Stop() {
				stop = true
				return false
			}
			if !reexecutionSuccess(result.Info, info.errno, call1) {
				// The call was not executed or failed.
				continue
			}
			thisSignal := getSignalAndCover(p1, result.Info, call1)
			if mergedSignal.Len() == 0 {
				mergedSignal = thisSignal
			} else {
				mergedSignal.Merge(thisSignal)
			}
			if info.newStableSignal.Intersection(mergedSignal).Len() == info.newStableSignal.Len() {
				job.info.Logf("[call #%d] minimization step success (|calls| = %d)",
					call, len(p1.Calls))
				return true
			}
		}
		job.info.Logf("[call #%d] minimization step failure", call)
		return false
	})
	if stop {
		return nil, 0
	}
	return p, call
}

func reexecutionSuccess(info *flatrpc.ProgInfo, oldErrno int32, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldErrno == 0 && info.Calls[call].Error != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return info.Extra != nil && len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *flatrpc.ProgInfo, call int) signal.Signal {
	inf := info.Extra
	if call != -1 {
		inf = info.Calls[call]
	}
	if inf == nil {
		return nil
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call))
}

func signalPreview(s signal.Signal) string {
	if s.Len() > 0 && s.Len() <= 3 {
		var sb strings.Builder
		sb.WriteString(" (")
		for i, x := range s.ToRaw() {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "0x%x", x)
		}
		sb.WriteByte(')')
		return sb.String()
	}
	return ""
}

func (job *triageJob) getInfo() *JobInfo {
	return job.info
}

type smashJob struct {
	exec queue.Executor
	p    *prog.Prog
	info *JobInfo
}

func (job *smashJob) run(fuzzer *Fuzzer) {
	fuzzer.Logf(2, "smashing the program %s:", job.p)
	job.info.Logf("\n%s", job.p.Serialize())

	const iters = 25
	rnd := fuzzer.rand()
	for i := 0; i < iters; i++ {
		p := job.p.Clone()
		p.Mutate(rnd, prog.RecommendedCalls,
			fuzzer.ChoiceTable(),
			fuzzer.Config.NoMutateCalls,
			fuzzer.Config.Corpus.Programs())
		req := &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:     fuzzer.statExecSmash,
		}
		// fuzzer.applyBarrier(req)
		result := fuzzer.execute(job.exec, req)
		if result.Stop() {
			return
		}
		job.info.Execs.Add(1)
	}
}

func (job *smashJob) getInfo() *JobInfo {
	return job.info
}

func randomCollide(origP *prog.Prog, rnd *rand.Rand) *prog.Prog {
	if rnd.Intn(5) == 0 {
		// Old-style collide with a 20% probability.
		p, err := prog.DoubleExecCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	if rnd.Intn(4) == 0 {
		// Duplicate random calls with a 20% probability (25% * 80%).
		p, err := prog.DupCallCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, rnd)
	if rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, rnd)
	}
	return p
}

type faultInjectionJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
}

func (job *faultInjectionJob) run(fuzzer *Fuzzer) {
	for nth := 1; nth <= 100; nth++ {
		fuzzer.Logf(2, "injecting fault into call %v, step %v",
			job.call, nth)
		newProg := job.p.Clone()
		newProg.Calls[job.call].Props.FailNth = nth
		req := &queue.Request{
			Prog: newProg,
			Stat: fuzzer.statExecFaultInject,
		}
		// fuzzer.applyBarrier(req)
		result := fuzzer.execute(job.exec, req)
		if result.Stop() {
			return
		}
		info := result.Info
		if info != nil && len(info.Calls) > job.call &&
			info.Calls[job.call].Flags&flatrpc.CallFlagFaultInjected == 0 {
			break
		}
	}
}

type hintsJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
	info *JobInfo
}

func (job *hintsJob) run(fuzzer *Fuzzer) {
	// First execute the original program several times to get comparisons from KCOV.
	// Additional executions lets us filter out flaky values, which seem to constitute ~30-40%.
	p := job.p
	job.info.Logf("\n%s", p.Serialize())

	var comps prog.CompMap
	for i := 0; i < 3; i++ {
		req := &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectComps),
			Stat:     fuzzer.statExecSeed,
		}
		// fuzzer.applyBarrier(req)
		result := fuzzer.execute(job.exec, req)
		if result.Stop() {
			return
		}
		job.info.Execs.Add(1)
		if result.Info == nil || len(result.Info.Calls[job.call].Comps) == 0 {
			continue
		}
		got := make(prog.CompMap)
		for _, cmp := range result.Info.Calls[job.call].Comps {
			got.Add(cmp.Pc, cmp.Op1, cmp.Op2, cmp.IsConst)
		}
		if i == 0 {
			comps = got
		} else {
			comps.InplaceIntersect(got)
		}
	}

	job.info.Logf("stable comps: %d", comps.Len())
	fuzzer.hintsLimiter.Limit(comps)
	job.info.Logf("stable comps (after the hints limiter): %d", comps.Len())

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(job.call, comps,
		func(p *prog.Prog) bool {
			defer job.info.Execs.Add(1)
			req := &queue.Request{
				Prog:     p,
				ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
				Stat:     fuzzer.statExecHint,
			}
			// fuzzer.applyBarrier(req)
			result := fuzzer.execute(job.exec, req)
			return !result.Stop()
		})
}

func (job *hintsJob) getInfo() *JobInfo {
	return job.info
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *syncBuffer) Logf(logFmt string, args ...any) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	fmt.Fprintf(&sb.buf, "%s: ", time.Now().Format(time.DateTime))
	fmt.Fprintf(&sb.buf, logFmt, args...)
	sb.buf.WriteByte('\n')
}

func (sb *syncBuffer) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Bytes()
}

// ============================================================================
// Solo Filter Job
// ============================================================================
// This job implements delayed solo filtering for cross-program race pair detection:
//   1. Barrier execution discovers new pairs (already done before this job starts)
//   2. Execute prog1 solo → collect pairs_prog1
//   3. Execute prog2 solo → collect pairs_prog2
//   4. Filter: cross_program_pairs = barrier_pairs - pairs_prog1 - pairs_prog2
//   5. Save only the filtered cross-program pairs
// ============================================================================

type soloFilterJob struct {
	exec         queue.Executor
	prog1        *prog.Prog
	prog2        *prog.Prog
	barrierPairs []*ddrd.MayUAFPair // pairs discovered from barrier execution
	req          *queue.Request     // original barrier request (for context)
	res          *queue.Result      // original barrier result (for context)
	stat         *stat.Val
	fuzzer       *Fuzzer
	info         *JobInfo
	source       PairSource // source of the pairs (fuzz or timing)
}

func (job *soloFilterJob) run(fuzzer *Fuzzer) {
	log.Logf(1, "[SOLO-FILTER] run() starting: prog1=%d calls, prog2=%d calls, barrierPairs=%d",
		len(job.prog1.Calls), len(job.prog2.Calls), len(job.barrierPairs))

	// Execute solo runs to collect intra-program pairs
	prog1SoloPairs := job.executeSolo(job.prog1, "prog1")
	prog2SoloPairs := job.executeSolo(job.prog2, "prog2")
	log.Logf(1, "[SOLO-FILTER] solo phases done: prog1=%d prog2=%d", prog1SoloPairs.Size(), prog2SoloPairs.Size())

	// Filter to get cross-program pairs
	// Cross-program pairs = barrier pairs - solo pairs from prog1 - solo pairs from prog2
	crossProgramPairs := job.filterCrossProgramPairs(
		job.barrierPairs,
		prog1SoloPairs,
		prog2SoloPairs,
	)
	log.Logf(1, "[SOLO-FILTER] filtered: %d cross-program pairs (from %d barrier pairs)",
		len(crossProgramPairs), len(job.barrierPairs))

	// Save the filtered cross-program pairs
	if len(crossProgramPairs) > 0 {
		fuzzer.statCrossProgPairs.Add(len(crossProgramPairs))

		// Save to UAF corpus
		if fuzzer.uaf != nil {
			fuzzer.uaf.handleFilteredPairs(job.req, job.res, job.prog1, job.prog2, crossProgramPairs, job.source)
			log.Logf(1, "[SOLO-FILTER] saved %d cross-program pairs", len(crossProgramPairs))
		}

		// Update Syscall Affinity Table (record interaction success)
		job.updateAffinityTable(crossProgramPairs)
		fuzzer.statAffinityUpdates.Add(len(crossProgramPairs))
	}

	job.info.Execs.Add(2) // Two solo executions
	log.Logf(1, "[SOLO-FILTER] run() completed")
}

// executeSolo runs a single program and collects VarName pairs.
func (job *soloFilterJob) executeSolo(p *prog.Prog, name string) *VarNamePairSet {
	// Try to get from cache first
	if job.fuzzer.raceGroup != nil {
		cache := job.fuzzer.raceGroup.GetSoloPairCache()
		if cache != nil {
			if cached, found := cache.Get(p); found {
				job.fuzzer.statSoloCacheHits.Add(1)
				log.Logf(2, "[SOLO-DDRD] %s: cache hit, %d pairs", name, cached.Size())
				return cached
			}
		}
	}

	req := &queue.Request{
		Prog: p.Clone(),
		ExecOpts: flatrpc.ExecOpts{
			// Solo执行需要收集DDRD数据，必须是单线程执行
			ExecFlags: flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectDdrdUaf | flatrpc.ExecFlagDedupCover,
		},
		Stat:            job.stat,
		IsSoloExecution: true, // 标记为solo执行，队列不会合并Threaded标志
	}
	inheritTimingThreshold(req, job.req)
	if job.req == nil || !job.req.IsTimingExploration {
		job.fuzzer.applyNormalTimingThreshold(req)
	}

	log.Logf(3, "[SOLO-DDRD] executeSolo starting: prog=%s", name)
	result := job.fuzzer.executeWithFlags(job.exec, req, 0)
	if result == nil {
		log.Logf(2, "[SOLO-DDRD] %s: result is nil", name)
		return NewVarNamePairSet()
	}

	// Extract VarName pairs from DDRD report
	pairSet := NewVarNamePairSet()
	if result.Ddrd != nil {
		log.Logf(2, "[SOLO-DDRD] %s: result.Ddrd has %d UAFPairs", name, len(result.Ddrd.UAFPairs))
		for _, pair := range result.Ddrd.UAFPairs {
			if pair != nil {
				vnPair := NewVarNamePair(pair.FreeAccessName, pair.UseAccessName)
				pairSet.Add(vnPair)
			}
		}
		// Cache if we got valid results
		if pairSet.Size() > 0 && job.fuzzer.raceGroup != nil {
			cache := job.fuzzer.raceGroup.GetSoloPairCache()
			if cache != nil {
				cache.Put(p, pairSet)
				log.Logf(2, "[SOLO-DDRD] %s: cached %d pairs", name, pairSet.Size())
			}
		}
	} else {
		log.Logf(2, "[SOLO-DDRD] %s: result.Ddrd is nil", name)
	}

	log.Logf(2, "[SOLO-DDRD] %s: collected %d unique VarName pairs", name, pairSet.Size())
	return pairSet
}

// filterCrossProgramPairs filters to keep only truly cross-program pairs.
func (job *soloFilterJob) filterCrossProgramPairs(
	barrierPairs []*ddrd.MayUAFPair,
	prog1SoloPairs *VarNamePairSet,
	prog2SoloPairs *VarNamePairSet,
) []*ddrd.MayUAFPair {

	// Merge solo pairs into one set
	soloPairs := NewVarNamePairSet()
	soloPairs.Merge(prog1SoloPairs)
	soloPairs.Merge(prog2SoloPairs)

	// Filter: keep only pairs not in solo runs
	var crossProgram []*ddrd.MayUAFPair
	for _, uafPair := range barrierPairs {
		if uafPair == nil {
			continue
		}
		pair := NewVarNamePair(uafPair.FreeAccessName, uafPair.UseAccessName)
		if !soloPairs.Contains(pair) {
			crossProgram = append(crossProgram, uafPair)
		}
	}

	job.fuzzer.Logf(2, "soloFilter: filtered %d barrier pairs to %d cross-program pairs (removed %d solo pairs from prog1=%d prog2=%d)",
		len(barrierPairs), len(crossProgram),
		len(barrierPairs)-len(crossProgram),
		prog1SoloPairs.Size(), prog2SoloPairs.Size())

	return crossProgram
}

func (job *soloFilterJob) getInfo() *JobInfo {
	return job.info
}

// updateAffinityTable records syscall pair interactions in the affinity table.
// Uses harmonic decay based on existing stack count:
// - New VarName pair (stack=0): full BaseWeight
// - Subsequent stacks: BaseWeight / (1 + existingStackCount)
// This ensures cumulative bonus from 100 stacks approaches BaseWeight.
func (job *soloFilterJob) updateAffinityTable(crossProgramPairs []*ddrd.MayUAFPair) {
	if job.fuzzer.raceGroup == nil {
		return
	}

	affinityTable := job.fuzzer.raceGroup.GetAffinityTable()
	if affinityTable == nil {
		return
	}

	// Get configured base weight or use default
	baseWeight := float64(job.fuzzer.Config.NewVarNamePairAffinityWeight)
	if baseWeight <= 0 {
		baseWeight = float64(DefaultNewVarNamePairAffinityWeight)
	}

	for _, pair := range crossProgramPairs {
		if pair == nil {
			continue
		}

		sig1, sig2 := ExtractSignaturesFromPair(job.prog1, job.prog2, pair)
		if sig1.IsEmpty() || sig2.IsEmpty() {
			continue
		}

		// Get newness info including existing stack count
		isNewVarNamePair, isNewStack, existingStackCount := job.fuzzer.raceGroup.CheckPairNewness(pair)

		var weight float64
		if isNewVarNamePair {
			// New VarName pair: full base weight
			weight = baseWeight
		} else if isNewStack {
			// New stack for existing VarName pair: harmonic decay
			// Weight = BaseWeight / (1 + existingStackCount)
			// This ensures sum(weight) for stacks 2..100 approaches BaseWeight
			weight = baseWeight / float64(1+existingStackCount)
		} else {
			// Already recorded pair, skip
			continue
		}

		affinityTable.RecordInteractionWithWeight(sig1, sig2, weight)
	}
}
