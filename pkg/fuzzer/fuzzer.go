// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/bits"
	"math/rand"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type Fuzzer struct {
	Stats
	Config *Config
	Cover  *Cover
	ddrd   *ddrd.Store
	uaf    *uafMode

	// Race-Guided Program-Group Fuzzing
	raceGroup *RaceGroupManager

	uafBootstrapDone atomic.Bool

	ctx          context.Context
	mu           sync.Mutex
	rnd          *rand.Rand
	target       *prog.Target
	hintsLimiter prog.HintsLimiter
	runningJobs  map[jobIntrospector]struct{}

	ct           *prog.ChoiceTable
	ctProgs      int
	ctMu         sync.Mutex // TODO: use RWLock.
	ctRegenerate chan struct{}

	coverageFlagOnce   sync.Once
	coverageInfoOnce   sync.Once
	coverageNoDiffOnce sync.Once
	coverageEmptyOnce  atomic.Bool

	execQueues
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	if cfg.NewInputFilter == nil {
		cfg.NewInputFilter = func(call string) bool {
			return true
		}
	}
	f := &Fuzzer{
		Stats:  newStats(target),
		Config: cfg,
		Cover:  newCover(),
		ddrd:   ddrd.NewStore(),

		ctx:         ctx,
		rnd:         rnd,
		target:      target,
		runningJobs: map[jobIntrospector]struct{}{},

		// We're okay to lose some of the messages -- if we are already
		// regenerating the table, we don't want to repeat it right away.
		ctRegenerate: make(chan struct{}),
	}
	f.uaf = newUAFMode(f)
	// Initialize Race-Guided Program-Group Manager
	if cfg.ModeUAF {
		raceConfig := DefaultRaceGroupConfig()
		// Override with user-configured MaxStacksPerVarNamePair if set
		if cfg.MaxStacksPerVarNamePair > 0 {
			raceConfig.MaxStacksPerVarPair = cfg.MaxStacksPerVarNamePair
		}
		// Override PairCooldown configuration if set
		if cfg.CooldownThreshold > 0 {
			raceConfig.CooldownThreshold = cfg.CooldownThreshold
		}
		if cfg.NewStackPenalty > 0 {
			raceConfig.NewStackPenalty = cfg.NewStackPenalty
		}
		if cfg.NoDiscoveryPenalty > 0 {
			raceConfig.NoDiscoveryPenalty = cfg.NoDiscoveryPenalty
		}
		// Random Baseline Mode: disable all intelligent strategies
		if cfg.RandomBaselineMode {
			raceConfig.RandomBaselineMode = true
			raceConfig.EnablePartnerSelection = false
			raceConfig.EnableRaceYieldFeedback = false
			raceConfig.EnableAffinityTable = false
			log.Logf(0, "[RANDOM-BASELINE] Race-guided strategies DISABLED for A/B testing")
		}
		f.raceGroup = NewRaceGroupManager(raceConfig)
	}
	f.execQueues = newExecQueues(f)
	f.updateChoiceTable(nil)
	go f.choiceTableUpdater()
	if cfg.Debug {
		go f.logCurrentStats()
	}
	return f
}

func (fuzzer *Fuzzer) RecommendedCalls() int {
	if fuzzer.Config.ModeKFuzzTest {
		return prog.RecommendedCallsKFuzzTest
	}
	return prog.RecommendedCalls
}

type execQueues struct {
	triageCandidateQueue *queue.DynamicOrderer
	candidateQueue       *queue.PlainQueue
	triageQueue          *queue.DynamicOrderer
	smashQueue           *queue.PlainQueue
	source               queue.Source
}

func newExecQueues(fuzzer *Fuzzer) execQueues {
	ret := execQueues{
		triageCandidateQueue: queue.DynamicOrder(),
		candidateQueue:       queue.Plain(),
		triageQueue:          queue.DynamicOrder(),
		smashQueue:           queue.Plain(),
	}
	// Alternate smash jobs with exec/fuzz to spread attention to the wider area.
	skipQueue := 3
	if fuzzer.Config.PatchTest {
		// When we do patch fuzzing, we do not focus on finding and persisting
		// new coverage that much, so it's reasonable to spend more time just
		// mutating various corpus programs.
		skipQueue = 2
	}
	sources := []queue.Source{
		ret.triageCandidateQueue,
		ret.candidateQueue,
	}
	if fuzzer.uaf != nil {
		// Set the smash queue for uaf mode to submit barrier requests
		fuzzer.uaf.setQueue(ret.smashQueue)
		sources = append(sources, ret.triageQueue)
		sources = append(sources,
			queue.Alternate(ret.smashQueue, skipQueue),
			queue.Callback(fuzzer.genFuzz),
		)

	} else {
		sources = append(sources, ret.triageQueue)
		sources = append(sources,
			queue.Callback(fuzzer.genFuzz),
		)
	}

	// Sources are listed in the order, in which they will be polled.
	ret.source = queue.Order(sources...)
	return ret
}

func (fuzzer *Fuzzer) CandidatesToTriage() int {
	count := fuzzer.statCandidates.Val() + fuzzer.statJobsTriageCandidate.Val()
	// log.Logf(1, "[DEBUG-TRIAGE] CandidatesToTriage: candidates=%d triageJobs=%d total=%d",
	// fuzzer.statCandidates.Val(), fuzzer.statJobsTriageCandidate.Val(), count)
	return count
}

func (fuzzer *Fuzzer) CandidateTriageFinished() bool {
	finished := fuzzer.CandidatesToTriage() == 0
	// log.Logf(1, "[DEBUG-TRIAGE] CandidateTriageFinished: %v", finished)
	return finished
}

func (fuzzer *Fuzzer) execute(executor queue.Executor, req *queue.Request) *queue.Result {
	return fuzzer.executeWithFlags(executor, req, 0)
}

func (fuzzer *Fuzzer) executeWithFlags(executor queue.Executor, req *queue.Request, flags ProgFlags) *queue.Result {
	fuzzer.enqueue(executor, req, flags, 0)
	return req.Wait(fuzzer.ctx)
}

func (fuzzer *Fuzzer) prepare(req *queue.Request, flags ProgFlags, attempt int) {
	req.OnDone(func(req *queue.Request, res *queue.Result) bool {
		return fuzzer.processResult(req, res, flags, attempt)
	})
}

func (fuzzer *Fuzzer) enqueue(executor queue.Executor, req *queue.Request, flags ProgFlags, attempt int) {
	fuzzer.prepare(req, flags, attempt)
	executor.Submit(req)
}

func (fuzzer *Fuzzer) processResult(req *queue.Request, res *queue.Result, flags ProgFlags, attempt int) bool {
	// Debug: Log every result processing
	var signalLen, coverLen int
	if res != nil && res.Info != nil {
		for _, call := range res.Info.Calls {
			if call != nil {
				signalLen += len(call.Signal)
				coverLen += len(call.Cover)
			}
		}
	}
	log.Logf(3, "[DEBUG-RESULT] processResult: flags=%d isCandidate=%v isBarrier=%v status=%v signalLen=%d coverLen=%d attempt=%d corpus=%d",
		flags, flags&progCandidate != 0, flags == ProgBarrier, res.Status, signalLen, coverLen, attempt, len(fuzzer.Config.Corpus.Programs()))

	// Check if VM was restarted and clear its history buffer
	if res != nil && res.Status == queue.Restarted && fuzzer.uaf != nil {
		fuzzer.Logf(1, "[history] VM %d restarted, clearing history buffer", res.Executor.VM)
		fuzzer.uaf.clearVMHistory(res.Executor.VM)
	}

	if fuzzer.uaf != nil && flags == ProgBarrier {
		// 先保存所有 barrier 执行收集到的 pairs
		// 然后如果有新 pairs，触发 solo 过滤 job 来去除非跨程序的 pairs
		if res.Ddrd != nil && len(res.Ddrd.UAFPairs) > 0 {
			// 检查是否有新的 pairs（通过检查是否被添加到 ddrd store）
			newPairs := fuzzer.ddrd.Add(res.Ddrd)
			if len(newPairs) > 0 {
				// 有新 pairs，触发 solo 过滤
				fuzzer.triggerSoloFilter(req, res, newPairs)
			}
		}
		// 记录执行并检测新覆盖率（pair 级别）
		newCover := fuzzer.uaf.recordExecution(req, res)
		if len(newCover) > 0 && len(req.BarrierPrograms) >= 2 {
			// 有新覆盖率，触发 coverage triage job
			fuzzer.triggerCoverageTriage(req, res, newCover)
		}
		return true
	}

	// If we are already triaging this exact prog, this is flaky coverage.
	// Hanged programs are harmful as they consume executor procs.
	dontTriage := flags&progInTriage > 0 || res.Status == queue.Hanged
	// Triage the program.
	// We do it before unblocking the waiting threads because
	// it may result it concurrent modification of req.Prog.
	var triage map[int]*triageCall
	collectSignal := req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0
	// log.Logf(1, "[DEBUG-TRIAGE] checking triage: collectSignal=%v hasInfo=%v dontTriage=%v",
	// collectSignal, res.Info != nil, dontTriage)
	if collectSignal && res.Info != nil && !dontTriage {
		for call, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Prog, info, call, &triage)
		}
		fuzzer.triageProgCall(req.Prog, res.Info.Extra, -1, &triage)
		// log.Logf(1, "[DEBUG-TRIAGE] after triageProgCall: triageCalls=%d", len(triage))

		if len(triage) != 0 {

			queue, stat := fuzzer.triageQueue, fuzzer.statJobsTriage
			if flags&progCandidate > 0 {
				queue, stat = fuzzer.triageCandidateQueue, fuzzer.statJobsTriageCandidate
			}
			job := &triageJob{
				p:        req.Prog.Clone(),
				executor: res.Executor,
				flags:    flags,
				queue:    queue.Append(),
				calls:    triage,
				info: &JobInfo{
					Name: req.Prog.String(),
					Type: "triage",
				},
			}
			for id := range triage {
				job.info.Calls = append(job.info.Calls, job.p.CallName(id))
			}
			sort.Strings(job.info.Calls)
			fuzzer.startJob(stat, job)
		}
	}

	if res.Info != nil {
		fuzzer.statExecTime.Add(int(res.Info.Elapsed / 1e6))
		for call, info := range res.Info.Calls {
			fuzzer.handleCallInfo(req, info, call)
		}
		fuzzer.handleCallInfo(req, res.Info.Extra, -1)
	}
	fuzzer.Logf(2, "[test]: Corpus candidates may have flaky coverage, so we give them a second chance")
	// Corpus candidates may have flaky coverage, so we give them a second chance.
	maxCandidateAttempts := 3
	if req.Risky() {
		// In non-snapshot mode usually we are not sure which exactly input caused the crash,
		// so give it one more chance. In snapshot mode we know for sure, so don't retry.
		maxCandidateAttempts = 2
		if fuzzer.Config.Snapshot || res.Status == queue.Hanged {
			maxCandidateAttempts = 0
		}
	}
	if len(triage) == 0 && flags&ProgFromCorpus != 0 && attempt < maxCandidateAttempts {
		// log.Logf(1, "[DEBUG-TRIAGE] no triage, retrying candidate attempt=%d/%d", attempt+1, maxCandidateAttempts)
		fuzzer.enqueue(fuzzer.candidateQueue, req, flags, attempt+1)
		return false
	}
	if flags&progCandidate != 0 {
		// log.Logf(1, "[DEBUG-TRIAGE] scandidate done, decrementing count, triageCalls=%d", len(triage))
		fuzzer.statCandidates.Add(-1)
	}
	return true
}

type Config struct {
	Debug          bool
	Corpus         *corpus.Corpus
	Logf           func(level int, msg string, args ...interface{})
	Snapshot       bool
	Coverage       bool
	FaultInjection bool
	Comparisons    bool
	Collide        bool
	EnabledCalls   map[*prog.Syscall]bool
	NoMutateCalls  map[int]bool
	FetchRawCover  bool
	NewInputFilter func(call string) bool
	PatchTest      bool
	ModeKFuzzTest  bool
	ModeUAF        bool
	BarrierMode    bool
	BarrierMask    uint64
	// History buffer configuration for UAF mode
	HistoryBufferSize            int // Size of per-VM history buffer (default: 1000)
	NewVarNamePairHistory        int // Records to save for new VarName pair (default: 1000)
	NewStackHistory              int // Records to save for new stack (default: 100)
	MaxStacksPerVarNamePair      int // Max unique stack pairs per VarName pair (default: 20)
	NewVarNamePairAffinityWeight int // Affinity weight for new VarName pair (default: 5)
	NewStackAffinityWeight       int // Affinity weight for new stack (default: 1)
	// PairCooldown configuration
	CooldownThreshold  int // Failure score threshold to enter cooldown (default: 20)
	NewStackPenalty    int // Failure score penalty for new stack only (default: 1)
	NoDiscoveryPenalty int // Failure score penalty for no discovery (default: 2)
	// A/B Testing
	RandomBaselineMode bool // Disable all race-guided strategies for baseline comparison
}

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *flatrpc.CallInfo, call int, triage *map[int]*triageCall) {
	if info == nil {
		return
	}
	prio := signalPrio(p, info, call)
	// log.Logf(1, "[DEBUG-SIGNAL] triageProgCall call=%d signalLen=%d prio=%d", call, len(info.Signal), prio)
	newMaxSignal := fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
	if newMaxSignal.Empty() {
		// log.Logf(1, "[DEBUG-SIGNAL] call=%d newMaxSignal is EMPTY (no new coverage)", call)
		return
	}
	if !fuzzer.Config.NewInputFilter(p.CallName(call)) {
		// log.Logf(1, "[DEBUG-SIGNAL] call=%d filtered out by NewInputFilter", call)
		return
	}
	// log.Logf(1, "[DEBUG-SIGNAL] call=%d found NEW signal, newMaxSignalLen=%d", call, newMaxSignal.Len())
	if *triage == nil {
		*triage = make(map[int]*triageCall)
	}
	(*triage)[call] = &triageCall{
		errno:     info.Error,
		newSignal: newMaxSignal,
		signals:   [deflakeNeedRuns]signal.Signal{signal.FromRaw(info.Signal, prio)},
	}
}

func (fuzzer *Fuzzer) handleCallInfo(req *queue.Request, info *flatrpc.CallInfo, call int) {
	if info == nil || info.Flags&flatrpc.CallFlagCoverageOverflow == 0 {
		return
	}
	log.Logf(3, "flatrpc.CallFlagCoverageOverflow detected in call %d in %s", call, req.Prog)
	syscallIdx := len(fuzzer.Syscalls) - 1
	if call != -1 {
		syscallIdx = req.Prog.Calls[call].Meta.ID
	}
	stat := &fuzzer.Syscalls[syscallIdx]
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps != 0 {
		stat.CompsOverflows.Add(1)
		fuzzer.statCompsOverflows.Add(1)
	} else {
		stat.CoverOverflows.Add(1)
		fuzzer.statCoverOverflows.Add(1)
	}
}

func signalPrio(p *prog.Prog, info *flatrpc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Error == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func (fuzzer *Fuzzer) genFuzz() *queue.Request {
	corpusLen := len(fuzzer.Config.Corpus.Programs())
	uafReady := fuzzer.uafReady()
	log.Logf(3, "[DEBUG-GENFUZZ] genFuzz called: corpus=%d uafReady=%v candidatesToTriage=%d",
		corpusLen, uafReady, fuzzer.statCandidates.Val())

	// Either generate a new input or mutate an existing one.
	mutateRate := 0.95
	// log.Logf(0, "corpus length: %d", len(fuzzer.Config.Corpus.Programs()))
	// for len(fuzzer.Config.Corpus.Programs()) == 0 {
	// 	continue
	// }
	if !fuzzer.Config.Coverage {
		// If we don't have real coverage signal, generate programs
		// more frequently because fallback signal is weak.
		mutateRate = 0.5
	}
	var req *queue.Request
	rnd := fuzzer.rand()
	if rnd.Float64() < mutateRate {
		req = mutateProgRequest(fuzzer, rnd)
	}
	if req == nil {
		req = genProgRequest(fuzzer, rnd)
	}
	if fuzzer.uafReady() {
		fuzzer.applyBarrier(req)
		flags := ProgFlags(0)
		if req.Barrier {
			flags |= ProgBarrier
		}
		fuzzer.prepare(req, flags, 0)
		return req
	}

	if fuzzer.Config.Collide && rnd.Intn(3) == 0 {
		base := req
		req = &queue.Request{
			Prog:     randomCollide(base.Prog, rnd),
			ExecOpts: base.ExecOpts,
			Stat:     fuzzer.statExecCollide,
		}
	}
	log.Logf(3, "[test]: genFuzz")
	if req != nil {
		fuzzer.prepare(req, 0, 0)
	}

	return req
}

func (fuzzer *Fuzzer) applyBarrier(req *queue.Request) {
	if req == nil {
		return
	}
	mask := fuzzer.Config.BarrierMask
	if !fuzzer.Config.BarrierMode || mask == 0 {
		req.SetBarrier(0)
		return
	}
	if bits.OnesCount64(mask) < 2 {
		fuzzer.Logf(1, "barrier mask %#x has less than 2 participants, disabling", mask)
		req.SetBarrier(0)
		return
	}
	req.SetBarrier(mask)
	programs := fuzzer.buildBarrierPrograms(req, mask)
	req.ExecOpts.ExecFlags |= flatrpc.ExecFlagCollectCover
	req.ExecOpts.ExecFlags &^= flatrpc.ExecFlagThreaded
	if err := req.SetBarrierPrograms(programs); err != nil {
		fuzzer.Logf(0, "failed to assign barrier programs: %v", err)
		req.SetBarrier(0)
	}
}

func (fuzzer *Fuzzer) buildBarrierPrograms(req *queue.Request, mask uint64) []*prog.Prog {
	count := bits.OnesCount64(mask)
	if count == 0 {
		return nil
	}

	// Use Race-Guided Partner Selection if available
	if fuzzer.raceGroup != nil {
		corpus := fuzzer.Config.Corpus.Programs()
		rnd := fuzzer.rand()
		programs := fuzzer.raceGroup.BuildBarrierProgramsWithRaceGuidance(req.Prog, count, corpus, rnd)

		// Sync ObjectLinker stats to Fuzzer stats
		if ol := fuzzer.raceGroup.GetObjectLinker(); ol != nil {
			_, successes, _ := ol.GetStats()
			if successes > 0 {
				// Update only the delta
				currentVal := int(fuzzer.statObjectLinkings.Val())
				delta := successes - currentVal
				if delta > 0 {
					fuzzer.statObjectLinkings.Add(delta)
				}
			}
		}

		return programs
	}

	// Fallback to original random selection
	programs := make([]*prog.Prog, count)
	programs[0] = req.Prog
	if count == 1 {
		return programs
	}
	rnd := fuzzer.rand()
	for i := 1; i < count; i++ {
		candidate := fuzzer.Config.Corpus.ChooseProgram(rnd)
		if candidate == nil {
			programs[i] = req.Prog.Clone()
			continue
		}
		programs[i] = candidate.Clone()
	}
	for i := range programs {
		if programs[i] == nil {
			programs[i] = req.Prog.Clone()
		}
	}
	return programs
}

// triggerSoloFilter starts a solo filter job to remove non-cross-program pairs.
// This is called after barrier execution discovers new pairs.
// The job executes prog1 solo and prog2 solo, then filters out pairs that also appear in solo runs.
func (fuzzer *Fuzzer) triggerSoloFilter(req *queue.Request, res *queue.Result, newPairs []*ddrd.MayUAFPair) {
	if req == nil || len(req.BarrierPrograms) < 2 || len(newPairs) == 0 {
		return
	}

	prog1 := req.BarrierPrograms[0]
	prog2 := req.BarrierPrograms[1]
	if prog1 == nil || prog2 == nil {
		return
	}

	// Use smashQueue as executor
	executor := fuzzer.smashQueue

	job := &soloFilterJob{
		exec:         executor,
		prog1:        prog1.Clone(),
		prog2:        prog2.Clone(),
		barrierPairs: newPairs, // pairs discovered from barrier execution
		req:          req,
		res:          res,
		stat:         fuzzer.statExecUAF,
		fuzzer:       fuzzer,
		info: &JobInfo{
			Name: "solo-filter",
			Type: "solo-filter",
		},
	}
	fuzzer.startJob(fuzzer.statJobsSoloFilter, job)
}

// triggerCoverageTriage starts a coverage triage job when new coverage is discovered from a pair.
// This job runs prog1 and prog2 solo to determine which program contributed the new coverage,
// then boosts the Bandit scores for programs that brought new coverage.
func (fuzzer *Fuzzer) triggerCoverageTriage(req *queue.Request, res *queue.Result, newCover cover.Cover) {
	if req == nil || len(req.BarrierPrograms) < 2 || len(newCover) == 0 {
		return
	}

	prog1 := req.BarrierPrograms[0]
	prog2 := req.BarrierPrograms[1]
	if prog1 == nil || prog2 == nil {
		return
	}

	// Use smashQueue as executor
	executor := fuzzer.smashQueue

	// Record new coverage discovery
	fuzzer.statNewCoverageFromPairs.Add(len(newCover))

	job := &coverageTriageJob{
		exec:     executor,
		prog1:    prog1.Clone(),
		prog2:    prog2.Clone(),
		newCover: newCover,
		req:      req,
		res:      res,
		fuzzer:   fuzzer,
		info: &JobInfo{
			Name: "coverage-triage",
			Type: "coverage-triage",
		},
	}
	fuzzer.startJob(fuzzer.statCoverageTriageJobs, job)
}

func (fuzzer *Fuzzer) startJob(stat *stat.Val, newJob job) {
	fuzzer.Logf(2, "started %T", newJob)
	go func() {
		stat.Add(1)
		defer stat.Add(-1)

		fuzzer.statJobs.Add(1)
		defer fuzzer.statJobs.Add(-1)

		if obj, ok := newJob.(jobIntrospector); ok {
			fuzzer.mu.Lock()
			fuzzer.runningJobs[obj] = struct{}{}
			fuzzer.mu.Unlock()

			defer func() {
				fuzzer.mu.Lock()
				delete(fuzzer.runningJobs, obj)
				fuzzer.mu.Unlock()
			}()
		}

		newJob.run(fuzzer)
	}()
}

func (fuzzer *Fuzzer) Next() *queue.Request {
	req := fuzzer.source.Next()
	if req == nil {
		// The fuzzer is not supposed to issue nil requests.
		panic("nil request from the fuzzer")
	}
	return req
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...interface{}) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

type ProgFlags int

const (
	// The candidate was loaded from our local corpus rather than come from hub.
	ProgFromCorpus ProgFlags = 1 << iota
	ProgMinimized
	ProgSmashed

	progCandidate
	progInTriage
	ProgBarrier
)

type Candidate struct {
	Prog  *prog.Prog
	Flags ProgFlags
}

func (fuzzer *Fuzzer) AddCandidates(candidates []Candidate) {
	fmt.Println("[SYNC-DEBUG] Entered AddCandidates, count=", len(candidates))
	log.Logf(1, "[DEBUG-CANDIDATES] AddCandidates: adding %d candidates", len(candidates))
	fuzzer.statCandidates.Add(len(candidates))
	for _, candidate := range candidates {
		req := &queue.Request{
			Prog:      candidate.Prog,
			ExecOpts:  setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:      fuzzer.statExecCandidate,
			Important: true,
		}
		// fuzzer.applyBarrier(req)
		fuzzer.enqueue(fuzzer.candidateQueue, req, candidate.Flags|progCandidate, 0)
	}
	log.Logf(1, "[DEBUG-CANDIDATES] AddCandidates done, total candidates=%d", fuzzer.statCandidates.Val())
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return rand.New(rand.NewSource(fuzzer.rnd.Int63()))
}

func (fuzzer *Fuzzer) updateChoiceTable(programs []*prog.Prog) {
	newCt := fuzzer.target.BuildChoiceTable(programs, fuzzer.Config.EnabledCalls)

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()
	if len(programs) >= fuzzer.ctProgs {
		fuzzer.ctProgs = len(programs)
		fuzzer.ct = newCt
	}
}

func (fuzzer *Fuzzer) choiceTableUpdater() {
	for {
		select {
		case <-fuzzer.ctx.Done():
			return
		case <-fuzzer.ctRegenerate:
		}
		fuzzer.updateChoiceTable(fuzzer.Config.Corpus.Programs())
	}
}

func (fuzzer *Fuzzer) ChoiceTable() *prog.ChoiceTable {
	progs := fuzzer.Config.Corpus.Programs()

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()

	// There were no deep ideas nor any calculations behind these numbers.
	regenerateEveryProgs := 333
	if len(progs) < 100 {
		regenerateEveryProgs = 33
	}
	if fuzzer.ctProgs+regenerateEveryProgs < len(progs) {
		select {
		case fuzzer.ctRegenerate <- struct{}{}:
		default:
			// We're okay to lose the message.
			// It means that we're already regenerating the table.
		}
	}
	return fuzzer.ct
}

func (fuzzer *Fuzzer) PendingUAFCorpusEntries() []*UAFCorpusEntry {
	if fuzzer.uaf == nil {
		return nil
	}
	return fuzzer.uaf.pendingEntries()
}

func (fuzzer *Fuzzer) EnqueueUAFCorpus(entries []*UAFCorpusEntry) int {
	if fuzzer.uaf == nil {
		return 0
	}
	return fuzzer.uaf.restore(entries)
}

func (fuzzer *Fuzzer) ActivateUAFMode() bool {
	if fuzzer == nil || fuzzer.uaf == nil {
		log.Logf(1, "[DEBUG-UAF] ActivateUAFMode: fuzzer or uaf is nil")
		return false
	}
	if !fuzzer.uafBootstrapDone.CompareAndSwap(false, true) {
		log.Logf(1, "[DEBUG-UAF] ActivateUAFMode: already activated")
		return false
	}
	log.Logf(1, "[DEBUG-UAF] ActivateUAFMode: enabling barrier fuzzing, corpus=%d", len(fuzzer.Config.Corpus.Programs()))
	fuzzer.Logf(1, "uaf: enabling barrier fuzzing after corpus triage")
	// Clear all history buffers to ensure replay history only contains UAF-mode executions.
	// Executions during corpus triage phase should not be included in replay history.
	if fuzzer.uaf.historyBuffer != nil {
		fuzzer.uaf.historyBuffer.ClearAll()
		fuzzer.Logf(0, "uaf: cleared all VM history buffers on UAF mode activation")
	}
	return true
}

func (fuzzer *Fuzzer) uafReady() bool {
	ready := fuzzer != nil && fuzzer.uaf != nil && fuzzer.uafBootstrapDone.Load()
	return ready
}

func (fuzzer *Fuzzer) RunningJobs() []*JobInfo {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()

	var ret []*JobInfo
	for item := range fuzzer.runningJobs {
		ret = append(ret, item.getInfo())
	}
	return ret
}

func (fuzzer *Fuzzer) logCurrentStats() {
	for {
		select {
		case <-time.After(time.Minute):
		case <-fuzzer.ctx.Done():
			return
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		str := fmt.Sprintf("running jobs: %d, heap (MB): %d",
			fuzzer.statJobs.Val(), m.Alloc/1000/1000)
		fuzzer.Logf(0, "%s", str)
	}
}

func setFlags(execFlags flatrpc.ExecFlag) flatrpc.ExecOpts {
	return flatrpc.ExecOpts{
		ExecFlags: execFlags,
	}
}

// TODO: This method belongs better to pkg/flatrpc, but we currently end up
// having a cyclic dependency error.
func DefaultExecOpts(cfg *mgrconfig.Config, features flatrpc.Feature, debug bool) flatrpc.ExecOpts {
	env := csource.FeaturesToFlags(features, nil)
	if debug {
		env |= flatrpc.ExecEnvDebug
	}
	if cfg.Experimental.ResetAccState {
		env |= flatrpc.ExecEnvResetState
	}
	if cfg.Experimental.DdrdMonitor {
		env |= flatrpc.ExecEnvEnableDdrdMonitor
	}
	if cfg.Cover {
		env |= flatrpc.ExecEnvSignal
	}
	sandbox, err := flatrpc.SandboxToFlags(cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	env |= sandbox

	exec := flatrpc.ExecFlagThreaded
	if !cfg.RawCover {
		exec |= flatrpc.ExecFlagDedupCover
	}
	return flatrpc.ExecOpts{
		EnvFlags:   env,
		ExecFlags:  exec,
		SandboxArg: cfg.SandboxArg,
	}
}
