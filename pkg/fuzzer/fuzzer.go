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

	// Dual-Queue Timing Exploration System
	timingScheduler *TimingScheduler

	// Unified pair evaluator for timing exploration and corpus saving decisions
	pairEvaluator *PairEvaluator

	// Dynamic threshold controller for balancing fuzzing and validation
	thresholdController *ThresholdController

	uafBootstrapDone atomic.Bool

	staticInputPool *staticInputPool

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

const raceSeedFuzzSampleRate = 0.5
const defaultRaceNormalTriageInterval = 8

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
		// RandomBaselineMode is now only a baseline marker plus a hard timing-off guard.
		if cfg.RandomBaselineMode {
			raceConfig.RandomBaselineMode = true
			// Baseline marker only; each optional mechanism has its own knob.
			cfg.EnableTimingExploration = false
			log.Logf(0, "[RANDOM-BASELINE] Timing exploration DISABLED for baseline run")
		}
		if cfg.RaceExecOnly {
			log.Logf(0, "[EXEC-ONLY] Race barrier execution keeps LOG_MODE tracing but skips pair analysis/output")
		}
		// EnableObjectLinking: default true, user can disable for ablation
		if cfg.EnableObjectLinking != nil && !*cfg.EnableObjectLinking {
			raceConfig.EnableObjectLinking = false
			log.Logf(0, "[ABLATION] Object-level program linking DISABLED (enable_object_linking=false)")
		}
		if !cfg.EnableSoloFilter {
			raceConfig.EnableSoloCache = false
			log.Logf(0, "[CLEAN-AUDIT] Solo filter DISABLED (enable_solo_filter=false); discovered pairs are persisted directly")
		}
		coverageTriageEnabled := cfg.EnableCoverageTriage != nil && *cfg.EnableCoverageTriage
		switch {
		case cfg.EnableAffinityTable != nil:
			raceConfig.EnableAffinityTable = *cfg.EnableAffinityTable
		case !cfg.EnableSoloFilter && !coverageTriageEnabled:
			raceConfig.EnableAffinityTable = false
		}
		if !raceConfig.EnableAffinityTable {
			log.Logf(0, "[CLEAN-AUDIT] Syscall affinity table DISABLED")
		}
		if raceConfig.EnableObjectLinking {
			objectLinkAttemptRatio := normalizeObjectLinkAttemptRatio(cfg.ObjectLinkAttemptRatio)
			if objectLinkAttemptRatio < 1 {
				log.Logf(0, "[OBJLINK] Barrier partner object-link attempt ratio=%.2f", objectLinkAttemptRatio)
			}
		}
		if cfg.EnableCoverageTriage != nil && !*cfg.EnableCoverageTriage {
			log.Logf(0, "[CLEAN-AUDIT] Coverage triage jobs DISABLED (enable_coverage_triage=false)")
		}
		if cfg.NoObjectKccwfNamespace {
			log.Logf(0, "[ABLATION] KCCWF partner-program namespacing ENABLED for no-object baseline")
		}
		if cfg.IsolateKccwfPartnerObjects {
			log.Logf(0, "[OBJLINK] KCCWF partner-program object isolation ENABLED before optional ObjectLinker alignment")
		}
		if cfg.EnableStateScopeGuidance {
			log.Logf(0, "[STATE-SCOPE] Program group construction ENABLED ratio=%.2f same_instance_ratio=%.2f samples=%d",
				normalizeStateScopeGuidanceRatio(cfg.StateScopeGuidanceRatio),
				normalizeStateScopeSameInstanceRatio(cfg.StateScopeSameInstanceRatio),
				normalizeStateScopePartnerSamples(cfg.StateScopePartnerSamples))
		}
		if cfg.StaticInputExploration {
			log.Logf(0, "[STATIC-INPUT] UAF input exploration will sample from frozen loaded corpus")
			if raceConfig.EnableObjectLinking {
				log.Logf(0, "[OBJLINK] Static input partner sampling will prefer semantic FS link opportunities")
			}
		}
		f.raceGroup = NewRaceGroupManager(raceConfig)

		if cfg.EnableTimingExploration {
			// Initialize Dual-Queue Timing Exploration System.
			timingConfig := DefaultTimingExplorationConfig()
			timingConfig.EnableTimingExploration = true
			if cfg.TimingExplorationQueueSize > 0 {
				timingConfig.TimingExplorationQueueSize = cfg.TimingExplorationQueueSize
			}
			if cfg.TimingExplorationRatio > 0 {
				timingConfig.TimingExplorationRatio = cfg.TimingExplorationRatio
			}
			if cfg.DelayMinMicros > 0 {
				timingConfig.DelayMinMicros = cfg.DelayMinMicros
			}
			if cfg.DelayMaxMicros > 0 {
				timingConfig.DelayMaxMicros = cfg.DelayMaxMicros
			}
			if cfg.MaxDelaysPerProgram > 0 {
				timingConfig.MaxDelaysPerProgram = cfg.MaxDelaysPerProgram
			}
			if cfg.TimingMutationStrategy != "" {
				timingConfig.TimingMutationStrategy = cfg.TimingMutationStrategy
			}
			if cfg.WidenedThresholdMicros > 0 {
				timingConfig.WidenedThresholdMicros = cfg.WidenedThresholdMicros
			}
			if cfg.MaxAttemptsPerPair > 0 {
				timingConfig.MaxAttemptsPerPair = cfg.MaxAttemptsPerPair
			}
			if cfg.MaxCorpusCountPerVarName > 0 {
				timingConfig.MaxCorpusCountPerVarName = cfg.MaxCorpusCountPerVarName
			}
			if cfg.SuccessThreshold > 0 {
				timingConfig.SuccessThreshold = cfg.SuccessThreshold
			}
			if cfg.ExecutionsPerAttempt > 0 {
				timingConfig.ExecutionsPerAttempt = cfg.ExecutionsPerAttempt
			}
			f.timingScheduler = NewTimingScheduler(
				target,
				timingConfig,
				f.raceGroup.GetVarPairRegistry(),
				rnd,
			)

			// Create unified pair evaluator for timing exploration candidates.
			evaluatorConfig := PairEvaluatorConfig{
				MaxCorpusCountPerVarName: timingConfig.MaxCorpusCountPerVarName,
				MaxTimingAttemptsPerPair: timingConfig.MaxAttemptsPerPair,
				MaxStacksPerVarName:      cfg.MaxStacksPerVarNamePair,
			}
			f.pairEvaluator = NewPairEvaluator(evaluatorConfig, f.raceGroup.GetVarPairRegistry())

			// Set corpus count checker for both scheduler and evaluator.
			if f.uaf != nil {
				f.timingScheduler.SetCorpusCountChecker(f.uaf.GetVarNamePairCount)
				f.pairEvaluator.SetCorpusCounter(f.uaf.GetVarNamePairCount)
			}
			log.Logf(0, "[TIMING] Dual-queue timing exploration initialized: queue_size=%d, ratio=%.2f, delays=%d-%dμs, max_corpus_per_varname=%d",
				timingConfig.TimingExplorationQueueSize, timingConfig.TimingExplorationRatio,
				timingConfig.DelayMinMicros, timingConfig.DelayMaxMicros, timingConfig.MaxCorpusCountPerVarName)
		} else {
			log.Logf(0, "[TIMING] Dual-queue timing exploration DISABLED")
		}
	}

	// Initialize dynamic threshold controller if enabled
	if cfg.EnableDynamicThreshold && cfg.ModeUAF {
		tcConfig := DefaultThresholdControllerConfig()
		if cfg.DynamicThresholdInitialUs > 0 {
			tcConfig.InitialThresholdUs = cfg.DynamicThresholdInitialUs
		}
		if cfg.DynamicThresholdMinUs > 0 {
			tcConfig.MinThresholdUs = cfg.DynamicThresholdMinUs
		}
		if cfg.DynamicThresholdMaxUs > 0 {
			tcConfig.MaxThresholdUs = cfg.DynamicThresholdMaxUs
		}
		if cfg.DynamicThresholdEvalSec > 0 {
			tcConfig.EvalWindowSeconds = cfg.DynamicThresholdEvalSec
		}
		tcConfig.Workdir = cfg.Workdir
		f.thresholdController = NewThresholdController(tcConfig, func() int {
			return f.ddrd.Count()
		})
		go f.thresholdController.Run(ctx.Done())
		log.Logf(0, "[THRESHOLD] Dynamic threshold controller started: init=%dμs, range=[%d, %d]μs, eval=%ds",
			tcConfig.InitialThresholdUs, tcConfig.MinThresholdUs, tcConfig.MaxThresholdUs, tcConfig.EvalWindowSeconds)
	}

	f.execQueues = newExecQueues(f)
	f.updateChoiceTable(nil)
	go f.choiceTableUpdater()
	if cfg.Debug {
		go f.logCurrentStats()
	}

	if f.timingScheduler != nil {
		stat.New("timing pending", "Pending timing exploration jobs (Phase 1 + Phase 2)",
			stat.Console, func() int {
				exploration, validation := f.timingScheduler.GetPendingJobCounts()
				return exploration + validation
			})
		stat.New("timing jobs generated", "Timing exploration jobs generated",
			stat.Console, func() int {
				return f.timingScheduler.GetStats().TotalJobsGenerated
			})
		stat.New("timing jobs completed", "Timing exploration jobs completed",
			stat.Console, func() int {
				return f.timingScheduler.GetStats().TotalJobsCompleted
			})
		stat.New("timing obj jobs", "Timing jobs generated from ObjLinked discoveries",
			stat.Console, func() int {
				return f.timingScheduler.GetStats().ObjectLinkedJobsGenerated
			})
		stat.New("timing lowpri pending", "Low-priority timing validation jobs pending",
			stat.Console, func() int {
				return f.timingScheduler.GetLowPriorityPendingJobCount()
			})
	}

	// Register ddrd.Store-based stats for source tracking
	stat.New("ddrd pairs total", "Total unique pairs in ddrd.Store",
		stat.Console, stat.Graph("ddrd"), func() int {
			return f.ddrd.Count()
		})
	stat.New("ddrd pairs fuzz", "Pairs from normal fuzzing",
		stat.Console, stat.Graph("ddrd"), func() int {
			return f.ddrd.CountFromFuzz()
		})
	stat.New("ddrd pairs timing", "Pairs from timing exploration (validated)",
		stat.Console, stat.Graph("ddrd"), func() int {
			return f.ddrd.CountFromTiming()
		})
	stat.New("ddrd varnames fuzz", "Varnames from normal fuzzing",
		stat.Console, stat.Graph("ddrd"), func() int {
			return f.ddrd.CountVarnamesFromFuzz()
		})
	stat.New("ddrd varnames timing", "Varnames from timing exploration",
		stat.Console, stat.Graph("ddrd"), func() int {
			return f.ddrd.CountVarnamesFromTiming()
		})

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
	}
	if fuzzer.uaf != nil {
		// Set the smash queue for uaf mode to submit barrier requests
		fuzzer.uaf.setQueue(ret.smashQueue)
		sources = append(sources,
			queue.Alternate(ret.smashQueue, skipQueue),
			ret.candidateQueue,
		)

		// Add timing exploration source if enabled
		if fuzzer.timingScheduler != nil && fuzzer.timingScheduler.Config().EnableTimingExploration {
			// Poll timing exploration before the continuously replenished triage
			// queue so Phase 1/2 jobs cannot starve behind triage backlog.
			// We still limit it to the configured ratio by only polling it every
			// Nth scheduling pass.
			timingEvery := 10 // Default: run 1 in 10 scheduling passes
			if fuzzer.timingScheduler.Config().TimingExplorationRatio > 0 {
				timingEvery = int(1.0 / fuzzer.timingScheduler.Config().TimingExplorationRatio)
				if timingEvery < 1 {
					timingEvery = 1
				}
			}
			sources = append(sources,
				queue.Periodic(queue.Callback(fuzzer.genTimingExploration), timingEvery),
			)
		}

		sources = append(sources,
			fuzzer.raceNormalTriageSource(ret.triageQueue),
			queue.Callback(fuzzer.genFuzz),
		)

	} else {
		sources = append(sources, ret.candidateQueue, ret.triageQueue)
		sources = append(sources,
			queue.Callback(fuzzer.genFuzz),
		)
	}

	// Sources are listed in the order, in which they will be polled.
	ret.source = queue.Order(sources...)
	return ret
}

func (fuzzer *Fuzzer) raceNormalTriageSource(source queue.Source) queue.Source {
	if fuzzer == nil || fuzzer.Config == nil || !fuzzer.Config.ModeUAF {
		return source
	}
	interval := fuzzer.Config.RaceNormalTriageInterval
	if interval <= 0 {
		interval = defaultRaceNormalTriageInterval
	}
	if interval <= 1 {
		return source
	}
	log.Logf(0, "[THROUGHPUT] Normal syzkaller triage polled every %d scheduler passes in race mode", interval)
	return queue.Periodic(source, interval)
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
	if req != nil && (flags&ProgBarrier != 0 || req.Barrier) {
		fuzzer.enableRaceExecCollection(req)
	}
	req.OnDone(func(req *queue.Request, res *queue.Result) bool {
		return fuzzer.processResult(req, res, flags, attempt)
	})
}

func (fuzzer *Fuzzer) applyNormalTimingThreshold(req *queue.Request) {
	if req == nil || req.IsTimingExploration || req.TimingThresholdUs > 0 {
		return
	}
	req.TimingThresholdUs = fuzzer.currentNormalTimingThreshold()
}

func (fuzzer *Fuzzer) currentNormalTimingThreshold() int64 {
	if fuzzer == nil {
		return 0
	}
	if fuzzer.thresholdController != nil {
		return fuzzer.thresholdController.CurrentThreshold()
	}
	if fuzzer.Config == nil || fuzzer.Config.NormalThresholdMicros <= 0 {
		return 0
	}
	return fuzzer.Config.NormalThresholdMicros
}

func (fuzzer *Fuzzer) currentWidenedTimingThreshold() int64 {
	if fuzzer == nil {
		return 0
	}

	var widened int64
	if fuzzer.timingScheduler != nil {
		widened = fuzzer.timingScheduler.Config().WidenedThresholdMicros
	}

	normal := fuzzer.currentNormalTimingThreshold()
	if normal <= 0 {
		return widened
	}

	// In dynamic-threshold mode, keep timing exploration tied to the current
	// normal threshold, but do not let Phase 1 collapse below the configured
	// widened threshold. This preserves a stable discovery window even when the
	// normal threshold temporarily shrinks to focus validation effort.
	if fuzzer.thresholdController != nil {
		dynamicWidened := normal * 8
		if dynamicWidened < normal {
			dynamicWidened = normal
		}
		if widened > 0 && dynamicWidened < widened {
			dynamicWidened = widened
		}
		return dynamicWidened
	}

	if widened > 0 {
		return widened
	}
	return normal
}

func inheritTimingThreshold(req, parent *queue.Request) {
	if req == nil || req.TimingThresholdUs > 0 || parent == nil || parent.TimingThresholdUs <= 0 {
		return
	}
	req.TimingThresholdUs = parent.TimingThresholdUs
}

func (fuzzer *Fuzzer) enqueue(executor queue.Executor, req *queue.Request, flags ProgFlags, attempt int) {
	fuzzer.prepare(req, flags, attempt)
	executor.Submit(req)
}

func (fuzzer *Fuzzer) processResult(req *queue.Request, res *queue.Result, flags ProgFlags, attempt int) bool {
	if log.V(3) {
		var signalLen, coverLen int
		var status any = "<nil>"
		if res != nil && res.Info != nil {
			status = res.Status
			for _, call := range res.Info.Calls {
				if call != nil {
					signalLen += len(call.Signal)
					coverLen += len(call.Cover)
				}
			}
		} else if res != nil {
			status = res.Status
		}
		log.Logf(3, "[DEBUG-RESULT] processResult: flags=%d isCandidate=%v isBarrier=%v status=%v signalLen=%d coverLen=%d attempt=%d corpus=%d",
			flags, flags&progCandidate != 0, flags == ProgBarrier, status, signalLen, coverLen, attempt, len(fuzzer.Config.Corpus.Programs()))
	}

	// Check if VM was restarted and clear its history buffer
	if res != nil && res.Status == queue.Restarted && fuzzer.uaf != nil {
		fuzzer.Logf(1, "[history] VM %d restarted, clearing history buffer", res.Executor.VM)
		fuzzer.uaf.clearVMHistory(res.Executor.VM)
	}

	if fuzzer.uaf != nil && flags&ProgBarrier != 0 {
		if fuzzer.Config.RaceExecOnly {
			newCover := fuzzer.uaf.recordExecution(req, res)
			if len(newCover) > 0 && len(req.BarrierPrograms) >= 2 {
				if fuzzer.Config.EnableCoverageTriage != nil && *fuzzer.Config.EnableCoverageTriage {
					fuzzer.triggerCoverageTriage(req, res, newCover)
				}
			}
			return true
		}
		// Check if this is a timing exploration result
		isTimingExploration := req.IsTimingExploration && req.TimingExplorationInfo != nil
		if isTimingExploration {
			// Timing exploration: let processTimingExplorationResult handle pair tracking
			// - Phase 1: Don't add pairs (just discover candidates)
			// - Phase 2: Add pairs with SourceTiming only if validated
			fuzzer.processTimingExplorationResult(req, res)
		} else {
			// Normal fuzzing: add pairs with SourceFuzz
			if res.Ddrd != nil && len(res.Ddrd.UAFPairs) > 0 {
				// 检查是否有新的 pairs（通过检查是否被添加到 ddrd store）
				newPairs := fuzzer.ddrd.AddWithSource(res.Ddrd, ddrd.SourceFuzz)
				if len(newPairs) > 0 {
					fuzzer.handleDiscoveredBarrierPairs(req, res, newPairs, SourceFuzz)
				}
			}
		}
		// 记录执行并检测新覆盖率（pair 级别）
		newCover := fuzzer.uaf.recordExecution(req, res)
		if len(newCover) > 0 && len(req.BarrierPrograms) >= 2 {
			if fuzzer.Config.EnableCoverageTriage != nil && *fuzzer.Config.EnableCoverageTriage {
				// 有新覆盖率，触发 coverage triage job
				fuzzer.triggerCoverageTriage(req, res, newCover)
			}
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
	Debug                 bool
	Corpus                *corpus.Corpus
	Logf                  func(level int, msg string, args ...interface{})
	Snapshot              bool
	Coverage              bool
	FaultInjection        bool
	Comparisons           bool
	Collide               bool
	EnabledCalls          map[*prog.Syscall]bool
	NoMutateCalls         map[int]bool
	FetchRawCover         bool
	NewInputFilter        func(call string) bool
	PersistUAFCorpusEntry func(*UAFCorpusEntry) error
	PatchTest             bool
	ModeKFuzzTest         bool
	ModeUAF               bool
	RaceExecOnly          bool
	BarrierMode           bool
	BarrierMask           uint64
	ThreadBarrier         bool    // Enable thread-barrier mode (intra-object race detection)
	ThreadBarrierRatio    float64 // Fraction of barrier executions using thread-barrier (default: 0.2)
	// History buffer configuration for race mode.
	HistoryBufferSize            int // Size of per-VM history buffer (default: 1000)
	DisableUAFHistory            bool
	NewVarNamePairHistory        int // Records to save for new VarName pair (default: 1000)
	NewStackHistory              int // Records to save for new stack (default: 100)
	MaxStacksPerVarNamePair      int // Max unique stack pairs per VarName pair (default: 20)
	NewVarNamePairAffinityWeight int // Affinity weight for new VarName pair (default: 5)
	NewStackAffinityWeight       int // Affinity weight for new stack (default: 1)
	// A/B Testing
	RandomBaselineMode bool // Baseline marker; forces timing exploration off but keeps other mechanisms intact

	// StaticInputExploration makes race input exploration sample concurrent program
	// groups from a frozen loaded-corpus pool. Normal syzkaller mutation/generation
	// is left unchanged unless this mode is explicitly enabled.
	StaticInputExploration bool
	StaticInputSeed        int64

	// EnableObjectLinking enables resource-aware object linking (ObjectLinker V2).
	// Defaults to true. Set to false for ablation experiments.
	EnableObjectLinking *bool
	// ObjectLinkAttemptRatio controls how often barrier partner selection actually
	// attempts ObjectLinker V2 when object linking is enabled. Values in (0,1]
	// are honored; other values fall back to the default 1.0.
	ObjectLinkAttemptRatio float64

	// NoObjectKccwfNamespace rewrites kccwf partner-program object names when
	// object linking is disabled, avoiding fixed-path same-object bias in
	// no-object ablation experiments.
	NoObjectKccwfNamespace bool
	// IsolateKccwfPartnerObjects rewrites kccwf partner-program object names
	// before optional ObjectLinker alignment, so fs object sharing is caused by
	// ObjectLinker rather than fixed corpus names.
	IsolateKccwfPartnerObjects bool

	// EnableStateScopeGuidance constructs barrier partner programs by increasing
	// the probability that programs perturb overlapping kernel state scopes. Exact
	// object alignment becomes one low-frequency operator rather than the whole
	// input construction policy.
	EnableStateScopeGuidance bool
	// StateScopeGuidanceRatio controls how often barrier partner selection uses
	// state-scope guidance. Values in (0,1] are honored; other values fall back
	// to 1.0 when guidance is enabled.
	StateScopeGuidanceRatio float64
	// StateScopeSameInstanceRatio is the operator budget for exact same-instance
	// construction within state-scope guidance. Zero disables this operator.
	StateScopeSameInstanceRatio float64
	// StateScopePartnerSamples controls how many candidate partners are sampled
	// when selecting a guided partner from the frozen/static input pool.
	StateScopePartnerSamples int

	// EnableCoverageTriage controls pair-level coverage triage jobs in race mode.
	// Nil keeps the paper/default path disabled.
	EnableCoverageTriage *bool
	// RaceNormalTriageInterval throttles ordinary syzkaller coverage triage in
	// race mode so deflake/minimization cannot starve barrier fuzzing.
	RaceNormalTriageInterval int
	// EnableSoloFilter controls the legacy solo re-execution filter in race mode.
	EnableSoloFilter bool
	// EnableAffinityTable controls the legacy syscall affinity table in race mode.
	// Nil enables it only when a legacy producer (solo filter or coverage triage) is enabled.
	EnableAffinityTable *bool

	// ======== Dual-Queue Timing Exploration Configuration ========
	// EnableTimingExploration enables the timing exploration queue
	EnableTimingExploration bool
	// TimingExplorationQueueSize is the max size of the timing exploration queue
	TimingExplorationQueueSize int
	// TimingExplorationRatio is the fraction of executions for timing exploration (0.0-1.0)
	TimingExplorationRatio float64
	// DelayMinMicros is the minimum delay in microseconds for syz_delay()
	// or barrier start-delay timing exploration.
	DelayMinMicros int64
	// DelayMaxMicros is the maximum delay in microseconds for syz_delay()
	// or barrier start-delay timing exploration.
	DelayMaxMicros int64
	// MaxDelaysPerProgram limits syz_delay() calls per program
	MaxDelaysPerProgram int
	// TimingMutationStrategy: "random", "targeted", "binary_search", "timediff", "start_delay"
	TimingMutationStrategy string
	// NormalThresholdMicros overrides the default 10ms threshold for barrier/solo DDRD requests.
	// 0 uses the executor default.
	NormalThresholdMicros int64
	// WidenedThresholdMicros is the widened timing threshold for exploration queue (microseconds).
	// In dynamic-threshold mode this acts as the minimum Phase 1 discovery window.
	// Current MRPFuzz experiment configs set 20000.
	WidenedThresholdMicros int64
	// MaxAttemptsPerPair is the maximum number of timing exploration attempts per unique pair
	MaxAttemptsPerPair int
	// MaxCorpusCountPerVarName: skip timing exploration if VarName pair has this many corpus entries
	MaxCorpusCountPerVarName int
	// SuccessThreshold is the trigger rate threshold to consider exploration successful (0.0-1.0)
	SuccessThreshold float64
	// ExecutionsPerAttempt is how many times to execute each delay plan
	ExecutionsPerAttempt int

	// ======== Dynamic Threshold Configuration ========
	// EnableDynamicThreshold enables dynamic threshold adjustment based on
	// fuzzer/validator supply-demand balancing.
	EnableDynamicThreshold bool
	// DynamicThresholdInitialUs is the starting threshold (microseconds).
	// Generic fallback: 1000. Current MRPFuzz experiment configs set 2500.
	DynamicThresholdInitialUs int64
	// DynamicThresholdMinUs is the minimum threshold (microseconds).
	// Generic fallback: 50. Current MRPFuzz experiment configs set 500.
	DynamicThresholdMinUs int64
	// DynamicThresholdMaxUs is the maximum threshold (microseconds).
	// Generic fallback: 50000. Current MRPFuzz experiment configs set 10000.
	DynamicThresholdMaxUs int64
	// DynamicThresholdEvalSec is how often to evaluate and adjust (seconds). Paper default: 30.
	DynamicThresholdEvalSec int
	// Workdir is used for the shared state file between fuzzer and validator.
	Workdir string
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

	if uafReady && fuzzer.Config.StaticInputExploration {
		return fuzzer.genStaticInputBarrierRequest()
	}

	rnd := fuzzer.rand()
	if uafReady && (corpusLen == 0 || rnd.Float64() < raceSeedFuzzSampleRate) {
		if req := fuzzer.uaf.sampleBarrierRequest(rnd); req != nil {
			return req
		}
	}

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

func (fuzzer *Fuzzer) genStaticInputBarrierRequest() *queue.Request {
	p := fuzzer.chooseStaticInputProgram()
	if p == nil {
		fuzzer.Logf(0, "[STATIC-INPUT] frozen input pool is empty")
		return nil
	}
	req := &queue.Request{
		Prog:     p,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecFuzz,
	}
	fuzzer.applyBarrier(req)
	flags := ProgFlags(0)
	if req.Barrier {
		flags |= ProgBarrier
	}
	fuzzer.prepare(req, flags, 0)
	return req
}

// genTimingExploration generates a timing exploration request.
// Two-phase strategy:
// - Phase 1 (PhaseWidenedDiscovery): Use widened threshold to discover candidate pairs (don't save)
// - Phase 2 (PhaseValidation): Insert delays, use NORMAL threshold to validate (save if successful)
func (fuzzer *Fuzzer) genTimingExploration() *queue.Request {
	if fuzzer.timingScheduler == nil {
		return nil
	}

	// Try to get the next timing exploration job
	job := fuzzer.timingScheduler.GetNextJob()
	if job == nil {
		// No jobs available, fall back to regular fuzzing
		return nil
	}

	// Get thresholds.
	widenedThreshold := fuzzer.currentWidenedTimingThreshold()
	normalThreshold := fuzzer.currentNormalTimingThreshold()

	// Determine phase based on whether timing controls exist.
	// Phase 1: no timing control, use widened threshold (discovery).
	// Phase 2: syscall-local delays or barrier start delays, use normal threshold.
	phase := queue.PhaseWidenedDiscovery
	threshold := widenedThreshold
	if len(job.DelayPlan) > 0 || len(job.StartDelays) > 0 {
		phase = queue.PhaseValidation
		threshold = normalThreshold // Use normal threshold for validation
	}

	phaseStr := "DISCOVERY"
	if phase == queue.PhaseValidation {
		phaseStr = "VALIDATION"
	}

	log.Logf(1, "[TIMING-EXPLORE] Phase=%s, attempt=%d, delays=%d, start_delays=%v, pair=0x%x/0x%x, threshold=%dus",
		phaseStr, job.AttemptNumber, len(job.DelayPlan), job.StartDelays,
		job.TargetPair.UseAccessName, job.TargetPair.FreeAccessName, threshold)

	// Convert delay plan to queue format
	var delayInsertions []queue.DelayInsertion
	for _, d := range job.DelayPlan {
		delayInsertions = append(delayInsertions, queue.DelayInsertion{
			ProgIdx:     d.ProgIdx,
			BeforeCall:  d.BeforeCall,
			DelayMicros: d.DelayMicros,
		})
	}

	// Create the request
	req := &queue.Request{
		Prog:                job.Prog1,
		ExecOpts:            flatrpc.ExecOpts{},
		Stat:                fuzzer.statExecFuzz,
		TimingThresholdUs:   threshold,
		IsTimingExploration: true,
		ObjectLink:          job.ObjectLink,
		TimingExplorationInfo: &queue.TimingExplorationInfo{
			Phase:          phase,
			TargetPair:     job.TargetPair,
			AttemptNumber:  job.AttemptNumber,
			DelayPlan:      delayInsertions,
			StartDelays:    append([]int64(nil), job.StartDelays...),
			OriginalProg1:  job.OriginalProg1,
			OriginalProg2:  job.OriginalProg2,
			CandidatePairs: job.CandidatePairs, // Pass candidate pairs from Phase 1
			ObjectLink:     job.ObjectLink,
			LowPriority:    job.LowPriority,
			PriorityReason: job.PriorityReason,
		},
	}

	// Apply barrier mode for the timing exploration
	if fuzzer.uafReady() && fuzzer.Config.BarrierMode {
		mask := fuzzer.Config.BarrierMask
		if mask != 0 {
			programs := []*prog.Prog{job.Prog1, job.Prog2}

			// Thread-barrier for timing exploration
			if fuzzer.Config.ThreadBarrier && len(job.StartDelays) == 0 {
				ratio := fuzzer.Config.ThreadBarrierRatio
				if ratio <= 0 {
					ratio = 0.2
				}
				rnd := fuzzer.rand()
				if rnd.Float64() < ratio {
					merged := prog.MergePrograms(programs[0], programs[1])
					lastA := len(programs[0].Calls) - 1
					lastB := len(programs[0].Calls) + len(programs[1].Calls) - 1
					if lastA >= 0 && lastA < len(merged.Calls) {
						merged.Calls[lastA].Props.Async = true
					}
					if lastB >= 0 && lastB < len(merged.Calls) {
						merged.Calls[lastB].Props.Async = true
					}
					req.Prog = merged
					req.Barrier = true
					req.ThreadBarrier = true
					req.BarrierPrograms = programs
					req.ExecOpts.ExecFlags |= flatrpc.ExecFlagThreaded
					fuzzer.enableRaceExecCollection(req)
					fuzzer.enableBarrierCoverage(req)

					flags := ProgFlags(ProgBarrier)
					fuzzer.prepare(req, flags, 0)
					fuzzer.timingScheduler.RecordJobExecution(job)
					return req
				}
			}

			// Default: multi-process barrier
			req.SetBarrier(mask)
			req.ThreadBarrier = false
			if err := req.SetBarrierPrograms(programs); err != nil {
				log.Logf(0, "[TIMING-EXPLORE] Failed to set barrier programs: %v", err)
				return nil
			}
			if len(job.StartDelays) != 0 {
				if err := req.SetBarrierStartDelays(job.StartDelays); err != nil {
					log.Logf(0, "[TIMING-EXPLORE] Failed to set barrier start delays: %v", err)
					return nil
				}
			}
			fuzzer.enableBarrierCoverage(req)
			fuzzer.enableRaceExecCollection(req)
			req.ExecOpts.ExecFlags &^= flatrpc.ExecFlagThreaded
		}
	}

	flags := ProgFlags(ProgBarrier)
	fuzzer.prepare(req, flags, 0)

	// Record timing exploration metrics
	fuzzer.timingScheduler.RecordJobExecution(job)

	return req
}

const timingLowPriorityCandidateThreshold = 128
const timingStartDelayCandidateLimit = 16

func timingValidationPriority(triggeredTarget bool, candidateCount int) (bool, string) {
	if triggeredTarget || candidateCount <= timingLowPriorityCandidateThreshold {
		return false, ""
	}
	return true, fmt.Sprintf("target_not_triggered_large_candidates_%d", candidateCount)
}

func timingStartDelayTargets(targetPair *ddrd.MayUAFPair, candidatePairs []*ddrd.MayUAFPair) []*ddrd.MayUAFPair {
	targets := make([]*ddrd.MayUAFPair, 0, len(candidatePairs)+1)
	seen := make(map[uint64]struct{})
	for _, pair := range candidatePairs {
		if pair == nil {
			continue
		}
		id := pair.UAFPairID()
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		targets = append(targets, pair)
	}
	if len(targets) == 0 && targetPair != nil {
		targets = append(targets, targetPair)
	}
	sort.SliceStable(targets, func(i, j int) bool {
		return targets[i].TimeDiff < targets[j].TimeDiff
	})
	return targets
}

func objectLinkProvenanceString(p queue.ObjectLinkProvenance) string {
	if p.Linked() {
		return fmt.Sprintf("linked(unified=%d exact=%d cross=%d)", p.Unified, p.Exact, p.CrossFamily)
	}
	if p.Attempted {
		return "attempted-no-link"
	}
	return "none"
}

func timingPendingString(ts *TimingScheduler) string {
	if ts == nil {
		return "pending=unknown"
	}
	exploration, validation := ts.GetPendingJobCounts()
	return fmt.Sprintf("pending=%d/%d lowpri=%d", exploration, validation, ts.GetLowPriorityPendingJobCount())
}

// processTimingExplorationResult handles the result of a timing exploration job.
// Two-phase strategy:
// - Phase 1 (Discovery): Found candidates with widened threshold → enqueue for Phase 2 (don't save)
// - Phase 2 (Validation): Confirmed with normal threshold + delays → SAVE programs
func (fuzzer *Fuzzer) processTimingExplorationResult(req *queue.Request, res *queue.Result) {
	info := req.TimingExplorationInfo
	if info == nil {
		return
	}

	targetPair := info.TargetPair
	pairsFound := 0

	// Check if we found any pairs in this execution
	if res.Ddrd != nil && len(res.Ddrd.UAFPairs) > 0 {
		pairsFound = len(res.Ddrd.UAFPairs)
	}

	// Check if we successfully triggered the target pair
	triggeredTarget := false
	if targetPair != nil && res.Ddrd != nil {
		for _, p := range res.Ddrd.UAFPairs {
			if p.UseAccessName == targetPair.UseAccessName &&
				p.FreeAccessName == targetPair.FreeAccessName {
				triggeredTarget = true
				break
			}
		}
	}

	// Build delay description for logging
	var delayDesc string
	for i, d := range info.DelayPlan {
		if i > 0 {
			delayDesc += ", "
		}
		delayDesc += fmt.Sprintf("prog%d[%d]=%dμs", d.ProgIdx, d.BeforeCall, d.DelayMicros)
	}
	controlDesc := fmt.Sprintf("delays=[%s]", delayDesc)
	if len(info.StartDelays) != 0 {
		controlDesc = fmt.Sprintf("start_delays=%v", info.StartDelays)
	}
	startDelayMode := len(info.StartDelays) != 0

	switch info.Phase {
	case queue.PhaseWidenedDiscovery:
		// Phase 1: Discovery with widened threshold
		// Collect candidate pairs (new ones we haven't seen before) - don't add them yet!
		var candidatePairs []*ddrd.MayUAFPair
		if res.Ddrd != nil && len(res.Ddrd.UAFPairs) > 0 {
			for _, p := range res.Ddrd.UAFPairs {
				if fuzzer.ddrd.IsNewPair(p) {
					candidatePairs = append(candidatePairs, p)
				}
			}
		}

		// Don't save programs yet, just log and enqueue for validation
		if len(candidatePairs) > 0 || triggeredTarget {
			lowPriority, priorityReason := timingValidationPriority(triggeredTarget, len(candidatePairs))
			log.Logf(0, "[TIMING-EXPLORE-PHASE1] CANDIDATES FOUND: attempt=%d, target=0x%x/0x%x, candidates=%d, total=%d, triggered=%v, obj=%s, lowpri=%v %s",
				info.AttemptNumber, targetPair.UseAccessName, targetPair.FreeAccessName,
				len(candidatePairs), pairsFound, triggeredTarget,
				objectLinkProvenanceString(info.ObjectLink), lowPriority, priorityReason)

			// Enqueue for Phase 2 validation with timing controls.
			if fuzzer.timingScheduler != nil && len(req.BarrierPrograms) >= 2 {
				if isStartDelayTimingStrategy(fuzzer.timingScheduler.Config().TimingMutationStrategy) {
					targets := timingStartDelayTargets(targetPair, candidatePairs)
					if len(targets) > timingStartDelayCandidateLimit {
						targets = targets[:timingStartDelayCandidateLimit]
					}
					for _, validationTarget := range targets {
						fuzzer.timingScheduler.EnqueueForValidationWithProvenance(
							req.BarrierPrograms[0],
							req.BarrierPrograms[1],
							validationTarget,
							nil,
							info.ObjectLink,
							lowPriority,
							priorityReason,
						)
					}
					log.Logf(0, "[TIMING-EXPLORE-PHASE1] start-delay validation targets=%d/%d",
						len(targets), len(candidatePairs))
				} else {
					// Pass candidate pairs to scheduler for validation.
					fuzzer.timingScheduler.EnqueueForValidationWithProvenance(
						req.BarrierPrograms[0],
						req.BarrierPrograms[1],
						targetPair,
						candidatePairs,
						info.ObjectLink,
						lowPriority,
						priorityReason,
					)
				}
			}
		} else {
			log.Logf(1, "[TIMING-EXPLORE-PHASE1] No candidates: attempt=%d, target=0x%x/0x%x, pairs=%d, obj=%s",
				info.AttemptNumber, targetPair.UseAccessName, targetPair.FreeAccessName,
				pairsFound, objectLinkProvenanceString(info.ObjectLink))
		}

	case queue.PhaseValidation:
		// Phase 2: Validation with normal threshold + timing controls.
		// For syscall-delay strategies, retain legacy Phase 1 candidates.
		// For start-delay resampling, require this execution to re-observe pairs.
		// Also check for any new pairs discovered in this execution
		var candidatePairs []*ddrd.MayUAFPair
		if !startDelayMode {
			candidatePairs = info.CandidatePairs // Pairs from Phase 1
		}

		// Check if Phase 2 also discovered new pairs not in Phase 1 candidates
		if res.Ddrd != nil && len(res.Ddrd.UAFPairs) > 0 {
			for _, p := range res.Ddrd.UAFPairs {
				if fuzzer.ddrd.IsNewPair(p) {
					// Check if this pair is already in Phase 1 candidates
					found := false
					for _, cp := range candidatePairs {
						if cp.UAFPairID() == p.UAFPairID() {
							found = true
							break
						}
					}
					if !found {
						candidatePairs = append(candidatePairs, p)
					}
				}
			}
		}

		// Filter candidates using PairEvaluator before saving
		// This prevents wasting resources on VarName pairs that already have enough corpus entries
		originalCount := len(candidatePairs)
		if fuzzer.pairEvaluator != nil && len(candidatePairs) > 0 {
			candidatePairs, _ = fuzzer.pairEvaluator.FilterCandidates(candidatePairs)
			if filteredOut := originalCount - len(candidatePairs); filteredOut > 0 {
				log.Logf(1, "[TIMING-EXPLORE-PHASE2] Filtered %d/%d candidates (corpus limit reached)",
					filteredOut, originalCount)
			}
		}

		// NOW we save programs if successful (have candidates or triggered target)
		if len(candidatePairs) > 0 || triggeredTarget {
			log.Logf(0, "[TIMING-EXPLORE-PHASE2-SUCCESS] VALIDATED with timing control: attempt=%d, target=0x%x/0x%x, triggered=%v, new_pairs=%d, obj=%s, lowpri=%v %s, %s, %s",
				info.AttemptNumber, targetPair.UseAccessName, targetPair.FreeAccessName,
				triggeredTarget, len(candidatePairs), objectLinkProvenanceString(info.ObjectLink),
				info.LowPriority, info.PriorityReason,
				timingPendingString(fuzzer.timingScheduler), controlDesc)

			// NOTE: Do NOT save to normal corpus here.
			// Programs with syz_delay calls would pollute normal corpus and waste
			// execution time on usleep during regular fuzzing mutations.
			// The full program group is saved to the race corpus via
			// handleDiscoveredBarrierPairs, which preserves Programs,
			// ReplayPlan.DelaysMicros, Pairs, and ReplayHistory.

			// Add validated pairs to the store with timing source and persist them.
			if len(candidatePairs) > 0 {
				for _, p := range candidatePairs {
					fuzzer.ddrd.AddPairWithSource(p, ddrd.SourceTiming)
				}
				fuzzer.handleDiscoveredBarrierPairs(req, res, candidatePairs, SourceTiming)
			}

			// Report success to timing scheduler
			if fuzzer.timingScheduler != nil {
				result := &TimingExplorationResult{
					Job: &TimingExplorationJob{
						TargetPair:     targetPair,
						AttemptNumber:  info.AttemptNumber,
						ObjectLink:     info.ObjectLink,
						LowPriority:    info.LowPriority,
						PriorityReason: info.PriorityReason,
					},
					TriggeredNewPairs: true,
					NewPairs:          candidatePairs,
					SuccessRate:       1.0,
				}
				fuzzer.timingScheduler.OnJobCompleted(result)
			}
		} else {
			log.Logf(1, "[TIMING-EXPLORE-PHASE2-FAIL] Not validated with timing control: attempt=%d, target=0x%x/0x%x, pairs=%d, obj=%s, %s, %s",
				info.AttemptNumber, targetPair.UseAccessName, targetPair.FreeAccessName,
				pairsFound, objectLinkProvenanceString(info.ObjectLink),
				timingPendingString(fuzzer.timingScheduler), controlDesc)

			// Report failure to timing scheduler
			if fuzzer.timingScheduler != nil {
				result := &TimingExplorationResult{
					Job: &TimingExplorationJob{
						TargetPair:     targetPair,
						AttemptNumber:  info.AttemptNumber,
						ObjectLink:     info.ObjectLink,
						LowPriority:    info.LowPriority,
						PriorityReason: info.PriorityReason,
					},
					TriggeredNewPairs: false,
					SuccessRate:       0.0,
				}
				fuzzer.timingScheduler.OnJobCompleted(result)
			}
		}
	}
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
	fuzzer.applyNormalTimingThreshold(req)
	programs := fuzzer.buildBarrierPrograms(req, mask)

	// Thread-barrier: merge two programs into one, execute with threads sharing fd table.
	// This allows detecting intra-object races (e.g., same hdev instance).
	if fuzzer.Config.ThreadBarrier && len(programs) >= 2 {
		ratio := fuzzer.Config.ThreadBarrierRatio
		if ratio <= 0 {
			ratio = 0.2
		}
		rnd := fuzzer.rand()
		if rnd.Float64() < ratio {
			merged := prog.MergePrograms(programs[0], programs[1])
			// Mark the last call of each sub-program as Async for concurrent execution
			lastA := len(programs[0].Calls) - 1
			lastB := len(programs[0].Calls) + len(programs[1].Calls) - 1
			if lastA >= 0 && lastA < len(merged.Calls) {
				merged.Calls[lastA].Props.Async = true
			}
			if lastB >= 0 && lastB < len(merged.Calls) {
				merged.Calls[lastB].Props.Async = true
			}
			req.Prog = merged
			req.Barrier = true
			req.ThreadBarrier = true
			req.BarrierPrograms = programs // Preserve for soloFilter
			req.ExecOpts.ExecFlags |= flatrpc.ExecFlagThreaded
			fuzzer.enableRaceExecCollection(req)
			fuzzer.enableBarrierCoverage(req)
			fuzzer.Logf(2, "thread-barrier: merged %d+%d calls, async at [%d,%d]",
				len(programs[0].Calls), len(programs[1].Calls), lastA, lastB)
			return
		}
	}

	// Default: multi-process barrier mode
	fuzzer.enableBarrierCoverage(req)
	fuzzer.enableRaceExecCollection(req)
	req.ExecOpts.ExecFlags &^= flatrpc.ExecFlagThreaded
	req.ThreadBarrier = false
	if err := req.SetBarrierPrograms(programs); err != nil {
		fuzzer.Logf(0, "failed to assign barrier programs: %v", err)
		req.SetBarrier(0)
	}
}

func (fuzzer *Fuzzer) enableRaceExecCollection(req *queue.Request) {
	if fuzzer == nil || fuzzer.Config == nil || req == nil {
		return
	}
	if fuzzer.Config.RaceExecOnly {
		req.ExecOpts.ExecFlags &^= flatrpc.ExecFlagCollectDdrdUaf
		req.ExecOpts.ExecFlags |= flatrpc.ExecFlagCollectDdrdRace
		return
	}
	req.ExecOpts.ExecFlags |= flatrpc.ExecFlagCollectDdrdUaf
	req.ExecOpts.ExecFlags &^= flatrpc.ExecFlagCollectDdrdRace
}

func (fuzzer *Fuzzer) enableBarrierCoverage(req *queue.Request) {
	if fuzzer == nil || fuzzer.Config == nil || req == nil {
		return
	}
	if fuzzer.Config.EnableCoverageTriage != nil && *fuzzer.Config.EnableCoverageTriage {
		req.ExecOpts.ExecFlags |= flatrpc.ExecFlagCollectCover
	}
}

func (fuzzer *Fuzzer) buildBarrierPrograms(req *queue.Request, mask uint64) []*prog.Prog {
	count := bits.OnesCount64(mask)
	if count == 0 {
		return nil
	}
	req.ObjectLink = queue.ObjectLinkProvenance{}

	programs := make([]*prog.Prog, count)
	programs[0] = req.Prog
	if count == 1 {
		return programs
	}

	rnd := fuzzer.rand()
	objectLinkAttemptRatio := normalizeObjectLinkAttemptRatio(fuzzer.Config.ObjectLinkAttemptRatio)
	stateScopeGuidanceRatio := normalizeStateScopeGuidanceRatio(fuzzer.Config.StateScopeGuidanceRatio)
	for i := 1; i < count; i++ {
		var objectLinker *ObjectLinker
		if fuzzer.raceGroup != nil {
			objectLinker = fuzzer.raceGroup.GetObjectLinker()
		}
		useStateScope := fuzzer.Config.EnableStateScopeGuidance &&
			(stateScopeGuidanceRatio >= 1 || rnd.Float64() < stateScopeGuidanceRatio)
		var stateScopeDecision stateScopeDecision
		attemptObjectLink := !useStateScope && objectLinker != nil &&
			(objectLinkAttemptRatio >= 1 || rnd.Float64() < objectLinkAttemptRatio)
		var candidate *prog.Prog
		if useStateScope {
			candidate, stateScopeDecision = fuzzer.chooseStateScopePartnerProgram(req.Prog, rnd)
			if candidate == nil {
				useStateScope = false
				attemptObjectLink = objectLinker != nil &&
					(objectLinkAttemptRatio >= 1 || rnd.Float64() < objectLinkAttemptRatio)
			}
		}
		if candidate == nil {
			candidate = fuzzer.chooseBarrierPartnerProgram(rnd)
			if attemptObjectLink {
				candidate = fuzzer.chooseObjectLinkPartnerProgram(req.Prog, rnd)
			}
		}
		if candidate == nil {
			programs[i] = req.Prog.Clone()
			continue
		}
		partner := candidate.Clone()
		if fuzzer.Config.IsolateKccwfPartnerObjects {
			partner = applyKccwfPartnerNamespace(partner, randomKccwfNamespaceSlot(rnd))
		}
		// Apply Object-Level Linking V2 to ensure shared kernel objects
		if useStateScope {
			fuzzer.recordStateScopeDecision(stateScopeDecision)
		}
		if useStateScope && stateScopeDecision.Operator == stateScopeOperatorSameInstance && objectLinker != nil {
			req.ObjectLink.Attempted = true
			var result objectLinkResult
			partner, result = objectLinker.LinkProgramsV2WithResult(req.Prog, partner)
			if result.unified > 0 {
				req.ObjectLink.Applied = true
				req.ObjectLink.Unified += result.unified
				req.ObjectLink.Exact += result.exact
				req.ObjectLink.CrossFamily += result.crossFamily
			}
		} else if attemptObjectLink {
			req.ObjectLink.Attempted = true
			var result objectLinkResult
			partner, result = objectLinker.LinkProgramsV2WithResult(req.Prog, partner)
			if result.unified > 0 {
				req.ObjectLink.Applied = true
				req.ObjectLink.Unified += result.unified
				req.ObjectLink.Exact += result.exact
				req.ObjectLink.CrossFamily += result.crossFamily
			}
		}
		if fuzzer.Config.NoObjectKccwfNamespace &&
			(fuzzer.raceGroup == nil || fuzzer.raceGroup.GetObjectLinker() == nil) {
			partner = applyKccwfPartnerNamespace(partner, randomKccwfNamespaceSlot(rnd))
		}
		programs[i] = partner
	}

	// Sync ObjectLinker stats to Fuzzer stats
	if fuzzer.raceGroup != nil {
		if ol := fuzzer.raceGroup.GetObjectLinker(); ol != nil {
			_, successes, _ := ol.GetStats()
			if successes > 0 {
				currentVal := int(fuzzer.statObjectLinkings.Val())
				delta := successes - currentVal
				if delta > 0 {
					fuzzer.statObjectLinkings.Add(delta)
				}
			}
		}
	}

	for i := range programs {
		if programs[i] == nil {
			programs[i] = req.Prog.Clone()
		}
	}
	return programs
}

func (fuzzer *Fuzzer) chooseBarrierPartnerProgram(rnd *rand.Rand) *prog.Prog {
	if fuzzer.Config.StaticInputExploration {
		return fuzzer.chooseStaticInputProgram()
	}
	return fuzzer.Config.Corpus.ChooseProgram(rnd)
}

const staticObjectLinkPartnerSamples = 32

func (fuzzer *Fuzzer) chooseObjectLinkPartnerProgram(source *prog.Prog, rnd *rand.Rand) *prog.Prog {
	if fuzzer.Config.StaticInputExploration {
		if p := fuzzer.chooseStaticObjectLinkPartnerProgram(source); p != nil {
			return p
		}
		return fuzzer.chooseStaticInputProgram()
	}
	return fuzzer.Config.Corpus.ChooseProgram(rnd)
}

func (fuzzer *Fuzzer) chooseStaticObjectLinkPartnerProgram(source *prog.Prog) *prog.Prog {
	if fuzzer == nil || fuzzer.staticInputPool == nil || source == nil {
		return nil
	}
	sourceRefs := extractSemanticObjectRefs(source)
	if len(sourceRefs) == 0 {
		return nil
	}

	fuzzer.staticInputPool.mu.Lock()
	defer fuzzer.staticInputPool.mu.Unlock()
	pool := fuzzer.staticInputPool.pool
	if len(pool) == 0 {
		return nil
	}
	samples := staticObjectLinkPartnerSamples
	if samples > len(pool) {
		samples = len(pool)
	}
	bestScore := 0
	var best *prog.Prog
	for i := 0; i < samples; i++ {
		candidate := pool[fuzzer.staticInputPool.rnd.Intn(len(pool))]
		score := semanticPartnerSelectionScore(sourceRefs, extractSemanticObjectRefs(candidate))
		if score > bestScore {
			bestScore = score
			best = candidate
		}
	}
	if best == nil {
		return nil
	}
	return best.Clone()
}

func normalizeObjectLinkAttemptRatio(ratio float64) float64 {
	if ratio <= 0 || ratio > 1 {
		return 1.0
	}
	return ratio
}

const defaultStaticInputSeed int64 = 0x5eed1234

type staticInputPool struct {
	mu   sync.Mutex
	rnd  *rand.Rand
	pool []*prog.Prog
}

func newStaticInputPool(programs []*prog.Prog, seed int64) *staticInputPool {
	if len(programs) == 0 {
		return nil
	}
	if seed == 0 {
		seed = defaultStaticInputSeed
	}
	pool := clonePrograms(programs)
	sort.Slice(pool, func(i, j int) bool {
		return string(pool[i].Serialize()) < string(pool[j].Serialize())
	})
	return &staticInputPool{
		rnd:  rand.New(rand.NewSource(seed)),
		pool: pool,
	}
}

func (fuzzer *Fuzzer) SetStaticInputPool(candidates []Candidate) int {
	if fuzzer == nil || !fuzzer.Config.StaticInputExploration {
		return 0
	}
	programs := make([]*prog.Prog, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Prog != nil {
			programs = append(programs, candidate.Prog)
		}
	}
	fuzzer.staticInputPool = newStaticInputPool(programs, fuzzer.Config.StaticInputSeed)
	if fuzzer.staticInputPool == nil {
		fuzzer.Logf(0, "[STATIC-INPUT] no loaded candidates available for frozen input pool")
		return 0
	}
	fuzzer.Logf(0, "[STATIC-INPUT] frozen input pool loaded: %d programs", len(fuzzer.staticInputPool.pool))
	return len(fuzzer.staticInputPool.pool)
}

func (fuzzer *Fuzzer) chooseStaticInputProgram() *prog.Prog {
	if fuzzer == nil || fuzzer.staticInputPool == nil {
		return nil
	}
	fuzzer.staticInputPool.mu.Lock()
	defer fuzzer.staticInputPool.mu.Unlock()
	if len(fuzzer.staticInputPool.pool) == 0 {
		return nil
	}
	idx := fuzzer.staticInputPool.rnd.Intn(len(fuzzer.staticInputPool.pool))
	return fuzzer.staticInputPool.pool[idx].Clone()
}

// handleDiscoveredBarrierPairs persists newly discovered barrier pairs. The
// paper/default path stores May-Race Pairs directly and leaves expensive
// confirmation to validation. The legacy solo filter can still be enabled for
// old audits that need intra-program pair filtering.
func (fuzzer *Fuzzer) handleDiscoveredBarrierPairs(req *queue.Request, res *queue.Result, newPairs []*ddrd.MayUAFPair, source PairSource) {
	if fuzzer == nil || fuzzer.uaf == nil || req == nil || len(req.BarrierPrograms) < 2 || len(newPairs) == 0 {
		return
	}
	if fuzzer.Config.EnableSoloFilter {
		fuzzer.triggerSoloFilter(req, res, newPairs, source)
		return
	}
	fuzzer.uaf.handleDiscoveredPairs(req, res, req.BarrierPrograms[0], req.BarrierPrograms[1], newPairs, source)
}

// triggerSoloFilter starts the legacy solo filter job to remove non-cross-program pairs.
// It executes prog1 solo and prog2 solo, then filters out pairs that also appear in solo runs.
func (fuzzer *Fuzzer) triggerSoloFilter(req *queue.Request, res *queue.Result, newPairs []*ddrd.MayUAFPair, source PairSource) {
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
		source: source,
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

func (fuzzer *Fuzzer) EnqueueBarrierProgramGroups(groups [][]*prog.Prog) int {
	if fuzzer == nil || fuzzer.smashQueue == nil || len(groups) == 0 {
		return 0
	}
	mask := fuzzer.Config.BarrierMask
	if !fuzzer.Config.ModeUAF || !fuzzer.Config.BarrierMode || mask == 0 {
		return 0
	}
	expected := bits.OnesCount64(mask)
	if expected < 2 {
		return 0
	}
	enqueued := 0
	for idx, group := range groups {
		if len(group) != expected || len(group) == 0 || group[0] == nil {
			fuzzer.Logf(0, "[LLM-SEED] skipping malformed group %d: have %d programs, want %d", idx, len(group), expected)
			continue
		}
		programs := clonePrograms(group)
		req := &queue.Request{
			Prog:      programs[0].Clone(),
			ExecOpts:  setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:      fuzzer.statExecFuzz,
			Important: true,
		}
		req.SetBarrier(mask)
		req.ThreadBarrier = false
		fuzzer.enableBarrierCoverage(req)
		fuzzer.enableRaceExecCollection(req)
		req.ExecOpts.ExecFlags &^= flatrpc.ExecFlagThreaded
		fuzzer.applyNormalTimingThreshold(req)
		if err := req.SetBarrierPrograms(programs); err != nil {
			fuzzer.Logf(0, "[LLM-SEED] failed to assign barrier programs for group %d: %v", idx, err)
			continue
		}
		fuzzer.prepare(req, ProgBarrier, 0)
		fuzzer.smashQueue.Submit(req)
		enqueued++
	}
	if enqueued != 0 {
		fuzzer.Logf(0, "[LLM-SEED] enqueued %d exact barrier program groups", enqueued)
	}
	return enqueued
}

func (fuzzer *Fuzzer) ActivateUAFMode() bool {
	if fuzzer == nil || fuzzer.uaf == nil {
		log.Logf(2, "[DEBUG-RACE] ActivateUAFMode: fuzzer or race state is nil")
		return false
	}
	if !fuzzer.uafBootstrapDone.CompareAndSwap(false, true) {
		log.Logf(2, "[DEBUG-RACE] ActivateUAFMode: already activated")
		return false
	}
	log.Logf(1, "[DEBUG-RACE] ActivateUAFMode: enabling barrier fuzzing, corpus=%d", len(fuzzer.Config.Corpus.Programs()))
	if fuzzer.Config.StaticInputExploration {
		fuzzer.Logf(1, "race: enabling barrier fuzzing with static input exploration")
	} else {
		fuzzer.Logf(1, "race: enabling barrier fuzzing after corpus triage")
	}
	// Clear all history buffers to ensure replay history only contains race-mode executions.
	// Executions during corpus triage phase should not be included in replay history.
	if fuzzer.uaf.historyBuffer != nil {
		fuzzer.uaf.historyBuffer.ClearAll()
		fuzzer.Logf(0, "race: cleared all VM history buffers on race mode activation")
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
