// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vmexec"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type Fuzzer struct {
	name        string
	outputType  OutputType
	config      *ipc.Config
	execOpts    *ipc.ExecOpts
	procs       []*Proc
	gate        *ipc.Gate
	workQueue   *WorkQueue
	needPoll    chan struct{}
	choiceTable *prog.ChoiceTable
	noMutate    map[int]bool

	// ===============DDRD====================
	// Separate race pair work queue for race pair mode
	uafPairWorkQueue *UAFPairWorkQueue

	// 模式标志位 (在启动时一次性确定，整个生命周期保持不变)
	isTestPairMode bool
	// ===============DDRD====================
	// ===============DDRD====================
	// The stats field cannot unfortunately be just an uint64 array, because it
	// results in "unaligned 64-bit atomic operation" errors on 32-bit platforms.
	stats             []uint64
	manager           *rpctype.RPCClient
	target            *prog.Target
	triagedCandidates uint32
	timeouts          targets.Timeouts

	faultInjectionEnabled    bool
	comparisonTracingEnabled bool
	fetchRawCover            bool

	corpusMu     sync.RWMutex
	corpus       []*prog.Prog
	corpusHashes map[hash.Sig]struct{}
	corpusPrios  []int64
	sumPrios     int64

	signalMu     sync.RWMutex
	corpusSignal signal.Signal // signal of inputs in corpus
	maxSignal    signal.Signal // max signal ever observed including flakes
	newSignal    signal.Signal // diff of maxSignal since last sync with master

	// ===============DDRD====================
	// Race coverage tracking
	raceCoverMu     sync.RWMutex
	corpusRaceCover ddrd.RaceCover // race coverage of inputs in corpus
	maxRaceCover    ddrd.RaceCover // max race coverage ever observed
	newRaceCover    ddrd.RaceCover // new race coverage since last sync

	// UAF coverage tracking
	uafCoverMu     sync.RWMutex
	corpusUAFCover ddrd.UAFCover // UAF coverage of inputs in corpus
	maxUAFCover    ddrd.UAFCover // max UAF coverage ever observed
	newUAFCover    ddrd.UAFCover // new UAF coverage since last sync

	// Race signal tracking (similar to coverage signals)
	raceSignalMu     sync.RWMutex
	corpusRaceSignal ddrd.Signal // race signals from corpus pairs
	maxUAFSignal     ddrd.Signal // max UAF signal ever observed
	newRaceSignal    ddrd.Signal // new race signals since last sync

	// UAF signal tracking
	uafSignalMu      sync.RWMutex
	corpusUAFSignal  ddrd.UAFSignal // UAF signals from corpus pairs
	maxUAFOnlySignal ddrd.UAFSignal // max UAF-only signal ever observed
	newUAFSignal     ddrd.UAFSignal // new UAF signals since last sync

	// VM execution sequence buffer for UAF context analysis
	vmExecBuffer *vmexec.VMExecutionSequenceBuffer
	// ===============DDRD====================
	checkResult *rpctype.CheckArgs
	logMu       sync.Mutex

	// Let's limit the number of concurrent NewInput requests.
	parallelNewInputs chan struct{}

	// Experimental flags.
	resetAccState bool

	// Current manager-advertised mode: "normal" | "concurrency" | "uaf-validate"
	currentMode string
}

type FuzzerSnapshot struct {
	corpus      []*prog.Prog
	corpusPrios []int64
	sumPrios    int64
}

type Stat int

const (
	StatGenerate Stat = iota
	StatFuzz
	StatCandidate
	StatTriage
	StatMinimize
	StatSmash
	StatHint
	StatSeed
	StatCollide
	StatBufferTooSmall
	StatCount
)

var statNames = [StatCount]string{
	StatGenerate:       "exec gen",
	StatFuzz:           "exec fuzz",
	StatCandidate:      "exec candidate",
	StatTriage:         "exec triage",
	StatMinimize:       "exec minimize",
	StatSmash:          "exec smash",
	StatHint:           "exec hints",
	StatSeed:           "exec seeds",
	StatCollide:        "exec collide",
	StatBufferTooSmall: "buffer too small",
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

func createIPCConfig(features *host.Features, config *ipc.Config) {
	if features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if features[host.FeatureDelayKcovMmap].Enabled {
		config.Flags |= ipc.FlagDelayKcovMmap
	}
	if features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	config.Flags |= ipc.FlagEnableNetReset
	config.Flags |= ipc.FlagEnableCgroups
	config.Flags |= ipc.FlagEnableCloseFds
	if features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}
	if features[host.FeatureNicVF].Enabled {
		config.Flags |= ipc.FlagEnableNicVF
	}
	if features[host.FeatureVhciInjection].Enabled {
		config.Flags |= ipc.FlagEnableVhciInjection
	}
	if features[host.FeatureWifiEmulation].Enabled {
		config.Flags |= ipc.FlagEnableWifi
	}
}

// Gate size controls how deep in the log the last executed by every proc
// program may be. The intent is to make sure that, given the output log,
// we always understand what was happening.
// Judging by the logs collected on syzbot, 32 should be a reasonable figure.
// It coincides with prog.MaxPids.
const gateSize = prog.MaxPids

// nolint: funlen
func main() {
	debug.SetGCPercent(50)

	var (
		flagName      = flag.String("name", "test", "unique name for manager")
		flagOS        = flag.String("os", runtime.GOOS, "target OS")
		flagArch      = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager   = flag.String("manager", "", "manager rpc address")
		flagProcs     = flag.Int("procs", 1, "number of parallel test processes")
		flagOutput    = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagTest      = flag.Bool("test", false, "enable image testing mode")      // used by syz-ci
		flagRunTest   = flag.Bool("runtest", false, "enable program testing mode") // used by pkg/runtest
		flagRawCover  = flag.Bool("raw_cover", false, "fetch raw coverage")
		flagPprofPort = flag.Int("pprof_port", 0, "HTTP port for the pprof endpoint (disabled if 0)")

		// Experimental flags.
		flagResetAccState = flag.Bool("reset_acc_state", false, "restarts executor before most executions")
	)
	defer tool.Init()()
	outputType := parseOutputType(*flagOutput)
	log.Logf(0, "fuzzer started")

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.SyzFatalf("%v", err)
	}

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.SyzFatalf("failed to create default ipc config: %v", err)
	}
	if *flagRawCover {
		execOpts.Flags &^= ipc.FlagDedupCover
	}
	timeouts := config.Timeouts
	sandbox := ipc.FlagsToSandbox(config.Flags)
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	if *flagPprofPort != 0 {
		setupPprofHandler(*flagPprofPort)
	}

	checkArgs := &checkArgs{
		target:         target,
		sandbox:        sandbox,
		ipcConfig:      config,
		ipcExecOpts:    execOpts,
		gitRevision:    prog.GitRevision,
		targetRevision: target.Revision,
	}
	if *flagTest {
		testImage(*flagManager, checkArgs)
		return
	}

	machineInfo, modules := collectMachineInfos(target)

	log.Logf(0, "dialing manager at %v", *flagManager)
	manager, err := rpctype.NewRPCClient(*flagManager, timeouts.Scale)
	if err != nil {
		log.SyzFatalf("failed to create an RPC client: %v ", err)
	}

	log.Logf(1, "connecting to manager...")
	a := &rpctype.ConnectArgs{
		Name:        *flagName,
		MachineInfo: machineInfo,
		Modules:     modules,
	}
	r := &rpctype.ConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		log.SyzFatalf("failed to call Manager.Connect(): %v ", err)
	}
	featureFlags, err := csource.ParseFeaturesFlags("none", "none", true)
	if err != nil {
		log.SyzFatalf("%v", err)
	}
	if r.CoverFilterBitmap != nil {
		if err := osutil.WriteFile("syz-cover-bitmap", r.CoverFilterBitmap); err != nil {
			log.SyzFatalf("failed to write syz-cover-bitmap: %v", err)
		}
	}
	if r.CheckResult == nil {
		checkArgs.gitRevision = r.GitRevision
		checkArgs.targetRevision = r.TargetRevision
		checkArgs.enabledCalls = r.EnabledCalls
		checkArgs.allSandboxes = r.AllSandboxes
		checkArgs.featureFlags = featureFlags
		r.CheckResult, err = checkMachine(checkArgs)
		if err != nil {
			if r.CheckResult == nil {
				r.CheckResult = new(rpctype.CheckArgs)
			}
			r.CheckResult.Error = err.Error()
		}
		r.CheckResult.Name = *flagName
		if err := manager.Call("Manager.Check", r.CheckResult, nil); err != nil {
			log.SyzFatalf("Manager.Check call failed: %v", err)
		}
		if r.CheckResult.Error != "" {
			log.SyzFatalf("%v", r.CheckResult.Error)
		}
	} else {
		target.UpdateGlobs(r.CheckResult.GlobFiles)
		if err = host.Setup(target, r.CheckResult.Features, featureFlags, config.Executor); err != nil {
			log.SyzFatalf("%v", err)
		}
	}
	log.Logf(0, "syscalls: %v", len(r.CheckResult.EnabledCalls[sandbox]))
	for _, feat := range r.CheckResult.Features.Supported() {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}
	createIPCConfig(r.CheckResult.Features, config)

	if *flagRunTest {
		runTest(target, manager, *flagName, config.Executor)
		return
	}

	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}
	fuzzer := &Fuzzer{
		name:                     *flagName,
		outputType:               outputType,
		config:                   config,
		execOpts:                 execOpts,
		workQueue:                newWorkQueue(*flagProcs, needPoll),
		needPoll:                 needPoll,
		manager:                  manager,
		target:                   target,
		timeouts:                 timeouts,
		faultInjectionEnabled:    r.CheckResult.Features[host.FeatureFault].Enabled,
		comparisonTracingEnabled: r.CheckResult.Features[host.FeatureComparisons].Enabled,
		corpusHashes:             make(map[hash.Sig]struct{}),
		checkResult:              r.CheckResult,
		fetchRawCover:            *flagRawCover,
		noMutate:                 r.NoMutateCalls,
		stats:                    make([]uint64, StatCount),
		// Queue no more than ~3 new inputs / proc.
		parallelNewInputs: make(chan struct{}, int64(3**flagProcs)),
		resetAccState:     *flagResetAccState,
		// ===============DDRD====================
		// Initialize separate race pair work queue
		uafPairWorkQueue: NewUAFPairWorkQueue(*flagProcs),
		// Initialize VM execution sequence buffer (keep last 1000 executions)
		vmExecBuffer: vmexec.NewVMExecutionSequenceBuffer(1000),
		// ===============DDRD====================
	}
	gateCallback := fuzzer.useBugFrames(r, *flagProcs)
	fuzzer.gate = ipc.NewGate(gateSize, gateCallback)

	for needCandidates, more := true, true; more; needCandidates = false {
		// Log before poll
		log.Logf(0, "fetching corpus: %v, signal %v/%v (before poll)",
			len(fuzzer.corpus), len(fuzzer.corpusSignal), len(fuzzer.maxSignal))

		more = fuzzer.poll(needCandidates, nil)

		// Log after poll
		log.Logf(0, "fetching corpus: %v, signal %v/%v (after poll)",
			len(fuzzer.corpus), len(fuzzer.corpusSignal), len(fuzzer.maxSignal))

		// This loop lead to "no output" in qemu emulation, tell manager we are not dead.
	}
	calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
	}
	fuzzer.choiceTable = target.BuildChoiceTable(fuzzer.corpus, calls)

	if r.CoverFilterBitmap != nil {
		fuzzer.execOpts.Flags |= ipc.FlagEnableCoverageFilter
	}

	// ===============DDRD====================
	// 在启动时一次性确定模式 (重启模式下整个生命周期保持不变)
	fuzzer.currentMode, fuzzer.isTestPairMode = fuzzer.determineCurrentMode()
	switch fuzzer.currentMode {
	case "uaf-validate":
		log.Logf(0, "fuzzer started in UAF VALIDATE mode")
	case "concurrency":
		log.Logf(0, "fuzzer started in RACE PAIR mode")
		go fuzzer.pairQueueMaintenanceLoop()
	default:
		log.Logf(0, "fuzzer started in NORMAL mode")
	}
	// ===============DDRD====================

	log.Logf(0, "starting %v fuzzer processes", *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzer, pid)
		if err != nil {
			log.SyzFatalf("failed to create proc: %v", err)
		}
		fuzzer.procs = append(fuzzer.procs, proc)
		// In UAF VALIDATE mode, we don't start normal proc loops.
		if fuzzer.currentMode != "uaf-validate" {
			go proc.loop()
		}
	}

	if fuzzer.currentMode == "uaf-validate" {
		fuzzer.validateLoop()
		return
	}

	fuzzer.pollLoop()
}

func collectMachineInfos(target *prog.Target) ([]byte, []host.KernelModule) {
	machineInfo, err := host.CollectMachineInfo()
	if err != nil {
		log.SyzFatalf("failed to collect machine information: %v", err)
	}
	modules, err := host.CollectModulesInfo()
	if err != nil {
		log.SyzFatalf("failed to collect modules info: %v", err)
	}
	return machineInfo, modules
}

// Returns gateCallback for leak checking if enabled.
func (fuzzer *Fuzzer) useBugFrames(r *rpctype.ConnectRes, flagProcs int) func() {
	var gateCallback func()

	if r.CheckResult.Features[host.FeatureLeak].Enabled {
		gateCallback = func() { fuzzer.gateCallback(r.MemoryLeakFrames) }
	}

	if r.CheckResult.Features[host.FeatureKCSAN].Enabled && len(r.DataRaceFrames) != 0 {
		fuzzer.filterDataRaceFrames(r.DataRaceFrames)
	}

	return gateCallback
}

func (fuzzer *Fuzzer) gateCallback(leakFrames []string) {
	// Leak checking is very slow so we don't do it while triaging the corpus
	// (otherwise it takes infinity). When we have presumably triaged the corpus
	// (triagedCandidates == 1), we run leak checking bug ignore the result
	// to flush any previous leaks. After that (triagedCandidates == 2)
	// we do actual leak checking and report leaks.
	triagedCandidates := atomic.LoadUint32(&fuzzer.triagedCandidates)
	if triagedCandidates == 0 {
		return
	}
	args := append([]string{"leak"}, leakFrames...)
	timeout := fuzzer.timeouts.NoOutput * 9 / 10
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil && triagedCandidates == 2 {
		// If we exit right away, dying executors will dump lots of garbage to console.
		os.Stdout.Write(output)
		fmt.Printf("BUG: leak checking failed\n")
		time.Sleep(time.Hour)
		os.Exit(1)
	}
	if triagedCandidates == 1 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 2)
	}
}

func (fuzzer *Fuzzer) filterDataRaceFrames(frames []string) {
	args := append([]string{"setup_kcsan_filterlist"}, frames...)
	timeout := time.Minute * fuzzer.timeouts.Scale
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil {
		log.SyzFatalf("failed to set KCSAN filterlist: %v", err)
	}
	log.Logf(0, "%s", output)
}

// determineInitialMode 在启动时确定fuzzer的运行模式 (整个生命周期不变)
func (fuzzer *Fuzzer) determineCurrentMode() (string, bool) {
	// Preferred: CheckCurrentMode returns explicit mode string.
	cur := &rpctype.CurrentModeRes{}
	if err := fuzzer.manager.Call("Manager.CheckCurrentMode", &rpctype.CurrentModeArgs{Name: fuzzer.name}, cur); err == nil {
		return cur.Mode, (cur.Mode == "concurrency")
	}
	// Fallback: legacy race pair boolean.
	args := &rpctype.CheckModeArgs{Name: fuzzer.name}
	res := &rpctype.CheckModeRes{}
	if err := fuzzer.manager.Call("Manager.CheckTestPairMode", args, res); err != nil {
		log.Logf(0, "CheckTestPairMode RPC失败: %v, 默认为normal模式", err)
		return "normal", false
	}
	if res.IsTestPairMode {
		return "concurrency", true
	}
	return "normal", false
}

// validateLoop runs UAF validate tasks dispatched by Manager.
func (fuzzer *Fuzzer) validateLoop() {
	log.Logf(0, "validateLoop: entering validation task loop")
	for {
		// Fetch next task
		gres := &rpctype.GetUAFValidateTaskRes{}
		if err := fuzzer.manager.Call("Manager.GetUAFValidateTask", &rpctype.GetUAFValidateTaskArgs{Name: fuzzer.name}, gres); err != nil {
			log.Logf(0, "GetUAFValidateTask RPC失败: %v", err)
			time.Sleep(3 * time.Second * fuzzer.timeouts.Scale)
			continue
		}
		if !gres.HasTask {
			log.Logf(0, "validateLoop: no tasks available, sleeping")
			time.Sleep(5 * time.Second * fuzzer.timeouts.Scale)
			continue
		}

		task := gres.Task
		var execErr error
		succeeded := false
		detectedCount := 0
		var reproducedUAFs []byte

		// Context replay (state restore) if provided: execute with no collection/detection side-effects
		if len(task.ExecutionContext) != 0 {
			var records []vmexec.ExecutionRecord
			if err := json.Unmarshal(task.ExecutionContext, &records); err != nil {
				log.Logf(1, "validateLoop: failed to unmarshal execution context for %x: %v", task.PairID, err)
			} else if len(records) > 0 {
				// Use first proc to replay sequence with minimal flags (no CollectUAF, no reporting)
				proc := fuzzer.procs[0]
				for _, rec := range records {
					p1, err1 := fuzzer.target.Deserialize(rec.Prog1Data, prog.NonStrict)
					p2, err2 := fuzzer.target.Deserialize(rec.Prog2Data, prog.NonStrict)
					if err1 != nil || err2 != nil {
						continue
					}
					opts1 := &ipc.ExecOpts{Flags: ipc.FlagTestPairSync}
					opts2 := &ipc.ExecOpts{Flags: ipc.FlagTestPairSync}
					_, _, _, _ = proc.env.ExecPair(opts1, opts2, p1, p2)
				}
			}
		}

		// Detection run on provided pair: allow detection but don't report or collect globally
		{
			proc := fuzzer.procs[0]
			p1, err1 := fuzzer.target.Deserialize(task.Prog1, prog.NonStrict)
			p2, err2 := fuzzer.target.Deserialize(task.Prog2, prog.NonStrict)
			if err1 != nil || err2 != nil {
				execErr = fmt.Errorf("failed to deserialize progs: %v / %v", err1, err2)
			} else {
				opts1 := &ipc.ExecOpts{Flags: ipc.FlagTestPairSync | ipc.FlagCollectUAF}
				opts2 := &ipc.ExecOpts{Flags: ipc.FlagTestPairSync | ipc.FlagCollectUAF}
				output, info, hanged, err := proc.env.ExecPair(opts1, opts2, p1, p2)
				_ = output
				_ = hanged
				if err != nil {
					execErr = err
				} else if info != nil && len(info.MayUAFPairs) > 0 {
					succeeded = true
					detectedCount = len(info.MayUAFPairs)
					if data, encErr := json.Marshal(info.MayUAFPairs); encErr != nil {
						log.Logf(1, "validateLoop: failed to marshal reproduced UAF pairs for %x: %v", task.PairID, encErr)
					} else {
						reproducedUAFs = data
					}
				}
			}
		}

		// Report result (never upsert corpus)
		res := &rpctype.ReportUAFValidateResultRes{}
		rargs := &rpctype.ReportUAFValidateResultArgs{
			Name: fuzzer.name,
			Result: rpctype.UAFValidateResult{
				PairID:        task.PairID,
				Succeeded:     succeeded,
				DetectedCount: detectedCount,
				UAFs:          reproducedUAFs,
			},
		}
		if execErr != nil {
			rargs.Result.Error = execErr.Error()
		}
		_ = fuzzer.manager.Call("Manager.ReportUAFValidateResult", rargs, res)

		// Reboot/exit as per task directive
		if task.RebootAfter {
			log.Logf(0, "validateLoop: task %x finished (succ=%v, cnt=%d), exiting for reboot", task.PairID, succeeded, detectedCount)
			os.Exit(0)
		}
	}
}

func (fuzzer *Fuzzer) pollLoop() {
	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second * fuzzer.timeouts.Scale).C
	for {
		poll := false
		select {
		case <-ticker:
		case <-fuzzer.needPoll:
			poll = true
		}

		if fuzzer.outputType != OutputStdout && time.Since(lastPrint) > 10*time.Second*fuzzer.timeouts.Scale {
			// Keep-alive for manager.
			log.Logf(0, "alive, executed %v", execTotal)
			lastPrint = time.Now()
		}
		if poll || time.Since(lastPoll) > 10*time.Second*fuzzer.timeouts.Scale {
			needCandidates := fuzzer.workQueue.wantCandidates()
			if poll && !needCandidates {
				continue
			}
			stats := make(map[string]uint64)
			for _, proc := range fuzzer.procs {
				execCount := atomic.SwapUint64(&proc.env.StatExecs, 0)
				stats["exec total"] += execCount

				// DDRD模式分离统计
				if fuzzer.isTestPairMode {
					stats["exec race"] += execCount
				} else {
					stats["exec normal"] += execCount
				}

				stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
			}
			for stat := Stat(0); stat < StatCount; stat++ {
				v := atomic.SwapUint64(&fuzzer.stats[stat], 0)
				stats[statNames[stat]] = v
				execTotal += v
			}
			if !fuzzer.poll(needCandidates, stats) {
				lastPoll = time.Now()
			}
		}
	}
}

func (fuzzer *Fuzzer) poll(needCandidates bool, stats map[string]uint64) bool {
	a := &rpctype.PollArgs{
		Name:           fuzzer.name,
		NeedCandidates: needCandidates,
		MaxSignal:      fuzzer.grabNewSignal().Serialize(),
		// ===============DDRD====================
		MaxUAFSignal: serializeRaceSignal(fuzzer.grabNewRaceSignal()),
		// ===============DDRD====================
		Stats: stats,
	}
	r := &rpctype.PollRes{}
	if err := fuzzer.manager.Call("Manager.Poll", a, r); err != nil {
		log.SyzFatalf("Manager.Poll call failed: %v", err)
	}
	maxSignal := r.MaxSignal.Deserialize()
	log.Logf(1, "poll: candidates=%v inputs=%v signal=%v",
		len(r.Candidates), len(r.NewInputs), maxSignal.Len())
	fuzzer.addMaxSignal(maxSignal)

	// ===============DDRD====================
	// Process race signal from manager
	if len(r.MaxUAFSignal) > 0 {
		if uafSignal := deserializeRaceSignal(r.MaxUAFSignal); uafSignal != nil {
			log.Logf(2, "[DDRD-DEBUG] Poll: Received UAF signal from manager: size=%d", len(*uafSignal))
			fuzzer.addMaxUAFSignal(*uafSignal)
		}
	}

	for _, inp := range r.NewInputs {
		fuzzer.addInputFromAnotherFuzzer(inp)
	}
	for _, candidate := range r.Candidates {
		fuzzer.addCandidateInput(candidate)
	}
	if needCandidates && len(r.Candidates) == 0 && atomic.LoadUint32(&fuzzer.triagedCandidates) == 0 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 1)
	}
	return len(r.NewInputs) != 0 || len(r.Candidates) != 0 || maxSignal.Len() != 0
}

func (fuzzer *Fuzzer) sendInputToManager(inp rpctype.Input) {
	fuzzer.parallelNewInputs <- struct{}{}
	go func() {
		defer func() { <-fuzzer.parallelNewInputs }()
		a := &rpctype.NewInputArgs{
			Name:  fuzzer.name,
			Input: inp,
		}
		if err := fuzzer.manager.Call("Manager.NewInput", a, nil); err != nil {
			log.SyzFatalf("Manager.NewInput call failed: %v", err)
		}
	}()
}

func (fuzzer *Fuzzer) addInputFromAnotherFuzzer(inp rpctype.Input) {
	p := fuzzer.deserializeInput(inp.Prog)
	if p == nil {
		return
	}
	sig := hash.Hash(inp.Prog)
	sign := inp.Signal.Deserialize()
	fuzzer.addInputToCorpus(p, sign, sig)
}

func (fuzzer *Fuzzer) addCandidateInput(candidate rpctype.Candidate) {
	p := fuzzer.deserializeInput(candidate.Prog)
	if p == nil {
		return
	}
	flags := ProgCandidate
	if candidate.Minimized {
		flags |= ProgMinimized
	}
	if candidate.Smashed {
		flags |= ProgSmashed
	}
	fuzzer.workQueue.enqueue(&WorkCandidate{
		p:     p,
		flags: flags,
	})
}

func (fuzzer *Fuzzer) deserializeInput(inp []byte) *prog.Prog {
	p, err := fuzzer.target.Deserialize(inp, prog.NonStrict)
	if err != nil {
		log.SyzFatalf("failed to deserialize prog: %v\n%s", err, inp)
	}
	// We build choice table only after we received the initial corpus,
	// so we don't check the initial corpus here, we check it later in BuildChoiceTable.
	if fuzzer.choiceTable != nil {
		fuzzer.checkDisabledCalls(p)
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil
	}
	return p
}

func (fuzzer *Fuzzer) checkDisabledCalls(p *prog.Prog) {
	for _, call := range p.Calls {
		if !fuzzer.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v [%v]\n", call.Meta.Name, call.Meta.ID)
			sandbox := ipc.FlagsToSandbox(fuzzer.config.Flags)
			fmt.Printf("check result for sandbox=%v:\n", sandbox)
			for _, id := range fuzzer.checkResult.EnabledCalls[sandbox] {
				meta := fuzzer.target.Syscalls[id]
				fmt.Printf("  %v [%v]\n", meta.Name, meta.ID)
			}
			fmt.Printf("choice table:\n")
			for i, meta := range fuzzer.target.Syscalls {
				fmt.Printf("  #%v: %v [%v]: enabled=%v\n", i, meta.Name, meta.ID, fuzzer.choiceTable.Enabled(meta.ID))
			}
			panic("disabled syscall")
		}
	}
}

func (fuzzer *FuzzerSnapshot) chooseProgram(r *rand.Rand) *prog.Prog {
	randVal := r.Int63n(fuzzer.sumPrios + 1)
	idx := sort.Search(len(fuzzer.corpusPrios), func(i int) bool {
		return fuzzer.corpusPrios[i] >= randVal
	})
	return fuzzer.corpus[idx]
}

func (fuzzer *Fuzzer) addInputToCorpus(p *prog.Prog, sign signal.Signal, sig hash.Sig) {
	fuzzer.corpusMu.Lock()
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		fuzzer.corpus = append(fuzzer.corpus, p)
		fuzzer.corpusHashes[sig] = struct{}{}
		prio := int64(len(sign))
		if sign.Empty() {
			prio = 1
		}
		fuzzer.sumPrios += prio
		fuzzer.corpusPrios = append(fuzzer.corpusPrios, fuzzer.sumPrios)
	}
	fuzzer.corpusMu.Unlock()

	if !sign.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSignal.Merge(sign)
		fuzzer.maxSignal.Merge(sign)
		fuzzer.signalMu.Unlock()
	}
}

func (fuzzer *Fuzzer) snapshot() FuzzerSnapshot {
	fuzzer.corpusMu.RLock()
	defer fuzzer.corpusMu.RUnlock()
	return FuzzerSnapshot{fuzzer.corpus, fuzzer.corpusPrios, fuzzer.sumPrios}
}

func (fuzzer *Fuzzer) addMaxSignal(sign signal.Signal) {
	if sign.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSignal.Merge(sign)
}

func (fuzzer *Fuzzer) grabNewSignal() signal.Signal {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	sign := fuzzer.newSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newSignal = nil
	return sign
}

// ===============DDRD====================
// grabNewRaceSignal returns new race signals since last poll and clears them
func (fuzzer *Fuzzer) grabNewRaceSignal() ddrd.Signal {
	fuzzer.raceSignalMu.Lock()
	defer fuzzer.raceSignalMu.Unlock()
	sign := fuzzer.newRaceSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newRaceSignal = nil
	return sign
}

// grabNewUAFSignal returns new UAF signals since last poll and clears them
func (fuzzer *Fuzzer) grabNewUAFSignal() ddrd.UAFSignal {
	fuzzer.uafSignalMu.Lock()
	defer fuzzer.uafSignalMu.Unlock()
	sign := fuzzer.newUAFSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newUAFSignal = nil
	return sign
}

// addRaceSignal adds race signal to fuzzer's tracking
func (fuzzer *Fuzzer) addRaceSignal(sign ddrd.Signal) {
	if sign.Empty() {
		return
	}
	fuzzer.raceSignalMu.Lock()
	defer fuzzer.raceSignalMu.Unlock()
	fuzzer.maxUAFSignal.Merge(sign)
	fuzzer.newRaceSignal.Merge(sign)
}

// addUAFSignal adds UAF signal to fuzzer's tracking
func (fuzzer *Fuzzer) addUAFSignal(sign ddrd.UAFSignal) {
	if sign.Empty() {
		return
	}
	fuzzer.uafSignalMu.Lock()
	defer fuzzer.uafSignalMu.Unlock()
	fuzzer.maxUAFOnlySignal.Merge(sign)
	fuzzer.newUAFSignal.Merge(sign)
}

// corpusRaceSignalDiff returns diff between race signal and corpus race signals
func (fuzzer *Fuzzer) corpusRaceSignalDiff(sign ddrd.Signal) ddrd.Signal {
	fuzzer.raceSignalMu.RLock()
	defer fuzzer.raceSignalMu.RUnlock()
	return fuzzer.corpusRaceSignal.Diff(sign)
}

// corpusUAFSignalDiff returns diff between UAF signal and corpus UAF signals
func (fuzzer *Fuzzer) corpusUAFSignalDiff(sign ddrd.UAFSignal) ddrd.UAFSignal {
	fuzzer.uafSignalMu.RLock()
	defer fuzzer.uafSignalMu.RUnlock()
	return fuzzer.corpusUAFSignal.Diff(sign)
}

// addMaxUAFSignal merges new UAF signals from manager
func (fuzzer *Fuzzer) addMaxUAFSignal(sign ddrd.Signal) {
	if sign.Empty() {
		return
	}
	fuzzer.raceSignalMu.Lock()
	defer fuzzer.raceSignalMu.Unlock()
	fuzzer.maxUAFSignal.Merge(sign)
}

// addMaxUAFOnlySignal merges new UAF-only signals from manager
func (fuzzer *Fuzzer) addMaxUAFOnlySignal(sign ddrd.UAFSignal) {
	if sign.Empty() {
		return
	}
	fuzzer.uafSignalMu.Lock()
	defer fuzzer.uafSignalMu.Unlock()
	fuzzer.maxUAFOnlySignal.Merge(sign)
}

// ===============DDRD====================

func (fuzzer *Fuzzer) corpusSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSignal.Diff(sign)
}

func (fuzzer *Fuzzer) checkNewSignal(p *prog.Prog, info *ipc.ProgInfo) (calls []int, extra bool) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	for i, inf := range info.Calls {
		if fuzzer.checkNewCallSignal(p, &inf, i) {
			calls = append(calls, i)
		}
	}
	extra = fuzzer.checkNewCallSignal(p, &info.Extra, -1)
	return
}

func (fuzzer *Fuzzer) checkNewCallSignal(p *prog.Prog, info *ipc.CallInfo, call int) bool {
	diff := fuzzer.maxSignal.DiffRaw(info.Signal, signalPrio(p, info, call))
	if diff.Empty() {
		return false
	}
	fuzzer.signalMu.RUnlock()
	fuzzer.signalMu.Lock()
	fuzzer.maxSignal.Merge(diff)
	fuzzer.newSignal.Merge(diff)
	fuzzer.signalMu.Unlock()
	fuzzer.signalMu.RLock()
	return true
}

// nolint: unused
// It's only needed for debugging.
func (fuzzer *Fuzzer) Logf(level int, msg string, args ...interface{}) {
	go func() {
		a := &rpctype.LogMessageReq{
			Level:   level,
			Name:    fuzzer.name,
			Message: fmt.Sprintf(msg, args...),
		}
		if err := fuzzer.manager.Call("Manager.LogMessage", a, nil); err != nil {
			log.SyzFatalf("Manager.LogMessage call failed: %v", err)
		}
	}()
}

func setupPprofHandler(port int) {
	// Necessary for pprof handlers.
	go func() {
		err := http.ListenAndServe(fmt.Sprintf("0.0.0.0:%v", port), nil)
		if err != nil {
			log.SyzFatalf("failed to setup a server: %v", err)
		}
	}()
}

func signalPrio(p *prog.Prog, info *ipc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Errno == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func parseOutputType(str string) OutputType {
	switch str {
	case "none":
		return OutputNone
	case "stdout":
		return OutputStdout
	case "dmesg":
		return OutputDmesg
	case "file":
		return OutputFile
	default:
		log.SyzFatalf("-output flag must be one of none/stdout/dmesg/file")
		return OutputNone
	}
}

func (fuzzer *Fuzzer) updateRaceCoverage(races []*ddrd.MayRacePair) {
	if len(races) == 0 {
		return
	}

	fuzzer.raceCoverMu.Lock()
	defer fuzzer.raceCoverMu.Unlock()

	// 初始化race coverage如果需要
	if fuzzer.corpusRaceCover == nil {
		fuzzer.corpusRaceCover = make(ddrd.RaceCover)
	}
	if fuzzer.maxRaceCover == nil {
		fuzzer.maxRaceCover = make(ddrd.RaceCover)
	}
	if fuzzer.newRaceCover == nil {
		fuzzer.newRaceCover = make(ddrd.RaceCover)
	}

	// ===============DDRD====================
	// Update max race coverage and detect new races (races already as pointers)
	newRaces := fuzzer.maxRaceCover.MergeDiff(races)
	if len(newRaces) > 0 {
		log.Logf(1, "discovered %d new race pairs", len(newRaces))
		// Add to new race coverage for manager sync
		fuzzer.newRaceCover.Merge(newRaces)
	}
	// ===============DDRD====================
}

func (fuzzer *Fuzzer) updateUAFCoverage(uafs []*ddrd.MayUAFPair) {
	if len(uafs) == 0 {
		return
	}

	fuzzer.uafCoverMu.Lock()
	defer fuzzer.uafCoverMu.Unlock()

	// 初始化UAF coverage如果需要
	if fuzzer.corpusUAFCover == nil {
		fuzzer.corpusUAFCover = make(ddrd.UAFCover)
	}
	if fuzzer.maxUAFCover == nil {
		fuzzer.maxUAFCover = make(ddrd.UAFCover)
	}
	if fuzzer.newUAFCover == nil {
		fuzzer.newUAFCover = make(ddrd.UAFCover)
	}

	// ===============DDRD====================
	// Update max UAF coverage and detect new UAFs (uafs already as pointers)
	newUAFs := fuzzer.maxUAFCover.MergeDiff(uafs)
	if len(newUAFs) > 0 {
		log.Logf(1, "discovered %d new UAF pairs", len(newUAFs))
		// Add to new UAF coverage for manager sync
		fuzzer.newUAFCover.Merge(newUAFs)
	}
	// ===============DDRD====================
}

// grabNewUAFCoverage returns new UAF coverage since last sync and clears it
func (fuzzer *Fuzzer) grabNewUAFCoverage() ddrd.UAFCover {
	fuzzer.uafCoverMu.Lock()
	defer fuzzer.uafCoverMu.Unlock()
	cover := fuzzer.newUAFCover
	if len(cover) == 0 {
		return nil
	}
	fuzzer.newUAFCover = make(ddrd.UAFCover)
	return cover
}

// addUAFCoverageFromManager merges UAF coverage from manager
func (fuzzer *Fuzzer) addUAFCoverageFromManager(cover ddrd.UAFCover) {
	if len(cover) == 0 {
		return
	}
	fuzzer.uafCoverMu.Lock()
	defer fuzzer.uafCoverMu.Unlock()

	// Convert cover map to slice for Merge method
	var uafPairs []*ddrd.MayUAFPair
	for _, uaf := range cover {
		uafPairs = append(uafPairs, uaf)
	}
	fuzzer.maxUAFCover.Merge(uafPairs)
}

// checkForNewRaceCoverage checks if a pair potentially brings new race coverage
func (fuzzer *Fuzzer) checkForNewRaceCoverage(p1, p2 *prog.Prog, races []*ddrd.MayRacePair) bool {
	if len(races) == 0 {
		return false
	}

	fuzzer.raceCoverMu.RLock()
	defer fuzzer.raceCoverMu.RUnlock()

	// Check if any of the races are new
	for _, race := range races {
		if !fuzzer.maxRaceCover.Contains(race) {
			return true
		}
	}

	return false
}

// checkForNewUAFCoverage checks if a pair potentially brings new UAF coverage
func (fuzzer *Fuzzer) checkForNewUAFCoverage(p1, p2 *prog.Prog, uafs []*ddrd.MayUAFPair) bool {
	if len(uafs) == 0 {
		return false
	}

	fuzzer.uafCoverMu.RLock()
	defer fuzzer.uafCoverMu.RUnlock()

	// Check if any of the UAFs are new
	for _, uaf := range uafs {
		if !fuzzer.maxUAFCover.Contains(uaf) {
			return true
		}
	}

	return false
}

// maintainRacePairQueues ensures race pair queues have sufficient work
func (fuzzer *Fuzzer) maintainRacePairQueues() {
	// ===============DDRD====================
	// Get pair candidates directly from manager instead of generating locally
	// ===============DDRD====================

	// Check if race pair work queue needs more pairs
	if fuzzer.uafPairWorkQueue == nil {
		log.Logf(0, "maintainUAFPairQueues: uafPairWorkQueue is nil")
		return
	}

	// Get current queue status - ONLY request if we're running low
	candidatesCount, triageCount, valuableCount := fuzzer.uafPairWorkQueue.getQueueStats()
	totalQueued := candidatesCount + triageCount + valuableCount

	// Only request more pairs if total queued work is low
	// Keep a buffer of at least 50 pairs per proc to avoid frequent requests
	minQueueSize := len(fuzzer.procs) * 50
	if totalQueued >= minQueueSize {
		// log.Logf(3, "maintainRacePairQueues: sufficient work queued (%d items), skipping request", totalQueued)
		return
	}

	// Request enough to refill to target size
	batchSize := minQueueSize - totalQueued
	if batchSize > 100 {
		batchSize = 100 // Cap at 100 per request to avoid overwhelming manager
	}

	// log.Logf(2, "maintainRacePairQueues: requesting %d pairs (current queue: %d candidates, %d triage, %d valuable)",
	// 	batchSize, candidatesCount, triageCount, valuableCount)

	// Get pair candidates from manager
	pairCandidates := fuzzer.getPairCandidatesFromManager(batchSize)
	if len(pairCandidates) == 0 {
		log.Logf(2, "maintainRacePairQueues: no pair candidates available from manager")
		return
	}

	// Convert manager's PairCandidate to local race pair work items
	added := 0
	for _, pairCandidate := range pairCandidates {
		// Deserialize the two programs
		prog1 := fuzzer.deserializeInput(pairCandidate.Prog1)
		prog2 := fuzzer.deserializeInput(pairCandidate.Prog2)

		if prog1 == nil || prog2 == nil {
			log.Logf(1, "maintainRacePairQueues: failed to deserialize pair candidate %x", pairCandidate.PairID)
			continue
		}

		// Add to race pair work queue
		fuzzer.uafPairWorkQueue.enqueueCorpusPair(prog1, prog2)
		added++

		// log.Logf(2, "maintainRacePairQueues: added pair %s from manager", pairIDStr)
	}

	if added > 0 {
		log.Logf(1, "maintainRacePairQueues: added %d race pairs from manager (requested %d)",
			added, len(pairCandidates))
	}
}

// pairQueueMaintenanceLoop runs in the background to periodically maintain pair queues
// This runs as a separate goroutine to avoid blocking proc execution loops
func (fuzzer *Fuzzer) pairQueueMaintenanceLoop() {
	// Check every 5 seconds
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Logf(0, "pair queue maintenance loop started (checking every 5 seconds)")

	for range ticker.C {
		// Call the maintenance function
		fuzzer.maintainRacePairQueues()
	}
}

// addRacePairWithNewCoverage adds a program pair that brings new race coverage
func (fuzzer *Fuzzer) addRacePairWithNewCoverage(p1, p2 *prog.Prog, races []*ddrd.MayRacePair) {
	pairID := fmt.Sprintf("newcover_%d_%d", time.Now().UnixNano(), len(races))
	// ===============DDRD====================
	// Use race pair work queue instead of normal work queue
	// Convert races to UAFs (this might need to be changed based on your UAF detection logic)
	var uafs []*ddrd.MayUAFPair
	for _, race := range races {
		// This is a placeholder conversion - you might need to adjust this
		// based on how you want to handle the race to UAF conversion
		if race != nil {
			uaf := &ddrd.MayUAFPair{
				// Map race fields to UAF fields as appropriate
				FreeAccessName: race.VarName1,
				UseAccessName:  race.VarName2,
				FreeCallStack:  race.CallStack1,
				UseCallStack:   race.CallStack2,
				Signal:         race.Signal,
				TimeDiff:       race.TimeDiff,
				// Add other field mappings as needed
			}
			uafs = append(uafs, uaf)
		}
	}
	fuzzer.uafPairWorkQueue.enqueueNewCoverPair(p1, p2, pairID, uafs)
	// ===============DDRD====================
	log.Logf(1, "added race pair with %d new races to queue", len(races))
}

// addUAFPairWithNewCoverage adds a program pair that brings new UAF coverage
func (fuzzer *Fuzzer) addUAFPairWithNewCoverage(p1, p2 *prog.Prog, uafs []*ddrd.MayUAFPair) {
	pairID := fmt.Sprintf("newuaf_%d_%d", time.Now().UnixNano(), len(uafs))
	// ===============DDRD====================
	// Use UAF pair work queue for UAF pairs
	fuzzer.uafPairWorkQueue.enqueueNewCoverPair(p1, p2, pairID, uafs)
	// ===============DDRD====================
	log.Logf(1, "added UAF pair with %d new UAFs to queue", len(uafs))
}

// ===============DDRD====================
// Race signal serialization helpers for fuzzer
// ===============DDRD====================

// deserializeRaceSignal deserializes race signal from byte array
func deserializeRaceSignal(data []byte) *ddrd.Signal {
	if len(data) == 0 {
		return nil
	}
	var serial ddrd.Serial
	if err := json.Unmarshal(data, &serial); err != nil {
		log.Logf(0, "Failed to deserialize race signal: %v", err)
		return nil
	}
	sig := serial.Deserialize()
	return &sig
}

// serializeRaceSignal serializes race signal to byte array
func serializeRaceSignal(sig ddrd.Signal) []byte {
	if sig.Empty() {
		return []byte{}
	}
	serial := sig.Serialize()
	data, err := json.Marshal(serial)
	if err != nil {
		log.Logf(0, "Failed to serialize race signal: %v", err)
		return []byte{}
	}
	return data
}

// deserializeUAFSignal deserializes UAF signal from byte array
func deserializeUAFSignal(data []byte) *ddrd.UAFSignal {
	if len(data) == 0 {
		return nil
	}
	var rawSignal []uint64
	if err := json.Unmarshal(data, &rawSignal); err != nil {
		log.Logf(0, "Failed to deserialize UAF signal: %v", err)
		return nil
	}
	sig := ddrd.DeserializeUAFSignal(rawSignal)
	return &sig
}

// serializeUAFSignal serializes UAF signal to byte array
func serializeUAFSignal(sig ddrd.UAFSignal) []byte {
	if sig.Empty() {
		return []byte{}
	}
	rawSignal := sig.Serialize()
	data, err := json.Marshal(rawSignal)
	if err != nil {
		log.Logf(0, "Failed to serialize UAF signal: %v", err)
		return []byte{}
	}
	return data
}

// getAllCandidatesFromManager requests all current candidates from manager
func (fuzzer *Fuzzer) getAllCandidatesFromManager() []rpctype.Candidate {
	args := &rpctype.GetAllCandidatesArgs{
		Name: fuzzer.name,
	}
	res := &rpctype.GetAllCandidatesRes{}

	if err := fuzzer.manager.Call("Manager.GetAllCandidates", args, res); err != nil {
		log.Logf(0, "GetAllCandidates RPC failed: %v", err)
		return nil
	}

	log.Logf(2, "getAllCandidatesFromManager: received %d candidates", len(res.Candidates))
	return res.Candidates
}

// getPairCandidatesFromManager requests a batch of pair candidates from manager
func (fuzzer *Fuzzer) getPairCandidatesFromManager(size int) []rpctype.PairCandidate {
	args := &rpctype.GetPairCandidatesArgs{
		Name: fuzzer.name,
		Size: size,
	}
	res := &rpctype.GetPairCandidatesRes{}

	if err := fuzzer.manager.Call("Manager.GetPairCandidates", args, res); err != nil {
		log.Logf(0, "GetPairCandidates RPC failed: %v", err)
		return nil
	}

	log.Logf(2, "getPairCandidatesFromManager: received %d pair candidates", len(res.PairCandidates))
	return res.PairCandidates
}

// ===============DDRD====================
