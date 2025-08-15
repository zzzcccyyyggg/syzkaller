// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
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

	"github.com/google/syzkaller/pkg/cover"
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

	// Race coverage tracking
	raceCoverMu     sync.RWMutex
	corpusRaceCover ddrd.RaceCover // race coverage of inputs in corpus
	maxRaceCover    ddrd.RaceCover // max race coverage ever observed
	newRaceCover    ddrd.RaceCover // new race coverage since last sync

	checkResult *rpctype.CheckArgs
	logMu       sync.Mutex

	// Let's limit the number of concurrent NewInput requests.
	parallelNewInputs chan struct{}

	// Experimental flags.
	resetAccState bool

	// Concurrency testing support
	concurrencyFuzzer *ConcurrencyFuzzer
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
	}
	gateCallback := fuzzer.useBugFrames(r, *flagProcs)
	fuzzer.gate = ipc.NewGate(gateSize, gateCallback)

	for needCandidates, more := true, true; more; needCandidates = false {
		more = fuzzer.poll(needCandidates, nil)
		// This loop lead to "no output" in qemu emulation, tell manager we are not dead.
		log.Logf(0, "fetching corpus: %v, signal %v/%v (executing program)",
			len(fuzzer.corpus), len(fuzzer.corpusSignal), len(fuzzer.maxSignal))
	}
	calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
	}
	fuzzer.choiceTable = target.BuildChoiceTable(fuzzer.corpus, calls)

	// Initialize concurrency fuzzer
	fuzzer.concurrencyFuzzer = NewConcurrencyFuzzer(fuzzer)
	fuzzer.concurrencyFuzzer.UpdateCorpus(fuzzer.corpus)

	if r.CoverFilterBitmap != nil {
		fuzzer.execOpts.Flags |= ipc.FlagEnableCoverageFilter
	}

	log.Logf(0, "starting %v fuzzer processes", *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzer, pid)
		if err != nil {
			log.SyzFatalf("failed to create proc: %v", err)
		}
		fuzzer.procs = append(fuzzer.procs, proc)
		go proc.loop()
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

// checkTestPairMode 检查当前是否处于test pair模式
func (fuzzer *Fuzzer) checkTestPairMode() bool {
	args := &rpctype.CheckModeArgs{
		Name: fuzzer.name,
	}
	res := &rpctype.CheckModeRes{}
	if err := fuzzer.manager.Call("Manager.CheckTestPairMode", args, res); err != nil {
		log.Logf(2, "CheckTestPairMode RPC失败: %v, 默认为normal模式", err)
		return false
	}
	if res.IsTestPairMode {
		log.Logf(2, "当前处于Test Pair模式")
	} else {
		log.Logf(3, "当前处于Normal模式")
	}
	return res.IsTestPairMode
}

// executeTestPairMode 执行test pair模式
func (fuzzer *Fuzzer) executeTestPairMode() {
	// 在test pair模式下，重点执行test pairs
	// proc.loop()会自动休眠，让出CPU给test pair执行
	log.Logf(1, "执行Test Pair模式 - 开始轮询test pairs")
	fuzzer.pollTestPairs()
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
				stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
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

			// 检查执行模式：要么test pair模式，要么normal模式，不能同时
			if fuzzer.checkTestPairMode() {
				// Test Pair模式：专注执行test pairs
				log.Logf(1, "当前处于Test Pair模式，开始执行test pairs")
				fuzzer.executeTestPairMode()
			} else {
				// Normal模式：通过proc执行常规工作队列
				// proc.loop()会自动处理workQueue，不需要在这里直接处理
				log.Logf(2, "当前处于Normal模式，proc将处理工作队列")
			}
		}
	}
}

func (fuzzer *Fuzzer) poll(needCandidates bool, stats map[string]uint64) bool {
	a := &rpctype.PollArgs{
		Name:           fuzzer.name,
		NeedCandidates: needCandidates,
		MaxSignal:      fuzzer.grabNewSignal().Serialize(),
		Stats:          stats,
	}
	r := &rpctype.PollRes{}
	if err := fuzzer.manager.Call("Manager.Poll", a, r); err != nil {
		log.SyzFatalf("Manager.Poll call failed: %v", err)
	}
	maxSignal := r.MaxSignal.Deserialize()
	log.Logf(1, "poll: candidates=%v inputs=%v signal=%v",
		len(r.Candidates), len(r.NewInputs), maxSignal.Len())
	fuzzer.addMaxSignal(maxSignal)
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

// pollTestPairs polls the manager for test pair tasks and executes them
func (fuzzer *Fuzzer) pollTestPairs() {
	args := &rpctype.PollTestPairsArgs{
		FuzzerName: fuzzer.name,
		MaxTasks:   2, // request up to 2 test pairs at a time
	}
	res := &rpctype.PollTestPairsRes{}

	if err := fuzzer.manager.Call("Manager.PollTestPairs", args, res); err != nil {
		log.Logf(1, "Manager.PollTestPairs call failed: %v", err)
		return
	}

	if len(res.Tasks) == 0 {
		log.Logf(2, "PollTestPairs: 没有可用的test pair任务")
		return
	}

	log.Logf(0, "received %d test pair tasks", len(res.Tasks))

	// Execute test pairs and collect results
	results := make([]rpctype.TestPairResult, 0, len(res.Tasks))
	for _, task := range res.Tasks {
		result := fuzzer.executeTestPair(task)
		results = append(results, result)
	}

	// Submit results back to manager
	submitArgs := &rpctype.SubmitTestPairResultsArgs{
		FuzzerName: fuzzer.name,
		Results:    results,
	}
	var submitRes int
	if err := fuzzer.manager.Call("Manager.SubmitTestPairResults", submitArgs, &submitRes); err != nil {
		log.Logf(1, "Manager.SubmitTestPairResults call failed: %v", err)
	}
}

// executeTestPair executes a single test pair and returns the result
func (fuzzer *Fuzzer) executeTestPair(task rpctype.TestPairTask) rpctype.TestPairResult {
	result := rpctype.TestPairResult{
		ID:      task.ID,
		Success: false,
	}

	startTime := time.Now()
	defer func() {
		result.ExecTime = time.Since(startTime).Nanoseconds()
	}()

	// Deserialize programs
	prog1 := fuzzer.deserializeInput(task.Prog1)
	if prog1 == nil {
		result.Error = "failed to deserialize first program"
		return result
	}

	prog2 := fuzzer.deserializeInput(task.Prog2)
	if prog2 == nil {
		result.Error = "failed to deserialize second program"
		return result
	}

	// Ensure both programs have the same target
	if prog1.Target != prog2.Target {
		result.Error = "programs have different targets"
		return result
	}

	// Validate programs are well-formed
	if len(prog1.Calls) == 0 || len(prog2.Calls) == 0 {
		result.Error = "one or both programs have no system calls"
		return result
	}

	// Get an available executor
	if len(fuzzer.procs) == 0 {
		result.Error = "no executor processes available"
		return result
	}

	// Find a free process or use a dedicated one for test pairs
	var proc *Proc
	var procIndex int = -1

	// Try to find a less busy process (avoid proc[0] which is heavily used)
	for i := len(fuzzer.procs) - 1; i >= 0; i-- {
		proc = fuzzer.procs[i]
		err := proc.env.RestartIfNeeded(prog1.Target)
		if err == nil {
			procIndex = i
			break
		}
	}

	if procIndex == -1 {
		result.Error = "no available executor processes for test pair"
		return result
	}

	log.Logf(2, "Using executor process %d for test pair %s", procIndex, task.ID)

	// 使用新的ExecPair API进行并发执行
	opts1 := &ipc.ExecOpts{
		Flags: ipc.FlagCollectRace | ipc.FlagTestPairSync, // 启用race检测和同步
	}
	opts2 := &ipc.ExecOpts{
		Flags: ipc.FlagCollectRace | ipc.FlagTestPairSync, // 启用race检测和同步
	}

	// 如果task有特殊选项，合并它们
	if task.Opts != nil {
		opts1.Flags |= task.Opts.Flags
		opts2.Flags |= task.Opts.Flags
	}

	// 执行并发程序对
	_, info, hanged, err := proc.env.ExecPair(opts1, opts2, prog1, prog2)
	if err != nil {
		result.Error = fmt.Sprintf("pair execution failed: %v", err)
		return result
	}

	// TODO:需要增加对pair返回的info的处理的逻辑 或者先看看fuzzer 处理返回信息的逻辑是神恶魔 其实也不一定是在这里处理的
	// 更新race coverage 是在这里做的吗
	result.Info1 = &ipc.ProgInfo{
		Calls: make([]ipc.CallInfo, len(prog1.Calls)),
		Extra: ipc.CallInfo{},
	}
	result.Info2 = &ipc.ProgInfo{
		Calls: make([]ipc.CallInfo, len(prog2.Calls)),
		Extra: ipc.CallInfo{},
	}

	// 从统一的info中提取两个程序的信息
	result.Success = !hanged

	// 详细解析race数据，提取May Race Pair列表和Syscall关联信息
	if info != nil {
		races := fuzzer.extractDetailedRaceInfo(prog1, prog2, info)
		result.Races = races

		// ≈
		if len(races) > 0 {
			fuzzer.updateRaceCoverage(races)
		}

		// 记录详细的race信息到日志
		fuzzer.logDetailedRaceInfo(task.ID, prog1, prog2, info, races)
	}

	if hanged {
		result.Error = "program execution hanged"
	}

	log.Logf(2, "executed test pair %s: success=%v, races=%d", task.ID, result.Success, len(result.Races))

	return result
}

// AccessInfo 表示变量访问信息
type AccessInfo struct {
	Address     uint64
	AccessType1 string // 读/写类型
	AccessType2 string
	Syscall1    string // 关联的syscall
	Syscall2    string
}

// parseMappingData 解析MappingData中的变量访问信息
func (fuzzer *Fuzzer) parseMappingData(mappingData []byte) map[string]AccessInfo {
	result := make(map[string]AccessInfo)

	// 这里需要根据您的具体MappingData格式进行解析
	// 假设的格式解析 (需要根据实际executor输出格式调整)
	if len(mappingData) < 16 {
		log.Logf(3, "MappingData太短，无法解析: %d bytes", len(mappingData))
		return result
	}

	// 简单的解析示例 (需要根据实际格式调整)
	// 假设格式: [地址8字节][访问类型1字节][访问类型1字节][syscall_name_len][syscall_name]...
	offset := 0
	entryCount := 0

	for offset+16 <= len(mappingData) && entryCount < 10 { // 限制最多解析10个条目
		// 解析地址 (8字节)
		address := uint64(mappingData[offset]) |
			uint64(mappingData[offset+1])<<8 |
			uint64(mappingData[offset+2])<<16 |
			uint64(mappingData[offset+3])<<24 |
			uint64(mappingData[offset+4])<<32 |
			uint64(mappingData[offset+5])<<40 |
			uint64(mappingData[offset+6])<<48 |
			uint64(mappingData[offset+7])<<56
		offset += 8

		// 解析访问类型 (2字节) - 使用统一的转换函数
		accessType1 := getAccessTypeNameLocal(mappingData[offset])
		accessType2 := getAccessTypeNameLocal(mappingData[offset+1])
		offset += 2

		// 跳过线程ID (8字节) - 我们不再使用这些字段
		offset += 8

		// 生成变量名
		varName := fmt.Sprintf("var_0x%x", address)

		result[varName] = AccessInfo{
			Address:     address,
			AccessType1: accessType1,
			AccessType2: accessType2,
			Syscall1:    "unknown_syscall_1", // 需要从mapping data中解析
			Syscall2:    "unknown_syscall_2", // 需要从mapping data中解析
		}

		entryCount++

		log.Logf(3, "解析mapping条目 %d: 地址=0x%x, 访问=%s vs %s",
			entryCount, address, accessType1, accessType2)

		// 检查是否还有更多数据
		if offset >= len(mappingData) {
			break
		}
	}

	log.Logf(2, "总共解析了 %d 个mapping条目", entryCount)
	return result
}

// 注意：getAccessTypeName 函数已移动到 pkg/cover/extract.go 中统一管理
// 使用 cover.getAccessTypeName 替代本地实现

// getAccessTypeNameLocal 本地辅助函数，用于解析mapping data
// TODO: 统一到 pkg/cover 包中
func getAccessTypeNameLocal(accessType byte) string {
	switch accessType {
	case 0:
		return "read"
	case 1:
		return "write"
	case 2:
		return "read_write"
	case 3:
		return "modify"
	default:
		return fmt.Sprintf("unknown_%d", accessType)
	}
}

// logDetailedRaceInfo 记录详细的race信息到日志
func (fuzzer *Fuzzer) logDetailedRaceInfo(taskID string, prog1, prog2 *prog.Prog,
	info *ipc.ProgInfo, races []rpctype.RaceInfo) {

	log.Logf(1, "=== 详细Race信息 for Task %s ===", taskID)
	log.Logf(1, "程序1: %d个syscalls", len(prog1.Calls))
	log.Logf(1, "程序2: %d个syscalls", len(prog2.Calls))
	log.Logf(1, "总执行信息: %d个calls", len(info.Calls))
	log.Logf(1, "Extra race signals: %d", len(info.Extra.RaceData.Signals))
	log.Logf(1, "Extra mapping data: %d bytes", len(info.Extra.RaceData.MappingData))

	log.Logf(1, "=== May Race Pair列表 ===")
	for i, race := range races {
		log.Logf(1, "Race %d: %s vs %s, 锁类型=%s, signals=%d",
			i+1, race.Syscall1, race.Syscall2, race.LockType, len(race.Signals))
	}

	log.Logf(1, "=== Syscall关联信息 ===")
	for i, call := range prog1.Calls {
		log.Logf(2, "Prog1[%d]: %s", i, call.Meta.Name)
	}
	for i, call := range prog2.Calls {
		log.Logf(2, "Prog2[%d]: %s", i, call.Meta.Name)
	}

	log.Logf(1, "=== Race信息结束 ===")
}

// updateRaceCoverage 更新race coverage统计
func (fuzzer *Fuzzer) updateRaceCoverage(races []rpctype.RaceInfo) {
	if len(races) == 0 {
		return
	}

	// 将RaceInfo转换为RacePair - 使用cover包中的函数
	racePairs := cover.ExtractRacePairsFromRpcInfo(races)

	fuzzer.raceCoverMu.Lock()
	defer fuzzer.raceCoverMu.Unlock()

	// 初始化race coverage如果需要
	if fuzzer.corpusRaceCover == nil {
		fuzzer.corpusRaceCover = make(cover.RaceCover)
	}
	if fuzzer.maxRaceCover == nil {
		fuzzer.maxRaceCover = make(cover.RaceCover)
	}
	if fuzzer.newRaceCover == nil {
		fuzzer.newRaceCover = make(cover.RaceCover)
	}

	// 获取新的race pairs
	newRacePairs := fuzzer.maxRaceCover.MergeDiff(racePairs)

	if len(newRacePairs) > 0 {
		// 添加到corpus race coverage
		fuzzer.corpusRaceCover.Merge(racePairs)

		// 添加到新的race coverage (用于与manager同步)
		fuzzer.newRaceCover.Merge(newRacePairs)

		log.Logf(1, "发现 %d 个新的race pairs (总计: %d)",
			len(newRacePairs), fuzzer.maxRaceCover.Len())

		// 记录详细的新race pairs
		for _, rp := range newRacePairs {
			log.Logf(2, "新Race Pair: %s", rp.String())
		}
	}
}

// getRaceCoverageStats 获取race coverage统计信息
func (fuzzer *Fuzzer) getRaceCoverageStats() cover.RaceCoverageStats {
	fuzzer.raceCoverMu.RLock()
	defer fuzzer.raceCoverMu.RUnlock()

	if fuzzer.maxRaceCover == nil {
		return cover.RaceCoverageStats{}
	}

	return fuzzer.maxRaceCover.GetStats()
}

// getNewRaceCoverage 获取并清空新的race coverage (用于与manager同步)
func (fuzzer *Fuzzer) getNewRaceCoverage() []*cover.RacePair {
	fuzzer.raceCoverMu.Lock()
	defer fuzzer.raceCoverMu.Unlock()

	if fuzzer.newRaceCover == nil || fuzzer.newRaceCover.Len() == 0 {
		return nil
	}

	newRaces := fuzzer.newRaceCover.Serialize()
	fuzzer.newRaceCover.Clear() // 清空已同步的race coverage

	return newRaces
}

// hasInterestingRaceCoverage 检查是否有有趣的race coverage
func (fuzzer *Fuzzer) hasInterestingRaceCoverage(races []rpctype.RaceInfo) bool {
	if len(races) == 0 {
		return false
	}

	racePairs := cover.ExtractRacePairsFromRpcInfo(races)

	fuzzer.raceCoverMu.RLock()
	defer fuzzer.raceCoverMu.RUnlock()

	if fuzzer.maxRaceCover == nil {
		return len(racePairs) > 0 // 如果没有之前的coverage，任何race都是新的
	}

	// 检查是否有新的race pairs
	for _, rp := range racePairs {
		if !fuzzer.maxRaceCover.Contains(rp) {
			return true
		}
	}

	return false
}
