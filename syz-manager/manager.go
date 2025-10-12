// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/asset"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	crash_pkg "github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
	flagDebug  = flag.Bool("debug", false, "dump all VM output to console")
	flagBench  = flag.String("bench", "", "write execution statistics into this file periodically")
)

type Manager struct {
	cfg            *mgrconfig.Config
	vmPool         *vm.Pool
	target         *prog.Target
	sysTarget      *targets.Target
	reporter       *report.Reporter
	crashdir       string
	uafdir         string // Directory for storing UAF logs
	serv           *RPCServer
	corpusDB       *db.DB
	startTime      time.Time
	firstConnect   time.Time
	fuzzingTime    time.Duration
	stats          *Stats
	crashTypes     map[string]bool
	vmStop         chan bool
	checkResult    *rpctype.CheckArgs
	fresh          bool
	numFuzzing     uint32
	numReproducing uint32

	// ===============DDRD====================
	// Fuzz scheduler for managing normal and race pair modes
	fuzzScheduler *FuzzScheduler

	// Race corpus management
	raceCorpusDB *db.DB
	raceCorpus   map[uint64]*RaceCorpusItem
	raceCorpusMu sync.RWMutex
	raceStats    struct {
		totalPairs   int64
		uniqueRaces  int64
		lastSaveTime time.Time
	}

	// UAF corpus management
	uafCorpusDB *db.DB
	uafCorpus   map[uint64]*UAFCorpusItem
	uafCorpusMu sync.RWMutex
	uafStats    struct {
		totalPairs   int64
		uniqueUAFs   int64
		lastSaveTime time.Time
	}

	// UAF Coverage and Signal tracking
	maxUAFCover  ddrd.UAFCover
	maxUAFSignal ddrd.UAFSignal
	uafCoverMu   sync.RWMutex
	uafSignalMu  sync.RWMutex
	// ===============DDRD====================

	dash *dashapi.Dashboard

	mu                    sync.RWMutex
	phase                 int
	targetEnabledSyscalls map[*prog.Syscall]bool

	candidates           []rpctype.Candidate     // untriaged inputs from corpus and hub
	pairCandidates       []rpctype.PairCandidate // pairs of candidates for race testing
	raceCorpusCandidates []rpctype.PairCandidate // high-priority race pairs from race corpus
	disabledHashes       map[string]struct{}
	corpus               map[string]CorpusItem
	seeds                [][]byte
	newRepros            [][]byte
	lastMinCorpus        int
	memoryLeakFrames     map[string]bool
	dataRaceFrames       map[string]bool
	// Track duplicate data race VarName combinations to avoid repeated reports
	reportedDataRaceCombinations map[string]bool
	saturatedCalls               map[string]bool

	needMoreRepros     chan chan bool
	externalReproQueue chan *Crash
	reproRequest       chan chan map[string]bool

	// For checking that files that we are using are not changing under us.
	// Maps file name to modification time.
	usedFiles map[string]time.Time

	modules             []host.KernelModule
	coverFilter         map[uint32]uint32
	execCoverFilter     map[uint32]uint32
	modulesInitialized  bool
	afterTriageStatSent bool

	assetStorage *asset.Storage
}

type CorpusItemUpdate struct {
	CallID   int
	RawCover []uint32
}

type CorpusItem struct {
	Call    string
	Prog    []byte
	Signal  signal.Serial
	Cover   []uint32
	Updates []CorpusItemUpdate
}

// ===============DDRD====================
// Race Corpus Data Structures
// ===============DDRD====================

// RaceCorpusItem represents a race pair item in the corpus
type RaceCorpusItem struct {
	PairID      string    `json:"pair_id"`
	Prog1       []byte    `json:"prog1"`
	Prog2       []byte    `json:"prog2"`
	RaceSignal  []byte    `json:"race_signal"` // serialized ddrd.Serial
	Races       []byte    `json:"races"`       // serialized []ddrd.MayRacePair
	FirstSeen   time.Time `json:"first_seen"`
	LastUpdated time.Time `json:"last_updated"`
	Source      string    `json:"source"`             // source fuzzer name
	LogPath     string    `json:"log_path,omitempty"` // path to log file for reproduction
	Count       int       `json:"count"`              // discovery count
}

// UAFCorpusItem represents a UAF pair item in the corpus
type UAFCorpusItem struct {
	PairID           string    `json:"pair_id"`
	Prog1            []byte    `json:"prog1"`
	Prog2            []byte    `json:"prog2"`
	UAFSignal        []byte    `json:"uaf_signal"`        // serialized UAF signal
	UAFs             []byte    `json:"uafs"`              // serialized []ddrd.MayUAFPair
	Output           []byte    `json:"output"`            // execution output for debugging
	ExecutionContext []byte    `json:"execution_context"` // serialized execution sequence context
	FirstSeen        time.Time `json:"first_seen"`
	LastUpdated      time.Time `json:"last_updated"`
	Source           string    `json:"source"`             // source fuzzer name
	LogPath          string    `json:"log_path,omitempty"` // path to log file for reproduction
	Count            int       `json:"count"`              // discovery count
}

// ===============DDRD====================

func (item *CorpusItem) RPCInput() rpctype.Input {
	return rpctype.Input{
		Call:   item.Call,
		Prog:   item.Prog,
		Signal: item.Signal,
		Cover:  item.Cover,
	}
}

const (
	// Just started, nothing done yet.
	phaseInit = iota
	// Corpus is loaded and machine is checked.
	phaseLoadedCorpus
	// Triaged all inputs from corpus.
	// This is when we start querying hub and minimizing persistent corpus.
	phaseTriagedCorpus
	// Done the first request to hub.
	phaseQueriedHub
	// Triaged all new inputs from hub.
	// This is when we start reproducing crashes.
	phaseTriagedHub
)

const currentDBVersion = 4

type Crash struct {
	vmIndex  int
	external bool // this crash was created based on a repro from hub or dashboard
	*report.Report
	machineInfo []byte
}

func main() {
	if prog.GitRevision == "" {
		log.Fatalf("bad syz-manager build: build with make, run bin/syz-manager")
	}
	flag.Parse()
	log.EnableLogCaching(1000, 1<<20)
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if cfg.DashboardAddr != "" {
		// This lets better distinguish logs of individual syz-manager instances.
		log.SetName(cfg.Name)
	}
	RunManager(cfg)
}

func RunManager(cfg *mgrconfig.Config) {
	var vmPool *vm.Pool
	// Type "none" is a special case for debugging/development when manager
	// does not start any VMs, but instead you start them manually
	// and start syz-fuzzer there.
	if cfg.Type != "none" {
		var err error
		vmPool, err = vm.Create(cfg, *flagDebug)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}

	crashdir := filepath.Join(cfg.Workdir, "crashes")
	osutil.MkdirAll(crashdir)

	uafdir := filepath.Join(cfg.Workdir, "uaf_logs")
	osutil.MkdirAll(uafdir)

	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	mgr := &Manager{
		cfg:                          cfg,
		vmPool:                       vmPool,
		target:                       cfg.Target,
		sysTarget:                    cfg.SysTarget,
		reporter:                     reporter,
		crashdir:                     crashdir,
		uafdir:                       uafdir,
		startTime:                    time.Now(),
		stats:                        &Stats{haveHub: cfg.HubClient != ""},
		crashTypes:                   make(map[string]bool),
		corpus:                       make(map[string]CorpusItem),
		disabledHashes:               make(map[string]struct{}),
		memoryLeakFrames:             make(map[string]bool),
		dataRaceFrames:               make(map[string]bool),
		reportedDataRaceCombinations: make(map[string]bool),
		fresh:                        true,
		vmStop:                       make(chan bool),
		externalReproQueue:           make(chan *Crash, 10),
		needMoreRepros:               make(chan chan bool),
		reproRequest:                 make(chan chan map[string]bool),
		usedFiles:                    make(map[string]time.Time),
		saturatedCalls:               make(map[string]bool),
		// ===============DDRD====================
		// Initialize fuzz scheduler for mode management
		fuzzScheduler: NewFuzzScheduler(FuzzMode(cfg.Experimental.FuzzMode)),
		// Initialize race corpus
		raceCorpus: make(map[uint64]*RaceCorpusItem),
		// Initialize UAF corpus
		uafCorpus: make(map[uint64]*UAFCorpusItem),
		// Initialize UAF coverage and signals
		maxUAFCover:  make(ddrd.UAFCover),
		maxUAFSignal: make(ddrd.UAFSignal),
		// ===============DDRD====================
	}

	// ===============DDRD====================
	// Initialize mode transition synchronization
	mgr.initModeTransitionSync()
	// ===============DDRD====================

	mgr.preloadCorpus()
	// ===============DDRD====================
	// Initialize race corpus
	// mgr.initRaceCorpus()
	// Initialize UAF corpus
	mgr.initUAFCorpus()
	// ===============DDRD====================
	mgr.initStats() // Initializes prometheus variables.

	mgr.initHTTP() // Creates HTTP server.
	mgr.collectUsedFiles()

	// Create RPC server for fuzzers.
	mgr.serv, err = startRPCServer(mgr)
	if err != nil {
		log.Fatalf("failed to create rpc server: %v", err)
	}

	if cfg.DashboardAddr != "" {
		mgr.dash, err = dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey)
		if err != nil {
			log.Fatalf("failed to create dashapi connection: %v", err)
		}
	}

	if !cfg.AssetStorage.IsEmpty() {
		mgr.assetStorage, err = asset.StorageFromConfig(cfg.AssetStorage, mgr.dash)
		if err != nil {
			log.Fatalf("failed to init asset storage: %v", err)
		}
	}

	go func() {
		for lastTime := time.Now(); ; {
			time.Sleep(10 * time.Second)
			now := time.Now()
			diff := now.Sub(lastTime)
			lastTime = now
			mgr.mu.Lock()
			if mgr.firstConnect.IsZero() {
				mgr.mu.Unlock()
				continue
			}
			mgr.fuzzingTime += diff * time.Duration(atomic.LoadUint32(&mgr.numFuzzing))
			executed := mgr.stats.execTotal.get()
			execNormal := mgr.stats.execNormal.get()
			execRace := mgr.stats.execRace.get()
			crashes := mgr.stats.crashes.get()
			corpusCover := mgr.stats.corpusCover.get()
			corpusSignal := mgr.stats.corpusSignal.get()
			maxSignal := mgr.stats.maxSignal.get()
			raceSignals := mgr.stats.raceSignals.get()
			newRaceSignals := mgr.stats.newRaceSignals.get()
			uafSignals := mgr.stats.uafSignals.get()
			newUAFSignals := mgr.stats.newUAFSignals.get()
			triageQLen := len(mgr.candidates)
			mgr.mu.Unlock()
			numReproducing := atomic.LoadUint32(&mgr.numReproducing)
			numFuzzing := atomic.LoadUint32(&mgr.numFuzzing)

			log.Logf(0, "VMs %v, executed %v (normal %v, race %v), cover %v, signal %v/%v, raceSignal %v/%v, uafSignal %v/%v, crashes %v, repro %v, triageQLen %v",
				numFuzzing, executed, execNormal, execRace, corpusCover, corpusSignal, maxSignal, newRaceSignals, raceSignals, newUAFSignals, uafSignals, crashes, numReproducing, triageQLen)
		}
	}()

	if *flagBench != "" {
		mgr.initBench()
	}

	if mgr.dash != nil {
		go mgr.dashboardReporter()
		go mgr.dashboardReproTasks()
	}

	osutil.HandleInterrupts(vm.Shutdown)
	if mgr.vmPool == nil {
		log.Logf(0, "no VMs started (type=none)")
		log.Logf(0, "you are supposed to start syz-fuzzer manually as:")
		log.Logf(0, "syz-fuzzer -manager=manager.ip:%v [other flags as necessary]", mgr.serv.port)
		<-vm.Shutdown
		return
	}
	mgr.vmLoop()
}

func (mgr *Manager) initBench() {
	f, err := os.OpenFile(*flagBench, os.O_WRONLY|os.O_CREATE|os.O_EXCL, osutil.DefaultFilePerm)
	if err != nil {
		log.Fatalf("failed to open bench file: %v", err)
	}
	go func() {
		for {
			time.Sleep(time.Minute)
			vals := mgr.stats.all()
			mgr.mu.Lock()
			if mgr.firstConnect.IsZero() {
				mgr.mu.Unlock()
				continue
			}
			mgr.minimizeCorpus()
			vals["corpus"] = uint64(len(mgr.corpus))
			vals["uptime"] = uint64(time.Since(mgr.firstConnect)) / 1e9
			vals["fuzzing"] = uint64(mgr.fuzzingTime) / 1e9
			vals["candidates"] = uint64(len(mgr.candidates))
			mgr.mu.Unlock()

			data, err := json.MarshalIndent(vals, "", "  ")
			if err != nil {
				log.Fatalf("failed to serialize bench data")
			}
			if _, err := f.Write(append(data, '\n')); err != nil {
				log.Fatalf("failed to write bench data")
			}
		}
	}()
}

// ===============DDRD====================
// initModeTransitionSync 初始化模式切换同步机制
// ===============DDRD====================
func (mgr *Manager) initModeTransitionSync() {
	if mgr.fuzzScheduler == nil {
		return
	}

	// 设置重启式切换管理器
	mgr.fuzzScheduler.SetupTransitionManager(mgr)

	log.Logf(1, "Restart-based mode transition initialized")
}

// ===============DDRD====================

type RunResult struct {
	idx   int
	crash *Crash
	err   error
}

type ReproResult struct {
	instances     []int
	report0       *report.Report // the original report we started reproducing
	repro         *repro.Result
	strace        *repro.StraceResult
	stats         *repro.Stats
	err           error
	external      bool   // repro came from hub or dashboard
	originalTitle string // crash title before we started bug reproduction
}

// Manager needs to be refactored (#605).
// nolint: gocyclo, gocognit, funlen
func (mgr *Manager) vmLoop() {
	log.Logf(0, "booting test machines...")
	log.Logf(0, "wait for the connection from test machine...")
	instancesPerRepro := 3
	vmCount := mgr.vmPool.Count()
	maxReproVMs := vmCount - mgr.cfg.FuzzingVMs
	if instancesPerRepro > maxReproVMs && maxReproVMs > 0 {
		instancesPerRepro = maxReproVMs
	}
	instances := SequentialResourcePool(vmCount, 10*time.Second*mgr.cfg.Timeouts.Scale)
	runDone := make(chan *RunResult, 1)
	pendingRepro := make(map[*Crash]bool)
	reproducing := make(map[string]bool)
	var reproQueue []*Crash
	reproDone := make(chan *ReproResult, 1)
	stopPending := false
	shutdown := vm.Shutdown
	for shutdown != nil || instances.Len() != vmCount {
		mgr.mu.Lock()
		phase := mgr.phase
		mgr.mu.Unlock()

		for crash := range pendingRepro {
			if reproducing[crash.Title] {
				continue
			}
			delete(pendingRepro, crash)
			if !mgr.needRepro(crash) {
				continue
			}
			log.Logf(1, "loop: add to repro queue '%v'", crash.Title)
			reproducing[crash.Title] = true
			reproQueue = append(reproQueue, crash)
		}

		log.Logf(1, "loop: phase=%v shutdown=%v instances=%v/%v %+v repro: pending=%v reproducing=%v queued=%v",
			phase, shutdown == nil, instances.Len(), vmCount, instances.Snapshot(),
			len(pendingRepro), len(reproducing), len(reproQueue))

		canRepro := func() bool {
			return phase >= phaseTriagedHub && len(reproQueue) != 0 &&
				(int(atomic.LoadUint32(&mgr.numReproducing))+1)*instancesPerRepro <= maxReproVMs
		}

		if shutdown != nil {
			for canRepro() {
				vmIndexes := instances.Take(instancesPerRepro)
				if vmIndexes == nil {
					break
				}
				last := len(reproQueue) - 1
				crash := reproQueue[last]
				reproQueue[last] = nil
				reproQueue = reproQueue[:last]
				atomic.AddUint32(&mgr.numReproducing, 1)
				log.Logf(0, "loop: starting repro of '%v' on instances %+v", crash.Title, vmIndexes)
				go func() {
					reproDone <- mgr.runRepro(crash, vmIndexes, instances.Put)
				}()
			}
			for !canRepro() {
				idx := instances.TakeOne()
				if idx == nil {
					break
				}
				log.Logf(1, "loop: starting instance %v", *idx)
				go func() {
					crash, err := mgr.runInstance(*idx)
					runDone <- &RunResult{*idx, crash, err}
				}()
			}
		}

		var stopRequest chan bool
		if !stopPending && canRepro() {
			stopRequest = mgr.vmStop
		}

	wait:
		select {
		case <-instances.Freed:
			// An instance has been released.
		case stopRequest <- true:
			log.Logf(1, "loop: issued stop request")
			stopPending = true
		case res := <-runDone:
			log.Logf(1, "loop: instance %v finished, crash=%v", res.idx, res.crash != nil)
			if res.err != nil && shutdown != nil {
				log.Logf(0, "%v", res.err)
			}
			stopPending = false
			instances.Put(res.idx)
			// On shutdown qemu crashes with "qemu: terminating on signal 2",
			// which we detect as "lost connection". Don't save that as crash.
			if shutdown != nil && res.crash != nil {
				needRepro := mgr.saveCrash(res.crash)
				if needRepro {
					log.Logf(1, "loop: add pending repro for '%v'", res.crash.Title)
					pendingRepro[res.crash] = true
				}
			}
		case res := <-reproDone:
			atomic.AddUint32(&mgr.numReproducing, ^uint32(0))
			crepro := false
			title := ""
			if res.repro != nil {
				crepro = res.repro.CRepro
				title = res.repro.Report.Title
			}
			log.Logf(0, "loop: repro on %+v finished '%v', repro=%v crepro=%v desc='%v'",
				res.instances, res.report0.Title, res.repro != nil, crepro, title)
			if res.err != nil {
				reportReproError(res.err)
			}
			delete(reproducing, res.report0.Title)
			if res.repro == nil {
				if !res.external {
					mgr.saveFailedRepro(res.report0, res.stats)
				}
			} else {
				mgr.saveRepro(res)
			}
		case <-shutdown:
			log.Logf(1, "loop: shutting down...")
			shutdown = nil
		case crash := <-mgr.externalReproQueue:
			log.Logf(1, "loop: got repro request")
			pendingRepro[crash] = true
		case reply := <-mgr.needMoreRepros:
			reply <- phase >= phaseTriagedHub &&
				len(reproQueue)+len(pendingRepro)+len(reproducing) == 0
			goto wait
		case reply := <-mgr.reproRequest:
			repros := make(map[string]bool)
			for title := range reproducing {
				repros[title] = true
			}
			reply <- repros
			goto wait
		}
	}
}

func reportReproError(err error) {
	shutdown := false
	select {
	case <-vm.Shutdown:
		shutdown = true
	default:
	}

	switch err {
	case repro.ErrNoPrograms:
		// This is not extraordinary as programs are collected via SSH.
		log.Logf(0, "repro failed: %v", err)
		return
	case repro.ErrNoVMs:
		// This error is to be expected if we're shutting down.
		if shutdown {
			return
		}
	}
	// Report everything else as errors.
	log.Errorf("repro failed: %v", err)
}

func (mgr *Manager) runRepro(crash *Crash, vmIndexes []int, putInstances func(...int)) *ReproResult {
	features := mgr.checkResult.Features
	res, stats, err := repro.Run(crash.Output, mgr.cfg, features, mgr.reporter, mgr.vmPool, vmIndexes)
	ret := &ReproResult{
		instances:     vmIndexes,
		report0:       crash.Report,
		repro:         res,
		stats:         stats,
		err:           err,
		external:      crash.external,
		originalTitle: crash.Title,
	}
	if err == nil && res != nil && mgr.cfg.StraceBin != "" {
		// We need only one instance to get strace output, release the rest.
		putInstances(vmIndexes[1:]...)
		defer putInstances(vmIndexes[0])

		const straceAttempts = 2
		for i := 1; i <= straceAttempts; i++ {
			strace := repro.RunStrace(res, mgr.cfg, mgr.reporter, mgr.vmPool, vmIndexes[0])
			sameBug := strace.IsSameBug(res)
			log.Logf(0, "strace run attempt %d/%d for '%s': same bug %v, error %v",
				i, straceAttempts, res.Report.Title, sameBug, strace.Error)
			// We only want to save strace output if it resulted in the same bug.
			// Otherwise, it will be hard to reproduce on syzbot and will confuse users.
			if sameBug {
				ret.strace = strace
				break
			}
		}
	} else {
		putInstances(vmIndexes...)
	}
	return ret
}

type ResourcePool struct {
	ids   []int
	mu    sync.RWMutex
	Freed chan interface{}
}

func SequentialResourcePool(count int, delay time.Duration) *ResourcePool {
	ret := &ResourcePool{Freed: make(chan interface{}, 1)}
	go func() {
		for i := 0; i < count; i++ {
			ret.Put(i)
			time.Sleep(delay)
		}
	}()
	return ret
}

func (pool *ResourcePool) Put(ids ...int) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pool.ids = append(pool.ids, ids...)
	// Notify the listener.
	select {
	case pool.Freed <- true:
	default:
	}
}

func (pool *ResourcePool) Len() int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return len(pool.ids)
}

func (pool *ResourcePool) Snapshot() []int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return append([]int{}, pool.ids...)
}

func (pool *ResourcePool) Take(cnt int) []int {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	totalItems := len(pool.ids)
	if totalItems < cnt {
		return nil
	}
	ret := append([]int{}, pool.ids[totalItems-cnt:]...)
	pool.ids = pool.ids[:totalItems-cnt]
	return ret
}

func (pool *ResourcePool) TakeOne() *int {
	ret := pool.Take(1)
	if ret == nil {
		return nil
	}
	return &ret[0]
}

func (mgr *Manager) preloadCorpus() {
	log.Logf(0, "loading corpus...")
	corpusDB, err := db.Open(filepath.Join(mgr.cfg.Workdir, "corpus.db"), true)
	if err != nil {
		if corpusDB == nil {
			log.Fatalf("failed to open corpus database: %v", err)
		}
		log.Errorf("read %v inputs from corpus and got error: %v", len(corpusDB.Records), err)
	}
	mgr.corpusDB = corpusDB

	if seedDir := filepath.Join(mgr.cfg.Syzkaller, "sys", mgr.cfg.TargetOS, "test"); osutil.IsExist(seedDir) {
		seeds, err := os.ReadDir(seedDir)
		if err != nil {
			log.Fatalf("failed to read seeds dir: %v", err)
		}
		for _, seed := range seeds {
			data, err := os.ReadFile(filepath.Join(seedDir, seed.Name()))
			if err != nil {
				log.Fatalf("failed to read seed %v: %v", seed.Name(), err)
			}
			mgr.seeds = append(mgr.seeds, data)
		}
	}
}

func (mgr *Manager) loadCorpus() {
	// By default we don't re-minimize/re-smash programs from corpus,
	// it takes lots of time on start and is unnecessary.
	// However, on version bumps we can selectively re-minimize/re-smash.
	minimized, smashed := true, true
	switch mgr.corpusDB.Version {
	case 0:
		// Version 0 had broken minimization, so we need to re-minimize.
		minimized = false
		fallthrough
	case 1:
		// Version 1->2: memory is preallocated so lots of mmaps become unnecessary.
		minimized = false
		fallthrough
	case 2:
		// Version 2->3: big-endian hints.
		smashed = false
		fallthrough
	case 3:
		// Version 3->4: to shake things up.
		minimized = false
		fallthrough
	case currentDBVersion:
	}
	broken := 0
	for key, rec := range mgr.corpusDB.Records {
		if !mgr.loadProg(rec.Val, minimized, smashed) {
			mgr.corpusDB.Delete(key)
			broken++
		}
	}
	mgr.fresh = len(mgr.corpusDB.Records) == 0
	corpusSize := len(mgr.candidates)
	log.Logf(0, "%-24v: %v (deleted %v broken)", "corpus", corpusSize, broken)

	for _, seed := range mgr.seeds {
		mgr.loadProg(seed, true, false)
	}
	log.Logf(0, "%-24v: %v/%v", "seeds", len(mgr.candidates)-corpusSize, len(mgr.seeds))
	mgr.seeds = nil

	// We duplicate all inputs in the corpus and shuffle the second part.
	// This solves the following problem. A fuzzer can crash while triaging candidates,
	// in such case it will also lost all cached candidates. Or, the input can be somewhat flaky
	// and doesn't give the coverage on first try. So we give each input the second chance.
	// Shuffling should alleviate deterministically losing the same inputs on fuzzer crashing.
	mgr.candidates = append(mgr.candidates, mgr.candidates...)
	shuffle := mgr.candidates[len(mgr.candidates)/2:]
	rand.Shuffle(len(shuffle), func(i, j int) {
		shuffle[i], shuffle[j] = shuffle[j], shuffle[i]
	})
	if mgr.phase != phaseInit {
		panic(fmt.Sprintf("loadCorpus: bad phase %v", mgr.phase))
	}
	mgr.phase = phaseLoadedCorpus

	// Generate initial pair candidates after corpus is loaded
	mgr.generatePairCandidates()
}

func (mgr *Manager) loadProg(data []byte, minimized, smashed bool) bool {
	bad, disabled := checkProgram(mgr.target, mgr.targetEnabledSyscalls, data)
	if bad != nil {
		return false
	}
	if disabled {
		if mgr.cfg.PreserveCorpus {
			// This program contains a disabled syscall.
			// We won't execute it, but remember its hash so
			// it is not deleted during minimization.
			mgr.disabledHashes[hash.String(data)] = struct{}{}
		} else {
			// We cut out the disabled syscalls and let syz-fuzzer retriage and
			// minimize what remains from the prog. The original prog will be
			// deleted from the corpus.
			leftover := programLeftover(mgr.target, mgr.targetEnabledSyscalls, data)
			if len(leftover) > 0 {
				mgr.candidates = append(mgr.candidates, rpctype.Candidate{
					Prog:      leftover,
					Minimized: false,
					Smashed:   smashed,
				})
			}
		}
		return true
	}
	mgr.candidates = append(mgr.candidates, rpctype.Candidate{
		Prog:      data,
		Minimized: minimized,
		Smashed:   smashed,
	})
	return true
}

func programLeftover(target *prog.Target, enabled map[*prog.Syscall]bool, data []byte) []byte {
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		panic(fmt.Sprintf("subsequent deserialization failed: %s", data))
	}
	for i := 0; i < len(p.Calls); {
		c := p.Calls[i]
		if !enabled[c.Meta] {
			p.RemoveCall(i)
			continue
		}
		i++
	}
	return p.Serialize()
}

func checkProgram(target *prog.Target, enabled map[*prog.Syscall]bool, data []byte) (bad error, disabled bool) {
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		return err, true
	}
	if len(p.Calls) > prog.MaxCalls {
		return fmt.Errorf("longer than %d calls", prog.MaxCalls), true
	}
	// For some yet unknown reasons, programs with fail_nth > 0 may sneak in. Ignore them.
	for _, call := range p.Calls {
		if call.Props.FailNth > 0 {
			return fmt.Errorf("input has fail_nth > 0"), true
		}
	}
	for _, c := range p.Calls {
		if !enabled[c.Meta] {
			return nil, true
		}
	}
	return nil, false
}

func (mgr *Manager) runInstance(index int) (*Crash, error) {
	mgr.checkUsedFiles()
	instanceName := fmt.Sprintf("vm-%d", index)

	rep, vmInfo, err := mgr.runInstanceInner(index, instanceName)

	machineInfo := mgr.serv.shutdownInstance(instanceName)
	if len(vmInfo) != 0 {
		machineInfo = append(append(vmInfo, '\n'), machineInfo...)
	}

	// Error that is not a VM crash.
	if err != nil {
		return nil, err
	}
	// No crash.
	if rep == nil {
		return nil, nil
	}
	crash := &Crash{
		vmIndex:     index,
		external:    false,
		Report:      rep,
		machineInfo: machineInfo,
	}
	return crash, nil
}

func (mgr *Manager) runInstanceInner(index int, instanceName string) (*report.Report, []byte, error) {
	inst, err := mgr.vmPool.Create(index)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create instance: %w", err)
	}
	defer inst.Close()

	fwdAddr, err := inst.Forward(mgr.serv.port)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup port forwarding: %w", err)
	}

	fuzzerBin, err := inst.Copy(mgr.cfg.FuzzerBin)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to copy binary: %w", err)
	}

	// If ExecutorBin is provided, it means that syz-executor is already in the image,
	// so no need to copy it.
	executorBin := mgr.sysTarget.ExecutorBin
	if executorBin == "" {
		executorBin, err = inst.Copy(mgr.cfg.ExecutorBin)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	fuzzerV := 0
	procs := mgr.cfg.Procs
	if *flagDebug {
		fuzzerV = 100
		procs = 1
	}

	// Run the fuzzer binary.
	start := time.Now()
	atomic.AddUint32(&mgr.numFuzzing, 1)
	defer atomic.AddUint32(&mgr.numFuzzing, ^uint32(0))

	args := &instance.FuzzerCmdArgs{
		Fuzzer:    fuzzerBin,
		Executor:  executorBin,
		Name:      instanceName,
		OS:        mgr.cfg.TargetOS,
		Arch:      mgr.cfg.TargetArch,
		FwdAddr:   fwdAddr,
		Sandbox:   mgr.cfg.Sandbox,
		Procs:     procs,
		Verbosity: fuzzerV,
		Cover:     mgr.cfg.Cover,
		Debug:     *flagDebug,
		Test:      false,
		Runtest:   false,
		Optional: &instance.OptionalFuzzerArgs{
			Slowdown:      mgr.cfg.Timeouts.Slowdown,
			RawCover:      mgr.cfg.RawCover,
			SandboxArg:    mgr.cfg.SandboxArg,
			PprofPort:     inst.PprofPort(),
			ResetAccState: mgr.cfg.Experimental.ResetAccState,
		},
	}
	cmd := instance.FuzzerCmd(args)
	outc, errc, err := inst.Run(mgr.cfg.Timeouts.VMRunningTime, mgr.vmStop, cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run fuzzer: %w", err)
	}

	var vmInfo []byte
	// Create monitor config for skipping duplicate data races
	monitorConfig := mgr.createMonitorConfig()
	rep := inst.MonitorExecutionWithConfig(outc, errc, mgr.reporter, vm.ExitTimeout, monitorConfig)
	if rep == nil {
		// This is the only "OK" outcome.
		log.Logf(0, "%s: running for %v, restarting", instanceName, time.Since(start))
	} else {
		vmInfo, err = inst.Info()
		if err != nil {
			vmInfo = []byte(fmt.Sprintf("error getting VM info: %v\n", err))
		}
	}

	return rep, vmInfo, nil
}

func (mgr *Manager) emailCrash(crash *Crash) {
	if len(mgr.cfg.EmailAddrs) == 0 {
		return
	}
	args := []string{"-s", "syzkaller: " + crash.Title}
	args = append(args, mgr.cfg.EmailAddrs...)
	log.Logf(0, "sending email to %v", mgr.cfg.EmailAddrs)

	cmd := exec.Command("mailx", args...)
	cmd.Stdin = bytes.NewReader(crash.Report.Report)
	if _, err := osutil.Run(10*time.Minute, cmd); err != nil {
		log.Logf(0, "failed to send email: %v", err)
	}
}

func (mgr *Manager) saveCrash(crash *Crash) bool {
	if err := mgr.reporter.Symbolize(crash.Report); err != nil {
		log.Errorf("failed to symbolize report: %v", err)
	}
	if crash.Type == crash_pkg.MemoryLeak {
		mgr.mu.Lock()
		mgr.memoryLeakFrames[crash.Frame] = true
		mgr.mu.Unlock()
	}
	if crash.Type == crash_pkg.DataRace {
		mgr.mu.Lock()
		mgr.dataRaceFrames[crash.Frame] = true
		mgr.mu.Unlock()

		// Handle custom datarace reports - simplified for queue-based system
		if crash.Report.IsDataRaceReport() {
			log.Logf(0, "vm-%v: new datarace report detected and logged", crash.vmIndex)

			// Output race summary if available
			if len(crash.Report.GetReportedRaces()) > 0 {
				raceSummary := crash.Report.FormatRacesSummary()
				log.Logf(0, "vm-%v: race details: %s", crash.vmIndex, raceSummary)
			}
		}

	}
	flags := ""
	if crash.Corrupted {
		flags += " [corrupted]"
	}
	if crash.Suppressed {
		flags += " [suppressed]"
	}
	log.Logf(0, "vm-%v: crash: %v%v", crash.vmIndex, crash.Title, flags)

	if crash.Suppressed {
		// Collect all of them into a single bucket so that it's possible to control and assess them,
		// e.g. if there are some spikes in suppressed reports.
		crash.Title = "suppressed report"
		mgr.stats.crashSuppressed.inc()
	}

	mgr.stats.crashes.inc()
	mgr.mu.Lock()
	if !mgr.crashTypes[crash.Title] {
		mgr.crashTypes[crash.Title] = true
		mgr.stats.crashTypes.inc()
	}
	mgr.mu.Unlock()

	if mgr.dash != nil {
		if crash.Type == crash_pkg.MemoryLeak {
			return true
		}
		dc := &dashapi.Crash{
			BuildID:     mgr.cfg.Tag,
			Title:       crash.Title,
			AltTitles:   crash.AltTitles,
			Corrupted:   crash.Corrupted,
			Suppressed:  crash.Suppressed,
			Recipients:  crash.Recipients.ToDash(),
			Log:         crash.Output,
			Report:      crash.Report.Report,
			MachineInfo: crash.machineInfo,
		}
		setGuiltyFiles(dc, crash.Report)
		resp, err := mgr.dash.ReportCrash(dc)
		if err != nil {
			log.Logf(0, "failed to report crash to dashboard: %v", err)
		} else {
			// Don't store the crash locally, if we've successfully
			// uploaded it to the dashboard. These will just eat disk space.
			return resp.NeedRepro
		}
	}

	sig := hash.Hash([]byte(crash.Title))
	id := sig.String()
	dir := filepath.Join(mgr.crashdir, id)
	osutil.MkdirAll(dir)
	if err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(crash.Title+"\n")); err != nil {
		log.Logf(0, "failed to write crash: %v", err)
	}

	// Save up to mgr.cfg.MaxCrashLogs reports, overwrite the oldest once we've reached that number.
	// Newer reports are generally more useful. Overwriting is also needed
	// to be able to understand if a particular bug still happens or already fixed.
	oldestI := 0
	var oldestTime time.Time
	for i := 0; i < mgr.cfg.MaxCrashLogs; i++ {
		info, err := os.Stat(filepath.Join(dir, fmt.Sprintf("log%v", i)))
		if err != nil {
			oldestI = i
			if i == 0 {
				go mgr.emailCrash(crash)
			}
			break
		}
		if oldestTime.IsZero() || info.ModTime().Before(oldestTime) {
			oldestI = i
			oldestTime = info.ModTime()
		}
	}
	writeOrRemove := func(name string, data []byte) {
		filename := filepath.Join(dir, name+fmt.Sprint(oldestI))
		if len(data) == 0 {
			os.Remove(filename)
			return
		}
		osutil.WriteFile(filename, data)
	}
	writeOrRemove("log", crash.Output)
	writeOrRemove("tag", []byte(mgr.cfg.Tag))
	writeOrRemove("report", crash.Report.Report)
	writeOrRemove("machineInfo", crash.machineInfo)
	return mgr.needLocalRepro(crash)
}

// saveUAFPair saves UAF pair information to disk, similar to saveCrash
//
// Method B: Direct saving to final location
// 1. This function (saveUAFPair): Create UAF directory + Signal monitor with target path + Save metadata
// 2. Monitor process: Receive signal + Save VM output directly to target log file
//
// Workflow:
// Step 1: Create UAF pair directory and determine log rotation index
// Step 2: Send signal to VM monitor with target file path
// Step 3: Monitor saves VM output directly to uafpairs/uaf_<pairID>/log<N>
// saveUAFPair saves UAF pair information to database instead of files
// This simplified version stores all UAF data including execution context in the database
func (mgr *Manager) saveUAFPair(args *rpctype.NewUAFPairArgs) {
	// Simply delegate to saveUAFCorpusItem for database storage
	mgr.saveUAFCorpusItem(args)

	log.Logf(1, "saved UAF pair %x to database (output: %d bytes, context: %t)",
		args.Pair.PairID, len(args.Pair.Output), args.Pair.ExecutionContext != nil)
}

const maxReproAttempts = 3

func (mgr *Manager) needLocalRepro(crash *Crash) bool {
	if !mgr.cfg.Reproduce || crash.Corrupted || crash.Suppressed {
		return false
	}
	sig := hash.Hash([]byte(crash.Title))
	dir := filepath.Join(mgr.crashdir, sig.String())
	if osutil.IsExist(filepath.Join(dir, "repro.prog")) {
		return false
	}
	for i := 0; i < maxReproAttempts; i++ {
		if !osutil.IsExist(filepath.Join(dir, fmt.Sprintf("repro%v", i))) {
			return true
		}
	}
	return false
}

func (mgr *Manager) needRepro(crash *Crash) bool {
	if crash.external {
		return true
	}
	if mgr.checkResult == nil || (mgr.checkResult.Features[host.FeatureLeak].Enabled &&
		crash.Type != crash_pkg.MemoryLeak) {
		// Leak checking is very slow, don't bother reproducing other crashes on leak instance.
		return false
	}
	if mgr.dash == nil {
		return mgr.needLocalRepro(crash)
	}
	cid := &dashapi.CrashID{
		BuildID:      mgr.cfg.Tag,
		Title:        crash.Title,
		Corrupted:    crash.Corrupted,
		Suppressed:   crash.Suppressed,
		MayBeMissing: crash.Type == crash_pkg.MemoryLeak, // we did not send the original crash w/o repro
	}
	needRepro, err := mgr.dash.NeedRepro(cid)
	if err != nil {
		log.Logf(0, "dashboard.NeedRepro failed: %v", err)
	}
	return needRepro
}

func (mgr *Manager) saveFailedRepro(rep *report.Report, stats *repro.Stats) {
	reproLog := fullReproLog(stats)
	if mgr.dash != nil {
		if rep.Type == crash_pkg.MemoryLeak {
			// Don't send failed leak repro attempts to dashboard
			// as we did not send the crash itself.
			return
		}
		cid := &dashapi.CrashID{
			BuildID:      mgr.cfg.Tag,
			Title:        rep.Title,
			Corrupted:    rep.Corrupted,
			Suppressed:   rep.Suppressed,
			MayBeMissing: rep.Type == crash_pkg.MemoryLeak,
			ReproLog:     reproLog,
		}
		if err := mgr.dash.ReportFailedRepro(cid); err != nil {
			log.Logf(0, "failed to report failed repro to dashboard: %v", err)
		} else {
			return
		}
	}
	dir := filepath.Join(mgr.crashdir, hash.String([]byte(rep.Title)))
	osutil.MkdirAll(dir)
	for i := 0; i < maxReproAttempts; i++ {
		name := filepath.Join(dir, fmt.Sprintf("repro%v", i))
		if !osutil.IsExist(name) && len(reproLog) > 0 {
			osutil.WriteFile(name, reproLog)
			break
		}
	}
}

func (mgr *Manager) saveRepro(res *ReproResult) {
	repro := res.repro
	opts := fmt.Sprintf("# %+v\n", repro.Opts)
	progText := repro.Prog.Serialize()

	// Append this repro to repro list to send to hub if it didn't come from hub originally.
	if !res.external {
		progForHub := []byte(fmt.Sprintf("# %+v\n# %v\n# %v\n%s",
			repro.Opts, repro.Report.Title, mgr.cfg.Tag, progText))
		mgr.mu.Lock()
		mgr.newRepros = append(mgr.newRepros, progForHub)
		mgr.mu.Unlock()
	}

	var cprogText []byte
	if repro.CRepro {
		cprog, err := csource.Write(repro.Prog, repro.Opts)
		if err == nil {
			formatted, err := csource.Format(cprog)
			if err == nil {
				cprog = formatted
			}
			cprogText = cprog
		} else {
			log.Logf(0, "failed to write C source: %v", err)
		}
	}

	if mgr.dash != nil {
		// Note: we intentionally don't set Corrupted for reproducers:
		// 1. This is reproducible so can be debugged even with corrupted report.
		// 2. Repro re-tried 3 times and still got corrupted report at the end,
		//    so maybe corrupted report detection is broken.
		// 3. Reproduction is expensive so it's good to persist the result.

		report := repro.Report
		output := report.Output

		var crashFlags dashapi.CrashFlags
		if res.strace != nil {
			// If syzkaller managed to successfully run the repro with strace, send
			// the report and the output generated under strace.
			report = res.strace.Report
			output = res.strace.Output
			crashFlags = dashapi.CrashUnderStrace
		}

		dc := &dashapi.Crash{
			BuildID:       mgr.cfg.Tag,
			Title:         report.Title,
			AltTitles:     report.AltTitles,
			Suppressed:    report.Suppressed,
			Recipients:    report.Recipients.ToDash(),
			Log:           output,
			Flags:         crashFlags,
			Report:        report.Report,
			ReproOpts:     repro.Opts.Serialize(),
			ReproSyz:      progText,
			ReproC:        cprogText,
			ReproLog:      fullReproLog(res.stats),
			Assets:        mgr.uploadReproAssets(repro),
			OriginalTitle: res.originalTitle,
		}
		setGuiltyFiles(dc, report)
		if _, err := mgr.dash.ReportCrash(dc); err != nil {
			log.Logf(0, "failed to report repro to dashboard: %v", err)
		} else {
			// Don't store the crash locally, if we've successfully
			// uploaded it to the dashboard. These will just eat disk space.
			return
		}
	}

	rep := repro.Report
	dir := filepath.Join(mgr.crashdir, hash.String([]byte(rep.Title)))
	osutil.MkdirAll(dir)

	if err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(rep.Title+"\n")); err != nil {
		log.Logf(0, "failed to write crash: %v", err)
	}
	osutil.WriteFile(filepath.Join(dir, "repro.prog"), append([]byte(opts), progText...))
	if mgr.cfg.Tag != "" {
		osutil.WriteFile(filepath.Join(dir, "repro.tag"), []byte(mgr.cfg.Tag))
	}
	if len(rep.Output) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.log"), rep.Output)
	}
	if len(rep.Report) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.report"), rep.Report)
	}
	if len(cprogText) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.cprog"), cprogText)
	}
	repro.Prog.ForEachAsset(func(name string, typ prog.AssetType, r io.Reader) {
		fileName := filepath.Join(dir, name+".gz")
		if err := osutil.WriteGzipStream(fileName, r); err != nil {
			log.Logf(0, "failed to write crash asset: type %d, write error %v", typ, err)
		}
	})
	if res.strace != nil {
		// Unlike dashboard reporting, we save strace output separately from the original log.
		if res.strace.Error != nil {
			osutil.WriteFile(filepath.Join(dir, "strace.error"),
				[]byte(fmt.Sprintf("%v", res.strace.Error)))
		}
		if len(res.strace.Output) > 0 {
			osutil.WriteFile(filepath.Join(dir, "strace.log"), res.strace.Output)
		}
	}
	if reproLog := fullReproLog(res.stats); len(reproLog) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.stats"), reproLog)
	}
}

func (mgr *Manager) uploadReproAssets(repro *repro.Result) []dashapi.NewAsset {
	if mgr.assetStorage == nil {
		return nil
	}

	ret := []dashapi.NewAsset{}
	repro.Prog.ForEachAsset(func(name string, typ prog.AssetType, r io.Reader) {
		dashTyp, ok := map[prog.AssetType]dashapi.AssetType{
			prog.MountInRepro: dashapi.MountInRepro,
		}[typ]
		if !ok {
			panic("unknown extracted prog asset")
		}
		asset, err := mgr.assetStorage.UploadCrashAsset(r, name, dashTyp, nil)
		if err != nil {
			log.Logf(1, "processing of the asset %v (%v) failed: %v", name, typ, err)
			return
		}
		ret = append(ret, asset)
	})
	return ret
}

func fullReproLog(stats *repro.Stats) []byte {
	if stats == nil {
		return nil
	}
	return []byte(fmt.Sprintf("Extracting prog: %v\nMinimizing prog: %v\n"+
		"Simplifying prog options: %v\nExtracting C: %v\nSimplifying C: %v\n\n\n%s",
		stats.ExtractProgTime, stats.MinimizeProgTime,
		stats.SimplifyProgTime, stats.ExtractCTime, stats.SimplifyCTime, stats.Log))
}

func (mgr *Manager) getMinimizedCorpus() (corpus, repros [][]byte) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.minimizeCorpus()
	corpus = make([][]byte, 0, len(mgr.corpus))
	for _, inp := range mgr.corpus {
		corpus = append(corpus, inp.Prog)
	}
	repros = mgr.newRepros
	mgr.newRepros = nil
	return
}

func (mgr *Manager) addNewCandidates(candidates []rpctype.Candidate) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if mgr.cfg.Experimental.ResetAccState {
		// Don't accept new candidates -- the execution is already very slow,
		// syz-hub will just overwhelm us.
		return
	}

	mgr.candidates = append(mgr.candidates, candidates...)

	if mgr.phase == phaseTriagedCorpus {
		mgr.phase = phaseQueriedHub
	}
}

// generatePairCandidates creates pair candidates from current candidates
func (mgr *Manager) generatePairCandidates() {
	if len(mgr.candidates) == 0 {
		return
	}

	// Generate pairs from recent candidates (avoid O(n^2) for large candidate sets)
	// Only pair the last few candidates with existing ones
	maxNewPairs := 1000000 // limit to avoid memory explosion
	startIndex := 0
	if len(mgr.candidates) > 1000 {
		startIndex = len(mgr.candidates) - 1000 // only use last 1000 candidates for pairing
	}

	// Track existing PairIDs to avoid duplicates
	existingPairs := make(map[uint64]bool)
	for _, pair := range mgr.pairCandidates {
		existingPairs[pair.PairID] = true
	}

	pairsGenerated := 0
	// Generate pairs: i with j where j >= i (allowing self-pairing when i==j)
	for i := startIndex; i < len(mgr.candidates) && pairsGenerated < maxNewPairs; i++ {
		for j := i; j < len(mgr.candidates) && pairsGenerated < maxNewPairs; j++ {
			pairID := ddrd.GeneratePairID(mgr.candidates[i].Prog, mgr.candidates[j].Prog)

			// Skip if this pair already exists
			if existingPairs[pairID] {
				continue
			}

			pair := rpctype.PairCandidate{
				Prog1:  mgr.candidates[i].Prog,
				Prog2:  mgr.candidates[j].Prog,
				PairID: pairID,
			}

			mgr.pairCandidates = append(mgr.pairCandidates, pair)
			existingPairs[pairID] = true
			pairsGenerated++
		}
	}

	if pairsGenerated > 0 {
		log.Logf(1, "generated %d pair candidates from %d candidates (including self-pairs)",
			pairsGenerated, len(mgr.candidates))
	}
}

// pairCandidateBatch returns a batch of pair candidates (similar to candidateBatch)
func (mgr *Manager) pairCandidateBatch(size int) []rpctype.PairCandidate {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	var res []rpctype.PairCandidate
	for i := 0; i < size && len(mgr.pairCandidates) > 0; i++ {
		last := len(mgr.pairCandidates) - 1
		res = append(res, mgr.pairCandidates[last])
		mgr.pairCandidates[last] = rpctype.PairCandidate{} // clear for GC
		mgr.pairCandidates = mgr.pairCandidates[:last]
	}

	log.Logf(2, "pairCandidateBatch: returning %d pairs, %d remaining", len(res), len(mgr.pairCandidates))
	return res
}

// getPriorityPairCandidates returns pair candidates with race pairs prioritized
func (mgr *Manager) getPriorityPairCandidates(size int) []rpctype.PairCandidate {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	var res []rpctype.PairCandidate

	// First, provide race pair candidates (high priority) - randomly selected
	if size > 0 && len(mgr.raceCorpusCandidates) > 0 {
		count := min(size, len(mgr.raceCorpusCandidates))

		// Use Fisher-Yates shuffle to randomly select 'count' elements
		for i := 0; i < count; i++ {
			// Pick a random index from [i, len-1]
			randIdx := i + rand.Intn(len(mgr.raceCorpusCandidates)-i)

			// Add the selected candidate to result
			res = append(res, mgr.raceCorpusCandidates[randIdx])

			// Move the selected element to position i and mark for removal
			mgr.raceCorpusCandidates[randIdx] = mgr.raceCorpusCandidates[i]
		}

		// Clear selected candidates from the slice
		for i := 0; i < count; i++ {
			mgr.raceCorpusCandidates[i] = rpctype.PairCandidate{} // clear for GC
		}
		mgr.raceCorpusCandidates = mgr.raceCorpusCandidates[count:]
	}

	// If still need more pairs, use generated pair candidates (randomly)
	remaining := size - len(res)
	if remaining > 0 && len(mgr.pairCandidates) > 0 {
		// Randomly shuffle and select
		count := min(remaining, len(mgr.pairCandidates))

		// Use Fisher-Yates shuffle to randomly select 'count' elements
		for i := 0; i < count; i++ {
			// Pick a random index from [i, len-1]
			randIdx := i + rand.Intn(len(mgr.pairCandidates)-i)

			// Add the selected candidate to result
			res = append(res, mgr.pairCandidates[randIdx])

			// Move the selected element to position i and mark for removal
			mgr.pairCandidates[randIdx] = mgr.pairCandidates[i]
		}

		// Clear selected candidates from the slice
		for i := 0; i < count; i++ {
			mgr.pairCandidates[i] = rpctype.PairCandidate{} // clear for GC
		}
		mgr.pairCandidates = mgr.pairCandidates[count:]
	}

	// log.Logf(2, "getPriorityPairCandidates: returning %d pairs (%d race, %d generated), %d race pairs remaining, %d generated pairs remaining",
	// 	len(res), size-remaining, len(res)-(size-remaining), len(mgr.raceCorpusCandidates), len(mgr.pairCandidates))
	return res
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getCorpusCandidatesCount returns the number of race corpus candidates available
func (mgr *Manager) getCorpusCandidatesCount() int {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	return len(mgr.raceCorpusCandidates)
}

// getGeneratedPairCount returns the number of generated pair candidates available
func (mgr *Manager) getGeneratedPairCount() int {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	return len(mgr.pairCandidates)
}

func (mgr *Manager) minimizeCorpus() {
	if mgr.phase < phaseLoadedCorpus || len(mgr.corpus) <= mgr.lastMinCorpus*103/100 {
		return
	}
	inputs := make([]signal.Context, 0, len(mgr.corpus))
	for _, inp := range mgr.corpus {
		inputs = append(inputs, signal.Context{
			Signal:  inp.Signal.Deserialize(),
			Context: inp,
		})
	}
	newCorpus := make(map[string]CorpusItem)
	// Note: inputs are unsorted (based on map iteration).
	// This gives some intentional non-determinism during minimization.
	for _, ctx := range signal.Minimize(inputs) {
		inp := ctx.(CorpusItem)
		newCorpus[hash.String(inp.Prog)] = inp
	}
	log.Logf(1, "minimized corpus: %v -> %v", len(mgr.corpus), len(newCorpus))
	mgr.corpus = newCorpus
	mgr.lastMinCorpus = len(newCorpus)

	// From time to time we get corpus explosion due to different reason:
	// generic bugs, per-OS bugs, problems with fallback coverage, kcov bugs, etc.
	// This has bad effect on the instance and especially on instances
	// connected via hub. Do some per-syscall sanity checking to prevent this.
	for call, info := range mgr.collectSyscallInfoUnlocked() {
		if mgr.cfg.Cover {
			// If we have less than 1K inputs per this call,
			// accept all new inputs unconditionally.
			if info.count < 1000 {
				continue
			}
			// If we have more than 3K already, don't accept any more.
			// Between 1K and 3K look at amount of coverage we are getting from these programs.
			// Empirically, real coverage for the most saturated syscalls is ~30-60
			// per program (even when we have a thousand of them). For explosion
			// case coverage tend to be much lower (~0.3-5 per program).
			if info.count < 3000 && len(info.cov)/info.count >= 10 {
				continue
			}
		} else {
			// If we don't have real coverage, signal is weak.
			// If we have more than several hundreds, there is something wrong.
			if info.count < 300 {
				continue
			}
		}
		if mgr.saturatedCalls[call] {
			continue
		}
		mgr.saturatedCalls[call] = true
		log.Logf(0, "coverage for %v has saturated, not accepting more inputs", call)
	}

	// Don't minimize persistent corpus until fuzzers have triaged all inputs from it.
	if mgr.phase < phaseTriagedCorpus {
		return
	}
	for key := range mgr.corpusDB.Records {
		_, ok1 := mgr.corpus[key]
		_, ok2 := mgr.disabledHashes[key]
		if !ok1 && !ok2 {
			mgr.corpusDB.Delete(key)
		}
	}
	mgr.corpusDB.BumpVersion(currentDBVersion)
}

// ===============DDRD====================
// Race Corpus Management Methods
// ===============DDRD====================

func (mgr *Manager) initRaceCorpus() {
	log.Logf(0, "loading race corpus...")
	raceCorpusPath := filepath.Join(mgr.cfg.Workdir, "race-corpus.db")
	raceCorpusDB, err := db.Open(raceCorpusPath, true)
	if err != nil {
		if raceCorpusDB == nil {
			log.Fatalf("failed to open race corpus database: %v", err)
		}
		log.Errorf("race corpus db error: %v", err)
	}

	mgr.raceCorpusDB = raceCorpusDB
	mgr.loadRaceCorpus()

	// Convert race corpus to high-priority pair candidates
	mgr.loadCandidatesFromCorpus()

	log.Logf(0, "race corpus initialized: %d items loaded, %d race corpus candidates created",
		len(mgr.raceCorpus), len(mgr.raceCorpusCandidates))
}

func (mgr *Manager) initUAFCorpus() {
	log.Logf(0, "loading UAF corpus...")
	uafCorpusPath := filepath.Join(mgr.cfg.Workdir, "uaf-corpus.db")
	uafCorpusDB, err := db.Open(uafCorpusPath, true)
	if err != nil {
		if uafCorpusDB == nil {
			log.Fatalf("failed to open UAF corpus database: %v", err)
		}
		log.Errorf("UAF corpus db error: %v", err)
	}

	mgr.uafCorpusDB = uafCorpusDB
	mgr.loadUAFCorpus()

	log.Logf(0, "UAF corpus initialized: %d items loaded",
		len(mgr.uafCorpus))
}

func (mgr *Manager) loadUAFCorpus() {
	mgr.uafCorpusMu.Lock()
	defer mgr.uafCorpusMu.Unlock()

	log.Logf(0, "Loading UAF corpus from database...")
	log.Logf(0, "Database has %d records", len(mgr.uafCorpusDB.Records))

	broken := 0
	for key, rec := range mgr.uafCorpusDB.Records {
		log.Logf(1, "Loading UAF corpus item: %s (size: %d bytes)", key, len(rec.Val))

		var item UAFCorpusItem
		if err := json.Unmarshal(rec.Val, &item); err != nil {
			log.Logf(0, "failed to unmarshal UAF corpus item %s: %v", key, err)
			mgr.uafCorpusDB.Delete(key)
			broken++
			continue
		}
		keyNum, _ := strconv.ParseUint(key, 16, 64)
		mgr.uafCorpus[keyNum] = &item

		// Load UAF signal from this corpus item
		if len(item.UAFSignal) > 0 {
			log.Logf(1, "Processing UAF signal for item %s: signal size=%d bytes", key, len(item.UAFSignal))
			if uafSignal, err := deserializeUAFSignal(item.UAFSignal); err == nil && uafSignal != nil {
				mgr.uafSignalMu.Lock()
				oldSignalLen := len(mgr.maxUAFSignal)
				mgr.maxUAFSignal.Merge(*uafSignal)
				newSignalLen := len(mgr.maxUAFSignal)
				mgr.uafSignalMu.Unlock()
				log.Logf(1, "Merged UAF signal for item %s: added %d signals (total: %d -> %d)",
					key, len(*uafSignal), oldSignalLen, newSignalLen)
			} else {
				log.Logf(0, "Failed to deserialize UAF signal for item %s: %v", key, err)
			}
		} else {
			log.Logf(1, "Item %s has no UAF signal data", key)
		}

		// Load UAF coverage from this corpus item
		if len(item.UAFs) > 0 {
			var uafs []ddrd.MayUAFPair
			if err := json.Unmarshal(item.UAFs, &uafs); err == nil {
				var uafPairs []*ddrd.MayUAFPair
				for i := range uafs {
					uafPairs = append(uafPairs, &uafs[i])
				}
				mgr.uafCoverMu.Lock()
				mgr.maxUAFCover.Merge(uafPairs)
				mgr.uafCoverMu.Unlock()
			}
		}

		log.Logf(0, "Loaded UAF pair: ID=%x, Count=%d, FirstSeen=%s, LastUpdated=%s",
			item.PairID, item.Count, item.FirstSeen.Format("15:04:05"), item.LastUpdated.Format("15:04:05"))
	}

	if broken > 0 {
		log.Logf(0, "removed %d broken UAF corpus items", broken)
	}

	// 初始化UAF信号统计（覆盖原有值）
	mgr.uafSignalMu.RLock()
	totalUAFSignals := len(mgr.maxUAFSignal)
	mgr.uafSignalMu.RUnlock()
	mgr.stats.uafSignals.set(totalUAFSignals)
	mgr.stats.newUAFSignals.set(0)
	log.Logf(0, "UAF signal statistics initialized: total signals=%d", totalUAFSignals)

	mgr.uafStats.totalPairs = int64(len(mgr.uafCorpus))
	log.Logf(0, "loaded %d UAF corpus items from database", len(mgr.uafCorpus))
}

func (mgr *Manager) loadRaceCorpus() {
	mgr.raceCorpusMu.Lock()
	defer mgr.raceCorpusMu.Unlock()

	log.Logf(0, "Loading race corpus from database...")
	log.Logf(0, "Database has %d records", len(mgr.raceCorpusDB.Records))

	broken := 0
	for key, rec := range mgr.raceCorpusDB.Records {
		log.Logf(1, "Loading race corpus item: %s (size: %d bytes)", key, len(rec.Val))

		var item RaceCorpusItem
		if err := json.Unmarshal(rec.Val, &item); err != nil {
			log.Logf(0, "failed to unmarshal race corpus item %s: %v", key, err)
			mgr.raceCorpusDB.Delete(key)
			broken++
			continue
		}
		keyNum, _ := strconv.ParseUint(key, 16, 64)
		mgr.raceCorpus[keyNum] = &item

		// 详细输出每个加载的条目
		log.Logf(0, "Loaded race pair: ID=%x, Count=%d, FirstSeen=%s, LastUpdated=%s",
			item.PairID, item.Count, item.FirstSeen.Format("15:04:05"), item.LastUpdated.Format("15:04:05"))

		// 输出程序信息
		if len(item.Prog1) > 0 {
			log.Logf(1, "  Prog1: %d bytes", len(item.Prog1))
		}
		if len(item.Prog2) > 0 {
			log.Logf(1, "  Prog2: %d bytes", len(item.Prog2))
		}

		// 输出race signal信息
		if len(item.RaceSignal) > 0 {
			log.Logf(1, "  RaceSignal: %d bytes", len(item.RaceSignal))
		}
	}

	log.Logf(0, "Race corpus loading complete: %d items loaded, %d broken items deleted",
		len(mgr.raceCorpus), broken)
}

func (mgr *Manager) saveUAFCorpusItem(args *rpctype.NewUAFPairArgs) {
	mgr.uafCorpusMu.Lock()
	defer mgr.uafCorpusMu.Unlock()

	now := time.Now()

	// ExecutionContext is already serialized as []byte from fuzzer, no need to serialize again
	var executionContextData []byte
	if args.Pair.ExecutionContext != nil {
		executionContextData = args.Pair.ExecutionContext
		log.Logf(2, "Using pre-serialized execution context for UAF pair %x (%d bytes)",
			args.Pair.PairID, len(executionContextData))
	}

	// Check if already exists
	if existing, exists := mgr.uafCorpus[args.Pair.PairID]; exists {
		// Update existing item
		existing.LastUpdated = now
		existing.Count++

		// Update UAF signal if provided
		if len(args.Pair.Signal) > 0 {
			existing.UAFSignal = args.Pair.Signal
			// Merge new signal
			if uafSignal, err := deserializeUAFSignal(args.Pair.Signal); err == nil && uafSignal != nil {
				mgr.uafSignalMu.Lock()
				oldSignalSize := len(mgr.maxUAFSignal)
				mgr.maxUAFSignal.Merge(*uafSignal)
				newSignalSize := len(mgr.maxUAFSignal)
				mgr.uafSignalMu.Unlock()

				// Update UAF statistics - set to current total and track new signals
				mgr.stats.uafSignals.set(newSignalSize)
				if newSignalSize > oldSignalSize {
					mgr.stats.newUAFSignals.add(newSignalSize - oldSignalSize)
				}

				log.Logf(2, "Merged UAF signal for existing pair %x (signal size: %d, new coverage: %d)",
					args.Pair.PairID, len(*uafSignal), newSignalSize-oldSignalSize)
			}
		}

		// Update execution context if provided
		if len(executionContextData) > 0 {
			existing.ExecutionContext = executionContextData
		}

		// Update output if provided
		if args.Pair.Output != nil {
			existing.Output = args.Pair.Output
		}

		log.Logf(2, "Updated existing UAF pair %x (count: %d)", args.Pair.PairID, existing.Count)
	} else {
		// Create new item
		item := &UAFCorpusItem{
			PairID:           strconv.FormatUint(args.Pair.PairID, 16),
			Prog1:            args.Pair.Prog1,
			Prog2:            args.Pair.Prog2,
			UAFSignal:        args.Pair.Signal,
			UAFs:             args.Pair.UAFs,
			Output:           args.Pair.Output,
			ExecutionContext: executionContextData,
			FirstSeen:        now,
			LastUpdated:      now,
			Source:           args.Name,
			Count:            1,
		}

		mgr.uafCorpus[args.Pair.PairID] = item

		// Update UAF stats for new item
		mgr.uafStats.uniqueUAFs++

		// Update UAF signal if provided
		if len(args.Pair.Signal) > 0 {
			if uafSignal, err := deserializeUAFSignal(args.Pair.Signal); err == nil && uafSignal != nil {
				mgr.uafSignalMu.Lock()
				oldSignalSize := len(mgr.maxUAFSignal)
				mgr.maxUAFSignal.Merge(*uafSignal)
				newSignalSize := len(mgr.maxUAFSignal)
				mgr.uafSignalMu.Unlock()

				// Update UAF statistics - set to current total and track new signals
				mgr.stats.uafSignals.set(newSignalSize)
				if newSignalSize > oldSignalSize {
					mgr.stats.newUAFSignals.add(newSignalSize - oldSignalSize)
				}

				log.Logf(2, "Merged UAF signal for new pair %x (signal size: %d, new coverage: %d)",
					args.Pair.PairID, len(*uafSignal), newSignalSize-oldSignalSize)
			}
		}

		// Update UAF coverage if provided
		if len(args.Pair.UAFs) > 0 {
			var uafs []ddrd.MayUAFPair
			if err := json.Unmarshal(args.Pair.UAFs, &uafs); err == nil {
				var uafPairs []*ddrd.MayUAFPair
				for i := range uafs {
					uafPairs = append(uafPairs, &uafs[i])
				}
				mgr.uafCoverMu.Lock()
				mgr.maxUAFCover.Merge(uafPairs)
				mgr.uafCoverMu.Unlock()
				log.Logf(2, "Merged UAF coverage for new pair %x (uaf count: %d)",
					args.Pair.PairID, len(uafs))
			}
		}

		log.Logf(2, "Added new UAF pair %x from %s (with execution context: %t)",
			args.Pair.PairID, args.Name, len(executionContextData) > 0)
	}

	// Persist to database
	mgr.persistUAFCorpusItem(args.Pair.PairID)
}

func (mgr *Manager) persistRaceCorpusItem(pairID uint64) {
	item, exists := mgr.raceCorpus[pairID]
	if !exists {
		log.Logf(1, "persistRaceCorpusItem: item %x not found in memory", pairID)
		return
	}

	data, err := json.Marshal(item)
	if err != nil {
		log.Logf(0, "failed to marshal race corpus item %x: %v", pairID, err)
		return
	}

	log.Logf(1, "Persisting race corpus item %x (%d bytes)", pairID, len(data))

	// Save to database
	mgr.raceCorpusDB.Save(strconv.FormatUint(pairID, 16), data, 0)

	// Flush to ensure data is written to disk
	if err := mgr.raceCorpusDB.Flush(); err != nil {
		log.Logf(0, "failed to flush race corpus database: %v", err)
	} else {
		log.Logf(1, "Successfully persisted race corpus item %x to disk", pairID)
	}
}

func (mgr *Manager) persistUAFCorpusItem(pairID uint64) {
	item, exists := mgr.uafCorpus[pairID]
	if !exists {
		log.Logf(1, "persistUAFCorpusItem: item %x not found in memory", pairID)
		return
	}

	data, err := json.Marshal(item)
	if err != nil {
		log.Logf(0, "failed to marshal UAF corpus item %x: %v", pairID, err)
		return
	}

	log.Logf(1, "Persisting UAF corpus item %x (%d bytes)", pairID, len(data))

	// Save to database
	mgr.uafCorpusDB.Save(strconv.FormatUint(pairID, 16), data, 0)

	// Flush to ensure data is written to disk
	if err := mgr.uafCorpusDB.Flush(); err != nil {
		log.Logf(0, "failed to flush UAF corpus database: %v", err)
	} else {
		log.Logf(1, "Successfully persisted UAF corpus item %x to disk", pairID)
	}
}

// loadRacePairCandidates converts race corpus items to high-priority pair candidates
func (mgr *Manager) loadCandidatesFromCorpus() {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.raceCorpusMu.RLock()
	defer mgr.raceCorpusMu.RUnlock()
	for _, item := range mgr.raceCorpus {
		PairID, _ := strconv.ParseUint(item.PairID, 16, 64)
		pair := rpctype.PairCandidate{
			Prog1:  item.Prog1,
			Prog2:  item.Prog2,
			PairID: PairID,
		}
		mgr.raceCorpusCandidates = append(mgr.raceCorpusCandidates, pair)
	}
	log.Logf(0, "Converted %d race corpus items to pair candidates", len(mgr.raceCorpusCandidates))
}

func (mgr *Manager) maintainRaceCorpus() {
	mgr.raceCorpusMu.Lock()
	defer mgr.raceCorpusMu.Unlock()

	log.Logf(1, "Starting race corpus maintenance...")

	before := len(mgr.raceCorpus)
	removed := 0

	// Clean up old and infrequent items
	cutoff := time.Now().Add(-24 * time.Hour * 7) // 7 days ago

	for pairID, item := range mgr.raceCorpus {
		// Remove items that are old and only appeared once
		if item.Count == 1 && item.LastUpdated.Before(cutoff) {
			delete(mgr.raceCorpus, pairID)
			mgr.raceCorpusDB.Delete(strconv.FormatUint(pairID, 16))
			removed++
		}
	}

	// Flush database
	if err := mgr.raceCorpusDB.Flush(); err != nil {
		log.Logf(0, "failed to flush race corpus database: %v", err)
	}

	mgr.raceStats.lastSaveTime = time.Now()

	log.Logf(1, "Race corpus maintenance completed: %d -> %d items (removed %d)",
		before, len(mgr.raceCorpus), removed)
}

func (mgr *Manager) getRaceCorpusStats() map[string]interface{} {
	mgr.raceCorpusMu.RLock()
	defer mgr.raceCorpusMu.RUnlock()

	return map[string]interface{}{
		"total_pairs":  len(mgr.raceCorpus),
		"unique_races": mgr.raceStats.uniqueRaces,
		"last_updated": mgr.raceStats.lastSaveTime,
	}
}

// deserializeRaceSignal deserializes race signal data from JSON.
func deserializeRaceSignal(data []byte) (*ddrd.Signal, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var serial ddrd.Serial
	if err := json.Unmarshal(data, &serial); err != nil {
		return nil, fmt.Errorf("failed to unmarshal race signal: %v", err)
	}
	sig := serial.Deserialize()
	return &sig, nil
}

// deserializeUAFSignal deserializes UAF signal data from JSON.
func deserializeUAFSignal(data []byte) (*ddrd.UAFSignal, error) {
	if len(data) == 0 {
		return nil, nil
	}

	// First try to deserialize as ddrd.Serial (JSON object format)
	var serial ddrd.Serial
	if err := json.Unmarshal(data, &serial); err == nil {
		// Successfully deserialized as Serial object
		signal := serial.Deserialize()
		// Convert ddrd.Signal to UAFSignal
		rawSignal := signal.ToRawUint64()
		uafSignal := ddrd.FromRawUAF(rawSignal, 0)
		return &uafSignal, nil
	}

	// Fallback: try to deserialize as []uint64 array (legacy format)
	var rawSignal []uint64
	if err := json.Unmarshal(data, &rawSignal); err != nil {
		return nil, fmt.Errorf("failed to unmarshal UAF signal as both Serial and []uint64: %v", err)
	}
	sig := ddrd.DeserializeUAFSignal(rawSignal)
	return &sig, nil
}

// serializeUAFSignal serializes UAF signal to JSON.
func serializeUAFSignal(sig ddrd.UAFSignal) ([]byte, error) {
	if sig.Empty() {
		return []byte{}, nil
	}
	rawSignal := sig.Serialize()
	data, err := json.Marshal(rawSignal)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize UAF signal: %v", err)
	}
	return data, nil
}

// ===============DDRD====================

func setGuiltyFiles(crash *dashapi.Crash, report *report.Report) {
	if report.GuiltyFile != "" {
		crash.GuiltyFiles = []string{report.GuiltyFile}
	}
}

type CallCov struct {
	count int
	cov   cover.Cover
}

func (mgr *Manager) collectSyscallInfo() map[string]*CallCov {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	return mgr.collectSyscallInfoUnlocked()
}

func (mgr *Manager) collectSyscallInfoUnlocked() map[string]*CallCov {
	if mgr.checkResult == nil {
		return nil
	}
	calls := make(map[string]*CallCov)
	for _, call := range mgr.checkResult.EnabledCalls[mgr.cfg.Sandbox] {
		calls[mgr.target.Syscalls[call].Name] = new(CallCov)
	}
	for _, inp := range mgr.corpus {
		if calls[inp.Call] == nil {
			calls[inp.Call] = new(CallCov)
		}
		cc := calls[inp.Call]
		cc.count++
		cc.cov.Merge(inp.Cover)
	}
	return calls
}

func (mgr *Manager) fuzzerConnect(modules []host.KernelModule) (
	[]rpctype.Input, BugFrames, map[uint32]uint32, map[uint32]uint32, error) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	mgr.minimizeCorpus()
	corpus := make([]rpctype.Input, 0, len(mgr.corpus))
	for _, inp := range mgr.corpus {
		corpus = append(corpus, inp.RPCInput())
	}
	frames := BugFrames{
		memoryLeaks: make([]string, 0, len(mgr.memoryLeakFrames)),
		dataRaces:   make([]string, 0, len(mgr.dataRaceFrames)),
	}
	for frame := range mgr.memoryLeakFrames {
		frames.memoryLeaks = append(frames.memoryLeaks, frame)
	}
	for frame := range mgr.dataRaceFrames {
		frames.dataRaces = append(frames.dataRaces, frame)
	}
	if !mgr.modulesInitialized {
		var err error
		mgr.modules = modules
		mgr.execCoverFilter, mgr.coverFilter, err = mgr.createCoverageFilter()
		if err != nil {
			log.Fatalf("failed to create coverage filter: %v", err)
		}
		mgr.modulesInitialized = true
	}
	return corpus, frames, mgr.coverFilter, mgr.execCoverFilter, nil
}

func (mgr *Manager) machineChecked(a *rpctype.CheckArgs, enabledSyscalls map[*prog.Syscall]bool) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.checkResult = a
	mgr.targetEnabledSyscalls = enabledSyscalls
	mgr.target.UpdateGlobs(a.GlobFiles)
	mgr.loadCorpus()
	mgr.firstConnect = time.Now()
}

func (mgr *Manager) newInput(inp rpctype.Input, sign signal.Signal) bool {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if mgr.saturatedCalls[inp.Call] {
		return false
	}

	update := CorpusItemUpdate{
		CallID:   inp.CallID,
		RawCover: inp.RawCover,
	}
	sig := hash.String(inp.Prog)
	if old, ok := mgr.corpus[sig]; ok {
		// The input is already present, but possibly with diffent signal/coverage/call.
		sign.Merge(old.Signal.Deserialize())
		old.Signal = sign.Serialize()
		var cov cover.Cover
		cov.Merge(old.Cover)
		cov.Merge(inp.Cover)
		old.Cover = cov.Serialize()
		const maxUpdates = 32
		old.Updates = append(old.Updates, update)
		if len(old.Updates) > maxUpdates {
			old.Updates = old.Updates[:maxUpdates]
		}
		mgr.corpus[sig] = old
	} else {
		mgr.corpus[sig] = CorpusItem{
			Call:    inp.Call,
			Prog:    inp.Prog,
			Signal:  inp.Signal,
			Cover:   inp.Cover,
			Updates: []CorpusItemUpdate{update},
		}
		mgr.corpusDB.Save(sig, inp.Prog, 0)
		if err := mgr.corpusDB.Flush(); err != nil {
			log.Errorf("failed to save corpus database: %v", err)
		}
	}
	return true
}

func (mgr *Manager) candidateBatch(size int) []rpctype.Candidate {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	var res []rpctype.Candidate
	for i := 0; i < size && len(mgr.candidates) > 0; i++ {
		last := len(mgr.candidates) - 1
		res = append(res, mgr.candidates[last])
		mgr.candidates[last] = rpctype.Candidate{}
		mgr.candidates = mgr.candidates[:last]
	}
	if len(mgr.candidates) == 0 {
		mgr.candidates = nil
		if mgr.phase == phaseLoadedCorpus {
			if mgr.cfg.HubClient != "" {
				mgr.phase = phaseTriagedCorpus
				go mgr.hubSyncLoop(pickGetter(mgr.cfg.HubKey))
			} else {
				mgr.phase = phaseTriagedHub
			}
		} else if mgr.phase == phaseQueriedHub {
			mgr.phase = phaseTriagedHub
		}
	}
	return res
}

func (mgr *Manager) getAllCandidates() []rpctype.Candidate {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	// Return a copy of all current candidates
	candidates := make([]rpctype.Candidate, len(mgr.candidates))
	copy(candidates, mgr.candidates)

	log.Logf(2, "getAllCandidates: returning %d candidates", len(candidates))
	return candidates
}

func (mgr *Manager) hubIsUnreachable() {
	var dash *dashapi.Dashboard
	mgr.mu.Lock()
	if mgr.phase == phaseTriagedCorpus {
		dash = mgr.dash
		mgr.phase = phaseTriagedHub
		log.Errorf("did not manage to connect to syz-hub; moving forward")
	}
	mgr.mu.Unlock()
	if dash != nil {
		mgr.dash.LogError(mgr.cfg.Name, "did not manage to connect to syz-hub")
	}
}

func (mgr *Manager) rotateCorpus() bool {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	return mgr.phase == phaseTriagedHub
}

func (mgr *Manager) collectUsedFiles() {
	if mgr.vmPool == nil {
		return
	}
	addUsedFile := func(f string) {
		if f == "" {
			return
		}
		stat, err := os.Stat(f)
		if err != nil {
			log.Fatalf("failed to stat %v: %v", f, err)
		}
		mgr.usedFiles[f] = stat.ModTime()
	}
	cfg := mgr.cfg
	addUsedFile(cfg.FuzzerBin)
	addUsedFile(cfg.ExecprogBin)
	addUsedFile(cfg.ExecutorBin)
	addUsedFile(cfg.SSHKey)
	if vmlinux := filepath.Join(cfg.KernelObj, mgr.sysTarget.KernelObject); osutil.IsExist(vmlinux) {
		addUsedFile(vmlinux)
	}
	if cfg.Image != "9p" {
		addUsedFile(cfg.Image)
	}
}

func (mgr *Manager) checkUsedFiles() {
	for f, mod := range mgr.usedFiles {
		stat, err := os.Stat(f)
		if err != nil {
			log.Fatalf("failed to stat %v: %v", f, err)
		}
		if mod != stat.ModTime() {
			log.Fatalf("file %v that syz-manager uses has been modified by an external program\n"+
				"this can lead to arbitrary syz-manager misbehavior\n"+
				"modification time has changed: %v -> %v\n"+
				"don't modify files that syz-manager uses. exiting to prevent harm",
				f, mod, stat.ModTime())
		}
	}
}

func (mgr *Manager) dashboardReporter() {
	webAddr := publicWebAddr(mgr.cfg.HTTP)
	var lastFuzzingTime time.Duration
	var lastCrashes, lastSuppressedCrashes, lastExecs uint64
	for {
		time.Sleep(time.Minute)
		mgr.mu.Lock()
		if mgr.firstConnect.IsZero() {
			mgr.mu.Unlock()
			continue
		}
		crashes := mgr.stats.crashes.get()
		suppressedCrashes := mgr.stats.crashSuppressed.get()
		execs := mgr.stats.execTotal.get()
		req := &dashapi.ManagerStatsReq{
			Name:              mgr.cfg.Name,
			Addr:              webAddr,
			UpTime:            time.Since(mgr.firstConnect),
			Corpus:            uint64(len(mgr.corpus)),
			PCs:               mgr.stats.corpusCover.get(),
			Cover:             mgr.stats.corpusSignal.get(),
			CrashTypes:        mgr.stats.crashTypes.get(),
			FuzzingTime:       mgr.fuzzingTime - lastFuzzingTime,
			Crashes:           crashes - lastCrashes,
			SuppressedCrashes: suppressedCrashes - lastSuppressedCrashes,
			Execs:             execs - lastExecs,
		}
		if mgr.phase >= phaseTriagedCorpus && !mgr.afterTriageStatSent {
			mgr.afterTriageStatSent = true
			req.TriagedCoverage = mgr.stats.corpusSignal.get()
			req.TriagedPCs = mgr.stats.corpusCover.get()
		}
		mgr.mu.Unlock()

		if err := mgr.dash.UploadManagerStats(req); err != nil {
			log.Logf(0, "failed to upload dashboard stats: %v", err)
			continue
		}
		mgr.mu.Lock()
		lastFuzzingTime += req.FuzzingTime
		lastCrashes += req.Crashes
		lastSuppressedCrashes += req.SuppressedCrashes
		lastExecs += req.Execs
		mgr.mu.Unlock()
	}
}

func (mgr *Manager) dashboardReproTasks() {
	if !mgr.cfg.Reproduce {
		return
	}
	for {
		time.Sleep(20 * time.Minute)
		needReproReply := make(chan bool)
		mgr.needMoreRepros <- needReproReply
		if !<-needReproReply {
			// We don't need reproducers at the moment.
			continue
		}
		resp, err := mgr.dash.LogToRepro(&dashapi.LogToReproReq{BuildID: mgr.cfg.Tag})
		if err != nil {
			log.Logf(0, "failed to query logs to reproduce: %v", err)
			continue
		}
		if len(resp.CrashLog) > 0 {
			mgr.externalReproQueue <- &Crash{
				vmIndex:  -1,
				external: true,
				Report: &report.Report{
					Title:  resp.Title,
					Output: resp.CrashLog,
				},
			}
		}
	}
}

func publicWebAddr(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err == nil && port != "" {
		if host, err := os.Hostname(); err == nil {
			addr = net.JoinHostPort(host, port)
		}
		if GCE, err := gce.NewContext(""); err == nil {
			addr = net.JoinHostPort(GCE.ExternalIP, port)
		}
	}
	return "http://" + addr
}

// ===============DDRD====================
// newUAFPair processes new UAF pair discoveries with full Manager integration
func (mgr *Manager) newUAFPair(args *rpctype.NewUAFPairArgs) bool {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	log.Logf(0, "Received new UAF pair: ID=%x from %s", args.Pair.PairID, args.Name)
	// 1. Save UAF log to disk (similar to saveCrash)
	mgr.saveUAFPair(args)

	// 2. Save to UAF corpus
	mgr.saveUAFCorpusItem(args)
	mgr.uafStats.totalPairs++

	// 3. UAF signal processing and propagation
	if len(args.Pair.Signal) > 0 {
		// Process UAF signal from the pair
		log.Logf(2, "Processing UAF signal: %d bytes", len(args.Pair.Signal))

		// Deserialize and merge UAF signal as generic signal for compatibility
		if uafSignal, err := deserializeRaceSignal(args.Pair.Signal); err == nil && uafSignal != nil {
			// Merge UAF signal with manager's max UAF signal tracking
			mgr.uafSignalMu.Lock()
			// Convert generic signal to UAF signal for proper tracking
			rawSignal := uafSignal.ToRawUint64()
			uafOnlySignal := ddrd.FromRawUAF(rawSignal, 0)
			mgr.maxUAFSignal.Merge(uafOnlySignal)
			mgr.uafSignalMu.Unlock()

			log.Logf(2, "Updated UAF signal: merged %d elements", len(rawSignal))
		} else if err != nil {
			log.Logf(1, "Failed to deserialize UAF signal: %v", err)
		}

		// Update UAF statistics
		mgr.uafStats.uniqueUAFs++
	}

	// 4. UAF coverage processing
	if len(args.Pair.UAFs) > 0 {
		var uafs []ddrd.MayUAFPair
		if err := json.Unmarshal(args.Pair.UAFs, &uafs); err == nil {
			var uafPairs []*ddrd.MayUAFPair
			for i := range uafs {
				uafPairs = append(uafPairs, &uafs[i])
			}
			mgr.uafCoverMu.Lock()
			mgr.maxUAFCover.Merge(uafPairs)
			mgr.uafCoverMu.Unlock()

			log.Logf(2, "Updated UAF coverage: merged %d UAF pairs", len(uafPairs))
		}
	}

	// 4. Integration with scheduler: adjust fuzzing strategy based on UAFs
	if mgr.fuzzScheduler != nil {
		// Could notify scheduler about UAF discoveries
		// This might influence the fuzzing phase transitions
		log.Logf(2, "Notifying fuzzing scheduler about UAF discoveries")
	}
	return true
}

// createMonitorConfig creates configuration for VM monitoring with duplicate data race filtering
func (mgr *Manager) createMonitorConfig() *vm.MonitorConfig {
	config := &vm.MonitorConfig{
		WorkDir: mgr.cfg.Workdir,
	}

	if mgr.cfg.Experimental.SkipDuplicateDataRaces {
		mgr.mu.RLock()
		skipCombinations := make(map[string]bool, len(mgr.reportedDataRaceCombinations))
		for key, value := range mgr.reportedDataRaceCombinations {
			skipCombinations[key] = value
		}
		mgr.mu.RUnlock()

		config.SkipDuplicateDataRaces = true
		config.SkipDataRaceCombinations = skipCombinations
	}

	return config
}

// ===============DDRD====================
