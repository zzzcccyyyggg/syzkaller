// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/vmexec"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer          *Fuzzer
	pid             int
	env             *ipc.Env
	rnd             *rand.Rand
	execOpts        *ipc.ExecOpts
	execOptsCollide *ipc.ExecOpts
	execOptsCover   *ipc.ExecOpts
	execOptsComps   *ipc.ExecOpts

	// Execution state tracking for scheduler debug
	executing     atomic.Bool // True if currently executing a program
	lastExecStart time.Time   // Time when last execution started
	lastExecEnd   time.Time   // Time when last execution ended

	// Race pair mode execution balancing
	candidateCounter int // Counter for consecutive candidate executions
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsCollide := *fuzzer.execOpts
	execOptsCollide.Flags &= ^ipc.FlagCollectSignal
	execOptsCover := *fuzzer.execOpts
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := *fuzzer.execOpts
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:          fuzzer,
		pid:             pid,
		env:             env,
		rnd:             rnd,
		execOpts:        fuzzer.execOpts,
		execOptsCollide: &execOptsCollide,
		execOptsCover:   &execOptsCover,
		execOptsComps:   &execOptsComps,
	}
	return proc, nil
}

func (proc *Proc) loop() {
	generatePeriod := 100
	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}

	// ===============DDRD====================
	// 使用启动时确定的模式标志位 (整个生命周期不变)
	isTestPairMode := proc.fuzzer.isTestPairMode
	if isTestPairMode {
		log.Logf(1, "proc %d running in RACE PAIR mode", proc.pid)
	} else {
		log.Logf(1, "proc %d running in NORMAL mode", proc.pid)
	}
	// ===============DDRD====================

	for i := 0; ; i++ {
		// Enhanced mode execution based on fixed mode
		if isTestPairMode {
			// ===============DDRD====================
			// Race pair mode: ONLY handle race pair work items from separate queue
			proc.handleRacePairMode()
			// ===============DDRD====================
			continue
		}

		// ===============DDRD====================
		// Normal mode: ONLY handle normal work items from normal queue
		// ===============DDRD====================
		item := proc.fuzzer.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				proc.triageInput(item)
			case *WorkCandidate:
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate, false)
			case *WorkSmash:
				proc.smashInput(item)
			default:
				log.SyzFatalf("unknown work type in normal mode: %#v", item)
			}
			continue
		}

		ct := proc.fuzzer.choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()
		if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
			// Generate a new prog.
			p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			log.Logf(1, "#%v: generated", proc.pid)
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatGenerate)
		} else {
			// Mutate an existing prog.
			p := fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
			p.Mutate(proc.rnd, prog.RecommendedCalls, ct, proc.fuzzer.noMutate, fuzzerSnapshot.corpus)
			log.Logf(1, "#%v: mutated", proc.pid)
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatFuzz)
		}
	}
}

// ===============DDRD====================
// handleRacePairMode handles execution in race pair testing mode
// ===============DDRD====================
func (proc *Proc) handleRacePairMode() {
	// Note: Pair queue maintenance is now handled by background goroutine
	// (fuzzer.pairQueueMaintenanceLoop) to avoid per-loop overhead
	
	// Process UAF pair work from queue with load balancing
	var item interface{}

	item = proc.fuzzer.uafPairWorkQueue.dequeue()

	if item == nil {
		// No work available - add a small sleep to prevent busy-waiting
		// This matches the pattern used in normal mode when no work is available
		time.Sleep(10 * time.Millisecond)
		return
	}

	// Process the work item synchronously (like normal mode)
	switch item := item.(type) {
	case *ProgPair:
		// Execute pair from corpus candidates
		proc.candidateCounter++
		log.Logf(3, "proc %d: executing candidate (consecutive count: %d)", proc.pid, proc.candidateCounter)
		proc.executePairFromCandidate(item)

	case *PairWorkValuable:
		// Execute pair from valuable queue
		proc.candidateCounter = 0 // Reset counter for valuable items too
		log.Logf(3, "proc %d: executing valuable (counter reset)", proc.pid)
		proc.executePairFromValuable(item)

	case *PairWorkTriage:
		// Execute pair from triage queue
		proc.candidateCounter = 0 // Reset counter when executing triage
		log.Logf(2, "proc %d: executing triage (counter reset)", proc.pid)
		proc.executePairFromTriage(item)

	default:
		log.SyzFatalf("unknown race pair work type: %#v", item)
	}
	// Note: Each execute function above is synchronous and will block
	// until the ExecPair completes, preventing rapid successive calls
}

func (proc *Proc) triageInput(item *WorkTriage) {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)

	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	rawCover := []uint32{}
	for i := 0; i < signalRuns; i++ {
		proc.resetAccState()
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover := getSignalAndCover(item.p, info, item.call)
		if len(rawCover) == 0 && proc.fuzzer.fetchRawCover {
			rawCover = append([]uint32{}, thisCover...)
		}
		newSignal = newSignal.Intersection(thisSignal)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			return
		}
		inputCover.Merge(thisCover)
	}
	if item.flags&ProgMinimized == 0 {
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					info := proc.execute(proc.execOpts, p1, ProgNormal,
						StatMinimize, i == 0)
					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _ := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						return true
					}
				}
				return false
			})
	}

	data := item.p.Serialize()
	sig := hash.Hash(data)

	log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)
	proc.fuzzer.sendInputToManager(rpctype.Input{
		Call:     callName,
		CallID:   item.call,
		Prog:     data,
		Signal:   inputSignal.Serialize(),
		Cover:    inputCover.Serialize(),
		RawCover: rawCover,
	})

	proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)

	if item.flags&ProgSmashed == 0 {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < 100; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, proc.fuzzer.noMutate, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 1; nth <= 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		newProg := p.Clone()
		newProg.Calls[call].Props.FailNth = nth
		info := proc.executeRaw(proc.execOpts, newProg, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed, true)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint, false)
	})
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat,
	resetState bool) *ipc.ProgInfo {
	if resetState {
		proc.resetAccState()
	}
	info := proc.executeRaw(execOpts, p, stat)
	if info == nil {
		return nil
	}
	calls, extra := proc.fuzzer.checkNewSignal(p, info)
	for _, callIndex := range calls {
		proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
	}
	if extra {
		proc.enqueueCallTriage(p, flags, -1, info.Extra)
	}
	return info
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:     p.Clone(),
		call:  callIndex,
		info:  info,
		flags: flags,
	})
}

func (proc *Proc) executeAndCollide(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) {
	proc.execute(execOpts, p, flags, stat, true)

	if proc.execOptsCollide.Flags&ipc.FlagThreaded == 0 {
		// We cannot collide syscalls without being in the threaded mode.
		return
	}
	const collideIterations = 2
	for i := 0; i < collideIterations; i++ {
		proc.executeRaw(proc.execOptsCollide, proc.randomCollide(p), StatCollide)
	}
}

func (proc *Proc) randomCollide(origP *prog.Prog) *prog.Prog {
	if proc.rnd.Intn(5) == 0 {
		// Old-style collide with a 20% probability.
		p, err := prog.DoubleExecCollide(origP, proc.rnd)
		if err == nil {
			return p
		}
	}
	if proc.rnd.Intn(4) == 0 {
		// Duplicate random calls with a 20% probability (25% * 80%).
		p, err := prog.DupCallCollide(origP, proc.rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, proc.rnd)
	if proc.rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, proc.rnd)
	}
	return p
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) *ipc.ProgInfo {
	proc.fuzzer.checkDisabledCalls(p)
	for try := 0; ; try++ {
		var output []byte
		var info *ipc.ProgInfo
		var hanged bool
		// On a heavily loaded VM, syz-executor may take significant time to start.
		// Let's do it outside of the gate ticket.
		err := proc.env.RestartIfNeeded(p.Target)
		if err == nil {
			// Mark as executing for scheduler tracking
			proc.executing.Store(true)
			proc.lastExecStart = time.Now()

			if log.V(2) {
				log.Logf(2, "[DDRD-DEBUG] proc %d: starting execution at %v", proc.pid, proc.lastExecStart)
			}

			// Limit concurrency.
			ticket := proc.fuzzer.gate.Enter()
			proc.logProgram(opts, p)
			atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
			output, info, hanged, err = proc.env.Exec(opts, p)
			proc.fuzzer.gate.Leave(ticket)

			// Mark as finished executing
			proc.executing.Store(false)
			proc.lastExecEnd = time.Now()

			if log.V(2) {
				execDuration := proc.lastExecEnd.Sub(proc.lastExecStart)
				log.Logf(2, "[DDRD-DEBUG] proc %d: finished execution at %v (duration=%v)",
					proc.pid, proc.lastExecEnd, execDuration)
			}
		}
		if err != nil {
			// Make sure to clear executing state on error
			proc.executing.Store(false)
			proc.lastExecEnd = time.Now()

			if err == prog.ErrExecBufferTooSmall {
				// It's bad if we systematically fail to serialize programs,
				// but so far we don't have a better handling than counting this.
				// This error is observed a lot on the seeded syz_mount_image calls.
				atomic.AddUint64(&proc.fuzzer.stats[StatBufferTooSmall], 1)
				return nil
			}
			if try > 10 {
				log.SyzFatalf("executor %v failed %v times: %v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info
	}
}

func (proc *Proc) logProgram(_ *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v:\n%s\n",
				proc.pid, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			f.Write(data)
			f.Close()
		}
	default:
		log.SyzFatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}

// logProgramPair logs execution of a program pair for race/UAF detection
// Output format is compatible with syz-execprog for later reproduction
func (proc *Proc) logProgramPair(p1, p2 *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data1 := p1.Serialize()
	data2 := p2.Serialize()

	// Format similar to syz-execprog for compatibility
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program pair %v:\n",
			now.Hour(), now.Minute(), now.Second(), proc.pid)
		fmt.Printf("Program 1:\n%s\n", data1)
		fmt.Printf("Program 2:\n%s\n", data2)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program pair %v:\n", proc.pid)
			fmt.Fprintf(buf, "Program 1:\n%s\n", data1)
			fmt.Fprintf(buf, "Program 2:\n%s\n", data2)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v-pair.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			fmt.Fprintf(f, "Program 1:\n%s\n", data1)
			fmt.Fprintf(f, "Program 2:\n%s\n", data2)
			f.Close()
		}
	default:
		log.SyzFatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}

func (proc *Proc) resetAccState() {
	if !proc.fuzzer.resetAccState {
		return
	}
	proc.env.ForceRestart()
}

// executeTestPair executes a single test pair and returns the result
func (proc *Proc) executeTestPair(opts1, opts2 *ipc.ExecOpts, p1, p2 *prog.Prog, _ ProgTypes) *ipc.PairProgInfo {
	// Validate inputs
	if p1 == nil || p2 == nil {
		log.Logf(0, "proc %d: executeTestPair called with nil programs", proc.pid)
		return nil
	}

	// Ensure both programs have the same target
	if p1.Target != p2.Target {
		log.Logf(0, "proc %d: executeTestPair called with programs having different targets", proc.pid)
		return nil
	}

	// Validate programs are well-formed
	if len(p1.Calls) == 0 || len(p2.Calls) == 0 {
		log.Logf(1, "proc %d: executeTestPair called with empty programs", proc.pid)
		return nil
	}

	// Log program pair execution (similar to syz-execprog)
	// proc.logProgramPair(p1, p2)

	// Always use local options to ensure proper flags are set
	if opts1 == nil {
		opts1 = &ipc.ExecOpts{}
	}
	if opts2 == nil {
		opts2 = &ipc.ExecOpts{}
	}

	// Reset executor state if needed
	proc.resetAccState()

	// ===============DDRD====================
	// Use the same concurrency control as normal execution to prevent
	// shared memory conflicts between concurrent ExecPair calls
	// log.Logf(0, "proc %d: about to acquire gate ticket (env=%p)", proc.pid, proc.env)
	ticket := proc.fuzzer.gate.Enter()
	// log.Logf(0, "proc %d: acquired gate ticket=%d (env=%p)", proc.pid, ticket, proc.env)
	defer func() {
		proc.fuzzer.gate.Leave(ticket)
		// log.Logf(0, "proc %d: released gate ticket=%d (env=%p)", proc.pid, ticket, proc.env)
	}()

	// Mark as executing for scheduler tracking
	proc.executing.Store(true)
	proc.lastExecStart = time.Now()

	if log.V(2) {
		log.Logf(2, "[DDRD-DEBUG] proc %d: starting pair execution at %v", proc.pid, proc.lastExecStart)
	}

	// Execute the pair using the IPC layer
	output, info, hanged, err := proc.env.ExecPair(opts1, opts2, p1, p2)

	// Mark as finished executing
	proc.executing.Store(false)
	proc.lastExecEnd = time.Now()

	if log.V(2) {
		execDuration := proc.lastExecEnd.Sub(proc.lastExecStart)
		log.Logf(2, "[DDRD-DEBUG] proc %d: finished pair execution at %v (duration=%v)",
			proc.pid, proc.lastExecEnd, execDuration)
	}
	// ===============DDRD====================
	if err != nil {
		log.Logf(0, "proc %d: pair execution failed: %v", proc.pid, err)
		return nil
	}

	if hanged {
		log.Logf(1, "proc %d: pair execution hanged", proc.pid)
		return info // Return partial info even if hanged
	}

	log.Logf(2, "proc %d: pair execution completed, output length: %d", proc.pid, len(output))

	// Record execution to VM sequence buffer for UAF context analysis
	if proc.fuzzer.vmExecBuffer != nil {
		prog1Data := p1.Serialize()
		prog2Data := p2.Serialize()
		proc.fuzzer.vmExecBuffer.AddExecution(prog1Data, prog2Data)
		log.Logf(2, "proc %d: recorded execution to VM buffer (seqID: %d)",
			proc.pid, proc.fuzzer.vmExecBuffer.GetLatestSeqID())

	}

	// ===============DDRD====================
	// Process UAF detection results from pair execution
	if info != nil && len(info.MayUAFPairs) > 0 {
		log.Logf(1, "proc %d: detected %d UAF pairs - processing immediately", proc.pid, len(info.MayUAFPairs))

		// Generate pair ID for identification
		prog1Data := p1.Serialize()
		prog2Data := p2.Serialize()
		pairID := ddrd.GeneratePairID(prog1Data, prog2Data)

		// Get recent execution sequence context before sending to manager
		var executionContext []vmexec.ExecutionRecord
		if proc.fuzzer.vmExecBuffer != nil {
			executionContext = proc.fuzzer.vmExecBuffer.GetRecentExecutions(100) // Last 100 executions
			log.Logf(2, "proc %d: gathered %d execution records for UAF %x context",
				proc.pid, len(executionContext), pairID)
		}

		// Generate UAF signals from detected pairs
		uafSignalData := make([]uint64, 0, len(info.MayUAFPairs))
		for _, pair := range info.MayUAFPairs {
			uafSignalData = append(uafSignalData, uint64(pair.Signal))
		}

		// Create UAF signal for fuzzer tracking
		if len(uafSignalData) > 0 {
			uafSignal := ddrd.FromRawUAF(uafSignalData, 0)
			proc.fuzzer.addUAFSignal(uafSignal)

			// Update UAF coverage - convert slice to pointer slice
			uafPairPtrs := make([]*ddrd.MayUAFPair, len(info.MayUAFPairs))
			for i := range info.MayUAFPairs {
				uafPairPtrs[i] = &info.MayUAFPairs[i]
			}
			proc.fuzzer.updateUAFCoverage(uafPairPtrs)
		}

		// Send UAF pair directly to manager with execution context
		// No triage needed - detected UAF is considered valid
		genericSignal := ddrd.FromRaw(uafSignalData, 0)
		res, err := proc.sendUAFPairsToManagerWithContext(p1, p2, info.MayUAFPairs,
			genericSignal, output, executionContext)

		if err != nil {
			log.Logf(0, "proc %d: failed to send UAF pair to manager: %v", proc.pid, err)
		} else if res != nil && res.Accepted {
			log.Logf(1, "proc %d: UAF pair %x accepted by manager", proc.pid, pairID)
			// Add to valuable queue for further mutation
			proc.fuzzer.uafPairWorkQueue.enqueue(&PairWorkValuable{&ProgPair{p1, p2}, len(info.MayUAFPairs)})
		} else {
			log.Logf(1, "proc %d: UAF pair %x rejected by manager", proc.pid, pairID)
		}
	} else {
		log.Logf(3, "proc %d: no UAF pairs detected", proc.pid)
	}
	// ===============DDRD====================

	return info
}

func (proc *Proc) sendUAFPairsToManagerWithContext(
	p1, p2 *prog.Prog,
	uafPairs []ddrd.MayUAFPair,
	uafSignal ddrd.Signal,
	output []byte,
	executionContext []vmexec.ExecutionRecord,
) (*rpctype.NewUAFPairRes, error) {
	if len(uafPairs) == 0 {
		return nil, nil
	}

	prog1Data := p1.Serialize()
	prog2Data := p2.Serialize()
	pairIDHash := ddrd.GeneratePairID(prog1Data, prog2Data)

	uafPairsData, err := json.Marshal(uafPairs)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize UAF pairs: %v", err)
	}

	// Serialize execution context
	executionContextData, err := json.Marshal(executionContext)
	if err != nil {
		log.Logf(1, "proc %d: failed to serialize execution context: %v", proc.pid, err)
		executionContextData = nil // Continue without context if serialization fails
	}

	uafPairInput := rpctype.UAFPairInput{
		PairID:           pairIDHash,
		Prog1:            prog1Data,
		Prog2:            prog2Data,
		Signal:           serializeRaceSignal(uafSignal),
		UAFs:             uafPairsData,
		Output:           output,
		ExecutionContext: executionContextData, // Include execution sequence context
	}

	args := &rpctype.NewUAFPairArgs{
		Name: proc.fuzzer.name,
		Pair: uafPairInput,
	}

	res := &rpctype.NewUAFPairRes{}
	if err := proc.fuzzer.manager.Call("Manager.NewUAFPair", args, res); err != nil {
		return nil, err
	}

	log.Logf(1, "proc %d: sent UAF pair %x to manager with %d execution records, accepted=%v",
		proc.pid, pairIDHash, len(executionContext), res.Accepted)

	return res, nil
}

func (proc *Proc) sendUAFPairsToManager(
	p1, p2 *prog.Prog,
	uafPairs []ddrd.MayUAFPair,
	uafSignal ddrd.Signal,
	output []byte,
) (*rpctype.NewUAFPairRes, error) {
	// Use the new function with empty execution context for backward compatibility
	return proc.sendUAFPairsToManagerWithContext(p1, p2, uafPairs, uafSignal, output, nil)
}

// ===============DDRD====================

// executePairFromCandidate executes a program pair from the candidates queue
func (proc *Proc) executePairFromCandidate(item *ProgPair) {
	if item == nil || item.p1 == nil || item.p2 == nil {
		log.Logf(0, "proc %d: executePairFromCandidate called with invalid item", proc.pid)
		return
	}

	// Use race collection options for candidates
	opts1 := &ipc.ExecOpts{
		Flags: ipc.FlagTestPairSync | ipc.FlagCollectUAF,
	}
	opts2 := &ipc.ExecOpts{
		Flags: ipc.FlagTestPairSync | ipc.FlagCollectUAF,
	}

	info := proc.executeTestPair(opts1, opts2, item.p1, item.p2, ProgNormal)
	if info == nil {
		return
	}
}

// executePairFromTriage executes a program pair from the triage queue
// Simplified: UAF detection is now handled directly in executeTestPair
func (proc *Proc) executePairFromTriage(item *PairWorkTriage) {
	if item == nil || item.progPair == nil {
		log.Logf(0, "proc %d: executePairFromTriage called with invalid item", proc.pid)
		return
	}

	// Simply execute the pair - UAF detection and reporting is handled in executeTestPair
	opts1 := &ipc.ExecOpts{
		Flags: ipc.FlagTestPairSync | ipc.FlagCollectUAF,
	}
	opts2 := &ipc.ExecOpts{
		Flags: ipc.FlagTestPairSync | ipc.FlagCollectUAF,
	}

	log.Logf(2, "proc %d: executing triage pair (simplified - no complex verification)", proc.pid)
	proc.executeTestPair(opts1, opts2, item.progPair.p1, item.progPair.p2, ProgNormal)
}

// executePairFromValuable executes a program pair from the valuable queue
func (proc *Proc) executePairFromValuable(item *PairWorkValuable) {
	// [!todo]: 主要进行变异，并将变异结果加入candidate队列
	for i := 0; i < item.score; i++ {
		fuzzerSnapshot := proc.fuzzer.snapshot()
		p := item.progPair.p1.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, proc.fuzzer.noMutate, fuzzerSnapshot.corpus)
		proc.fuzzer.uafPairWorkQueue.enqueue(&ProgPair{p, item.progPair.p2})
	}
	for i := 0; i < item.score; i++ {
		fuzzerSnapshot := proc.fuzzer.snapshot()
		p := item.progPair.p2.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, proc.fuzzer.noMutate, fuzzerSnapshot.corpus)
		proc.fuzzer.uafPairWorkQueue.enqueue(&ProgPair{item.progPair.p1, p})
	}
}

// isExecuting checks if this proc is currently executing a program
// This implementation uses actual execution state tracking
func (proc *Proc) isExecuting() bool {
	if proc.env == nil {
		if log.V(2) {
			log.Logf(2, "[DDRD-DEBUG] proc %d: env is nil, considered idle", proc.pid)
		}
		return false
	}

	// Primary check: is the proc currently executing?
	isCurrentlyExecuting := proc.executing.Load()
	if isCurrentlyExecuting {
		if log.V(2) {
			log.Logf(2, "[DDRD-DEBUG] proc %d: currently executing (started at %v)",
				proc.pid, proc.lastExecStart)
		}
		return true
	}

	// Secondary check: has it finished executing very recently? (within 100ms)
	// This helps catch the brief gap between executions
	now := time.Now()
	if !proc.lastExecEnd.IsZero() {
		timeSinceLastExec := now.Sub(proc.lastExecEnd)
		if timeSinceLastExec < 100*time.Millisecond {
			if log.V(2) {
				log.Logf(2, "[DDRD-DEBUG] proc %d: recently finished executing (%v ago), considered busy",
					proc.pid, timeSinceLastExec)
			}
			return true
		}
	}

	// Check if there's ongoing execution activity (heuristic)
	if proc.env.StatExecs > 0 || proc.env.StatRestarts > 0 {
		if log.V(2) {
			log.Logf(2, "[DDRD-DEBUG] proc %d: env stats indicate activity (execs=%d, restarts=%d)",
				proc.pid, proc.env.StatExecs, proc.env.StatRestarts)
		}
		return true
	}

	if log.V(3) {
		log.Logf(3, "[DDRD-DEBUG] proc %d: all checks passed, considered idle (last exec ended %v ago)",
			proc.pid, now.Sub(proc.lastExecEnd))
	}

	return false
}

// enqueueUAFPairTriage adds detected UAF pair race pairs to the triage queue for verification
func (proc *Proc) enqueueUAFPairTriage(p1, p2 *prog.Prog, racePairs []ddrd.MayUAFPair, _ ddrd.Signal, output []byte) {
	// Create PairProgInfo from the race pairs
	info := &ipc.PairProgInfo{
		PairCount:   uint32(len(racePairs)),
		MayUAFPairs: make([]ddrd.MayUAFPair, len(racePairs)),
	}

	// Copy races to the proper format
	for i, race := range racePairs {
		info.MayUAFPairs[i] = race
	}

	// Create triage work item
	triage := &PairWorkTriage{
		progPair: &ProgPair{p1: p1, p2: p2},
		info:     info,
		output:   append([]byte{}, output...), // Copy output to avoid reference issues
	}

	// Add to triage queue
	proc.fuzzer.uafPairWorkQueue.enqueueTriage(triage)

	log.Logf(1, "proc %d: enqueued UAF pair triage with %d pairs", proc.pid, len(racePairs))
}
