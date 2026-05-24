package uafvalidate

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
)

// isConnectionClosedError checks if the error is due to a closed network connection.
// This typically happens during normal shutdown or snapshot restore.
func isConnectionClosedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe")
}

// ExecutorAdapter wraps an ExecProgInstance so it can be reused by the validator.
type ExecutorAdapter struct {
	inst *instance.ExecProgInstance
	cfg  Config
}

func NewExecutorAdapter(inst *instance.ExecProgInstance, cfg Config) *ExecutorAdapter {
	return &ExecutorAdapter{inst: inst, cfg: cfg.withDefaults()}
}

func (e *ExecutorAdapter) batchTimeout(requests int) time.Duration {
	timeout := e.cfg.ExecutionTimeout * time.Duration(requests+1)
	if e.cfg.MaxBatchTimeout > 0 && timeout > e.cfg.MaxBatchTimeout {
		return e.cfg.MaxBatchTimeout
	}
	return timeout
}

func (e *ExecutorAdapter) Run(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	if e == nil || e.inst == nil {
		return nil, fmt.Errorf("executor instance is nil")
	}
	if req == nil || req.Entry == nil {
		return nil, fmt.Errorf("missing program for execution")
	}
	if e.cfg.Debug {
		vmIndex := -1
		if e.inst.VMInstance != nil {
			vmIndex = e.inst.VMInstance.Index()
		}
		log.Logf(0, "uafvalidate: vm=%d starting run barrier=%t", vmIndex, e.requiresBarrier(req.Entry))
	}
	if e.requiresBarrier(req.Entry) {
		return e.runBarrier(ctx, req)
	}
	// If we are in verification phase (RepeatTimes > 0) and barrier is not required by default,
	// we still might want to enforce barrier mode if the original reproduction used it,
	// but here we follow the logic: if requiresBarrier returns false, it means it's a single-threaded repro or similar.
	// However, the user asked to run 100 times with barrier mode if possible.
	// But wait, if requiresBarrier is true, we go to runBarrier.
	// If we are in verification phase, we should pass RepeatTimes to runBarrier as well if it supports it.
	return e.runSingle(ctx, req)
}

func (e *ExecutorAdapter) runSingle(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	entry := req.Entry
	var program *prog.Prog
	if entry.Prog != nil {
		program = entry.Prog.Clone()
	} else {
		for _, p := range entry.Programs {
			if p != nil {
				program = p.Clone()
				break
			}
		}
	}
	if program == nil {
		return nil, fmt.Errorf("no program available for execution")
	}
	opts := e.inst.DefaultExecOpts()
	opts.Threaded = false
	opts.Collide = false
	opts.Repeat = false
	opts.RepeatTimes = 0
	opts.Procs = 1

	if req.RepeatTimes > 0 {
		opts.Repeat = true
		opts.RepeatTimes = req.RepeatTimes
	}

	params := instance.ExecParams{
		SyzProg:  program.Serialize(),
		Duration: e.cfg.ExecutionTimeout,
		Opts:     opts,
		UkcPair:  req.TargetPair,
	}
	res, err := e.inst.RunSyzProg(params)
	if err != nil {
		return nil, err
	}
	if e.cfg.Debug && e.inst.VMInstance != nil {
		log.Logf(0, "uafvalidate: vm=%d finished single run duration=%s crashed=%t", e.inst.VMInstance.Index(), res.Duration, res.Report != nil)
	}
	result := &ExecutionResult{
		Output:   append([]byte{}, res.Output...),
		Duration: res.Duration,
	}
	if res.Report != nil {
		result.Crashed = true
		result.CrashTitle = res.Report.Title
		if len(res.Report.Report) != 0 {
			result.CrashReport = append([]byte{}, res.Report.Report...)
		}
	}
	return result, nil
}

func (e *ExecutorAdapter) runBarrier(parentCtx context.Context, execReq *ExecutionRequest) (*ExecutionResult, error) {
	entry := execReq.Entry
	mask := barrierMask(entry)
	participants := bits.OnesCount64(mask)
	if participants < 2 {
		return e.runSingle(parentCtx, execReq)
	}
	// Reset forward port after barrier execution completes.
	// This allows multiple runBarrier calls on the same VM instance,
	// each with its own RPC server and port forwarding.
	defer func() {
		if e.inst != nil && e.inst.VMInstance != nil {
			e.inst.VMInstance.ResetForwardPort()
		}
	}()
	vmIndex := -1
	if e.inst.VMInstance != nil {
		vmIndex = e.inst.VMInstance.Index()
	}

	mgrCfg := e.inst.ManagerConfig()
	if mgrCfg == nil {
		return nil, fmt.Errorf("missing manager configuration for execprog instance")
	}
	cfgCopy := *mgrCfg

	executorBin := e.inst.ExecutorBinary()
	if executorBin == "" {
		return nil, fmt.Errorf("executor binary path is empty")
	}
	reporter := e.inst.Reporter()
	if reporter == nil {
		return nil, fmt.Errorf("execprog reporter is not configured")
	}

	baseProg := entry.Prog
	if baseProg == nil {
		for _, p := range entry.Programs {
			if p != nil {
				baseProg = p
				break
			}
		}
	}
	if baseProg == nil {
		return nil, fmt.Errorf("missing base program for barrier execution")
	}
	baseProg = baseProg.Clone()

	// Use different program preparation based on phase:
	// - Discovery phase (TargetPair == nil): use original programs
	// - Verification phase (TargetPair != nil): split into sync/async parts for true concurrency
	//   (unless DisableAsyncSplit is set)
	var programs []*prog.Prog
	if execReq.TargetPair != nil && !e.cfg.DisableAsyncSplit {
		// Verification phase: split programs to maximize race triggering
		programs = barrierProgramsForVerify(entry, mask)
		log.Logf(1, "uafvalidate: vm=%d verification phase, split programs: original=%d split=%d",
			vmIndex, participants, len(programs))
	} else {
		// Discovery phase or async split disabled: use original programs
		programs = barrierPrograms(entry, mask)
		if execReq.TargetPair != nil && e.cfg.DisableAsyncSplit {
			log.Logf(1, "uafvalidate: vm=%d verification phase, async split disabled, using %d programs",
				vmIndex, len(programs))
		}
	}

	// Update participants count based on actual programs
	participants = len(programs)
	if participants < 2 {
		return e.runSingle(parentCtx, execReq)
	}

	// RPC address will be set after we know the server port
	if participants > cfgCopy.Procs {
		cfgCopy.Procs = participants
	}

	// Update mask to match new participant count
	mask = (uint64(1) << participants) - 1

	request := &queue.Request{
		Prog:               baseProg,
		ReturnOutput:       true,
		ReturnError:        true,
		Important:          true,
		DisableDdrd:        execReq.DisableDdrd,
		IsValidationMode:   true,
		UkcTargetDelaySide: execReq.TargetDelaySideKernel,
		UkcTargetDelayMode: execReq.TargetDelayModeKernel,
	}
	if execReq.RepeatTimes > 0 {
		// For barrier mode, we can't easily use syz-execprog's -repeat flag because
		// the execution is driven by syz-manager via RPC (syz-executor runner).
		// We need to tell the runner to repeat the execution.
		// Currently syz-executor runner mode doesn't support "repeat N times" in one request easily
		// without changing the protocol or the runner logic significantly.
		// However, we can simulate it by sending the request multiple times or
		// if we want "continuous" execution, we might need to adjust how we construct the request.

		// Actually, syz-executor's runner mode executes what it receives.
		// If we want to repeat 100 times, we might need to loop here or support it in the runner.
		// But the user asked for "run 100 times (without restart)".
		// The current runBarrier implementation sets up a temporary RPC server and runs `syz-executor runner`.
		// The `syz-executor runner` connects back and asks for work.
		// We can serve the same request 100 times.
	}

	// Override UkcPair if TargetPair is provided in the request (verification phase)
	if execReq.TargetPair != nil {
		request.UkcPair = execReq.TargetPair
	} else {
		// If not in verification phase, ensure UkcPair is invalid or nil
		// to avoid setting it in the kernel.
		request.UkcPair = nil
	}

	request.SetBarrier(mask)
	if len(entry.Barrier.ProcList) != 0 && len(entry.Barrier.ProcList) == len(request.BarrierProcList) {
		request.BarrierProcList = append([]int(nil), entry.Barrier.ProcList...)
	}
	if err := request.SetBarrierPrograms(programs); err != nil {
		return nil, fmt.Errorf("assign barrier programs: %w", err)
	}
	delays := barrierDelays(execReq.Delays, entry.ReplayPlan.DelaysMicros, len(programs))
	if len(delays) != 0 {
		if err := request.SetBarrierStartDelays(delays); err != nil {
			return nil, fmt.Errorf("assign barrier delays: %w", err)
		}
	}

	resCh := make(chan *queue.Result, 100)
	request.OnDone(func(_ *queue.Request, res *queue.Result) bool {
		select {
		case resCh <- res:
		default:
		}
		return true
	})

	// If we are in verification phase (RepeatTimes > 0), we want to repeat the request.
	// The current architecture of runBarrier sets up a single request in the manager.
	// The runner connects, gets the request, executes it, and reports back.
	// To support repetition, we can wrap the request in a loop inside the manager's Next() logic,
	// but here we are using a simplified validationManager which holds a single request.
	//
	// A simple way to support repetition here without changing validationManager too much
	// is to make validationManager return the same request multiple times if RepeatTimes is set.
	// However, validationManager is defined in this package (likely unexported).
	// Let's check validationManager implementation.

	log.Logf(0, "uafvalidate: vm=%d executing barrier request mask=0x%x participants=%d delays=%d repeat=%d", vmIndex, mask, participants, len(delays), execReq.RepeatTimes)

	manager := newValidationManager(&cfgCopy, request, e.cfg.Debug, e.cfg)
	if execReq.RepeatTimes > 0 {
		manager.repeatCount = execReq.RepeatTimes
	}
	serv, err := rpcserver.New(&rpcserver.RemoteConfig{
		Config:  &cfgCopy,
		Manager: manager,
		Stats:   rpcserver.NewNamedStats("uaf-validate"),
		Debug:   e.cfg.Debug,
	})
	if err != nil {
		return nil, fmt.Errorf("create rpc server: %w", err)
	}
	defer serv.Close()

	if err := serv.Listen(); err != nil {
		return nil, fmt.Errorf("listen rpc server: %w", err)
	}

	// Always forward the new RPC server port; don't try to reuse old port mappings
	// since the RPC server creates a new listener each time with a potentially different port.
	addr, err := e.inst.VMInstance.Forward(serv.Port())
	if err != nil {
		return nil, fmt.Errorf("forward runner port: %w", err)
	}
	fwdAddr := addr
	host, portStr, err := net.SplitHostPort(fwdAddr)
	if err != nil {
		return nil, fmt.Errorf("split forwarded address: %w", err)
	}

	// Use runner ID 0 since each validation task has its own RPC server.
	// The runner ID must match what we pass to CreateInstance below.
	command := fmt.Sprintf("%s runner 0 %s %s", executorBin, host, portStr)

	ctx, cancel := context.WithTimeout(parentCtx, e.cfg.ExecutionTimeout)
	defer cancel()

	serveCtx, serveCancel := context.WithCancel(ctx)
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- serv.Serve(serveCtx)
	}()
	cleanupCalled := false
	cleanupServe := func() error {
		if cleanupCalled {
			return nil
		}
		cleanupCalled = true
		serveCancel()
		return <-serveErrCh
	}
	defer cleanupServe()

	connErr := serv.CreateInstance(0, nil, nil)
	crashed := false
	defer func() {
		serv.StopFuzzing(0)
		serv.ShutdownInstance(0, crashed)
	}()

	type runOutcome struct {
		output  []byte
		reports []*report.Report
		err     error
	}

	start := time.Now()
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	runOutcomeCh := make(chan runOutcome, 1)
	go func() {
		output, reports, runErr := e.inst.VMInstance.Run(runCtx, reporter, command,
			vm.WithExitCondition(vm.ExitNormal|vm.ExitError|vm.ExitTimeout))
		runOutcomeCh <- runOutcome{output: output, reports: reports, err: runErr}
	}()

	var (
		res         *queue.Result
		execOutcome runOutcome
		haveOutcome bool
	)
	// If repeating, we might get multiple results.
	// But currently resCh is size 1 and we only take the first one.
	// If we repeat 100 times, we probably want to know if ANY of them crashed or succeeded.
	// Or maybe we want to collect stats.
	// For now, let's just wait until the runner finishes all requests or crashes.
	// The runner will keep asking for requests until validationManager returns nil.
	// When validationManager returns nil, the runner will exit (or wait?).
	// Actually syz-executor runner mode exits when there are no more requests if we configure it so?
	// No, it polls.
	// But we close the server when we are done.

	// We need to wait for ALL repetitions to finish if we are in verification mode.
	// But the current logic waits for the FIRST result in resCh.
	// And request.OnDone puts the result in resCh.
	// If we reuse the same request object, OnDone will be called multiple times?
	// Yes, if the manager returns the same request pointer.

	// So we need to consume multiple results from resCh.

	completed := 0
	target := 1
	if execReq.RepeatTimes > 0 {
		target = execReq.RepeatTimes
	}

	triggeredCount := 0
	observedTargetCount := 0

	for (completed < target) || !haveOutcome {
		select {
		case r := <-resCh:
			// We got a result from one execution.
			// If it crashed, we might want to stop early or record it.
			// For verification, we want to see if we can reproduce the UAF.
			// The result contains Ddrd info.
			// We should probably aggregate the results or just log them.
			// For now, let's keep the LAST result or the one that crashed.

			if res == nil || (r.Status != queue.Success && res.Status == queue.Success) {
				res = r
			}

			// Check if the target pair was triggered in this run
			if execReq.TargetPair != nil && r.Ddrd != nil {
				for _, pair := range r.Ddrd.UAFPairs {
					if targetPairMatches(pair, execReq.TargetPair) {
						observedTargetCount++
						if !execReq.ObserveTargetPairOnly {
							triggeredCount++
						}
						if execReq.StopOnSuccess && triggeredCount > 0 {
							runCancel()
							completed = target
						}
						break
					}
				}
			}

			// If we found a crash/UAF, maybe we can stop?
			// The user said "run 100 times".
			// But if the VM crashes, we can't continue easily without restarting.
			// If the VM crashes, the runner loop will break and we will get a crash report via runOutcomeCh.

			completed++
			if completed >= target {
				runCancel()
			}

		case outcome := <-runOutcomeCh:
			execOutcome = outcome
			haveOutcome = true
			// If the VM exited/crashed, we can't run more.
			if completed < target {
				log.Logf(0, "uafvalidate: vm exited early after %d/%d runs", completed, target)
			}
			// Force loop exit
			completed = target

		case <-ctx.Done():
			if res == nil {
				res = &queue.Result{Status: queue.ExecFailure, Err: queue.ErrRequestAborted}
			}
			runCancel()
			completed = target
		}
	}
	output := execOutcome.output
	reports := execOutcome.reports
	runErr := execOutcome.err

	if execReq.TargetPair != nil {
		if matches := crashMatchesTargetPair(reports, execReq.TargetPair); matches > triggeredCount {
			triggeredCount = matches
			if execReq.StopOnSuccess && triggeredCount > 0 {
				runCancel()
			}
		}
	}

	serveErr := cleanupServe()

	var runnerErr error
	select {
	case runnerErr = <-connErr:
	default:
	}

	if res != nil {
		switch res.Status {
		case queue.Crashed, queue.ExecFailure, queue.Hanged:
			crashed = true
		}
	}

	if runErr != nil {
		if result := crashFallbackResult(execReq, reports, output, start); result != nil {
			log.Logf(0, "uafvalidate: barrier request recovered crash result after VM error: %v", runErr)
			return result, nil
		}
		if errors.Is(runErr, context.DeadlineExceeded) {
			return &ExecutionResult{
				Duration:    time.Since(start),
				CrashTitle:  crashTimedOut,
				Crashed:     true,
				Output:      append([]byte{}, output...),
				CrashReport: cloneReportBody(firstNonNilReport(reports)),
			}, nil
		}
		if !errors.Is(runErr, context.Canceled) {
			return nil, fmt.Errorf("run barrier request: %w", runErr)
		}
	}
	if runnerErr != nil && !errors.Is(runnerErr, context.Canceled) && !isConnectionClosedError(runnerErr) {
		if result := crashFallbackResult(execReq, reports, output, start); result != nil {
			log.Logf(0, "uafvalidate: barrier request recovered crash result after runner error: %v", runnerErr)
			return result, nil
		}
		return nil, fmt.Errorf("runner error: %w", runnerErr)
	}
	if serveErr != nil && !errors.Is(serveErr, context.Canceled) && !isConnectionClosedError(serveErr) {
		if result := crashFallbackResult(execReq, reports, output, start); result != nil {
			log.Logf(0, "uafvalidate: barrier request recovered crash result after rpc server error: %v", serveErr)
			return result, nil
		}
		return nil, fmt.Errorf("rpc server error: %w", serveErr)
	}
	if res == nil {
		if result := crashFallbackResult(execReq, reports, output, start); result != nil {
			log.Logf(0, "uafvalidate: barrier request recovered crash result with no queue result")
			return result, nil
		}
		log.Logf(0, "uafvalidate: barrier request returned no result after %s", time.Since(start))
		return nil, fmt.Errorf("barrier execution produced no result")
	}

	execOutput := res.Output
	if len(execOutput) == 0 && len(output) != 0 {
		execOutput = output
	}
	rep := firstNonNilReport(reports)

	result := &ExecutionResult{
		Output:              append([]byte{}, execOutput...),
		Duration:            time.Since(start),
		TriggeredCount:      triggeredCount,
		ObservedTargetCount: observedTargetCount,
	}
	if rep != nil {
		result.CrashReport = cloneReportBody(rep)
	}
	if res.Ddrd != nil {
		result.Ddrd = res.Ddrd.Clone()
	}

	if rep != nil {
		result.Crashed = true
		result.CrashTitle = rep.Title
		log.Logf(0, "uafvalidate: vm=%d barrier request status=%s crashed=true crash=%q duration=%s", vmIndex, res.Status, rep.Title, result.Duration)
		return result, nil
	}

	switch res.Status {
	case queue.Success, queue.Restarted:
		result.Crashed = false
	case queue.Hanged:
		result.Crashed = true
		result.CrashTitle = crashTimedOut
	case queue.ExecFailure:
		result.Crashed = true
		if res.Err != nil {
			result.CrashTitle = res.Err.Error()
		} else {
			result.CrashTitle = "execution failure"
		}
	case queue.Crashed:
		result.Crashed = true
		if res.Err != nil {
			result.CrashTitle = res.Err.Error()
		} else {
			result.CrashTitle = crashLostConnection
		}
	default:
		result.Crashed = true
		result.CrashTitle = "unknown execution status"
	}

	crashInfo := ""
	if result.Crashed && result.CrashTitle != "" {
		crashInfo = fmt.Sprintf(" crash=%q", result.CrashTitle)
	}
	log.Logf(0, "uafvalidate: vm=%d barrier request status=%s crashed=%t%s duration=%s", vmIndex, res.Status, result.Crashed, crashInfo, result.Duration)

	return result, nil
}

func (e *ExecutorAdapter) requiresBarrier(entry *fuzzer.UAFCorpusEntry) bool {
	if entry == nil {
		return false
	}
	if entry.AsyncMode {
		return false
	}
	if bits.OnesCount64(entry.Barrier.Participants) >= 2 {
		return true
	}
	if entry.Barrier.GroupSize >= 2 {
		return true
	}
	return len(entry.Programs) >= 2
}

// isAsyncMode returns true if the entry uses intra-process async execution.
func (e *ExecutorAdapter) isAsyncMode(entry *fuzzer.UAFCorpusEntry) bool {
	return entry != nil && entry.AsyncMode
}

func (e *ExecutorAdapter) Close() error {
	if e == nil || e.inst == nil || e.inst.VMInstance == nil {
		return nil
	}
	return e.inst.VMInstance.Close()
}

// CloseExecutorOnly is a no-op that keeps the VM running.
// This is used for snapshot mode where we want to reuse the VM.
// The actual cleanup (RPC connections etc) happens when the next Run() is called
// which will re-establish connections as needed.
func (e *ExecutorAdapter) CloseExecutorOnly() error {
	// No-op: we intentionally don't close anything here.
	// The VM stays running, and new SSH/executor connections will be
	// established when the snapshot is restored and SetupExecProg is called.
	return nil
}

func barrierMask(entry *fuzzer.UAFCorpusEntry) uint64 {
	if entry == nil {
		return 0
	}
	mask := entry.Barrier.Participants
	if mask != 0 {
		return mask
	}
	if entry.Barrier.GroupSize >= 2 {
		for i := 0; i < entry.Barrier.GroupSize; i++ {
			mask |= 1 << uint(i)
		}
	}
	if mask == 0 && len(entry.Programs) >= 2 {
		for i := range entry.Programs {
			mask |= 1 << uint(i)
		}
	}
	return mask
}

func barrierPrograms(entry *fuzzer.UAFCorpusEntry, mask uint64) []*prog.Prog {
	if entry == nil {
		return nil
	}
	count := bits.OnesCount64(mask)
	if count == 0 {
		return nil
	}
	programs := make([]*prog.Prog, count)
	for i := 0; i < count; i++ {
		if i < len(entry.Programs) && entry.Programs[i] != nil {
			programs[i] = entry.Programs[i].Clone()
			continue
		}
		if entry.Prog != nil {
			programs[i] = entry.Prog.Clone()
		}
	}
	for i := range programs {
		if programs[i] == nil && entry.Prog != nil {
			programs[i] = entry.Prog.Clone()
		}
	}
	return programs
}

// barrierProgramsForVerify creates barrier programs for verification phase.
// It duplicates each program: one original, one with async calls marked.
// For each original program that has async-capable calls, it creates two programs:
// - prog1: the original program (sequential execution)
// - prog2: a clone with async calls marked (parallel execution within proc)
// This doubles the number of barrier participants to maximize race triggering.
func barrierProgramsForVerify(entry *fuzzer.UAFCorpusEntry, mask uint64) []*prog.Prog {
	if entry == nil {
		return nil
	}
	count := bits.OnesCount64(mask)
	if count == 0 {
		return nil
	}

	// First, collect original programs
	origPrograms := make([]*prog.Prog, count)
	for i := 0; i < count; i++ {
		if i < len(entry.Programs) && entry.Programs[i] != nil {
			origPrograms[i] = entry.Programs[i].Clone()
			continue
		}
		if entry.Prog != nil {
			origPrograms[i] = entry.Prog.Clone()
		}
	}
	for i := range origPrograms {
		if origPrograms[i] == nil && entry.Prog != nil {
			origPrograms[i] = entry.Prog.Clone()
		}
	}

	// Split each program: original + async version
	var result []*prog.Prog
	for i, p := range origPrograms {
		if p == nil {
			continue
		}
		prog1, prog2 := prog.SplitAsyncCalls(p)
		if prog1 != nil {
			result = append(result, prog1)
		}
		if prog2 != nil {
			result = append(result, prog2)
			log.Logf(0, "uafvalidate: prog[%d] duplicated with async: %d calls", i, len(prog2.Calls))
		}
	}

	// If no programs after split, fallback to original
	if len(result) == 0 {
		return origPrograms
	}

	log.Logf(0, "uafvalidate: verification split result: %d original -> %d total (doubled with async)",
		count, len(result))

	return result
}

func barrierDelays(requestDelays, storedDelays []int64, participants int) []int64 {
	delays := requestDelays
	if len(delays) == 0 {
		delays = storedDelays
	}
	if len(delays) == 0 || participants == 0 {
		return nil
	}
	if len(delays) > participants {
		copied := make([]int64, participants)
		copy(copied, delays[:participants])
		delays = copied
	} else if len(delays) < participants {
		padded := make([]int64, participants)
		copy(padded, delays)
		delays = padded
	} else {
		delays = append([]int64(nil), delays...)
	}
	return delays
}

func cloneUkcPair(entry *fuzzer.UAFCorpusEntry) *ddrd.MayUAFPair {
	if entry == nil {
		return nil
	}
	pair := entry.PairBasicInfo
	if isZeroUkcPair(pair) {
		return nil
	}
	clone := pair
	return &clone
}

func isZeroUkcPair(pair ddrd.MayUAFPair) bool {
	return pair.FreeAccessName == 0 && pair.UseAccessName == 0 &&
		pair.FreeCallStack == 0 && pair.UseCallStack == 0
}

func targetPairMatches(pair *ddrd.MayUAFPair, target *ddrd.MayUAFPair) bool {
	if pair == nil || target == nil {
		return false
	}
	if target.FreeCallStack == 0 && target.UseCallStack == 0 {
		forward := targetFieldMatches(target.FreeAccessName, pair.FreeAccessName) &&
			targetFieldMatches(target.UseAccessName, pair.UseAccessName)
		reverse := targetFieldMatches(target.FreeAccessName, pair.UseAccessName) &&
			targetFieldMatches(target.UseAccessName, pair.FreeAccessName)
		return forward || reverse
	}
	return targetFieldMatches(target.FreeAccessName, pair.FreeAccessName) &&
		targetFieldMatches(target.UseAccessName, pair.UseAccessName) &&
		targetFieldMatches(target.FreeCallStack, pair.FreeCallStack) &&
		targetFieldMatches(target.UseCallStack, pair.UseCallStack) &&
		targetSNMatches(pair.FreeSN, target.FreeSN, target.FreeSNMin, target.FreeSNMax) &&
		targetSNMatches(pair.UseSN, target.UseSN, target.UseSNMin, target.UseSNMax) &&
		targetInt32Matches(target.FreeTid, pair.FreeTid) &&
		targetInt32Matches(target.UseTid, pair.UseTid)
}

func targetFieldMatches(want, got uint64) bool {
	return want == 0 || want == got
}

func targetSNMatches(got, want, min, max int32) bool {
	if min != 0 || max != 0 {
		if min != 0 && got < min {
			return false
		}
		if max != 0 && got > max {
			return false
		}
		return true
	}
	return want == 0 || want == got
}

func targetInt32Matches(want, got int32) bool {
	return want == 0 || want == got
}

func newValidationManager(cfg *mgrconfig.Config, req *queue.Request, debug bool, valCfg Config) *validationManager {
	return &validationManager{
		cfg:     cfg,
		request: req,
		debug:   debug,
		valCfg:  valCfg,
	}
}

// calculateSweepDelay computes start_delay using exponential curve: delay(i) = maxDelay * (i/n)^power
// This produces slow growth initially and fast growth towards the end.
func calculateSweepDelay(iteration, totalIterations int, maxDelayUs int64, power float64) int64 {
	if totalIterations <= 1 {
		return 0
	}
	if iteration <= 0 {
		return 0
	}
	if iteration >= totalIterations {
		return maxDelayUs
	}
	// ratio = i / n, where i is 0-based iteration
	ratio := float64(iteration) / float64(totalIterations-1)
	// Apply power to create exponential curve
	return int64(float64(maxDelayUs) * math.Pow(ratio, power))
}

func crashMatchesTargetPair(reports []*report.Report, target *ddrd.MayUAFPair) int {
	if target == nil || len(reports) == 0 {
		log.Logf(2, "crashMatchesTargetPair: no reports or target (reports=%d, target=%v)", len(reports), target != nil)
		return 0
	}
	want := targetVarNames(target)
	if len(want) == 0 {
		log.Logf(2, "crashMatchesTargetPair: no target varnames")
		return 0
	}
	log.Logf(2, "crashMatchesTargetPair: checking %d reports against target varnames=%v", len(reports), want)
	matches := 0
	for i, rep := range reports {
		if rep != nil {
			log.Logf(2, "crashMatchesTargetPair: report[%d] title=%q reportLen=%d", i, rep.Title, len(rep.Report))
		}
		if reportMatchesVarNames(rep, want) {
			matches++
			log.Logf(1, "crashMatchesTargetPair: report[%d] MATCHED target", i)
		}
	}
	log.Logf(2, "crashMatchesTargetPair: total matches=%d", matches)
	return matches
}

func firstNonNilReport(reports []*report.Report) *report.Report {
	for _, rep := range reports {
		if rep != nil {
			return rep
		}
	}
	return nil
}

func cloneReportBody(rep *report.Report) []byte {
	if rep == nil || len(rep.Report) == 0 {
		return nil
	}
	return append([]byte{}, rep.Report...)
}

func crashFallbackResult(execReq *ExecutionRequest, reports []*report.Report, output []byte, start time.Time) *ExecutionResult {
	if execReq == nil || execReq.TargetPair == nil {
		return nil
	}
	matches := crashMatchesTargetPair(reports, execReq.TargetPair)
	if matches == 0 {
		return nil
	}
	rep := firstNonNilReport(reports)
	title := ""
	if rep != nil {
		title = rep.Title
	}
	return &ExecutionResult{
		Output:         append([]byte{}, output...),
		Duration:       time.Since(start),
		TriggeredCount: matches,
		Crashed:        true,
		CrashTitle:     title,
		CrashReport:    cloneReportBody(rep),
	}
}

func targetVarNames(pair *ddrd.MayUAFPair) map[string]struct{} {
	if pair == nil {
		return nil
	}
	want := make(map[string]struct{}, 2)
	if pair.FreeAccessName != 0 {
		want[strconv.FormatUint(pair.FreeAccessName, 10)] = struct{}{}
	}
	if pair.UseAccessName != 0 {
		want[strconv.FormatUint(pair.UseAccessName, 10)] = struct{}{}
	}
	return want
}

func reportMatchesVarNames(rep *report.Report, want map[string]struct{}) bool {
	if rep == nil || len(want) == 0 {
		return false
	}
	info := rep.CustomDataRace
	if info == nil {
		info = report.ParseCustomDataRace(rep.Report)
	}
	if info == nil || len(info.Entries) == 0 {
		log.Logf(2, "reportMatchesVarNames: no CustomDataRace entries parsed from report")
		return false
	}
	log.Logf(2, "reportMatchesVarNames: checking %d entries against want=%v", len(info.Entries), want)
	for _, entry := range info.Entries {
		if entry == nil {
			continue
		}
		log.Logf(2, "reportMatchesVarNames: entry.VarName=%q", entry.VarName)
		if _, ok := want[entry.VarName]; ok {
			log.Logf(1, "reportMatchesVarNames: MATCHED entry.VarName=%s", entry.VarName)
			return true
		}
	}
	return false
}

type validationManager struct {
	cfg         *mgrconfig.Config
	request     *queue.Request
	debug       bool
	served      atomic.Bool
	repeatCount int
	servedCount int
	valCfg      Config // Validation config for delay sweep
}

func (m *validationManager) MaxSignal() signal.Signal { return nil }

func (m *validationManager) BugFrames() ([]string, []string) { return nil, nil }

func (m *validationManager) CoverageFilter(_ []*vminfo.KernelModule) ([]uint64, error) {
	return nil, nil
}

func (m *validationManager) MachineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) (queue.Source, error) {
	if len(syscalls) == 0 {
		return nil, fmt.Errorf("all system calls are disabled")
	}
	opts := fuzzer.DefaultExecOpts(m.cfg, features, m.debug)
	opts.ExecFlags &^= flatrpc.ExecFlagThreaded
	if m.request.UkcPair != nil {
		if !m.request.DisableDdrd {
			opts.ExecFlags |= flatrpc.ExecFlagCollectDdrdUaf
		}
	}
	source := queue.Callback(func() *queue.Request {
		if m.request == nil {
			return nil
		}
		if m.repeatCount > 0 {
			if m.servedCount < m.repeatCount {
				currentIteration := m.servedCount
				m.servedCount++

				// Apply delay sweep if enabled
				if m.valCfg.VerifyDelaySweep && len(m.request.BarrierStartDelayUs) > 0 {
					sweepDelay := calculateSweepDelay(
						currentIteration,
						m.repeatCount,
						m.valCfg.VerifyDelayMaxUs,
						m.valCfg.VerifyDelayPower,
					)
					// Create a copy of the request with updated delays
					reqCopy := *m.request
					newDelays := make([]int64, len(m.request.BarrierStartDelayUs))
					copy(newDelays, m.request.BarrierStartDelayUs)
					// Apply sweep delay to the first participant (free side)
					newDelays[0] = sweepDelay
					reqCopy.BarrierStartDelayUs = newDelays

					if m.debug || currentIteration%10 == 0 {
						log.Logf(0, "uafvalidate: delay sweep iteration %d/%d start_delay=%dus",
							currentIteration+1, m.repeatCount, sweepDelay)
					}
					return &reqCopy
				}
				return m.request
			}
			return nil
		}
		if m.served.CompareAndSwap(false, true) {
			return m.request
		}
		return nil
	})
	return queue.DefaultOpts(source, opts), nil
}

// RunBatch executes multiple requests in a single RPC session.
// This is more efficient than calling Run multiple times as it avoids
// re-establishing SSH connections and RPC servers for each request.
// All requests share the same runner process, which maintains kernel state
// between executions (important for replay + validate workflow).
func (e *ExecutorAdapter) RunBatch(ctx context.Context, reqs []*ExecutionRequest) ([]*ExecutionResult, error) {
	if e == nil || e.inst == nil {
		return nil, fmt.Errorf("executor instance is nil")
	}
	if len(reqs) == 0 {
		return nil, nil
	}

	// Classify requests
	allBarrier := true
	allAsync := true
	for _, req := range reqs {
		if req == nil || req.Entry == nil {
			continue
		}
		if !e.requiresBarrier(req.Entry) {
			allBarrier = false
		}
		if !e.isAsyncMode(req.Entry) {
			allAsync = false
		}
	}

	if allBarrier {
		return e.runBarrierBatch(ctx, reqs)
	}
	if allAsync {
		return e.runAsyncBatch(ctx, reqs)
	}

	// Mixed mode (e.g., barrier replay + async main): split into sub-batches
	// preserving original request ordering in the results.
	results := make([]*ExecutionResult, len(reqs))
	var barrierReqs []*ExecutionRequest
	var barrierIdx []int
	var asyncReqs []*ExecutionRequest
	var asyncIdx []int
	for i, req := range reqs {
		if req == nil || req.Entry == nil {
			continue
		}
		if e.isAsyncMode(req.Entry) {
			asyncReqs = append(asyncReqs, req)
			asyncIdx = append(asyncIdx, i)
		} else {
			barrierReqs = append(barrierReqs, req)
			barrierIdx = append(barrierIdx, i)
		}
	}
	if len(barrierReqs) > 0 {
		bResults, err := e.runBarrierBatch(ctx, barrierReqs)
		if err != nil {
			return results, err
		}
		for j, idx := range barrierIdx {
			if j < len(bResults) {
				results[idx] = bResults[j]
			}
		}
	}
	if len(asyncReqs) > 0 {
		aResults, err := e.runAsyncBatch(ctx, asyncReqs)
		if err != nil {
			return results, err
		}
		for j, idx := range asyncIdx {
			if j < len(aResults) {
				results[idx] = aResults[j]
			}
		}
	}
	return results, nil
}

// runBarrierBatch executes multiple barrier requests in a single RPC session.
func (e *ExecutorAdapter) runBarrierBatch(parentCtx context.Context, reqs []*ExecutionRequest) ([]*ExecutionResult, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	// Reset forward port after batch execution completes
	defer func() {
		if e.inst != nil && e.inst.VMInstance != nil {
			e.inst.VMInstance.ResetForwardPort()
		}
	}()

	vmIndex := -1
	if e.inst.VMInstance != nil {
		vmIndex = e.inst.VMInstance.Index()
	}

	mgrCfg := e.inst.ManagerConfig()
	if mgrCfg == nil {
		return nil, fmt.Errorf("missing manager configuration for execprog instance")
	}
	cfgCopy := *mgrCfg

	executorBin := e.inst.ExecutorBinary()
	if executorBin == "" {
		return nil, fmt.Errorf("executor binary path is empty")
	}
	reporter := e.inst.Reporter()
	if reporter == nil {
		return nil, fmt.Errorf("execprog reporter is not configured")
	}

	// Build queue requests for all execution requests
	queueReqs := make([]*queue.Request, 0, len(reqs))
	for i, execReq := range reqs {
		if execReq == nil || execReq.Entry == nil {
			continue
		}
		entry := execReq.Entry
		mask := barrierMask(entry)
		participants := bits.OnesCount64(mask)
		if participants < 2 {
			continue
		}

		programs := barrierPrograms(entry, mask)
		if len(programs) < 2 {
			continue
		}

		baseProg := entry.Prog
		if baseProg == nil {
			for _, p := range entry.Programs {
				if p != nil {
					baseProg = p
					break
				}
			}
		}
		if baseProg == nil {
			continue
		}

		request := &queue.Request{
			Prog:               baseProg.Clone(),
			Stat:               stat.New(fmt.Sprintf("batch-request-%d", i), "", stat.NoGraph),
			ExecOpts:           flatrpc.ExecOpts{},
			ReturnOutput:       true,
			ReturnError:        true,
			DisableDdrd:        execReq.DisableDdrd,
			IsValidationMode:   true,
			UkcTargetDelaySide: execReq.TargetDelaySideKernel,
			UkcTargetDelayMode: execReq.TargetDelayModeKernel,
		}
		// Note: We set DisableDdrd above; rpcserver/runner.go will handle ExecFlags
		// based on that field when serializing for barrier execution.

		// Set UkcPair for verification phase (TargetPair != nil means we're verifying a specific pair)
		if execReq.TargetPair != nil {
			request.UkcPair = execReq.TargetPair
		}

		request.SetBarrier(mask)
		if err := request.SetBarrierPrograms(programs); err != nil {
			continue
		}
		delays := barrierDelays(execReq.Delays, entry.ReplayPlan.DelaysMicros, len(programs))
		if len(delays) != 0 {
			request.SetBarrierStartDelays(delays)
		}

		queueReqs = append(queueReqs, request)
	}

	if len(queueReqs) == 0 {
		return nil, fmt.Errorf("no valid barrier requests in batch")
	}

	log.Logf(0, "uafvalidate: vm=%d executing batch of %d barrier requests", vmIndex, len(queueReqs))

	// Create multi-request manager
	manager := newMultiRequestManager(&cfgCopy, queueReqs, e.cfg.Debug, e.cfg)

	serv, err := rpcserver.New(&rpcserver.RemoteConfig{
		Config:  &cfgCopy,
		Manager: manager,
		Stats:   rpcserver.NewNamedStats("uaf-validate-batch"),
		Debug:   e.cfg.Debug,
	})
	if err != nil {
		return nil, fmt.Errorf("create rpc server: %w", err)
	}
	defer serv.Close()

	if err := serv.Listen(); err != nil {
		return nil, fmt.Errorf("listen rpc server: %w", err)
	}

	addr, err := e.inst.VMInstance.Forward(serv.Port())
	if err != nil {
		return nil, fmt.Errorf("forward runner port: %w", err)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split forwarded address: %w", err)
	}

	command := fmt.Sprintf("%s runner 0 %s %s", executorBin, host, portStr)

	ctx, cancel := context.WithTimeout(parentCtx, e.batchTimeout(len(queueReqs)))
	defer cancel()

	serveCtx, serveCancel := context.WithCancel(ctx)
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- serv.Serve(serveCtx)
	}()
	defer serveCancel()

	connErr := serv.CreateInstance(0, nil, nil)
	defer func() {
		serv.StopFuzzing(0)
		serv.ShutdownInstance(0, false)
	}()

	start := time.Now()
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	type runOutcome struct {
		output  []byte
		reports []*report.Report
		err     error
	}
	runOutcomeCh := make(chan runOutcome, 1)
	go func() {
		output, reports, runErr := e.inst.VMInstance.Run(runCtx, reporter, command,
			vm.WithExitCondition(vm.ExitNormal|vm.ExitError|vm.ExitTimeout))
		runOutcomeCh <- runOutcome{output: output, reports: reports, err: runErr}
	}()

	// Collect results from all requests
	results := make([]*ExecutionResult, len(queueReqs))
	completed := 0

	type indexedQueueResult struct {
		idx int
		res *queue.Result
	}
	resCh := make(chan indexedQueueResult, len(queueReqs))
	for i := range queueReqs {
		reqIdx := i
		queueReqs[i].OnDone(func(_ *queue.Request, res *queue.Result) bool {
			select {
			case resCh <- indexedQueueResult{idx: reqIdx, res: res}:
			default:
			}
			return true
		})
	}

	// Wait for all results or VM exit
	// haveOutcome tracks whether we've received the final VM.Run outcome
	haveOutcome := false
	var finalOutcome runOutcome

	for completed < len(queueReqs) || !haveOutcome {
		select {
		case item := <-resCh:
			resultIdx := item.idx
			res := item.res
			if resultIdx >= 0 && resultIdx < len(results) && results[resultIdx] == nil {
				results[resultIdx] = &ExecutionResult{
					Output:   append([]byte{}, res.Output...),
					Duration: time.Since(start),
				}
				if res.Ddrd != nil {
					results[resultIdx].Ddrd = res.Ddrd.Clone()
				}
				switch res.Status {
				case queue.Crashed, queue.ExecFailure, queue.Hanged:
					results[resultIdx].Crashed = true
					if res.Err != nil {
						results[resultIdx].CrashTitle = res.Err.Error()
					}
				}

				// Check if this request has a TargetPair and if DDRD data matches
				if resultIdx < len(reqs) && reqs[resultIdx].TargetPair != nil && res.Ddrd != nil {
					target := reqs[resultIdx].TargetPair
					for _, pair := range res.Ddrd.UAFPairs {
						if targetPairMatches(pair, target) {
							results[resultIdx].ObservedTargetCount++
							if !reqs[resultIdx].ObserveTargetPairOnly {
								results[resultIdx].TriggeredCount++
							}
							break
						}
					}
				}
			}
			completed++
			// Cancel VM.Run when all requests are done to trigger final output collection
			if completed >= len(queueReqs) {
				runCancel()
			}

		case outcome := <-runOutcomeCh:
			finalOutcome = outcome
			haveOutcome = true
			if outcome.err != nil && !errors.Is(outcome.err, context.Canceled) {
				log.Logf(0, "uafvalidate: vm=%d batch run error: %v", vmIndex, outcome.err)
			}
			// Fill remaining results with crash info from VM exit
			for i := range results {
				if results[i] != nil {
					continue
				}
				results[i] = &ExecutionResult{
					Output:   outcome.output,
					Duration: time.Since(start),
					Crashed:  len(outcome.reports) > 0,
				}
				if len(outcome.reports) > 0 && outcome.reports[0] != nil {
					results[i].CrashTitle = outcome.reports[0].Title
					results[i].CrashReport = cloneReportBody(outcome.reports[0])

					// Check if crash matches TargetPair for remaining verify requests
					if i < len(reqs) && reqs[i].TargetPair != nil {
						if matches := crashMatchesTargetPair(outcome.reports, reqs[i].TargetPair); matches > 0 {
							results[i].TriggeredCount = matches
							log.Logf(1, "uafvalidate: batch crash matched target pair for request %d, triggered=%d", i, matches)
						}
					}
				}
			}
			// Force all requests complete since VM exited
			if completed < len(queueReqs) {
				log.Logf(0, "uafvalidate: vm=%d exited early after %d/%d requests", vmIndex, completed, len(queueReqs))
				completed = len(queueReqs)
			}

		case <-ctx.Done():
			for i := range results {
				if results[i] != nil {
					continue
				}
				results[i] = &ExecutionResult{
					Duration: time.Since(start),
					Crashed:  true,
				}
			}
			completed = len(queueReqs)
			// Still wait for runOutcomeCh to get final crash info
			if !haveOutcome {
				select {
				case outcome := <-runOutcomeCh:
					finalOutcome = outcome
					haveOutcome = true
				case <-time.After(5 * time.Second):
					// Timeout waiting for VM.Run to finish
					haveOutcome = true
				}
			}

		case err := <-connErr:
			if err != nil {
				log.Logf(0, "uafvalidate: vm=%d batch connection error: %v", vmIndex, err)
			}
		}
	}

	// After loop: check if finalOutcome has crash reports that weren't applied to results
	// This handles the case where all requests completed successfully but VM detected a crash afterward
	if haveOutcome && len(finalOutcome.reports) > 0 {
		for i := range results {
			if results[i] == nil {
				continue
			}
			// If this result doesn't have crash info but VM has crash reports, update it
			if !results[i].Crashed && finalOutcome.reports[0] != nil {
				results[i].Crashed = true
				results[i].CrashTitle = finalOutcome.reports[0].Title
				results[i].CrashReport = cloneReportBody(finalOutcome.reports[0])
				results[i].Output = finalOutcome.output
			}
			// Check if crash matches TargetPair for verify requests
			if i < len(reqs) && reqs[i].TargetPair != nil && results[i].TriggeredCount == 0 {
				if matches := crashMatchesTargetPair(finalOutcome.reports, reqs[i].TargetPair); matches > 0 {
					results[i].TriggeredCount = matches
					log.Logf(0, "uafvalidate: batch final crash matched target pair for request %d, triggered=%d", i, matches)
				}
			}
		}
	}

	if haveOutcome && len(finalOutcome.output) != 0 {
		for i := range results {
			if results[i] == nil {
				continue
			}
			if len(results[i].Output) == 0 {
				results[i].Output = append([]byte{}, finalOutcome.output...)
			} else {
				results[i].Output = append(results[i].Output, finalOutcome.output...)
			}
		}
	}

	log.Logf(0, "uafvalidate: vm=%d batch completed %d requests in %s", vmIndex, len(results), time.Since(start))
	return results, nil
}

// runAsyncBatch executes multiple async (intra-process) requests in a single RPC session.
// Unlike runBarrierBatch, this mode:
// - Does NOT use barrier synchronization (single process, not two)
// - Keeps ExecFlagThreaded enabled so async calls run on separate threads
// - Each program already has CallProps.Async=true on the racing calls
func (e *ExecutorAdapter) runAsyncBatch(parentCtx context.Context, reqs []*ExecutionRequest) ([]*ExecutionResult, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	defer func() {
		if e.inst != nil && e.inst.VMInstance != nil {
			e.inst.VMInstance.ResetForwardPort()
		}
	}()

	vmIndex := -1
	if e.inst.VMInstance != nil {
		vmIndex = e.inst.VMInstance.Index()
	}

	mgrCfg := e.inst.ManagerConfig()
	if mgrCfg == nil {
		return nil, fmt.Errorf("missing manager configuration for execprog instance")
	}
	cfgCopy := *mgrCfg
	cfgCopy.Procs = 1 // Force single proc to prevent concurrent ddrd_controller_ corruption

	executorBin := e.inst.ExecutorBinary()
	if executorBin == "" {
		return nil, fmt.Errorf("executor binary path is empty")
	}
	reporter := e.inst.Reporter()
	if reporter == nil {
		return nil, fmt.Errorf("execprog reporter is not configured")
	}

	// Build queue requests for all async execution requests
	queueReqs := make([]*queue.Request, 0, len(reqs))
	for i, execReq := range reqs {
		if execReq == nil || execReq.Entry == nil {
			continue
		}
		entry := execReq.Entry
		if entry.Prog == nil {
			continue
		}

		// Ensure the racing calls have Async=true
		p := entry.Prog.Clone()
		for _, callIdx := range entry.AsyncRaceCalls {
			if callIdx >= 0 && callIdx < len(p.Calls) {
				p.Calls[callIdx].Props.Async = true
			}
		}

		request := &queue.Request{
			Prog:               p,
			Stat:               stat.New(fmt.Sprintf("async-batch-%d", i), "", stat.NoGraph),
			ExecOpts:           flatrpc.ExecOpts{},
			ReturnOutput:       true,
			ReturnError:        true,
			DisableDdrd:        execReq.DisableDdrd,
			IsValidationMode:   true,
			UkcTargetDelaySide: execReq.TargetDelaySideKernel,
			UkcTargetDelayMode: execReq.TargetDelayModeKernel,
		}

		if execReq.TargetPair != nil {
			request.UkcPair = execReq.TargetPair
		}

		queueReqs = append(queueReqs, request)
	}

	if len(queueReqs) == 0 {
		return nil, fmt.Errorf("no valid async requests in batch")
	}

	log.Logf(0, "uafvalidate: vm=%d executing batch of %d async requests", vmIndex, len(queueReqs))

	// Create async request manager (keeps ExecFlagThreaded set)
	manager := newAsyncRequestManager(&cfgCopy, queueReqs, e.cfg.Debug, e.cfg)

	serv, err := rpcserver.New(&rpcserver.RemoteConfig{
		Config:  &cfgCopy,
		Manager: manager,
		Stats:   rpcserver.NewNamedStats("uaf-validate-async"),
		Debug:   e.cfg.Debug,
	})
	if err != nil {
		return nil, fmt.Errorf("create rpc server: %w", err)
	}
	defer serv.Close()

	if err := serv.Listen(); err != nil {
		return nil, fmt.Errorf("listen rpc server: %w", err)
	}

	addr, err := e.inst.VMInstance.Forward(serv.Port())
	if err != nil {
		return nil, fmt.Errorf("forward runner port: %w", err)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split forwarded address: %w", err)
	}

	command := fmt.Sprintf("%s runner 0 %s %s", executorBin, host, portStr)

	ctx, cancel := context.WithTimeout(parentCtx, e.batchTimeout(len(queueReqs)))
	defer cancel()

	serveCtx, serveCancel := context.WithCancel(ctx)
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- serv.Serve(serveCtx)
	}()
	defer serveCancel()

	connErr := serv.CreateInstance(0, nil, nil)
	defer func() {
		serv.StopFuzzing(0)
		serv.ShutdownInstance(0, false)
	}()

	start := time.Now()
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	type runOutcome struct {
		output  []byte
		reports []*report.Report
		err     error
	}
	runOutcomeCh := make(chan runOutcome, 1)
	go func() {
		output, reports, runErr := e.inst.VMInstance.Run(runCtx, reporter, command,
			vm.WithExitCondition(vm.ExitNormal|vm.ExitError|vm.ExitTimeout))
		runOutcomeCh <- runOutcome{output: output, reports: reports, err: runErr}
	}()

	// Collect results
	results := make([]*ExecutionResult, len(queueReqs))
	completed := 0

	type indexedQueueResult struct {
		idx int
		res *queue.Result
	}
	resCh := make(chan indexedQueueResult, len(queueReqs))
	for i := range queueReqs {
		reqIdx := i
		queueReqs[i].OnDone(func(_ *queue.Request, res *queue.Result) bool {
			select {
			case resCh <- indexedQueueResult{idx: reqIdx, res: res}:
			default:
			}
			return true
		})
	}

	haveOutcome := false
	var finalOutcome runOutcome

	for completed < len(queueReqs) || !haveOutcome {
		select {
		case item := <-resCh:
			resultIdx := item.idx
			res := item.res
			if resultIdx >= 0 && resultIdx < len(results) && results[resultIdx] == nil {
				results[resultIdx] = &ExecutionResult{
					Output:   append([]byte{}, res.Output...),
					Duration: time.Since(start),
				}
				if res.Ddrd != nil {
					results[resultIdx].Ddrd = res.Ddrd.Clone()
				}
				switch res.Status {
				case queue.Crashed, queue.ExecFailure, queue.Hanged:
					results[resultIdx].Crashed = true
					if res.Err != nil {
						results[resultIdx].CrashTitle = res.Err.Error()
					}
				}

				if resultIdx < len(reqs) && reqs[resultIdx].TargetPair != nil && res.Ddrd != nil {
					target := reqs[resultIdx].TargetPair
					for _, pair := range res.Ddrd.UAFPairs {
						if targetPairMatches(pair, target) {
							results[resultIdx].ObservedTargetCount++
							if !reqs[resultIdx].ObserveTargetPairOnly {
								results[resultIdx].TriggeredCount++
							}
							break
						}
					}
				}
			}
			completed++
			if completed >= len(queueReqs) {
				runCancel()
			}

		case outcome := <-runOutcomeCh:
			finalOutcome = outcome
			haveOutcome = true
			if outcome.err != nil && !errors.Is(outcome.err, context.Canceled) {
				log.Logf(0, "uafvalidate: vm=%d async batch run error: %v", vmIndex, outcome.err)
			}
			for i := range results {
				if results[i] != nil {
					continue
				}
				results[i] = &ExecutionResult{
					Output:   outcome.output,
					Duration: time.Since(start),
					Crashed:  len(outcome.reports) > 0,
				}
				if len(outcome.reports) > 0 && outcome.reports[0] != nil {
					results[i].CrashTitle = outcome.reports[0].Title
					results[i].CrashReport = cloneReportBody(outcome.reports[0])

					if i < len(reqs) && reqs[i].TargetPair != nil {
						if matches := crashMatchesTargetPair(outcome.reports, reqs[i].TargetPair); matches > 0 {
							results[i].TriggeredCount = matches
						}
					}
				}
			}
			if completed < len(queueReqs) {
				log.Logf(0, "uafvalidate: vm=%d async exited early after %d/%d requests", vmIndex, completed, len(queueReqs))
				completed = len(queueReqs)
			}

		case <-ctx.Done():
			for i := range results {
				if results[i] != nil {
					continue
				}
				results[i] = &ExecutionResult{
					Duration: time.Since(start),
					Crashed:  true,
				}
			}
			completed = len(queueReqs)
			if !haveOutcome {
				select {
				case outcome := <-runOutcomeCh:
					finalOutcome = outcome
					haveOutcome = true
				case <-time.After(5 * time.Second):
					haveOutcome = true
				}
			}

		case err := <-connErr:
			if err != nil {
				log.Logf(0, "uafvalidate: vm=%d async batch connection error: %v", vmIndex, err)
			}
		}
	}

	if haveOutcome && len(finalOutcome.reports) > 0 {
		for i := range results {
			if results[i] == nil {
				continue
			}
			if !results[i].Crashed && finalOutcome.reports[0] != nil {
				results[i].Crashed = true
				results[i].CrashTitle = finalOutcome.reports[0].Title
				results[i].CrashReport = cloneReportBody(finalOutcome.reports[0])
				results[i].Output = finalOutcome.output
			}
			if i < len(reqs) && reqs[i].TargetPair != nil && results[i].TriggeredCount == 0 {
				if matches := crashMatchesTargetPair(finalOutcome.reports, reqs[i].TargetPair); matches > 0 {
					results[i].TriggeredCount = matches
				}
			}
		}
	}

	log.Logf(0, "uafvalidate: vm=%d async batch completed %d requests in %s", vmIndex, len(results), time.Since(start))
	return results, nil
}

// asyncRequestManager manages async (intra-process) requests.
// Unlike multiRequestManager, it keeps ExecFlagThreaded enabled.
type asyncRequestManager struct {
	cfg      *mgrconfig.Config
	requests []*queue.Request
	debug    bool
	valCfg   Config
	mu       sync.Mutex
	idx      int
}

func newAsyncRequestManager(cfg *mgrconfig.Config, requests []*queue.Request, debug bool, valCfg Config) *asyncRequestManager {
	return &asyncRequestManager{
		cfg:      cfg,
		requests: requests,
		debug:    debug,
		valCfg:   valCfg,
	}
}

func (m *asyncRequestManager) MaxSignal() signal.Signal { return nil }

func (m *asyncRequestManager) BugFrames() ([]string, []string) { return nil, nil }

func (m *asyncRequestManager) CoverageFilter(_ []*vminfo.KernelModule) ([]uint64, error) {
	return nil, nil
}

// MachineChecked keeps ExecFlagThreaded enabled so that async calls
// run concurrently on separate threads within the same executor process.
func (m *asyncRequestManager) MachineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) (queue.Source, error) {
	if len(syscalls) == 0 {
		return nil, fmt.Errorf("all system calls are disabled")
	}
	opts := fuzzer.DefaultExecOpts(m.cfg, features, m.debug)
	// Key difference from multiRequestManager: do NOT clear ExecFlagThreaded
	// This ensures the executor runs async-marked calls on separate threads.
	// Enable DDRD collection for async mode (no barrier, so runner won't set it).
	opts.ExecFlags |= flatrpc.ExecFlagCollectDdrdUaf

	source := queue.Callback(func() *queue.Request {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.idx >= len(m.requests) {
			return nil
		}
		req := m.requests[m.idx]
		m.idx++
		if m.debug {
			log.Logf(0, "uafvalidate: async batch serving request %d/%d", m.idx, len(m.requests))
		}
		return req
	})
	return queue.DefaultOpts(source, opts), nil
}

// multiRequestManager manages a queue of requests for batch execution.
type multiRequestManager struct {
	cfg      *mgrconfig.Config
	requests []*queue.Request
	debug    bool
	valCfg   Config
	mu       sync.Mutex
	idx      int
}

func newMultiRequestManager(cfg *mgrconfig.Config, requests []*queue.Request, debug bool, valCfg Config) *multiRequestManager {
	return &multiRequestManager{
		cfg:      cfg,
		requests: requests,
		debug:    debug,
		valCfg:   valCfg,
	}
}

func (m *multiRequestManager) MaxSignal() signal.Signal { return nil }

func (m *multiRequestManager) BugFrames() ([]string, []string) { return nil, nil }

func (m *multiRequestManager) CoverageFilter(_ []*vminfo.KernelModule) ([]uint64, error) {
	return nil, nil
}

func (m *multiRequestManager) MachineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) (queue.Source, error) {
	if len(syscalls) == 0 {
		return nil, fmt.Errorf("all system calls are disabled")
	}
	opts := fuzzer.DefaultExecOpts(m.cfg, features, m.debug)
	opts.ExecFlags &^= flatrpc.ExecFlagThreaded
	// Note: Do NOT set ExecFlagCollectDdrdUaf here - each request has its own ExecFlags
	// set in runBarrierBatch based on DisableDdrd field

	source := queue.Callback(func() *queue.Request {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.idx >= len(m.requests) {
			return nil
		}
		req := m.requests[m.idx]
		m.idx++
		if m.debug {
			log.Logf(0, "uafvalidate: batch serving request %d/%d DisableDdrd=%v",
				m.idx, len(m.requests), req.DisableDdrd)
		}
		return req
	})
	return queue.DefaultOpts(source, opts), nil
}
