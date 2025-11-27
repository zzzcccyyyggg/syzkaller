package uafvalidate

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net"
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
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
)

// ExecutorAdapter wraps an ExecProgInstance so it can be reused by the validator.
type ExecutorAdapter struct {
	inst         *instance.ExecProgInstance
	cfg          Config
	rpcAddr      string
	forwardPort  int
	forwardAddr  string
	forwardReady bool
}

func NewExecutorAdapter(inst *instance.ExecProgInstance, cfg Config) *ExecutorAdapter {
	adapter := &ExecutorAdapter{inst: inst, cfg: cfg.withDefaults()}
	if inst != nil && inst.ManagerConfig() != nil {
		adapter.rpcAddr = inst.ManagerConfig().RPC
	}
	return adapter
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
	vmIndex := -1
	if e.inst.VMInstance != nil {
		vmIndex = e.inst.VMInstance.Index()
	}

	mgrCfg := e.inst.ManagerConfig()
	if mgrCfg == nil {
		return nil, fmt.Errorf("missing manager configuration for execprog instance")
	}
	cfgCopy := *mgrCfg
	if e.forwardReady && e.forwardPort != 0 {
		cfgCopy.RPC = fmt.Sprintf("127.0.0.1:%d", e.forwardPort)
	}
	if participants > cfgCopy.Procs {
		cfgCopy.Procs = participants
	}

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

	programs := barrierPrograms(entry, mask)
	if len(programs) != participants {
		return nil, fmt.Errorf("incomplete barrier program set: have %d want %d", len(programs), participants)
	}

	request := &queue.Request{
		Prog:         baseProg,
		ReturnOutput: true,
		ReturnError:  true,
		Important:    true,
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

	manager := newValidationManager(&cfgCopy, request, e.cfg.Debug)
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

	if e.forwardReady && e.forwardPort != 0 && serv.Port() != e.forwardPort {
		return nil, fmt.Errorf("rpc server port mismatch: got %d want %d", serv.Port(), e.forwardPort)
	}
	var fwdAddr string
	if !e.forwardReady || e.forwardAddr == "" {
		addr, err := e.inst.VMInstance.Forward(serv.Port())
		if err != nil {
			return nil, fmt.Errorf("forward runner port: %w", err)
		}
		fwdAddr = addr
		e.forwardAddr = addr
		e.forwardPort = serv.Port()
		e.forwardReady = true
	} else {
		fwdAddr = e.forwardAddr
	}
	host, portStr, err := net.SplitHostPort(fwdAddr)
	if err != nil {
		return nil, fmt.Errorf("split forwarded address: %w", err)
	}

	vmIdx := e.inst.VMInstance.Index()
	command := fmt.Sprintf("%s runner %d %s %s", executorBin, vmIdx, host, portStr)

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
					if pair.FreeAccessName == execReq.TargetPair.FreeAccessName &&
						pair.UseAccessName == execReq.TargetPair.UseAccessName &&
						pair.FreeCallStack == execReq.TargetPair.FreeCallStack &&
						pair.UseCallStack == execReq.TargetPair.UseCallStack {
						triggeredCount++
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
		if errors.Is(runErr, context.DeadlineExceeded) {
			return &ExecutionResult{Duration: time.Since(start), CrashTitle: crashTimedOut, Crashed: true, Output: append([]byte{}, output...)}, nil
		}
		if !errors.Is(runErr, context.Canceled) {
			return nil, fmt.Errorf("run barrier request: %w", runErr)
		}
	}
	if runnerErr != nil && !errors.Is(runnerErr, context.Canceled) {
		return nil, fmt.Errorf("runner error: %w", runnerErr)
	}
	if serveErr != nil && !errors.Is(serveErr, context.Canceled) {
		return nil, fmt.Errorf("rpc server error: %w", serveErr)
	}
	if res == nil {
		log.Logf(0, "uafvalidate: barrier request returned no result after %s", time.Since(start))
		return nil, fmt.Errorf("barrier execution produced no result")
	}

	execOutput := res.Output
	if len(execOutput) == 0 && len(output) != 0 {
		execOutput = output
	}

	result := &ExecutionResult{
		Output:         append([]byte{}, execOutput...),
		Duration:       time.Since(start),
		TriggeredCount: triggeredCount,
	}
	if res.Ddrd != nil {
		result.Ddrd = res.Ddrd.Clone()
	}

	if len(reports) != 0 && reports[0] != nil {
		result.Crashed = true
		result.CrashTitle = reports[0].Title
		log.Logf(0, "uafvalidate: barrier request status=%s crashed=true duration=%s", res.Status, result.Duration)
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

	log.Logf(0, "uafvalidate: vm=%d barrier request status=%s crashed=%t duration=%s", vmIndex, res.Status, result.Crashed, result.Duration)

	return result, nil
}

func (e *ExecutorAdapter) requiresBarrier(entry *fuzzer.UAFCorpusEntry) bool {
	if entry == nil {
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

func (e *ExecutorAdapter) Close() error {
	if e == nil || e.inst == nil || e.inst.VMInstance == nil {
		return nil
	}
	return e.inst.VMInstance.Close()
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

func newValidationManager(cfg *mgrconfig.Config, req *queue.Request, debug bool) *validationManager {
	return &validationManager{cfg: cfg, request: req, debug: debug}
}

type validationManager struct {
	cfg         *mgrconfig.Config
	request     *queue.Request
	debug       bool
	served      atomic.Bool
	repeatCount int
	servedCount int
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
		opts.ExecFlags |= flatrpc.ExecFlagCollectDdrdUaf
	}
	source := queue.Callback(func() *queue.Request {
		if m.request == nil {
			return nil
		}
		if m.repeatCount > 0 {
			if m.servedCount < m.repeatCount {
				m.servedCount++
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
