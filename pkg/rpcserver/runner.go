// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/dispatcher"
)

type Runner struct {
	id            int
	source        *queue.Distributor
	procs         int
	cover         bool
	coverEdges    bool
	filterSignal  bool
	debug         bool
	debugTimeouts bool
	sysTarget     *targets.Target
	stats         *runnerStats
	finished      chan bool
	injectExec    chan<- bool
	infoc         chan chan []byte
	canonicalizer *cover.CanonicalizerInstance
	nextRequestID int64
	requests      map[int64]*requestContext
	executing     map[int64]bool
	hanged        map[int64]bool
	lastExec      *LastExecuting
	updInfo       dispatcher.UpdateInfo
	resultCh      chan error

	barrierGroups      map[int64]*barrierGroup
	nextBarrierGroupID int64

	coverageFlagOnce sync.Once

	// The mutex protects all the fields below.
	mu          sync.Mutex
	conn        *flatrpc.Conn
	stopped     bool
	machineInfo []byte
}

type requestContext struct {
	req          *queue.Request
	program      *prog.Prog
	barrier      *barrierGroup
	barrierIndex int
	requestID    int64
}

type barrierGroup struct {
	id           int64
	req          *queue.Request
	participants []int
	contexts     []*requestContext
	results      []*queue.BarrierMemberResult
	completed    int
}

func requestTypeName(t flatrpc.RequestType) string {
	switch t {
	case flatrpc.RequestTypeProgram:
		return "program"
	case flatrpc.RequestTypeBinary:
		return "binary"
	case flatrpc.RequestTypeGlob:
		return "glob"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

var errRequestSerialization = errors.New("request serialization failed")

type serializationError struct {
	err error
}

func (e *serializationError) Error() string {
	return fmt.Sprintf("program serialization failed: %v", e.err)
}

func (e *serializationError) Unwrap() error {
	return e.err
}

func (e *serializationError) Is(target error) bool {
	return target == errRequestSerialization
}

type runnerStats struct {
	statExecs              *stat.Val
	statExecRetries        *stat.Val
	statExecutorRestarts   *stat.Val
	statExecBufferTooSmall *stat.Val
	statNoExecRequests     *stat.Val
	statNoExecDuration     *stat.Val
}

type handshakeConfig struct {
	VMLess     bool
	Timeouts   targets.Timeouts
	LeakFrames []string
	RaceFrames []string
	Files      []string
	Features   flatrpc.Feature

	// Callback() is called in the middle of the handshake process.
	// The return arguments are the coverage filter and the (possible) error.
	Callback func(*flatrpc.InfoRequestRawT) (handshakeResult, error)
}

type handshakeResult struct {
	Files         []*flatrpc.FileInfo
	Features      []*flatrpc.FeatureInfo
	CovFilter     []uint64
	MachineInfo   []byte
	Canonicalizer *cover.CanonicalizerInstance
}

func (runner *Runner) Handshake(conn *flatrpc.Conn, cfg *handshakeConfig) (handshakeResult, error) {
	if runner.updInfo != nil {
		runner.updInfo(func(info *dispatcher.Info) {
			info.Status = "handshake"
		})
	}

	connectReply := &flatrpc.ConnectReply{
		Debug:            runner.debug,
		Cover:            runner.cover,
		CoverEdges:       runner.coverEdges,
		Kernel64Bit:      runner.sysTarget.PtrSize == 8,
		Procs:            int32(runner.procs),
		Slowdown:         int32(cfg.Timeouts.Slowdown),
		SyscallTimeoutMs: int32(cfg.Timeouts.Syscall / time.Millisecond),
		ProgramTimeoutMs: int32(cfg.Timeouts.Program / time.Millisecond),
		LeakFrames:       cfg.LeakFrames,
		RaceFrames:       cfg.RaceFrames,
		Files:            cfg.Files,
		Features:         cfg.Features,
	}
	if err := flatrpc.Send(conn, connectReply); err != nil {
		return handshakeResult{}, err
	}
	infoReq, err := flatrpc.Recv[*flatrpc.InfoRequestRaw](conn)
	if err != nil {
		return handshakeResult{}, err
	}
	ret, err := cfg.Callback(infoReq)
	if err != nil {
		return handshakeResult{}, err
	}
	infoReply := &flatrpc.InfoReply{
		CoverFilter: ret.CovFilter,
	}
	if err := flatrpc.Send(conn, infoReply); err != nil {
		return handshakeResult{}, err
	}
	runner.mu.Lock()
	runner.conn = conn
	runner.machineInfo = ret.MachineInfo
	runner.canonicalizer = ret.Canonicalizer
	runner.mu.Unlock()

	if runner.updInfo != nil {
		runner.updInfo(func(info *dispatcher.Info) {
			info.MachineInfo = runner.MachineInfo
			info.DetailedStatus = runner.QueryStatus
		})
	}
	return ret, nil
}

func (runner *Runner) ConnectionLoop() error {
	// log.Logf(0, "runner %d: ConnectionLoop started", runner.id)
	if runner.updInfo != nil {
		runner.updInfo(func(info *dispatcher.Info) {
			info.Status = "executing"
		})
	}

	runner.mu.Lock()
	stopped := runner.stopped
	if !stopped {
		runner.finished = make(chan bool)
	}
	runner.mu.Unlock()

	if stopped {
		// The instance was shut down in between, see the shutdown code.
		return nil
	}
	defer close(runner.finished)

	var infoc chan []byte
	defer func() {
		if infoc != nil {
			infoc <- []byte("VM has crashed")
		}
	}()
	for {
		if infoc == nil {
			select {
			case infoc = <-runner.infoc:
				err := runner.sendStateRequest()
				if err != nil {
					return err
				}
			default:
			}
		}
		for len(runner.requests)-len(runner.executing) < 2*runner.procs {
			req := runner.source.Next(runner.id)
			if req == nil {
				// log.Logf(0, "runner %d: no more requests, sleeping", runner.id)
				break
			}
			// log.Logf(0, "runner %d fetched request type=%s barrier=%t", runner.id, requestTypeName(req.Type), req.Barrier)
			if err := runner.sendRequest(req); err != nil {
				// log.Logf(0, "runner %d: failed to send request: %v", runner.id, err)
				return err
			}
		}
		if len(runner.requests) == 0 {
			if !runner.Alive() {
				return nil
			}
			// The runner has no new requests, so don't wait to receive anything from it.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		raw, err := wrappedRecv[*flatrpc.ExecutorMessageRaw](runner)
		if err != nil {
			log.Logf(0, "runner %d: failed to receive message: %v", runner.id, err)
			return err
		}
		if raw.Msg == nil || raw.Msg.Value == nil {
			return errors.New("received no message")
		}
		switch msg := raw.Msg.Value.(type) {
		case *flatrpc.ExecutingMessage:
			// log.Logf(0, "runner %d: handling ExecutingMessage for req %d", runner.id, msg.Id)
			err = runner.handleExecutingMessage(msg)
		case *flatrpc.ExecResult:
			// log.Logf(0, "runner %d: handling ExecResult for req %d", runner.id, msg.Id)
			err = runner.handleExecResult(msg)
		case *flatrpc.StateResult:
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "pending requests on the VM:")
			for id := range runner.requests {
				fmt.Fprintf(buf, " %v", id)
			}
			fmt.Fprintf(buf, "\n\n")
			result := append(buf.Bytes(), msg.Data...)
			if infoc != nil {
				infoc <- result
				infoc = nil
			} else {
				// The request was solicited in detectTimeout().
				log.Logf(0, "status result: %s", result)
			}
		default:
			return fmt.Errorf("received unknown message type %T", msg)
		}
		if err != nil {
			return err
		}
	}
}

func wrappedRecv[Raw flatrpc.RecvType[T], T any](runner *Runner) (*T, error) {
	if runner.debugTimeouts {
		abort := runner.detectTimeout()
		defer close(abort)
	}
	return flatrpc.Recv[Raw](runner.conn)
}

func (runner *Runner) detectTimeout() chan struct{} {
	abort := make(chan struct{})
	go func() {
		select {
		case <-time.After(time.Minute):
			log.Logf(0, "timed out waiting for executor reply, aborting the connection in 1 minute")
			go func() {
				time.Sleep(time.Minute)
				runner.conn.Close()
			}()
			err := runner.sendStateRequest()
			if err != nil {
				log.Logf(0, "failed to send state request: %v", err)
				return
			}

		case <-abort:
			return
		case <-runner.finished:
			return
		}
	}()
	return abort
}

func (runner *Runner) sendStateRequest() error {
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type:  flatrpc.HostMessagesRawStateRequest,
			Value: &flatrpc.StateRequest{},
		},
	}
	return flatrpc.Send(runner.conn, msg)
}

func (runner *Runner) handleExecutingMessage(msg *flatrpc.ExecutingMessage) error {
	ctx := runner.requests[msg.Id]
	if ctx == nil {
		if runner.hanged[msg.Id] {
			return nil
		}
		return fmt.Errorf("can't find executing request %v", msg.Id)
	}
	req := ctx.req
	proc := int(msg.ProcId)
	if proc < 0 || proc >= prog.MaxPids {
		return fmt.Errorf("got bad proc id %v", proc)
	}
	runner.stats.statExecs.Add(1)
	if msg.Try == 0 {
		if msg.WaitDuration != 0 {
			runner.stats.statNoExecRequests.Add(1)
			// Cap wait duration to 1 second to avoid extreme peaks on the graph
			// which make it impossible to see real data (the rest becomes a flat line).
			runner.stats.statNoExecDuration.Add(int(min(msg.WaitDuration, 1e9)))
		}
	} else {
		runner.stats.statExecRetries.Add(1)
	}
	var data []byte
	switch req.Type {
	case flatrpc.RequestTypeProgram:
		prog := ctx.program
		if prog == nil {
			prog = req.Prog
		}
		if prog != nil {
			data = prog.Serialize()
		}
	case flatrpc.RequestTypeBinary:
		data = []byte(fmt.Sprintf("executing binary %v\n", req.BinaryFile))
	case flatrpc.RequestTypeGlob:
		data = []byte(fmt.Sprintf("expanding glob: %v\n", req.GlobPattern))
	default:
		panic(fmt.Sprintf("unhandled request type %v", req.Type))
	}
	runner.lastExec.Note(int(msg.Id), proc, data, osutil.MonotonicNano())
	select {
	case runner.injectExec <- true:
	default:
	}
	runner.executing[msg.Id] = true
	return nil
}

func (runner *Runner) handleExecResult(msg *flatrpc.ExecResult) error {
	ctx := runner.requests[msg.Id]
	if ctx == nil {
		if runner.hanged[msg.Id] {
			delete(runner.hanged, msg.Id)
			return nil
		}
		return fmt.Errorf("can't find executed request %v", msg.Id)
	}
	delete(runner.requests, msg.Id)
	delete(runner.executing, msg.Id)
	runner.prepareProgramResult(ctx, msg)
	analysis := ddrd.FromProgInfo(msg.Info)
	var barrierID int64
	if ctx.barrier != nil {
		barrierID = ctx.barrier.id
	}
	if analysis != nil {
		log.Logf(0, "ddrd: collected report for req=%d vm=%d proc=%d barrier=%t barrier_id=%d uaf=%d extended=%d", msg.Id, runner.id, msg.Proc, ctx.barrier != nil, barrierID, len(analysis.UAFPairs), len(analysis.Extended))
	} else if runner.debug {
		log.Logf(1, "ddrd: no report for req=%d vm=%d proc=%d barrier=%t barrier_id=%d", msg.Id, runner.id, msg.Proc, ctx.barrier != nil, barrierID)
	}
	status := queue.Success
	var resErr error
	if msg.Error != "" {
		status = queue.ExecFailure
		resErr = errors.New(msg.Error)
	} else if msg.Hanged {
		status = queue.Hanged
		if ctx.program != nil {
			runner.lastExec.Hanged(int(msg.Id), int(msg.Proc), ctx.program.Serialize(), osutil.MonotonicNano())
		}
		runner.hanged[msg.Id] = true
	}
	if ctx.barrier == nil {
		ctx.req.Done(&queue.Result{
			Executor: queue.ExecutorID{
				VM:   runner.id,
				Proc: int(msg.Proc),
			},
			Status:              status,
			Info:                msg.Info,
			Ddrd:                analysis,
			Output:              slices.Clone(msg.Output),
			Err:                 resErr,
			BarrierParticipants: msg.BarrierProcs,
			BarrierGroupID:      msg.BarrierGroupId,
			BarrierGroupSize:    int(msg.BarrierGroupSize),
		})
		return nil
	}
	groupID := msg.BarrierGroupId
	if groupID == 0 {
		groupID = ctx.barrier.id
	}
	groupSize := int(msg.BarrierGroupSize)
	if groupSize == 0 {
		groupSize = len(ctx.barrier.participants)
	}
	member := &queue.BarrierMemberResult{
		Index:     ctx.barrierIndex,
		GroupID:   groupID,
		GroupSize: groupSize,
		Proc:      int(msg.Proc),
		Prog:      ctx.program,
		Executor:  queue.ExecutorID{VM: runner.id, Proc: int(msg.Proc)},
		Info:      msg.Info,
		Ddrd:      analysis,
		Output:    slices.Clone(msg.Output),
		Status:    status,
		Err:       resErr,
	}
	if ctx.barrier.results[ctx.barrierIndex] == nil {
		ctx.barrier.completed++
	}
	ctx.barrier.results[ctx.barrierIndex] = member
	ctx.barrier.contexts[ctx.barrierIndex] = nil
	if ctx.barrier.completed == len(ctx.barrier.contexts) {
		runner.finishBarrierGroup(ctx.barrier)
	}
	return nil
}

func (runner *Runner) sendRequest(req *queue.Request) error {
	if err := req.Validate(); err != nil {
		panic(err)
	}
	if req.Barrier {
		// log.Logf(0, "Sending barrier request")
		return runner.sendBarrierRequest(req)
	}
	ctx := &requestContext{
		req:     req,
		program: req.Prog,
	}
	if err := runner.dispatchSingle(ctx); err != nil {
		if errors.Is(err, errRequestSerialization) {
			req.Done(&queue.Result{
				Status: queue.ExecFailure,
				Err:    err,
			})
			return nil
		}
		return err
	}
	return nil
}

func (runner *Runner) dispatchSingle(ctx *requestContext) error {
	id, msg, err := runner.prepareDispatch(ctx)
	if err != nil {
		return err
	}
	runner.requests[id] = ctx
	if err := flatrpc.Send(runner.conn, msg); err != nil {
		delete(runner.requests, id)
		return err
	}
	return nil
}

func (runner *Runner) sendBarrierRequest(req *queue.Request) error {
	participants := req.BarrierProcList
	if len(participants) == 0 {
		if req.BarrierParticipants != 0 {
			req.SetBarrier(req.BarrierParticipants)
			participants = req.BarrierProcList
		}
		if len(participants) == 0 {
			req.SetBarrier(0)
			return runner.sendRequest(req)
		}
	}
	if runner.procs > 0 {
		mask := uint64(0)
		dropped := false
		for _, proc := range participants {
			if proc < 0 || proc >= runner.procs {
				if runner.debug {
					log.Logf(1, "barrier request proc %d exceeds available procs=%d, dropping", proc, runner.procs)
				}
				dropped = true
				continue
			}
			mask |= 1 << proc
		}
		if dropped {
			if bits.OnesCount64(mask) < 2 {
				log.Logf(0, "barrier request downgraded: insufficient valid participants (mask=0x%x available=%d)", req.BarrierParticipants, runner.procs)
				req.SetBarrier(0)
				return runner.sendRequest(req)
			}
			req.SetBarrier(mask)
			participants = req.BarrierProcList
		}
	}
	runner.nextBarrierGroupID++
	groupID := runner.nextBarrierGroupID
	group := &barrierGroup{
		id:           groupID,
		req:          req,
		participants: append([]int(nil), participants...),
		contexts:     make([]*requestContext, len(participants)),
		results:      make([]*queue.BarrierMemberResult, len(participants)),
	}
	if runner.barrierGroups == nil {
		runner.barrierGroups = make(map[int64]*barrierGroup)
	}
	runner.barrierGroups[groupID] = group
	type prepared struct {
		id  int64
		msg *flatrpc.HostMessage
		ctx *requestContext
	}
	preparedReqs := make([]prepared, len(participants))
	for idx := range participants {
		prog := req.Prog
		if len(req.BarrierPrograms) > idx && req.BarrierPrograms[idx] != nil {
			prog = req.BarrierPrograms[idx]
		}
		ctx := &requestContext{
			req:          req,
			program:      prog,
			barrier:      group,
			barrierIndex: idx,
		}
		group.contexts[idx] = ctx
		id, msg, err := runner.prepareDispatch(ctx)
		if err != nil {
			delete(runner.barrierGroups, group.id)
			if errors.Is(err, errRequestSerialization) {
				req.Done(&queue.Result{
					Status: queue.ExecFailure,
					Err:    fmt.Errorf("barrier member %d: %w", idx, err),
				})
				return nil
			}
			return err
		}
		preparedReqs[idx] = prepared{id: id, msg: msg, ctx: ctx}
	}
	for _, item := range preparedReqs {
		runner.requests[item.id] = item.ctx
		if err := flatrpc.Send(runner.conn, item.msg); err != nil {
			delete(runner.requests, item.id)
			delete(runner.barrierGroups, group.id)
			return err
		}
	}
	return nil
}

func (runner *Runner) prepareDispatch(ctx *requestContext) (int64, *flatrpc.HostMessage, error) {
	runner.nextRequestID++
	id := runner.nextRequestID
	ctx.requestID = id
	msg, err := runner.buildExecRequest(id, ctx)
	if err != nil {
		return 0, nil, err
	}
	return id, msg, nil
}

func (runner *Runner) buildExecRequest(id int64, ctx *requestContext) (*flatrpc.HostMessage, error) {
	req := ctx.req
	var flags flatrpc.RequestFlag
	if req.ReturnOutput {
		flags |= flatrpc.RequestFlagReturnOutput
	}
	if req.ReturnError {
		flags |= flatrpc.RequestFlagReturnError
	}
	allSignal := make([]int32, len(req.ReturnAllSignal))
	for i, call := range req.ReturnAllSignal {
		allSignal[i] = int32(call)
	}
	opts := req.ExecOpts
	if ctx.barrier != nil {
		opts.ExecFlags |= flatrpc.ExecFlagCollectDdrdUaf
	}
	if runner.debug {
		opts.EnvFlags |= flatrpc.ExecEnvDebug
	}
	var data []byte
	switch req.Type {
	case flatrpc.RequestTypeProgram:
		prog := ctx.program
		if prog == nil {
			prog = req.Prog
		}
		if prog == nil {
			return nil, &serializationError{err: fmt.Errorf("missing program for request %d", id)}
		}
		progData, err := prog.SerializeForExec()
		if err != nil {
			runner.stats.statExecBufferTooSmall.Add(1)
			return nil, &serializationError{err: err}
		}
		data = progData
	case flatrpc.RequestTypeBinary:
		fileData, err := os.ReadFile(req.BinaryFile)
		if err != nil {
			return nil, err
		}
		data = fileData
	case flatrpc.RequestTypeGlob:
		data = append([]byte(req.GlobPattern), 0)
		flags |= flatrpc.RequestFlagReturnOutput
	default:
		panic("unhandled request type")
	}
	var avoid uint64
	for _, avoidID := range req.Avoid {
		if avoidID.VM == runner.id {
			avoid |= uint64(1 << avoidID.Proc)
		}
	}
	execReq := &flatrpc.ExecRequest{
		Id:        id,
		Type:      req.Type,
		Avoid:     avoid,
		Data:      data,
		Flags:     flags,
		ExecOpts:  &opts,
		AllSignal: allSignal,
	}
	if ctx.barrier != nil {
		execReq.BarrierParticipants = req.BarrierParticipants
		execReq.BarrierGroupId = ctx.barrier.id
		execReq.BarrierIndex = int32(ctx.barrierIndex)
		execReq.BarrierGroupSize = int32(len(ctx.barrier.participants))
	}
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type:  flatrpc.HostMessagesRawExecRequest,
			Value: execReq,
		},
	}
	return msg, nil
}

func (runner *Runner) prepareProgramResult(ctx *requestContext, msg *flatrpc.ExecResult) {
	req := ctx.req
	if req.Type != flatrpc.RequestTypeProgram || msg.Info == nil {
		return
	}
	prog := ctx.program
	if prog == nil {
		prog = req.Prog
	}
	if prog == nil {
		return
	}
	for len(msg.Info.Calls) < len(prog.Calls) {
		msg.Info.Calls = append(msg.Info.Calls, &flatrpc.CallInfo{Error: 999})
	}
	msg.Info.Calls = msg.Info.Calls[:len(prog.Calls)]
	if msg.Info.Freshness == 0 {
		runner.stats.statExecutorRestarts.Add(1)
	}
	for _, call := range msg.Info.Calls {
		runner.convertCallInfo(call)
	}
	if len(msg.Info.ExtraRaw) != 0 {
		msg.Info.Extra = msg.Info.ExtraRaw[0]
		for _, info := range msg.Info.ExtraRaw[1:] {
			msg.Info.Extra.Cover = append(msg.Info.Extra.Cover, info.Cover...)
			msg.Info.Extra.Signal = append(msg.Info.Extra.Signal, info.Signal...)
		}
		msg.Info.ExtraRaw = nil
		runner.convertCallInfo(msg.Info.Extra)
	}
	if !runner.cover && req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal != 0 {
		addFallbackSignal(prog, msg.Info)
	}
}

func (runner *Runner) finishBarrierGroup(group *barrierGroup) {
	delete(runner.barrierGroups, group.id)
	members := make([]*queue.BarrierMemberResult, len(group.results))
	copy(members, group.results)
	if totalUAF, totalExtended := summarizeDdrdResults(members); totalUAF != 0 || totalExtended != 0 {
		log.Logf(0, "ddrd: barrier group %d aggregated results uaf=%d extended=%d", group.id, totalUAF, totalExtended)
	}
	status, resErr := summarizeBarrierStatus(members)
	// log.Logf(0, "barrier group %d finished: status=%s members=%d err=%v", group.id, status.String(), len(members), resErr)
	var primary *queue.BarrierMemberResult
	if len(members) != 0 {
		primary = members[0]
	}
	if primary == nil {
		for _, member := range members {
			if member != nil {
				primary = member
				break
			}
		}
	}
	groupSize := len(group.participants)
	for _, member := range members {
		if member != nil && member.GroupSize != 0 {
			groupSize = member.GroupSize
			break
		}
	}
	result := &queue.Result{
		Status:              status,
		Err:                 resErr,
		BarrierParticipants: group.req.BarrierParticipants,
		BarrierGroupID:      group.id,
		BarrierGroupSize:    groupSize,
		BarrierMembers:      members,
	}
	if primary != nil {
		result.Executor = primary.Executor
		result.Info = primary.Info
		result.Ddrd = primary.Ddrd
		result.Output = slices.Clone(primary.Output)
	}
	group.req.Done(result)
}

func summarizeDdrdResults(members []*queue.BarrierMemberResult) (int, int) {
	totalUAF := 0
	totalExtended := 0
	for _, member := range members {
		if member == nil || member.Ddrd == nil {
			continue
		}
		totalUAF += len(member.Ddrd.UAFPairs)
		totalExtended += len(member.Ddrd.Extended)
	}
	return totalUAF, totalExtended
}

func summarizeBarrierStatus(members []*queue.BarrierMemberResult) (queue.Status, error) {
	status := queue.Success
	var resErr error
	for _, member := range members {
		if member == nil {
			continue
		}
		switch member.Status {
		case queue.ExecFailure:
			return queue.ExecFailure, member.Err
		case queue.Crashed:
			status = queue.Crashed
			if resErr == nil {
				resErr = member.Err
			}
		case queue.Hanged:
			if status != queue.Crashed {
				status = queue.Hanged
				if resErr == nil {
					resErr = member.Err
				}
			}
		case queue.Restarted:
			if status == queue.Success {
				status = queue.Restarted
			}
		}
	}
	return status, resErr
}

func (runner *Runner) convertCallInfo(call *flatrpc.CallInfo) {
	call.Cover = runner.canonicalizer.Canonicalize(call.Cover)
	call.Signal = runner.canonicalizer.Canonicalize(call.Signal)

	call.Comps = slices.DeleteFunc(call.Comps, func(cmp *flatrpc.Comparison) bool {
		converted := runner.canonicalizer.Canonicalize([]uint64{cmp.Pc})
		if len(converted) == 0 {
			return true
		}
		cmp.Pc = converted[0]
		return false
	})

	var kernelAddresses targets.KernelAddresses
	if runner.filterSignal {
		kernelAddresses = runner.sysTarget.KernelAddresses
	}
	textStart, textEnd := kernelAddresses.TextStart, kernelAddresses.TextEnd
	if textStart != 0 {
		for _, sig := range call.Signal {
			if sig < textStart || sig > textEnd {
				call.Signal = []uint64{}
				call.Cover = []uint64{}
				break
			}
		}
	}

	dataStart, dataEnd := kernelAddresses.DataStart, kernelAddresses.DataEnd
	if len(call.Comps) != 0 && (textStart != 0 || dataStart != 0) {
		if runner.sysTarget.PtrSize == 4 {
			textStart = uint64(int64(int32(textStart)))
			textEnd = uint64(int64(int32(textEnd)))
			dataStart = uint64(int64(int32(dataStart)))
			dataEnd = uint64(int64(int32(dataEnd)))
		}
		isKptr := func(val uint64) bool {
			return val >= textStart && val <= textEnd || val >= dataStart && val <= dataEnd || val == 0
		}
		call.Comps = slices.DeleteFunc(call.Comps, func(cmp *flatrpc.Comparison) bool {
			return isKptr(cmp.Op1) && isKptr(cmp.Op2)
		})
	}
}

func (runner *Runner) SendSignalUpdate(plus []uint64) error {
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type: flatrpc.HostMessagesRawSignalUpdate,
			Value: &flatrpc.SignalUpdate{
				NewMax: runner.canonicalizer.Decanonicalize(plus),
			},
		},
	}
	return flatrpc.Send(runner.conn, msg)
}

func (runner *Runner) SendCorpusTriaged() error {
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type:  flatrpc.HostMessagesRawCorpusTriaged,
			Value: &flatrpc.CorpusTriaged{},
		},
	}
	return flatrpc.Send(runner.conn, msg)
}

func (runner *Runner) Stop() {
	runner.mu.Lock()
	runner.stopped = true
	conn := runner.conn
	runner.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (runner *Runner) Shutdown(crashed bool, extraExecs ...report.ExecutorInfo) []ExecRecord {
	runner.mu.Lock()
	runner.stopped = true
	finished := runner.finished
	runner.mu.Unlock()

	if finished != nil {
		// Wait for the connection goroutine to finish and stop touching data.
		<-finished
	}
	records := runner.lastExec.Collect()
	for _, info := range extraExecs {
		ctx := runner.requests[int64(info.ExecID)]
		if ctx != nil && !runner.executing[int64(info.ExecID)] {
			progData := []byte(nil)
			if ctx.program != nil {
				progData = ctx.program.Serialize()
			} else if ctx.req != nil && ctx.req.Prog != nil {
				progData = ctx.req.Prog.Serialize()
			}
			if progData != nil {
				records = append(records, ExecRecord{
					ID:   info.ExecID,
					Proc: info.ProcID,
					Prog: progData,
				})
			}
		}
	}
	type shutdownState struct {
		status queue.Status
	}
	pending := make(map[*queue.Request]*shutdownState)
	for id, ctx := range runner.requests {
		if ctx == nil || ctx.req == nil {
			continue
		}
		state := pending[ctx.req]
		if state == nil {
			state = &shutdownState{status: queue.Restarted}
			pending[ctx.req] = state
		}
		if crashed && runner.executing[id] {
			state.status = queue.Crashed
		}
	}
	for req, state := range pending {
		req.Done(&queue.Result{Status: state.status})
	}
	return records
}

func (runner *Runner) MachineInfo() []byte {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.machineInfo
}

func (runner *Runner) QueryStatus() []byte {
	resc := make(chan []byte, 1)
	timeout := time.After(time.Minute)
	select {
	case runner.infoc <- resc:
	case <-timeout:
		return []byte("VM loop is not responding")
	}
	select {
	case res := <-resc:
		return res
	case <-timeout:
		return []byte("VM is not responding")
	}
}

func (runner *Runner) Alive() bool {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.conn != nil && !runner.stopped
}

// addFallbackSignal computes simple fallback signal in cases we don't have real coverage signal.
// We use syscall number or-ed with returned errno value as signal.
// At least this gives us all combinations of syscall+errno.
func addFallbackSignal(p *prog.Prog, info *flatrpc.ProgInfo) {
	callInfos := make([]prog.CallInfo, len(info.Calls))
	for i, inf := range info.Calls {
		if inf.Flags&flatrpc.CallFlagExecuted != 0 {
			callInfos[i].Flags |= prog.CallExecuted
		}
		if inf.Flags&flatrpc.CallFlagFinished != 0 {
			callInfos[i].Flags |= prog.CallFinished
		}
		if inf.Flags&flatrpc.CallFlagBlocked != 0 {
			callInfos[i].Flags |= prog.CallBlocked
		}
		callInfos[i].Errno = int(inf.Error)
	}
	p.FallbackSignal(callInfos)
	for i, inf := range callInfos {
		info.Calls[i].Signal = inf.Signal
	}
}
