// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"math/bits"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

// TimingExplorationPhase indicates the current phase of timing exploration.
type TimingExplorationPhase int

const (
	// PhaseWidenedDiscovery: Phase 1 - use widened threshold to discover candidate pairs (don't save)
	PhaseWidenedDiscovery TimingExplorationPhase = iota
	// PhaseValidation: Phase 2 - use normal threshold with delays to validate (save if successful)
	PhaseValidation
)

// ObjectLinkProvenance describes whether a barrier request came from an
// ObjectLinker-aligned program pair. It is diagnostic metadata only; it does
// not affect executor semantics.
type ObjectLinkProvenance struct {
	Attempted   bool
	Applied     bool
	Unified     int
	Exact       int
	CrossFamily int
}

func (p ObjectLinkProvenance) Linked() bool {
	return p.Applied || p.Unified > 0
}

// TimingExplorationInfo holds metadata about a timing exploration job.
type TimingExplorationInfo struct {
	// Phase indicates which phase of timing exploration this is
	Phase TimingExplorationPhase
	// TargetPair is the pair being explored
	TargetPair *ddrd.MayUAFPair
	// AttemptNumber is the current attempt number for this pair
	AttemptNumber int
	// DelayPlan describes the delay insertions
	DelayPlan []DelayInsertion
	// StartDelays carries per-barrier-participant launch delays. Unlike
	// DelayPlan, this does not mutate the syscall program.
	StartDelays []int64
	// OriginalProg1 and OriginalProg2 are the original programs before mutation
	OriginalProg1 *prog.Prog
	OriginalProg2 *prog.Prog
	// CandidatePairs holds pairs discovered in PhaseWidenedDiscovery, to be validated in PhaseValidation
	CandidatePairs []*ddrd.MayUAFPair
	// ObjectLink records whether the original discovery pair was ObjLinker-aligned.
	ObjectLink ObjectLinkProvenance
	// LowPriority marks validation jobs that were intentionally delayed behind fresh discovery.
	LowPriority    bool
	PriorityReason string
}

// DelayInsertion describes a single syz_delay insertion.
type DelayInsertion struct {
	ProgIdx     int   // 0 or 1, which program
	BeforeCall  int   // index of the call before which to insert delay
	DelayMicros int64 // delay in microseconds
}

type Request struct {
	// Type of the request.
	// RequestTypeProgram executes Prog, and is used by most requests (also the default zero value).
	// RequestTypeBinary executes binary with file name stored in Data.
	// RequestTypeGlob expands glob pattern stored in Data.
	Type        flatrpc.RequestType
	ExecOpts    flatrpc.ExecOpts
	Prog        *prog.Prog // for RequestTypeProgram
	BinaryFile  string     // for RequestTypeBinary
	GlobPattern string     // for 	RequestTypeGlob

	// Barrier controls synchronized execution across a set of procs.
	// When Barrier is true, BarrierParticipants identifies the proc set as a bitmask.
	Barrier             bool
	BarrierParticipants uint64
	// BarrierPrograms holds per-proc programs for barrier execution. Order matches BarrierProcList.
	BarrierPrograms []*prog.Prog
	// BarrierProcList contains proc indices extracted from BarrierParticipants in ascending order.
	BarrierProcList []int
	// BarrierStartDelayUs carries per-proc start delays in microseconds, ordered like BarrierProcList.
	BarrierStartDelayUs []int64

	// Return all signal for these calls instead of new signal.
	ReturnAllSignal []int
	ReturnError     bool
	ReturnOutput    bool

	// UkcPair optionally carries May-UAF metadata to preload the UKC controller.
	UkcPair *ddrd.MayUAFPair
	// UkcTargetDelaySide controls which target side gets the kernel access delay:
	// 0=both, 1=use, 2=free, 3=none.
	UkcTargetDelaySide int32
	// UkcTargetDelayMode controls how target access delay is applied:
	// 0=sleep in the matched access, 1=nonblocking watchpoint window.
	UkcTargetDelayMode int32

	// DisableDdrd prevents automatic DDRD collection even for barrier executions.
	DisableDdrd bool

	// IsSoloExecution marks requests that should run single-threaded for solo DDRD collection.
	// When true, the queue will NOT merge the Threaded flag from default options.
	IsSoloExecution bool

	// IsValidationMode indicates this request is from validation framework (use FINE modes)
	IsValidationMode bool

	// TimingThresholdUs is the timing threshold in microseconds for race pair detection.
	// If > 0, overrides the default 10ms threshold in executor.
	// Used by timing exploration queue to use widened threshold (e.g., 500ms = 500000us).
	TimingThresholdUs int64

	// IsTimingExploration marks this request as a timing exploration job.
	// When true, results are processed specially to track exploration success.
	IsTimingExploration bool

	// ThreadBarrier marks requests created via merged-program thread-barrier mode.
	// This is more precise than checking ExecFlagThreaded because default executor
	// options may also enable threaded execution for ordinary barrier requests.
	ThreadBarrier bool

	// ObjectLink records whether this barrier request had partner objects aligned
	// by ObjLinker before execution.
	ObjectLink ObjectLinkProvenance

	// TimingExplorationInfo holds metadata about the timing exploration job.
	// Only set when IsTimingExploration is true.
	TimingExplorationInfo *TimingExplorationInfo

	// This stat will be incremented on request completion.
	Stat *stat.Val

	// Important requests will be retried even from crashed VMs.
	Important bool

	// Avoid specifies set of executors that are preferable to avoid when executing this request.
	// The restriction is soft since there can be only one executor at all or available right now.
	Avoid []ExecutorID

	// The callback will be called on request completion in the LIFO order.
	// If it returns false, all further processing will be stopped.
	// It allows wrappers to intercept Done() requests.
	callback DoneCallback

	onceCrashed  bool
	delayedSince uint64

	mu     sync.Mutex
	result *Result
	done   chan struct{}
}

// SetBarrier configures the request for barrier execution across procs represented by mask.
// Passing mask=0 clears barrier behavior.
func (r *Request) SetBarrier(mask uint64) {
	r.BarrierParticipants = mask
	r.Barrier = mask != 0
	if r.Barrier {
		r.ExecOpts.ExecFlags |= flatrpc.ExecFlagBarrier
		r.BarrierProcList = enumerateBarrierProcs(mask)
	} else {
		r.ExecOpts.ExecFlags &^= flatrpc.ExecFlagBarrier
		r.BarrierPrograms = nil
		r.BarrierProcList = nil
		r.BarrierStartDelayUs = nil
	}
}

// SetBarrierPrograms assigns per-proc programs for barrier execution. The provided slice must
// follow the same ordering as BarrierProcList (ascending proc indices). Passing nil clears any plan.
func (r *Request) SetBarrierPrograms(programs []*prog.Prog) error {
	if len(programs) == 0 {
		r.BarrierPrograms = nil
		return nil
	}
	if !r.Barrier {
		return fmt.Errorf("barrier programs require barrier execution")
	}
	expected := bits.OnesCount64(r.BarrierParticipants)
	if expected == 0 {
		return fmt.Errorf("barrier participants mask is empty")
	}
	if len(programs) != expected {
		return fmt.Errorf("mismatched barrier program count: have %d want %d", len(programs), expected)
	}
	if len(r.BarrierProcList) != expected {
		r.BarrierProcList = enumerateBarrierProcs(r.BarrierParticipants)
	}
	for i, prog := range programs {
		if prog == nil {
			return fmt.Errorf("nil program at barrier slot %d", i)
		}
	}
	r.BarrierPrograms = programs
	return nil
}

// SetBarrierStartDelays assigns per-proc executor start delays in microseconds. The provided slice must
// correspond to BarrierProcList ordering. Passing nil clears the plan.
func (r *Request) SetBarrierStartDelays(delays []int64) error {
	if len(delays) == 0 {
		r.BarrierStartDelayUs = nil
		return nil
	}
	if !r.Barrier {
		return fmt.Errorf("barrier delays require barrier execution")
	}
	expected := bits.OnesCount64(r.BarrierParticipants)
	if expected == 0 {
		return fmt.Errorf("barrier participants mask is empty")
	}
	if len(delays) != expected {
		return fmt.Errorf("mismatched barrier delay count: have %d want %d", len(delays), expected)
	}
	if len(r.BarrierProcList) != expected {
		r.BarrierProcList = enumerateBarrierProcs(r.BarrierParticipants)
	}
	r.BarrierStartDelayUs = append([]int64(nil), delays...)
	return nil
}

type ExecutorID struct {
	VM   int
	Proc int
}

type DoneCallback func(*Request, *Result) bool

func (r *Request) OnDone(cb DoneCallback) {
	oldCallback := r.callback
	r.callback = func(req *Request, res *Result) bool {
		r.callback = oldCallback
		if !cb(req, res) {
			return false
		}
		if oldCallback == nil {
			return true
		}
		return oldCallback(req, res)
	}
}

func (r *Request) Done(res *Result) {
	if r.callback != nil {
		if !r.callback(r, res) {
			return
		}
	}
	if r.Stat != nil {
		r.Stat.Add(1)
	}
	r.initChannel()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.result == nil {
		r.result = res
		close(r.done)
	}
}

var ErrRequestAborted = errors.New("context closed while waiting the result")

// Wait() blocks until we have the result.
func (r *Request) Wait(ctx context.Context) *Result {
	r.initChannel()
	select {
	case <-ctx.Done():
		return &Result{Status: ExecFailure, Err: ErrRequestAborted}
	case <-r.done:
		return r.result
	}
}

// Risky() returns true if there's a substantial risk of the input crashing the VM.
func (r *Request) Risky() bool {
	return r.onceCrashed
}

func (r *Request) Validate() error {
	collectSignal := r.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0
	if len(r.ReturnAllSignal) != 0 && !collectSignal {
		return fmt.Errorf("ReturnAllSignal is set, but FlagCollectSignal is not")
	}
	collectComps := r.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps > 0
	collectCover := r.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectCover > 0
	if (collectComps) && (collectSignal || collectCover) {
		return fmt.Errorf("hint collection is mutually exclusive with signal/coverage")
	}
	switch r.Type {
	case flatrpc.RequestTypeProgram:
		if r.Prog == nil {
			return fmt.Errorf("program is not set")
		}
		sandboxes := flatrpc.ExecEnvSandboxNone | flatrpc.ExecEnvSandboxSetuid |
			flatrpc.ExecEnvSandboxNamespace | flatrpc.ExecEnvSandboxAndroid
		if r.ExecOpts.EnvFlags&sandboxes == 0 {
			return fmt.Errorf("no sandboxes set")
		}
	case flatrpc.RequestTypeBinary:
		if r.BinaryFile == "" {
			return fmt.Errorf("binary file name is not set")
		}
	case flatrpc.RequestTypeGlob:
		if r.GlobPattern == "" {
			return fmt.Errorf("glob pattern is not set")
		}
	default:
		return fmt.Errorf("unknown request type")
	}
	if r.Barrier {
		if r.ExecOpts.ExecFlags&flatrpc.ExecFlagBarrier == 0 {
			return fmt.Errorf("barrier request must set ExecFlagBarrier")
		}
		if r.BarrierParticipants == 0 {
			return fmt.Errorf("barrier request requires non-zero participants mask")
		}
		expected := bits.OnesCount64(r.BarrierParticipants)
		if expected < 2 {
			return fmt.Errorf("barrier request requires at least 2 participants")
		}
		if len(r.BarrierPrograms) != 0 && len(r.BarrierPrograms) != expected {
			return fmt.Errorf("barrier programs are incomplete: have %d want %d", len(r.BarrierPrograms), expected)
		}
	}
	if len(r.BarrierStartDelayUs) != 0 {
		if !r.Barrier {
			return fmt.Errorf("barrier delays require barrier execution")
		}
		expected := bits.OnesCount64(r.BarrierParticipants)
		if expected == 0 {
			return fmt.Errorf("barrier participants mask is empty")
		}
		if len(r.BarrierStartDelayUs) != expected {
			return fmt.Errorf("barrier delay count mismatch: have %d want %d", len(r.BarrierStartDelayUs), expected)
		}
	}
	return nil
}

func (r *Request) hash() hash.Sig {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(r.Type); err != nil {
		panic(err)
	}
	if err := enc.Encode(r.ExecOpts); err != nil {
		panic(err)
	}
	if err := enc.Encode(r.Barrier); err != nil {
		panic(err)
	}
	if err := enc.Encode(r.ThreadBarrier); err != nil {
		panic(err)
	}
	if err := enc.Encode(r.BarrierParticipants); err != nil {
		panic(err)
	}
	if err := enc.Encode(r.BarrierProcList); err != nil {
		panic(err)
	}
	if err := enc.Encode(r.BarrierStartDelayUs); err != nil {
		panic(err)
	}
	if err := enc.Encode(len(r.BarrierPrograms)); err != nil {
		panic(err)
	}
	if err := enc.Encode(r.DisableDdrd); err != nil {
		panic(err)
	}
	for _, prog := range r.BarrierPrograms {
		if err := enc.Encode(prog.Serialize()); err != nil {
			panic(err)
		}
	}
	var data []byte
	switch r.Type {
	case flatrpc.RequestTypeProgram:
		data = r.Prog.Serialize()
	case flatrpc.RequestTypeBinary:
		data = []byte(r.BinaryFile)
	case flatrpc.RequestTypeGlob:
		data = []byte(r.GlobPattern)
	default:
		panic("unknown request type")
	}
	return hash.Hash(data, buf.Bytes())
}

func enumerateBarrierProcs(mask uint64) []int {
	if mask == 0 {
		return nil
	}
	procs := make([]int, 0, bits.OnesCount64(mask))
	for proc := 0; mask != 0; proc++ {
		if mask&1 == 1 {
			procs = append(procs, proc)
		}
		mask >>= 1
	}
	return procs
}

func (r *Request) initChannel() {
	r.mu.Lock()
	if r.done == nil {
		r.done = make(chan struct{})
	}
	r.mu.Unlock()
}

type Result struct {
	Info     *flatrpc.ProgInfo
	Ddrd     *ddrd.Report
	Executor ExecutorID
	Output   []byte
	Status   Status
	Err      error // More details in case of ExecFailure.
	// BarrierParticipants mirrors ExecResult.barrier_procs for analysis.
	BarrierParticipants uint64
	BarrierGroupID      int64
	BarrierGroupSize    int
	BarrierMembers      []*BarrierMemberResult
}

func (r *Result) clone() *Result {
	ret := *r
	if ret.Info != nil {
		ret.Info = ret.Info.Clone()
	}
	if ret.Ddrd != nil {
		ret.Ddrd = ret.Ddrd.Clone()
	}
	if ret.Output != nil {
		ret.Output = append([]byte{}, ret.Output...)
	}
	if len(ret.BarrierMembers) != 0 {
		members := make([]*BarrierMemberResult, len(ret.BarrierMembers))
		for i, member := range ret.BarrierMembers {
			if member == nil {
				continue
			}
			clone := *member
			if member.Info != nil {
				clone.Info = member.Info.Clone()
			}
			if member.Ddrd != nil {
				clone.Ddrd = member.Ddrd.Clone()
			}
			if member.Output != nil {
				clone.Output = append([]byte{}, member.Output...)
			}
			if member.Prog != nil {
				clone.Prog = member.Prog.Clone()
			}
			members[i] = &clone
		}
		ret.BarrierMembers = members
	}
	return &ret
}

// BarrierMemberResult describes the outcome for a single participant of a barrier execution.
type BarrierMemberResult struct {
	Index     int
	GroupID   int64
	GroupSize int
	Proc      int
	Prog      *prog.Prog
	Executor  ExecutorID
	Info      *flatrpc.ProgInfo
	Ddrd      *ddrd.Report
	Output    []byte
	Status    Status
	Err       error
}

func (r *Result) Stop() bool {
	switch r.Status {
	case Success, Restarted:
		return false
	case ExecFailure, Crashed, Hanged:
		return true
	default:
		panic(fmt.Sprintf("unhandled status %v", r.Status))
	}
}

// Globs returns result of RequestTypeGlob.
func (r *Result) GlobFiles() []string {
	out := strings.Trim(string(r.Output), "\000")
	if out == "" {
		return nil
	}
	return strings.Split(out, "\000")
}

type Status int

//go:generate go run golang.org/x/tools/cmd/stringer -type Status
const (
	Success     Status = iota
	ExecFailure        // For e.g. serialization errors.
	Crashed            // The VM crashed holding the request.
	Restarted          // The VM was restarted holding the request.
	Hanged             // The program has hanged (can't be killed/waited).
)

// Executor describes the interface wanted by the producers of requests.
// After a Request is submitted, it's expected that the consumer will eventually
// take it and report the execution result via Done().
type Executor interface {
	Submit(req *Request)
}

// Source describes the interface wanted by the consumers of requests.
type Source interface {
	Next() *Request
}

// PlainQueue is a straighforward thread-safe Request queue implementation.
type PlainQueue struct {
	mu    sync.Mutex
	queue []*Request
	pos   int
}

func Plain() *PlainQueue {
	return &PlainQueue{}
}

func (pq *PlainQueue) Len() int {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return len(pq.queue) - pq.pos
}

func (pq *PlainQueue) Submit(req *Request) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	// It doesn't make sense to compact the queue too often.
	const minSizeToCompact = 128
	if pq.pos > len(pq.queue)/2 && len(pq.queue) >= minSizeToCompact {
		copy(pq.queue, pq.queue[pq.pos:])
		for pq.pos > 0 {
			newLen := len(pq.queue) - 1
			pq.queue[newLen] = nil
			pq.queue = pq.queue[:newLen]
			pq.pos--
		}
	}
	pq.queue = append(pq.queue, req)
}

func (pq *PlainQueue) Next() *Request {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return pq.nextLocked()
}

func (pq *PlainQueue) tryNext() *Request {
	if !pq.mu.TryLock() {
		return nil
	}
	defer pq.mu.Unlock()
	return pq.nextLocked()
}

func (pq *PlainQueue) nextLocked() *Request {
	if pq.pos == len(pq.queue) {
		return nil
	}
	ret := pq.queue[pq.pos]
	pq.queue[pq.pos] = nil
	pq.pos++
	return ret
}

// Order combines several different sources in a particular order.
type orderImpl struct {
	sources []Source
}

func Order(sources ...Source) Source {
	return &orderImpl{sources: sources}
}

func (o *orderImpl) Next() *Request {
	for _, s := range o.sources {
		req := s.Next()
		if req != nil {
			return req
		}
	}
	return nil
}

type callback struct {
	cb func() *Request
}

// Callback produces a source that calls the callback to serve every Next() request.
func Callback(cb func() *Request) Source {
	return &callback{cb}
}

func (cb *callback) Next() *Request {
	return cb.cb()
}

type alternate struct {
	base Source
	nth  int
	seq  atomic.Int64
}

// Alternate proxies base, but returns nil every nth Next() call.
func Alternate(base Source, nth int) Source {
	return &alternate{
		base: base,
		nth:  nth,
	}
}

func (a *alternate) Next() *Request {
	if a.seq.Add(1)%int64(a.nth) == 0 {
		return nil
	}
	return a.base.Next()
}

type periodic struct {
	base Source
	nth  int
	seq  atomic.Int64
}

// Periodic proxies base, but only polls it every nth Next() call.
func Periodic(base Source, nth int) Source {
	if nth <= 1 {
		return base
	}
	return &periodic{
		base: base,
		nth:  nth,
	}
}

func (p *periodic) Next() *Request {
	if p.seq.Add(1)%int64(p.nth) != 0 {
		return nil
	}
	return p.base.Next()
}

type DynamicOrderer struct {
	mu       sync.Mutex
	currPrio int
	ops      *priorityQueueOps[*Request]
}

// DynamicOrder() can be used to form nested queues dynamically.
// That is, if
// q1 := pq.Append()
// q2 := pq.Append()
// All elements added via q2.Submit() will always have a *lower* priority
// than all elements added via q1.Submit().
func DynamicOrder() *DynamicOrderer {
	return &DynamicOrderer{
		ops: &priorityQueueOps[*Request]{},
	}
}

func (do *DynamicOrderer) Append() Executor {
	do.mu.Lock()
	defer do.mu.Unlock()
	do.currPrio++
	return &dynamicOrdererItem{
		parent: do,
		prio:   do.currPrio,
	}
}

func (do *DynamicOrderer) submit(req *Request, prio int) {
	do.mu.Lock()
	defer do.mu.Unlock()
	do.ops.Push(req, prio)
}

func (do *DynamicOrderer) Next() *Request {
	do.mu.Lock()
	defer do.mu.Unlock()
	return do.ops.Pop()
}

type dynamicOrdererItem struct {
	parent *DynamicOrderer
	prio   int
}

func (doi *dynamicOrdererItem) Submit(req *Request) {
	doi.parent.submit(req, doi.prio)
}

type DynamicSourceCtl struct {
	value atomic.Pointer[Source]
}

// DynamicSource is assumed never to point to nil.
func DynamicSource(source Source) *DynamicSourceCtl {
	var ret DynamicSourceCtl
	ret.Store(source)
	return &ret
}

func (ds *DynamicSourceCtl) Store(source Source) {
	ds.value.Store(&source)
}

func (ds *DynamicSourceCtl) Next() *Request {
	return (*ds.value.Load()).Next()
}

// Deduplicator() keeps track of the previously run requests to avoid re-running them.
type Deduplicator struct {
	mu     sync.Mutex
	source Source
	mm     map[hash.Sig]*duplicateState
}

type duplicateState struct {
	res    *Result
	queued []*Request // duplicate requests waiting for the result.
}

func Deduplicate(source Source) Source {
	return &Deduplicator{
		source: source,
		mm:     map[hash.Sig]*duplicateState{},
	}
}

func (d *Deduplicator) Next() *Request {
	for {
		req := d.source.Next()
		if req == nil {
			return nil
		}
		hash := req.hash()
		d.mu.Lock()
		entry, ok := d.mm[hash]
		if !ok {
			d.mm[hash] = &duplicateState{}
		} else if entry.res == nil {
			// There's no result yet, put the request to the queue.
			entry.queued = append(entry.queued, req)
		} else {
			// We already know the result.
			req.Done(entry.res.clone())
		}
		d.mu.Unlock()
		if !ok {
			// This is the first time we see such a request.
			req.OnDone(d.onDone)
			return req
		}
	}
}

func (d *Deduplicator) onDone(req *Request, res *Result) bool {
	hash := req.hash()
	clonedRes := res.clone()

	d.mu.Lock()
	entry := d.mm[hash]
	queued := entry.queued
	entry.queued = nil
	entry.res = clonedRes
	d.mu.Unlock()

	// Broadcast the result.
	for _, waitingReq := range queued {
		waitingReq.Done(res.clone())
	}
	return true
}

// DefaultOpts applies opts to all requests in source.
func DefaultOpts(source Source, opts flatrpc.ExecOpts) Source {
	return &defaultOpts{source, opts}
}

type defaultOpts struct {
	source Source
	opts   flatrpc.ExecOpts
}

func (do *defaultOpts) Next() *Request {
	req := do.source.Next()
	if req == nil {
		return nil
	}
	// Solo执行（3-phase验证中的单程序执行）需要单线程运行
	// 不能合并Threaded标志，否则会导致多线程执行
	if req.IsSoloExecution {
		// 只合并非Threaded的exec flags
		req.ExecOpts.ExecFlags |= (do.opts.ExecFlags &^ flatrpc.ExecFlagThreaded)
	} else {
		req.ExecOpts.ExecFlags |= do.opts.ExecFlags
	}
	// DisableDdrd的请求不应继承CollectDdrdUaf，防止与正在执行的Solo DDRD冲突
	if req.DisableDdrd {
		req.ExecOpts.ExecFlags &^= flatrpc.ExecFlagCollectDdrdUaf
	}
	req.ExecOpts.EnvFlags |= do.opts.EnvFlags
	req.ExecOpts.SandboxArg = do.opts.SandboxArg
	return req
}

// RandomQueue holds up to |size| elements.
// Next() evicts a random one.
// On Submit(), if the queue is full, a random element is replaced.
type RandomQueue struct {
	mu      sync.Mutex
	queue   []*Request
	maxSize int
	rnd     *rand.Rand
}

func NewRandomQueue(size int, rnd *rand.Rand) *RandomQueue {
	return &RandomQueue{
		maxSize: size,
		rnd:     rnd,
	}
}

func (rq *RandomQueue) Next() *Request {
	rq.mu.Lock()
	defer rq.mu.Unlock()
	if len(rq.queue) == 0 {
		return nil
	}
	pos := rq.rnd.Intn(len(rq.queue))
	item := rq.queue[pos]

	last := len(rq.queue) - 1
	rq.queue[pos] = rq.queue[last]
	rq.queue[last] = nil
	rq.queue = rq.queue[0 : len(rq.queue)-1]
	return item
}

var errEvictedFromQueue = errors.New("evicted from the random queue")

func (rq *RandomQueue) Submit(req *Request) {
	rq.mu.Lock()
	defer rq.mu.Unlock()
	if len(rq.queue) < rq.maxSize {
		rq.queue = append(rq.queue, req)
	} else {
		pos := rq.rnd.Intn(rq.maxSize + 1)
		if pos < len(rq.queue) {
			rq.queue[pos].Done(&Result{
				Status: ExecFailure,
				Err:    errEvictedFromQueue,
			})
			rq.queue[pos] = req
		}
	}
}

type tee struct {
	queue Executor
	src   Source
}

func Tee(src Source, queue Executor) Source {
	return &tee{src: src, queue: queue}
}

func (t *tee) Next() *Request {
	req := t.src.Next()
	if req == nil {
		return nil
	}
	t.queue.Submit(&Request{
		// It makes little sense to copy other fields if these requests
		// are to be executed in a different environment.
		Type:        req.Type,
		ExecOpts:    req.ExecOpts,
		Prog:        req.Prog.Clone(),
		BinaryFile:  req.BinaryFile,
		GlobPattern: req.GlobPattern,
	})
	return req
}
