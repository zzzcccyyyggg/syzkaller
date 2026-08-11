// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"testing"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func TestRunnerCallStatsCountAttemptsAndResultFlags(t *testing.T) {
	p := parseRunnerTestProg(t, "syz_test_fuzzer1()\nsyz_test_fuzzer1()\nsyz_test_fuzzer1()")
	stats := NewStats()
	req := &queue.Request{Prog: p}
	runner := runnerWithRequestForStats(stats, 1, req, p)

	if err := runner.handleExecutingMessage(&flatrpc.ExecutingMessage{Id: 1, ProcId: 0}); err != nil {
		t.Fatal(err)
	}
	if err := runner.handleExecutingMessage(&flatrpc.ExecutingMessage{Id: 1, ProcId: 0, Try: 1}); err != nil {
		t.Fatal(err)
	}

	if got, want := stats.StatExecs.Val(), 2; got != want {
		t.Fatalf("program attempts: got %d, want %d", got, want)
	}
	if got, want := stats.StatCallsScheduled.Val(), 2*len(p.Calls); got != want {
		t.Fatalf("scheduled calls: got %d, want %d", got, want)
	}

	runner.recordProgramCallResult(runner.requests[1], nil)
	if got := stats.StatCallsExecuted.Val(); got != 0 {
		t.Fatalf("executed calls after nil result: got %d, want 0", got)
	}

	err := runner.handleExecResult(&flatrpc.ExecResult{
		Id:   1,
		Proc: 0,
		Info: &flatrpc.ProgInfo{
			Calls: []*flatrpc.CallInfo{
				{Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished},
				{Flags: flatrpc.CallFlagExecuted},
				{Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagBlocked},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := stats.StatCallsExecuted.Val(), 3; got != want {
		t.Fatalf("executed calls: got %d, want %d", got, want)
	}
	if got, want := stats.StatCallsFinished.Val(), 1; got != want {
		t.Fatalf("finished calls: got %d, want %d", got, want)
	}
}

func TestRunnerCallStatsIgnoreNonProgramRequests(t *testing.T) {
	stats := NewStats()
	req := &queue.Request{Type: flatrpc.RequestTypeBinary, BinaryFile: "/tmp/not-used"}
	runner := runnerWithRequestForStats(stats, 1, req, nil)

	if err := runner.handleExecutingMessage(&flatrpc.ExecutingMessage{Id: 1, ProcId: 0}); err != nil {
		t.Fatal(err)
	}
	runner.recordProgramCallResult(runner.requests[1], &flatrpc.ProgInfo{
		Calls: []*flatrpc.CallInfo{
			{Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished},
		},
	})

	if got, want := stats.StatExecs.Val(), 1; got != want {
		t.Fatalf("program attempts: got %d, want %d", got, want)
	}
	if got := stats.StatCallsScheduled.Val(); got != 0 {
		t.Fatalf("scheduled calls for binary request: got %d, want 0", got)
	}
	if got := stats.StatCallsExecuted.Val(); got != 0 {
		t.Fatalf("executed calls for binary request: got %d, want 0", got)
	}
	if got := stats.StatCallsFinished.Val(); got != 0 {
		t.Fatalf("finished calls for binary request: got %d, want 0", got)
	}
}

func runnerWithRequestForStats(stats Stats, id int64, req *queue.Request, p *prog.Prog) *Runner {
	return &Runner{
		id: 0,
		stats: &runnerStats{
			statExecs:              stats.StatExecs,
			statCallsScheduled:     stats.StatCallsScheduled,
			statCallsExecuted:      stats.StatCallsExecuted,
			statCallsFinished:      stats.StatCallsFinished,
			statExecRetries:        statDiscard(),
			statExecutorRestarts:   stats.StatExecutorRestarts,
			statExecBufferTooSmall: statDiscard(),
			statNoExecRequests:     statDiscard(),
			statNoExecDuration:     statDiscard(),
		},
		requests: map[int64]*requestContext{
			id: {
				req:       req,
				program:   p,
				requestID: id,
			},
		},
		executing:  make(map[int64]bool),
		hanged:     make(map[int64]bool),
		lastExec:   MakeLastExecuting(1, 8),
		injectExec: make(chan bool, 1),
		canonicalizer: cover.NewCanonicalizer([]*vminfo.KernelModule{
			{Name: "test", Addr: 0x1000, Size: 0x1000},
		}, true).NewInstance([]*vminfo.KernelModule{
			{Name: "test", Addr: 0x1000, Size: 0x1000},
		}),
	}
}

func statDiscard() *stat.Val {
	return stat.New("discard", "", stat.NoGraph)
}

func parseRunnerTestProg(t *testing.T, text string) *prog.Prog {
	t.Helper()
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(text), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
