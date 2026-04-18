package uafvalidate

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
)

type fakeExecutor struct {
	mu   sync.Mutex
	runs int
}

func (f *fakeExecutor) Run(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	f.mu.Lock()
	f.runs++
	f.mu.Unlock()
	return &ExecutionResult{Duration: time.Millisecond * 5}, nil
}

func (f *fakeExecutor) RunBatch(ctx context.Context, reqs []*ExecutionRequest) ([]*ExecutionResult, error) {
	results := make([]*ExecutionResult, 0, len(reqs))
	for _, req := range reqs {
		res, err := f.Run(ctx, req)
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}

func TestStageManagerDedup(t *testing.T) {
	exec := &fakeExecutor{}
	cfg := Config{MaxConcurrent: 1}
	mgr := NewStageManager(cfg, func(ctx context.Context) (Executor, error) {
		return exec, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		mgr.Run(ctx)
		close(done)
	}()

	profile := fuzzer.UAFPairProfile{FreeAccessName: 0x10, UseAccessName: 0x20, FreeCallStack: 0x30, UseCallStack: 0x40}
	entry := &fuzzer.UAFCorpusEntry{
		Profile: profile,
		PairBasicInfo: ddrd.MayUAFPair{
			FreeAccessName: profile.FreeAccessName,
			UseAccessName:  profile.UseAccessName,
			FreeCallStack:  profile.FreeCallStack,
			UseCallStack:   profile.UseCallStack,
			Signal:         0xdeadbeef,
		},
	}

	mgr.Enqueue(entry)
	mgr.Enqueue(entry)
	mgr.Close()

	var results []*ValidationResult
	for res := range mgr.Results() {
		results = append(results, res)
	}
	<-done
	cancel()

	if len(results) != 1 {
		t.Fatalf("expected single result, got %d", len(results))
	}
	if !results[0].Success {
		t.Fatalf("expected success result")
	}
	if results[0].Attempt != 1 {
		t.Fatalf("expected attempt 1, got %d", results[0].Attempt)
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	if exec.runs != 1 {
		t.Fatalf("expected executor run count 1, got %d", exec.runs)
	}
}

type flakyExecutor struct {
	mu    sync.Mutex
	runs  int
	fails int
}

func (f *flakyExecutor) Run(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs++
	if f.runs == 1 {
		return &ExecutionResult{
			Duration:   time.Millisecond,
			Crashed:    true,
			CrashTitle: crashLostConnection,
		}, nil
	}
	return &ExecutionResult{Duration: time.Millisecond}, nil
}

func (f *flakyExecutor) RunBatch(ctx context.Context, reqs []*ExecutionRequest) ([]*ExecutionResult, error) {
	results := make([]*ExecutionResult, 0, len(reqs))
	for _, req := range reqs {
		res, err := f.Run(ctx, req)
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}

type pairSequenceExecutor struct {
	mu       sync.Mutex
	runs     int
	sequence [][]ddrd.MayUAFPair
}

func (p *pairSequenceExecutor) Run(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	p.mu.Lock()
	idx := p.runs
	p.runs++
	p.mu.Unlock()
	if len(p.sequence) == 0 {
		return &ExecutionResult{Duration: time.Millisecond}, nil
	}
	seq := p.sequence[idx%len(p.sequence)]
	var report *ddrd.Report
	if len(seq) != 0 {
		report = &ddrd.Report{UAFPairs: make([]*ddrd.MayUAFPair, 0, len(seq))}
		for _, pair := range seq {
			copyPair := pair
			report.UAFPairs = append(report.UAFPairs, &copyPair)
		}
	}
	return &ExecutionResult{Duration: time.Millisecond, Ddrd: report}, nil
}

func (p *pairSequenceExecutor) RunBatch(ctx context.Context, reqs []*ExecutionRequest) ([]*ExecutionResult, error) {
	results := make([]*ExecutionResult, 0, len(reqs))
	for _, req := range reqs {
		res, err := p.Run(ctx, req)
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}

func TestStageManagerRetryInfraFailure(t *testing.T) {
	exec := &flakyExecutor{}
	cfg := Config{MaxConcurrent: 1, DelayRetryBudget: 2}
	mgr := NewStageManager(cfg, func(ctx context.Context) (Executor, error) {
		return exec, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		mgr.Run(ctx)
		close(done)
	}()

	profile := fuzzer.UAFPairProfile{FreeAccessName: 0x10, UseAccessName: 0x20, FreeCallStack: 0x30, UseCallStack: 0x40}
	entry := &fuzzer.UAFCorpusEntry{
		Profile: profile,
		PairBasicInfo: ddrd.MayUAFPair{
			FreeAccessName: profile.FreeAccessName,
			UseAccessName:  profile.UseAccessName,
			FreeCallStack:  profile.FreeCallStack,
			UseCallStack:   profile.UseCallStack,
			Signal:         0xdeadbeef,
		},
	}

	mgr.Enqueue(entry)
	mgr.Close()

	var results []*ValidationResult
	for res := range mgr.Results() {
		results = append(results, res)
	}
	<-done
	cancel()

	if len(results) != 1 {
		t.Fatalf("expected single result, got %d", len(results))
	}
	if !results[0].Success {
		t.Fatalf("expected final success result")
	}
	if results[0].Attempt != 2 {
		t.Fatalf("expected attempt 2, got %d", results[0].Attempt)
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	if exec.runs != 2 {
		t.Fatalf("expected executor run count 2, got %d", exec.runs)
	}
}

func TestStageManagerRepeat(t *testing.T) {
	shared := ddrd.MayUAFPair{FreeAccessName: 0x1, UseAccessName: 0x2, FreeCallStack: 0x3, UseCallStack: 0x4, Signal: 0xaa}
	other := ddrd.MayUAFPair{FreeAccessName: 0x5, UseAccessName: 0x6, FreeCallStack: 0x7, UseCallStack: 0x8, Signal: 0xbb}
	exec := &pairSequenceExecutor{
		sequence: [][]ddrd.MayUAFPair{
			{shared, other},
			{shared},
			{shared, ddrd.MayUAFPair{FreeAccessName: 0x9, UseAccessName: 0xa, FreeCallStack: 0xb, UseCallStack: 0xc, Signal: 0xdd}},
		},
	}
	cfg := Config{MaxConcurrent: 1, RepeatCount: 3}
	mgr := NewStageManager(cfg, func(ctx context.Context) (Executor, error) {
		return exec, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		mgr.Run(ctx)
		close(done)
	}()

	profile := fuzzer.UAFPairProfile{FreeAccessName: 0x10, UseAccessName: 0x20, FreeCallStack: 0x30, UseCallStack: 0x40}
	entry := &fuzzer.UAFCorpusEntry{
		Profile: profile,
		PairBasicInfo: ddrd.MayUAFPair{
			FreeAccessName: profile.FreeAccessName,
			UseAccessName:  profile.UseAccessName,
			FreeCallStack:  profile.FreeCallStack,
			UseCallStack:   profile.UseCallStack,
			Signal:         0xdeadbeef,
		},
	}

	mgr.Enqueue(entry)
	mgr.Close()

	var results []*ValidationResult
	for res := range mgr.Results() {
		results = append(results, res)
	}
	<-done
	cancel()

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	for i, res := range results {
		if res.RepeatIndex != i {
			t.Fatalf("result %d repeat index mismatch got=%d", i, res.RepeatIndex)
		}
		if res.RepeatTotal != 3 {
			t.Fatalf("result %d repeat total mismatch got=%d", i, res.RepeatTotal)
		}
		if !res.Success {
			t.Fatalf("result %d expected success", i)
		}
		if res.Attempt != 1 {
			t.Fatalf("result %d expected attempt 1, got %d", i, res.Attempt)
		}
	}
	final := results[len(results)-1]
	if len(final.StablePairs) != 1 {
		t.Fatalf("expected 1 stable pair, got %d", len(final.StablePairs))
	}
	if final.StablePairs[0] != shared {
		t.Fatalf("stable pair mismatch got=%+v want=%+v", final.StablePairs[0], shared)
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	// 3 repeats + 1 verification phase run = 4 total
	if exec.runs != 4 {
		t.Fatalf("expected executor run count 4, got %d", exec.runs)
	}
}
