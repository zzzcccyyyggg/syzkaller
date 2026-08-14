// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"bytes"
	"context"
	"fmt"
	"hash/crc32"
	"math/rand"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestFuzz(t *testing.T) {
	defer checkGoroutineLeaks()

	target, err := getTestTarget()
	if err != nil {
		t.Fatal(err)
	}
	sysTarget := targets.Get(target.OS, target.Arch)
	if sysTarget.BrokenCompiler != "" {
		t.Skipf("skipping, broken cross-compiler: %v", sysTarget.BrokenCompiler)
	}
	executor := csource.BuildExecutor(t, target, "../..", "-fsanitize-coverage=trace-pc", "-g")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	corpusUpdates := make(chan corpus.NewItemEvent)
	fuzzer := NewFuzzer(ctx, &Config{
		Debug:  true,
		Corpus: corpus.NewMonitoredCorpus(ctx, corpusUpdates),
		Logf: func(level int, msg string, args ...interface{}) {
			if level > 1 {
				return
			}
			t.Logf(msg, args...)
		},
		Coverage: true,
		EnabledCalls: map[*prog.Syscall]bool{
			target.SyscallMap["syz_test_fuzzer1"]: true,
		},
	}, rand.New(testutil.RandSource(t)), target)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case u := <-corpusUpdates:
				t.Logf("new prog:\n%s", u.ProgData)
			}
		}
	}()

	tf := &testFuzzer{
		t:         t,
		target:    target,
		fuzzer:    fuzzer,
		executor:  executor,
		iterLimit: 10000,
		expectedCrashes: map[string]bool{
			"first bug":  true,
			"second bug": true,
		},
	}
	tf.run()

	t.Logf("resulting corpus:")
	for _, p := range fuzzer.Config.Corpus.Programs() {
		t.Logf("-----")
		t.Logf("%s", p.Serialize())
	}
}

func BenchmarkFuzzer(b *testing.B) {
	b.ReportAllocs()
	target, err := getTestTarget()
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := map[*prog.Syscall]bool{}
	for _, c := range target.Syscalls {
		calls[c] = true
	}
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:       corpus.NewCorpus(ctx),
		Coverage:     true,
		EnabledCalls: calls,
	}, rand.New(rand.NewSource(time.Now().UnixNano())), target)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := fuzzer.Next()
			res, _, _ := emulateExec(req)
			req.Done(res)
		}
	})
}

func TestApplyNormalTimingThreshold(t *testing.T) {
	fuzzer := &Fuzzer{Config: &Config{NormalThresholdMicros: 2500}}

	t.Run("applies to regular requests", func(t *testing.T) {
		req := &queue.Request{}
		fuzzer.applyNormalTimingThreshold(req)
		assert.Equal(t, int64(2500), req.TimingThresholdUs)
	})

	t.Run("does not overwrite explicit threshold", func(t *testing.T) {
		req := &queue.Request{TimingThresholdUs: 777}
		fuzzer.applyNormalTimingThreshold(req)
		assert.Equal(t, int64(777), req.TimingThresholdUs)
	})

	t.Run("skips timing exploration requests", func(t *testing.T) {
		req := &queue.Request{IsTimingExploration: true}
		fuzzer.applyNormalTimingThreshold(req)
		assert.Zero(t, req.TimingThresholdUs)
	})

	t.Run("uses dynamic controller when active", func(t *testing.T) {
		config := DefaultThresholdControllerConfig()
		config.InitialThresholdUs = 3333
		tc := NewThresholdController(config, func() int { return 0 })
		f := &Fuzzer{
			Config:              &Config{NormalThresholdMicros: 2500},
			thresholdController: tc,
		}
		req := &queue.Request{}
		f.applyNormalTimingThreshold(req)
		assert.Equal(t, int64(3333), req.TimingThresholdUs,
			"should use dynamic controller threshold, not static config")
	})

	t.Run("dynamic controller overridden by explicit threshold", func(t *testing.T) {
		config := DefaultThresholdControllerConfig()
		config.InitialThresholdUs = 3333
		tc := NewThresholdController(config, func() int { return 0 })
		f := &Fuzzer{
			Config:              &Config{NormalThresholdMicros: 2500},
			thresholdController: tc,
		}
		req := &queue.Request{TimingThresholdUs: 777}
		f.applyNormalTimingThreshold(req)
		assert.Equal(t, int64(777), req.TimingThresholdUs,
			"explicit threshold should not be overwritten")
	})
}

func TestInheritTimingThreshold(t *testing.T) {
	t.Run("inherits parent threshold", func(t *testing.T) {
		req := &queue.Request{}
		parent := &queue.Request{TimingThresholdUs: 4321}
		inheritTimingThreshold(req, parent)
		assert.Equal(t, int64(4321), req.TimingThresholdUs)
	})

	t.Run("keeps explicit request threshold", func(t *testing.T) {
		req := &queue.Request{TimingThresholdUs: 111}
		parent := &queue.Request{TimingThresholdUs: 4321}
		inheritTimingThreshold(req, parent)
		assert.Equal(t, int64(111), req.TimingThresholdUs)
	})
}

func TestRaceNormalTriageSource(t *testing.T) {
	t.Run("default interval throttles in race mode", func(t *testing.T) {
		req := &queue.Request{}
		sourceQueue := queue.Plain()
		sourceQueue.Submit(req)
		fuzzer := &Fuzzer{Config: &Config{ModeUAF: true}}
		source := fuzzer.raceNormalTriageSource(sourceQueue)
		for i := 1; i < defaultRaceNormalTriageInterval; i++ {
			assert.Nil(t, source.Next())
		}
		assert.Same(t, req, source.Next())
	})

	t.Run("interval one preserves legacy priority", func(t *testing.T) {
		req := &queue.Request{}
		sourceQueue := queue.Plain()
		sourceQueue.Submit(req)
		fuzzer := &Fuzzer{Config: &Config{ModeUAF: true, RaceNormalTriageInterval: 1}}
		source := fuzzer.raceNormalTriageSource(sourceQueue)
		assert.Same(t, req, source.Next())
	})

	t.Run("non race mode is unchanged", func(t *testing.T) {
		req := &queue.Request{}
		sourceQueue := queue.Plain()
		sourceQueue.Submit(req)
		fuzzer := &Fuzzer{Config: &Config{}}
		source := fuzzer.raceNormalTriageSource(sourceQueue)
		assert.Same(t, req, source.Next())
	})
}

func TestRaceNormalTriageJobLimit(t *testing.T) {
	target, err := getTestTarget()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("limits combined race triage backlog", func(t *testing.T) {
		fuzzer := &Fuzzer{
			Stats:  newStats(target),
			Config: &Config{ModeUAF: true, RaceNormalTriageMaxJobs: 2},
		}
		assert.True(t, fuzzer.shouldStartRaceNormalTriageJob())
		fuzzer.statJobsTriage.Add(1)
		fuzzer.statJobsTriageCandidate.Add(1)
		assert.False(t, fuzzer.shouldStartRaceNormalTriageJob())
		assert.Equal(t, 1, fuzzer.statNormalTriageSkips.Val())
	})

	t.Run("non race mode is unchanged", func(t *testing.T) {
		fuzzer := &Fuzzer{Config: &Config{}}
		assert.True(t, fuzzer.shouldStartRaceNormalTriageJob())
	})
}

func TestCurrentWidenedTimingThreshold(t *testing.T) {
	t.Run("uses static widened threshold without controller", func(t *testing.T) {
		f := &Fuzzer{
			Config: &Config{NormalThresholdMicros: 2500},
			timingScheduler: &TimingScheduler{
				config: TimingExplorationConfig{WidenedThresholdMicros: 20000},
			},
		}
		assert.Equal(t, int64(20000), f.currentWidenedTimingThreshold())
	})

	t.Run("uses dynamic threshold scaled by 8x", func(t *testing.T) {
		config := DefaultThresholdControllerConfig()
		config.InitialThresholdUs = 1000
		tc := NewThresholdController(config, func() int { return 0 })
		f := &Fuzzer{
			Config:              &Config{NormalThresholdMicros: 2500},
			thresholdController: tc,
			timingScheduler: &TimingScheduler{
				config: TimingExplorationConfig{WidenedThresholdMicros: 20000},
			},
		}
		assert.Equal(t, int64(20000), f.currentWidenedTimingThreshold())
	})

	t.Run("lets dynamic widened threshold grow above configured floor", func(t *testing.T) {
		config := DefaultThresholdControllerConfig()
		config.InitialThresholdUs = 4000
		tc := NewThresholdController(config, func() int { return 0 })
		f := &Fuzzer{
			Config:              &Config{NormalThresholdMicros: 2500},
			thresholdController: tc,
			timingScheduler: &TimingScheduler{
				config: TimingExplorationConfig{WidenedThresholdMicros: 20000},
			},
		}
		assert.Equal(t, int64(32000), f.currentWidenedTimingThreshold())
	})
}

func TestNormalizeObjectLinkAttemptRatio(t *testing.T) {
	assert.Equal(t, 1.0, normalizeObjectLinkAttemptRatio(0))
	assert.Equal(t, 1.0, normalizeObjectLinkAttemptRatio(-0.5))
	assert.Equal(t, 1.0, normalizeObjectLinkAttemptRatio(1.5))
	assert.Equal(t, 0.1, normalizeObjectLinkAttemptRatio(0.1))
	assert.Equal(t, 1.0, normalizeObjectLinkAttemptRatio(1.0))
}

func TestStaticInputExplorationSamplesFrozenPool(t *testing.T) {
	target, err := getTestTarget()
	if err != nil {
		t.Fatal(err)
	}
	call := target.SyscallMap["syz_test_fuzzer1"]
	p0 := &prog.Prog{Target: target, Calls: []*prog.Call{{
		Meta: call,
		Args: []prog.Arg{
			prog.MakeConstArg(call.Args[0].Type, prog.DirIn, 1),
			prog.MakeConstArg(call.Args[1].Type, prog.DirIn, 2),
			prog.MakeConstArg(call.Args[2].Type, prog.DirIn, 3),
		},
	}}}
	p1 := &prog.Prog{Target: target, Calls: []*prog.Call{{
		Meta: call,
		Args: []prog.Arg{
			prog.MakeConstArg(call.Args[0].Type, prog.DirIn, 4),
			prog.MakeConstArg(call.Args[1].Type, prog.DirIn, 5),
			prog.MakeConstArg(call.Args[2].Type, prog.DirIn, 6),
		},
	}}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:                 corpus.NewCorpus(ctx),
		Coverage:               true,
		EnabledCalls:           map[*prog.Syscall]bool{call: true},
		ModeUAF:                true,
		BarrierMode:            true,
		BarrierMask:            0x3,
		StaticInputExploration: true,
		StaticInputSeed:        7,
	}, rand.New(rand.NewSource(0)), target)
	assert.Equal(t, 2, fuzzer.SetStaticInputPool([]Candidate{{Prog: p1}, {Prog: p0}}))
	assert.True(t, fuzzer.ActivateUAFMode())

	req := fuzzer.genFuzz()
	if assert.NotNil(t, req) && assert.Len(t, req.BarrierPrograms, 2) {
		allowed := map[string]bool{
			string(p0.Serialize()): true,
			string(p1.Serialize()): true,
		}
		assert.True(t, req.Barrier, "static exploration should execute barrier groups")
		assert.True(t, allowed[string(req.BarrierPrograms[0].Serialize())])
		assert.True(t, allowed[string(req.BarrierPrograms[1].Serialize())])
	}
	assert.Zero(t, fuzzer.Config.Corpus.StatProgs.Val(), "static pool must not be inserted into normal corpus")
}

func TestBarrierCoverageCollectionFollowsCoverageTriage(t *testing.T) {
	target, err := getTestTarget()
	if err != nil {
		t.Fatal(err)
	}
	call := target.SyscallMap["syz_test_fuzzer1"]
	program := &prog.Prog{Target: target, Calls: []*prog.Call{{
		Meta: call,
		Args: []prog.Arg{
			prog.MakeConstArg(call.Args[0].Type, prog.DirIn, 1),
			prog.MakeConstArg(call.Args[1].Type, prog.DirIn, 2),
			prog.MakeConstArg(call.Args[2].Type, prog.DirIn, 3),
		},
	}}}

	for _, tc := range []struct {
		name           string
		coverageTriage bool
		wantCover      bool
	}{
		{name: "disabled"},
		{name: "enabled", coverageTriage: true, wantCover: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fuzzer := NewFuzzer(ctx, &Config{
				Corpus:               corpus.NewCorpus(ctx),
				Coverage:             true,
				EnabledCalls:         map[*prog.Syscall]bool{call: true},
				ModeUAF:              true,
				BarrierMode:          true,
				BarrierMask:          0x3,
				EnableCoverageTriage: &tc.coverageTriage,
			}, rand.New(rand.NewSource(0)), target)
			req := &queue.Request{
				Prog:     program.Clone(),
				ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
			}
			fuzzer.applyBarrier(req)

			assert.NotZero(t, req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectDdrdUaf)
			hasCover := req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectCover != 0
			assert.Equal(t, tc.wantCover, hasCover)
		})
	}
}

func getTestTarget() (*prog.Target, error) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err == nil {
		return target, nil
	}
	return prog.GetTarget(targets.TestOS, targets.TestArch64)
}

// Based on the example from Go documentation.
var crc32q = crc32.MakeTable(0xD5828281)

func emulateExec(req *queue.Request) (*queue.Result, string, error) {
	serializedLines := bytes.Split(req.Prog.Serialize(), []byte("\n"))
	var info flatrpc.ProgInfo
	for i, call := range req.Prog.Calls {
		cover := []uint64{uint64(call.Meta.ID*1024) +
			uint64(crc32.Checksum(serializedLines[i], crc32q)%4)}
		callInfo := &flatrpc.CallInfo{}
		if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectCover > 0 {
			callInfo.Cover = cover
		}
		if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0 {
			callInfo.Signal = cover
		}
		info.Calls = append(info.Calls, callInfo)
	}
	return &queue.Result{Info: &info}, "", nil
}

type testFuzzer struct {
	t               testing.TB
	target          *prog.Target
	fuzzer          *Fuzzer
	executor        string
	mu              sync.Mutex
	crashes         map[string]int
	expectedCrashes map[string]bool
	iter            int
	iterLimit       int
	done            func()
	finished        atomic.Bool
}

func (f *testFuzzer) run() {
	f.crashes = make(map[string]int)
	ctx, done := context.WithCancel(context.Background())
	f.done = done
	var output bytes.Buffer
	cfg := &rpcserver.LocalConfig{
		Config: rpcserver.Config{
			Config: vminfo.Config{
				Debug:    true,
				Cover:    true,
				Target:   f.target,
				Features: flatrpc.FeatureSandboxNone | flatrpc.FeatureCoverage,
				Sandbox:  flatrpc.ExecEnvSandboxNone,
			},
			Procs:    4,
			Slowdown: 1,
		},
		Executor:     f.executor,
		Dir:          f.t.TempDir(),
		OutputWriter: &output,
	}
	cfg.MachineChecked = func(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source {
		return f
	}
	if err := rpcserver.RunLocal(ctx, cfg); err != nil {
		f.t.Logf("executor output:\n%s", output.String())
		f.t.Fatal(err)
	}
	assert.Equal(f.t, len(f.expectedCrashes), len(f.crashes), "not all expected crashes were found")
	assert.NotEmpty(f.t, f.fuzzer.Config.Corpus.StatProgs.Val(), "must have non-empty corpus")
	assert.NotEmpty(f.t, f.fuzzer.Config.Corpus.StatSignal.Val(), "must have non-empty signal")
}

func (f *testFuzzer) Next() *queue.Request {
	if f.finished.Load() {
		return nil
	}
	req := f.fuzzer.Next()
	req.ExecOpts.EnvFlags |= flatrpc.ExecEnvSignal | flatrpc.ExecEnvSandboxNone
	req.ReturnOutput = true
	req.ReturnError = true
	req.OnDone(f.OnDone)
	return req
}

func (f *testFuzzer) OnDone(req *queue.Request, res *queue.Result) bool {
	// TODO: support hints emulation.
	match := crashRe.FindSubmatch(res.Output)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.finished.Load() {
		// Don't touch f.crashes in this case b/c it can cause races with the main goroutine,
		// and logging can cause "Log in goroutine after TestFuzz has completed" panic.
		return true
	}
	if match != nil {
		crash := string(match[1])
		f.t.Logf("CRASH: %s", crash)
		res.Status = queue.Crashed
		if !f.expectedCrashes[crash] {
			f.t.Errorf("unexpected crash: %q", crash)
		}
		f.crashes[crash]++
	}
	f.iter++
	corpusProgs := f.fuzzer.Config.Corpus.StatProgs.Val()
	signal := f.fuzzer.Config.Corpus.StatSignal.Val()
	if f.iter%100 == 0 {
		f.t.Logf("<iter %d>: corpus %d, signal %d, max signal %d, crash types %d, running jobs %d",
			f.iter, corpusProgs, signal, len(f.fuzzer.Cover.maxSignal),
			len(f.crashes), f.fuzzer.statJobs.Val())
	}
	criteriaMet := len(f.crashes) == len(f.expectedCrashes) &&
		corpusProgs > 0 && signal > 0
	if f.iter > f.iterLimit || criteriaMet {
		f.done()
		f.finished.Store(true)
	}
	return true
}

var crashRe = regexp.MustCompile(`{{CRASH: (.*?)}}`)

func checkGoroutineLeaks() {
	// Inspired by src/net/http/main_test.go.
	buf := make([]byte, 2<<20)
	err := ""
	for i := 0; i < 3; i++ {
		buf = buf[:runtime.Stack(buf, true)]
		err = ""
		for _, g := range strings.Split(string(buf), "\n\n") {
			if !strings.Contains(g, "pkg/fuzzer/fuzzer.go") {
				continue
			}
			err = fmt.Sprintf("%sLeaked goroutine:\n%s", err, g)
		}
		if err == "" {
			return
		}
		// Give ctx.Done() a chance to propagate to all goroutines.
		time.Sleep(100 * time.Millisecond)
	}
	if err != "" {
		panic(err)
	}
}
