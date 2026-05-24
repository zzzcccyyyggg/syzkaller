package uafvalidate

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/prog"
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

func TestTargetPairForMatchModeSiteOnlyClearsDynamicFields(t *testing.T) {
	pair := ddrd.MayUAFPair{
		FreeAccessName: 1,
		UseAccessName:  2,
		FreeCallStack:  3,
		UseCallStack:   4,
		FreeSN:         5,
		UseSN:          6,
		FreeSNMin:      4,
		FreeSNMax:      6,
		UseSNMin:       5,
		UseSNMax:       7,
		FreeTid:        7,
		UseTid:         8,
	}
	got := targetPairForMatchMode(pair, TargetMatchModeSiteOnly)
	if got.FreeCallStack != 0 || got.UseCallStack != 0 ||
		got.FreeSN != 0 || got.UseSN != 0 ||
		got.FreeSNMin != 0 || got.FreeSNMax != 0 || got.UseSNMin != 0 || got.UseSNMax != 0 ||
		got.FreeTid != 0 || got.UseTid != 0 {
		t.Fatalf("site-only target retained dynamic fields: %+v", got)
	}
	if got.FreeAccessName != pair.FreeAccessName || got.UseAccessName != pair.UseAccessName {
		t.Fatalf("site-only target changed VarName fields: got=%+v want=%+v", got, pair)
	}
}

func TestTargetPairForMatchModeStackOnlyKeepsStacks(t *testing.T) {
	pair := ddrd.MayUAFPair{
		FreeAccessName: 1,
		UseAccessName:  2,
		FreeCallStack:  3,
		UseCallStack:   4,
		FreeSN:         5,
		UseSN:          6,
		FreeSNMin:      4,
		FreeSNMax:      6,
		UseSNMin:       5,
		UseSNMax:       7,
		FreeTid:        7,
		UseTid:         8,
	}
	got := targetPairForMatchMode(pair, TargetMatchModeStackOnly)
	if got.FreeCallStack != pair.FreeCallStack || got.UseCallStack != pair.UseCallStack {
		t.Fatalf("stack-only target changed stacks: got=%+v want=%+v", got, pair)
	}
	if got.FreeSN != 0 || got.UseSN != 0 ||
		got.FreeSNMin != 0 || got.FreeSNMax != 0 || got.UseSNMin != 0 || got.UseSNMax != 0 ||
		got.FreeTid != 0 || got.UseTid != 0 {
		t.Fatalf("stack-only target retained SN/TID fields: %+v", got)
	}
	if got.FreeAccessName != pair.FreeAccessName || got.UseAccessName != pair.UseAccessName {
		t.Fatalf("stack-only target changed VarName fields: got=%+v want=%+v", got, pair)
	}
}

func TestTargetPairForMatchModeSNOnlyClearsStacksKeepsSN(t *testing.T) {
	pair := ddrd.MayUAFPair{
		FreeAccessName: 1,
		UseAccessName:  2,
		FreeCallStack:  3,
		UseCallStack:   4,
		FreeSN:         5,
		UseSN:          6,
		FreeSNMin:      4,
		FreeSNMax:      6,
		UseSNMin:       5,
		UseSNMax:       7,
		FreeTid:        7,
		UseTid:         8,
	}
	got := targetPairForMatchMode(pair, TargetMatchModeSNOnly)
	if got.FreeCallStack != 0 || got.UseCallStack != 0 {
		t.Fatalf("sn-only target retained stacks: %+v", got)
	}
	if got.FreeSN != pair.FreeSN || got.UseSN != pair.UseSN {
		t.Fatalf("sn-only target changed SN: got=%+v want=%+v", got, pair)
	}
	if got.FreeSNMin != 0 || got.FreeSNMax != 0 || got.UseSNMin != 0 || got.UseSNMax != 0 ||
		got.FreeTid != 0 || got.UseTid != 0 {
		t.Fatalf("sn-only target retained range/TID fields: %+v", got)
	}
}

func TestTargetPairMatchesTreatsZeroTargetStackAsWildcard(t *testing.T) {
	target := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
	}
	got := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
	}
	if !targetPairMatches(&got, &target) {
		t.Fatalf("zero target stack did not wildcard match: got=%+v target=%+v", got, target)
	}
	got.UseAccessName = 0x21
	if targetPairMatches(&got, &target) {
		t.Fatalf("different VarName matched unexpectedly: got=%+v target=%+v", got, target)
	}
}

func TestTargetPairMatchesSiteOnlyAllowsReversedVarNames(t *testing.T) {
	target := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
	}
	got := ddrd.MayUAFPair{
		FreeAccessName: 0x20,
		UseAccessName:  0x10,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
	}
	if !targetPairMatches(&got, &target) {
		t.Fatalf("site-only target did not match reversed VarName order: got=%+v target=%+v", got, target)
	}
	target.FreeCallStack = 0x30
	target.UseCallStack = 0x40
	if targetPairMatches(&got, &target) {
		t.Fatalf("strict stack target matched reversed VarName order unexpectedly: got=%+v target=%+v", got, target)
	}
}

func TestTargetPairMatchesSNRange(t *testing.T) {
	target := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
		FreeSNMin:      3,
		FreeSNMax:      5,
		UseSNMin:       9,
		UseSNMax:       11,
	}
	got := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
		FreeSN:         4,
		UseSN:          10,
	}
	if !targetPairMatches(&got, &target) {
		t.Fatalf("SN-range target did not match: got=%+v target=%+v", got, target)
	}
	got.UseSN = 12
	if targetPairMatches(&got, &target) {
		t.Fatalf("out-of-range SN matched unexpectedly: got=%+v target=%+v", got, target)
	}
}

func TestTargetMatchAttemptsFallbackUsesStackOnlyWhenWindowDisabled(t *testing.T) {
	pair := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
		FreeSN:         7,
		UseSN:          11,
		FreeTid:        3,
		UseTid:         4,
	}
	got := targetMatchAttempts(pair, TargetMatchModeSNFallback, Config{})
	if len(got) != 2 {
		t.Fatalf("got %d attempts, want 2", len(got))
	}
	if got[0].mode != TargetMatchModeStrictSN || got[1].mode != TargetMatchModeStackOnly {
		t.Fatalf("unexpected fallback order: %+v", got)
	}
	if got[1].pair.FreeCallStack != pair.FreeCallStack || got[1].pair.UseCallStack != pair.UseCallStack {
		t.Fatalf("stack-only fallback should preserve call stacks: %+v", got[1].pair)
	}
	if got[1].pair.FreeSN != 0 || got[1].pair.UseSN != 0 || got[1].pair.FreeTid != 0 || got[1].pair.UseTid != 0 {
		t.Fatalf("stack-only fallback should clear SN/TID: %+v", got[1].pair)
	}
}

func TestTargetMatchAttemptsSNRangeOnlyClearsStacks(t *testing.T) {
	pair := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
		FreeSN:         7,
		UseSN:          11,
		FreeTid:        3,
		UseTid:         4,
	}
	got := targetMatchAttempts(pair, TargetMatchModeSNRangeOnly, Config{SNFallbackRange: 2})
	if len(got) != 1 || got[0].mode != TargetMatchModeSNRangeOnly {
		t.Fatalf("unexpected sn-range-only attempts: %+v", got)
	}
	attempt := got[0].pair
	if attempt.FreeCallStack != 0 || attempt.UseCallStack != 0 ||
		attempt.FreeTid != 0 || attempt.UseTid != 0 {
		t.Fatalf("sn-range-only should clear stacks/TID: %+v", attempt)
	}
	if attempt.FreeSNMin != 5 || attempt.FreeSNMax != 9 ||
		attempt.UseSNMin != 9 || attempt.UseSNMax != 13 {
		t.Fatalf("unexpected SN ranges: %+v", attempt)
	}
}

func TestTargetMatchAttemptsFallbackUsesSNRangeBeforeStackOnly(t *testing.T) {
	pair := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
		FreeSN:         1,
		UseSN:          11,
		FreeTid:        3,
		UseTid:         4,
	}
	got := targetMatchAttempts(pair, TargetMatchModeSNFallback, Config{SNFallbackRange: 2})
	wantModes := []string{TargetMatchModeStrictSN, TargetMatchModeSNRange, TargetMatchModeStackOnly}
	if len(got) != len(wantModes) {
		t.Fatalf("got %d attempts, want %d: %+v", len(got), len(wantModes), got)
	}
	for i, want := range wantModes {
		if got[i].mode != want {
			t.Fatalf("attempt %d got mode %q want %q: %+v", i, got[i].mode, want, got)
		}
	}
	rangeAttempt := got[1].pair
	if rangeAttempt.FreeTid != 0 || rangeAttempt.UseTid != 0 {
		t.Fatalf("sn-range should clear TID: %+v", rangeAttempt)
	}
	if rangeAttempt.FreeSNMin != 1 || rangeAttempt.FreeSNMax != 3 {
		t.Fatalf("unexpected free SN range: %+v", rangeAttempt)
	}
	if rangeAttempt.UseSNMin != 9 || rangeAttempt.UseSNMax != 13 {
		t.Fatalf("unexpected use SN range: %+v", rangeAttempt)
	}
}

func TestTargetMatchAttemptsWildcardTargetTID(t *testing.T) {
	pair := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
		FreeSN:         7,
		UseSN:          11,
		FreeTid:        3,
		UseTid:         4,
	}
	got := targetMatchAttempts(pair, TargetMatchModeStrictSN, Config{WildcardTargetTID: true})
	if len(got) != 1 {
		t.Fatalf("got %d attempts, want 1", len(got))
	}
	if got[0].pair.FreeSN != pair.FreeSN || got[0].pair.UseSN != pair.UseSN {
		t.Fatalf("wildcard TID should preserve SN: %+v", got[0].pair)
	}
	if got[0].pair.FreeCallStack != pair.FreeCallStack || got[0].pair.UseCallStack != pair.UseCallStack {
		t.Fatalf("wildcard TID should preserve stacks: %+v", got[0].pair)
	}
	if got[0].pair.FreeTid != 0 || got[0].pair.UseTid != 0 {
		t.Fatalf("wildcard TID should clear TIDs: %+v", got[0].pair)
	}
}

func TestCollectStablePairsOriginMatchVarNameAllowsStackDrift(t *testing.T) {
	original := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
		TimeDiff:       50_000,
	}
	runtime := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x300,
		UseCallStack:   0x400,
		TimeDiff:       90_000,
	}
	latest := map[string]ddrd.MayUAFPair{pairKey(runtime): runtime}
	counts := map[string]int{pairKey(runtime): 1}
	originalPairs := []*ddrd.MayUAFPair{&original}

	if got := collectStablePairs(latest, counts, 1, originalPairs, false, OriginMatchModeExact, 0, 0); len(got) != 0 {
		t.Fatalf("exact origin match accepted stack drift: %+v", got)
	}
	got := collectStablePairs(latest, counts, 1, originalPairs, false, OriginMatchModeVarName, 0, 0)
	if len(got) != 1 {
		t.Fatalf("varname origin match rejected stack drift: got %d", len(got))
	}
	if got[0] != runtime {
		t.Fatalf("stable pair mismatch got=%+v want=%+v", got[0], runtime)
	}
}

func TestCollectStablePairsWithDelaysUsesOriginalVarNameDelay(t *testing.T) {
	original := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
		TimeDiff:       50_000,
	}
	runtime := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x300,
		UseCallStack:   0x400,
		TimeDiff:       90_000,
	}
	latest := map[string]ddrd.MayUAFPair{pairKey(runtime): runtime}
	counts := map[string]int{pairKey(runtime): 1}
	originalPairs := []*ddrd.MayUAFPair{&original}

	got := collectStablePairsWithDelays(latest, counts, nil, 1, originalPairs, false, OriginMatchModeVarName, 0, 0)
	if len(got) != 1 {
		t.Fatalf("expected one varname-matched pair, got %d", len(got))
	}
	if got[0].StartDelayUs != 50 {
		t.Fatalf("expected original start delay 50us, got %d", got[0].StartDelayUs)
	}
	if got[0].AccessDelayUs != 90 {
		t.Fatalf("expected max access delay 90us, got %d", got[0].AccessDelayUs)
	}
}

func TestVerificationAccessDelayFloor(t *testing.T) {
	cfg := Config{VerifyAccessDelayMinUs: 50_000}
	if got := verificationAccessDelayUs(5_000, cfg); got != 50_000 {
		t.Fatalf("expected access delay floor 50000us, got %d", got)
	}
	if got := verificationAccessDelayUs(80_000, cfg); got != 80_000 {
		t.Fatalf("expected existing larger access delay, got %d", got)
	}
	cfg.DisableAccessDelay = true
	if got := verificationAccessDelayUs(80_000, cfg); got != 0 {
		t.Fatalf("disable access delay should win, got %d", got)
	}
}

func TestCollectStablePairsLimitsStackVariantsPerOrigin(t *testing.T) {
	original := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
	}
	runtimeA := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x300,
		UseCallStack:   0x400,
	}
	runtimeB := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x301,
		UseCallStack:   0x401,
	}
	latest := map[string]ddrd.MayUAFPair{
		pairKey(runtimeA): runtimeA,
		pairKey(runtimeB): runtimeB,
	}
	counts := map[string]int{
		pairKey(runtimeA): 1,
		pairKey(runtimeB): 1,
	}
	got := collectStablePairs(latest, counts, 1, []*ddrd.MayUAFPair{&original}, false, OriginMatchModeVarName, 1, 0)
	if len(got) != 1 {
		t.Fatalf("expected one stable pair after per-origin cap, got %d", len(got))
	}
}

func TestCollectStablePairsLimitsTotalPerEntry(t *testing.T) {
	originalA := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
	}
	originalB := ddrd.MayUAFPair{
		FreeAccessName: 0x11,
		UseAccessName:  0x21,
		FreeCallStack:  0x31,
		UseCallStack:   0x41,
	}
	runtimeA := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x300,
		UseCallStack:   0x400,
	}
	runtimeB := ddrd.MayUAFPair{
		FreeAccessName: 0x11,
		UseAccessName:  0x21,
		FreeCallStack:  0x301,
		UseCallStack:   0x401,
	}
	latest := map[string]ddrd.MayUAFPair{
		pairKey(runtimeA): runtimeA,
		pairKey(runtimeB): runtimeB,
	}
	counts := map[string]int{
		pairKey(runtimeA): 1,
		pairKey(runtimeB): 1,
	}
	got := collectStablePairs(latest, counts, 1, []*ddrd.MayUAFPair{&originalA, &originalB}, false, OriginMatchModeVarName, 1, 1)
	if len(got) != 1 {
		t.Fatalf("expected one stable pair after per-entry cap, got %d", len(got))
	}
}

func TestCollectStablePairsEntryCapPrefersExactOriginalThenCount(t *testing.T) {
	original := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
		TimeDiff:       100_000,
	}
	exactRuntime := original
	exactRuntime.TimeDiff = 120_000
	driftRuntime := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x300,
		UseCallStack:   0x400,
		TimeDiff:       100_000,
	}
	latest := map[string]ddrd.MayUAFPair{
		pairKey(exactRuntime): exactRuntime,
		pairKey(driftRuntime): driftRuntime,
	}
	counts := map[string]int{
		pairKey(exactRuntime): 1,
		pairKey(driftRuntime): 99,
	}

	got := collectStablePairs(latest, counts, 1, []*ddrd.MayUAFPair{&original}, false, OriginMatchModeVarName, 1, 1)
	if len(got) != 1 {
		t.Fatalf("expected one stable pair after caps, got %d", len(got))
	}
	if got[0].FreeCallStack != original.FreeCallStack || got[0].UseCallStack != original.UseCallStack {
		t.Fatalf("expected exact original stack to win entry cap, got %+v", got[0])
	}
}

func TestCollectStablePairsEntryCapPrefersHigherRuntimeCount(t *testing.T) {
	original := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x30,
		UseCallStack:   0x40,
		TimeDiff:       100_000,
	}
	lowCount := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x300,
		UseCallStack:   0x400,
		TimeDiff:       110_000,
	}
	highCount := ddrd.MayUAFPair{
		FreeAccessName: 0x10,
		UseAccessName:  0x20,
		FreeCallStack:  0x301,
		UseCallStack:   0x401,
		TimeDiff:       150_000,
	}
	latest := map[string]ddrd.MayUAFPair{
		pairKey(lowCount):  lowCount,
		pairKey(highCount): highCount,
	}
	counts := map[string]int{
		pairKey(lowCount):  2,
		pairKey(highCount): 10,
	}

	got := collectStablePairs(latest, counts, 1, []*ddrd.MayUAFPair{&original}, false, OriginMatchModeVarName, 1, 1)
	if len(got) != 1 {
		t.Fatalf("expected one stable pair after caps, got %d", len(got))
	}
	if got[0].FreeCallStack != highCount.FreeCallStack || got[0].UseCallStack != highCount.UseCallStack {
		t.Fatalf("expected higher-count runtime pair to win entry cap, got %+v", got[0])
	}
}

func TestPrimaryOriginPairsUsesPairBasicInfo(t *testing.T) {
	entry := &fuzzer.UAFCorpusEntry{
		PairBasicInfo: ddrd.MayUAFPair{
			FreeAccessName: 0x10,
			UseAccessName:  0x20,
			FreeCallStack:  0x30,
			UseCallStack:   0x40,
		},
		Pairs: []*ddrd.MayUAFPair{
			{
				FreeAccessName: 0x99,
				UseAccessName:  0x88,
				FreeCallStack:  0x77,
				UseCallStack:   0x66,
			},
		},
	}
	got := primaryOriginPairs(entry)
	if len(got) != 1 {
		t.Fatalf("expected one primary origin pair, got %d", len(got))
	}
	if got[0].FreeAccessName != 0x10 || got[0].UseAccessName != 0x20 {
		t.Fatalf("unexpected primary origin pair: %+v", got[0])
	}
}

func TestBuildReplayRequestsCapsToLatestHistory(t *testing.T) {
	mgr := NewStageManager(Config{
		MaxConcurrent:    1,
		EnableReplay:     true,
		MaxReplayHistory: 2,
	}, nil)
	entry := &fuzzer.UAFCorpusEntry{
		ReplayHistory: []*fuzzer.BarrierExecutionRecord{
			{Programs: []*prog.Prog{{}}, GroupID: 1},
			{Programs: []*prog.Prog{{}}, GroupID: 2},
			{Programs: []*prog.Prog{{}}, GroupID: 3},
		},
	}
	reqs := mgr.buildReplayRequests(&validationTask{entry: entry})
	if len(reqs) != 2 {
		t.Fatalf("expected 2 replay requests, got %d", len(reqs))
	}
	if got := reqs[0].Entry.Barrier.GroupID; got != 2 {
		t.Fatalf("expected first replay group 2, got %d", got)
	}
	if got := reqs[1].Entry.Barrier.GroupID; got != 3 {
		t.Fatalf("expected second replay group 3, got %d", got)
	}
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
	if results[0].Success || !results[0].NoStablePairs {
		t.Fatalf("expected no-stable-pairs result, got success=%t no_stable=%t",
			results[0].Success, results[0].NoStablePairs)
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
	if results[0].Success || !results[0].NoStablePairs {
		t.Fatalf("expected final no-stable-pairs result, got success=%t no_stable=%t",
			results[0].Success, results[0].NoStablePairs)
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
	cfg := Config{MaxConcurrent: 1, RepeatCount: 3, TargetMatchMode: TargetMatchModeStrictSN}
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
