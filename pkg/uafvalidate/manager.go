package uafvalidate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/log"
)

type Executor interface {
	Run(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error)
}

type ExecutorFactory func(ctx context.Context) (Executor, error)

type ExecutionRequest struct {
	Entry         *fuzzer.UAFCorpusEntry
	Delays        []int64
	TargetPair    *ddrd.MayUAFPair
	RepeatTimes   int
	DisableDdrd   bool
	StopOnSuccess bool

	// Per-pair computed delays for verification phase
	// StartDelayUs: original delay - used for barrier start delay (nanosleep in executor), same as discovery phase
	// AccessDelayUs: max(original, runtime) - used for UAF access delay (udelay in kernel)
	StartDelayUs  int64
	AccessDelayUs int64
}

// StablePairWithDelays extends MayUAFPair with computed delay values for verification
type StablePairWithDelays struct {
	Pair          ddrd.MayUAFPair
	StartDelayUs  int64 // original TimeDiff in microseconds (same as discovery phase)
	AccessDelayUs int64 // max(original TimeDiff, runtime TimeDiff) in microseconds
}

type ExecutionResult struct {
	Output         []byte
	Duration       time.Duration
	Crashed        bool
	CrashTitle     string
	CrashReport    []byte
	Ddrd           *ddrd.Report
	TriggeredCount int
}

type ValidationResult struct {
	Entry       *fuzzer.UAFCorpusEntry
	Signature   fuzzer.UAFPairProfile
	Delays      []int64
	Duration    time.Duration
	Output      []byte
	Success     bool
	CrashTitle  string
	Err         error
	Attempt     int
	RepeatIndex int
	RepeatTotal int
	Pairs       []ddrd.MayUAFPair
	StablePairs []ddrd.MayUAFPair
}

type StageManager struct {
	cfg     Config
	delay   DelayManager
	factory ExecutorFactory
	stable  int

	tasks   chan *validationTask
	results chan *ValidationResult

	invalidDB *db.DB
	validDB   *db.DB

	// Layer 2: VarNamePair HB statistics store
	varNameHBDB    *db.DB
	varNameHBStore *VarNameHBStore

	mu          sync.Mutex
	pending     map[string]*validationTask
	seenKeys    map[string]struct{} // tracks all keys that have been enqueued (including completed)
	closed      bool
	seq         uint64
	tasksClosed bool

	closeOnce sync.Once
}

var zeroSignatureKey = SignatureKey(fuzzer.UAFPairProfile{})

const (
	crashLostConnection = "lost connection to test machine"
	crashTimedOut       = "timed out"
	maxCrashReportSize  = 64 << 10
	crashReportFallback = "no report captured"
)

type validationTask struct {
	entry          *fuzzer.UAFCorpusEntry
	signature      fuzzer.UAFPairProfile
	key            string
	attempts       int
	repeats        int
	pairLatest     map[string]ddrd.MayUAFPair // latest runtime pair (with runtime TimeDiff)
	pairCounts     map[string]int
	pairOriginalTD map[string]uint64 // original TimeDiff from entry.Pairs (nanoseconds)
}

func NewStageManager(cfg Config, factory ExecutorFactory) *StageManager {
	cfg = cfg.withDefaults()
	if factory == nil {
		factory = func(context.Context) (Executor, error) {
			return nil, fmt.Errorf("no executor factory configured")
		}
	}
	sm := &StageManager{
		cfg:      cfg,
		delay:    NewDelayManager(defaultMaxBarrierDelays, cfg.DelayRetryBudget),
		factory:  factory,
		tasks:    make(chan *validationTask, cfg.MaxConcurrent*2),
		results:  make(chan *ValidationResult, cfg.MaxConcurrent*2),
		pending:  make(map[string]*validationTask),
		seenKeys: make(map[string]struct{}),
		stable:   requiredStableCount(cfg.RepeatCount),
	}

	if cfg.Workdir != "" {
		// Layer 1: Exact match invalid DB
		dbPath := filepath.Join(cfg.Workdir, "invalid_uaf.db")
		d, err := db.Open(dbPath, true)
		if err != nil {
			log.Logf(0, "uafvalidate: failed to open invalid pair db: %v", err)
		} else {
			sm.invalidDB = d
			log.Logf(0, "uafvalidate: loaded %d invalid pairs from db", len(d.Records))
		}

		// Validated DB
		validPath := filepath.Join(cfg.Workdir, "validated_uaf.db")
		vd, err := db.Open(validPath, true)
		if err != nil {
			log.Logf(0, "uafvalidate: failed to open validated pair db: %v", err)
		} else {
			sm.validDB = vd
			log.Logf(0, "uafvalidate: loaded %d validated pairs from db", len(vd.Records))
		}

		// Layer 2: VarNamePair HB statistics DB
		hbPath := filepath.Join(cfg.Workdir, "varname_hb_stats.db")
		hbDB, err := db.Open(hbPath, true)
		if err != nil {
			log.Logf(0, "uafvalidate: failed to open varname HB stats db: %v", err)
		} else {
			sm.varNameHBDB = hbDB
			sm.varNameHBStore = NewVarNameHBStore(hbDB)
		}
	}

	return sm
}

func (sm *StageManager) Enqueue(entry *fuzzer.UAFCorpusEntry) {
	if entry == nil {
		return
	}
	task := sm.prepareTask(entry)
	if task == nil {
		return
	}
	sm.dispatch(task)
}

func (sm *StageManager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < sm.cfg.MaxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sm.worker(ctx)
		}()
	}
	wg.Wait()
	close(sm.results)
}

// Close signals that no more entries will be enqueued. Use Shutdown for immediate termination.
func (sm *StageManager) Close() {
	sm.closeOnce.Do(func() {
		sm.mu.Lock()
		sm.closed = true
		sm.maybeCloseTasksLocked()
		sm.mu.Unlock()
	})
}

// Shutdown forces immediate shutdown by closing the tasks channel.
func (sm *StageManager) Shutdown() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.closed = true
	if !sm.tasksClosed {
		close(sm.tasks)
		sm.tasksClosed = true
	}
}

// HasPending returns true if there are tasks currently being processed.
func (sm *StageManager) HasPending() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return len(sm.pending) > 0
}

// PendingCount returns the number of tasks currently being processed.
func (sm *StageManager) PendingCount() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return len(sm.pending)
}

// SeenCount returns the total number of entries that have been enqueued (including completed).
func (sm *StageManager) SeenCount() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return len(sm.seenKeys)
}

func (sm *StageManager) Results() <-chan *ValidationResult {
	return sm.results
}

func (sm *StageManager) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-sm.tasks:
			if !ok {
				return
			}
			sm.handleTask(ctx, task)
		}
	}
}

func (sm *StageManager) handleTask(ctx context.Context, task *validationTask) {
	if task == nil || task.entry == nil {
		return
	}
	for task.repeats < sm.cfg.RepeatCount {
		if ctx.Err() != nil {
			sm.complete(task)
			return
		}
		task.attempts++
		delays := sm.delay.BuildDelays(task.entry)
		log.Logf(0, "uafvalidate: task start key=%s attempt=%d repeat=%d/%d delays=%d", task.key, task.attempts, task.repeats+1, sm.cfg.RepeatCount, len(delays))
		result := &ValidationResult{
			Entry:     task.entry.Clone(),
			Signature: task.signature,
			Delays:    append([]int64(nil), delays...),
			Attempt:   task.attempts,
		}
		exec, err := sm.factory(ctx)
		if err != nil {
			result.Err = err
		} else {
			execRes, runErr := exec.Run(ctx, &ExecutionRequest{Entry: task.entry, Delays: delays})
			if closer, ok := exec.(interface{ Close() error }); ok {
				if cerr := closer.Close(); cerr != nil {
					log.Logf(0, "uafvalidate: executor close error key=%s err=%v", task.key, cerr)
				}
			}
			if runErr != nil {
				result.Err = runErr
			} else {
				result.Duration = execRes.Duration
				result.Output = append([]byte{}, execRes.Output...)
				result.Success = !execRes.Crashed
				result.CrashTitle = execRes.CrashTitle
				if execRes.Ddrd != nil {
					result.Pairs = clonePairs(execRes.Ddrd)
				}
			}
		}
		if err := ctx.Err(); err != nil || errors.Is(result.Err, context.Canceled) || errors.Is(result.Err, context.DeadlineExceeded) {
			reason := err
			if reason == nil {
				reason = result.Err
			}
			log.Logf(0, "uafvalidate: aborting key=%s repeat=%d/%d reason=%v", task.key, task.repeats+1, sm.cfg.RepeatCount, reason)
			sm.complete(task)
			return
		}
		if sm.shouldRetry(task, result) {
			log.Logf(0, "uafvalidate: retrying key=%s after attempt=%d repeat=%d/%d reason=%s", task.key, task.attempts, task.repeats+1, sm.cfg.RepeatCount, retryReason(result))
			continue
		}
		result.RepeatIndex = task.repeats
		result.RepeatTotal = sm.cfg.RepeatCount
		if result.Success {
			log.Logf(0, "uafvalidate: task success key=%s repeat=%d/%d pairs=%d", task.key, task.repeats+1, sm.cfg.RepeatCount, len(result.Pairs))
		} else if result.Err != nil {
			log.Logf(0, "uafvalidate: task error key=%s repeat=%d/%d err=%v", task.key, task.repeats+1, sm.cfg.RepeatCount, result.Err)
		} else {
			log.Logf(0, "uafvalidate: task crash key=%s repeat=%d/%d title=%s", task.key, task.repeats+1, sm.cfg.RepeatCount, result.CrashTitle)
		}
		sm.updateIntersection(task, result)
		if task.repeats+1 >= sm.cfg.RepeatCount {
			var originalPairs []*ddrd.MayUAFPair
			if task.entry != nil {
				originalPairs = task.entry.Pairs
			}
			result.StablePairs = collectStablePairs(task.pairLatest, task.pairCounts, sm.stable, originalPairs)
			if len(result.StablePairs) > 0 {
				// Compute stable pairs with per-pair delays (min/max of original vs runtime TimeDiff)
				stablePairsWithDelays := collectStablePairsWithDelays(
					task.pairLatest,
					task.pairCounts,
					task.pairOriginalTD,
					sm.stable,
					originalPairs,
				)
				sm.runVerificationPhaseWithDelays(ctx, task, stablePairsWithDelays)
			}
		}
		sm.results <- result
		task.repeats++
		task.attempts = 0
		if task.repeats < sm.cfg.RepeatCount {
			log.Logf(0, "uafvalidate: scheduling next repeat key=%s next=%d/%d", task.key, task.repeats+1, sm.cfg.RepeatCount)
		}
	}
	sm.complete(task)
}

func retryReason(res *ValidationResult) string {
	if res == nil {
		return "unknown"
	}
	if res.Err != nil {
		return res.Err.Error()
	}
	if res.CrashTitle != "" {
		return res.CrashTitle
	}
	return "unknown"
}

// entrySkipThreshold is the minimum skip probability for a pair to be considered "skippable"
const entrySkipThreshold = 0.8

// shouldSkipEntry checks if all pairs in the entry have high HB confidence
// and should be skipped entirely to avoid unnecessary execution
func (sm *StageManager) shouldSkipEntry(entry *fuzzer.UAFCorpusEntry) (skip bool, reason string) {
	if sm.varNameHBStore == nil {
		return false, ""
	}

	// Collect all pairs from entry
	var pairs []*ddrd.MayUAFPair
	for _, p := range entry.Pairs {
		if p != nil {
			pairs = append(pairs, p)
		}
	}

	// If no pairs in Pairs slice, check PairBasicInfo
	if len(pairs) == 0 {
		if entry.PairBasicInfo.FreeAccessName != 0 || entry.PairBasicInfo.UseAccessName != 0 {
			pairs = append(pairs, &entry.PairBasicInfo)
		}
	}

	if len(pairs) == 0 {
		return false, "" // No pairs, don't skip
	}

	// Check each pair's skip status
	skippedCount := 0
	verifiedCount := 0
	totalProb := 0.0
	validPairCount := 0

	for _, pair := range pairs {
		if pair == nil {
			continue
		}
		validPairCount++

		fullKey := pairKey(*pair)

		// Layer 1: Exact match skip (invalid or already validated)
		if sm.isInvalid(fullKey) || sm.isValidated(fullKey) {
			skippedCount++
			totalProb += 1.0
			continue
		}

		// Layer 2: Check if VarName pair is already verified (success)
		// Once a VarName pair is verified, ALL entries with that VarName should be skipped
		if sm.varNameHBStore.IsVerified(pair) {
			skippedCount++
			verifiedCount++
			totalProb += 1.0
			continue
		}

		// Layer 3: VarName HB probability check (for high-failure pairs)
		stats := sm.varNameHBStore.GetByPair(pair)
		prob := stats.SkipProbability()
		totalProb += prob

		// If probability is high enough, count as skippable
		if prob >= entrySkipThreshold {
			skippedCount++
		}
	}

	// If all pairs would be skipped, skip the entire entry
	if skippedCount == validPairCount && validPairCount > 0 {
		avgProb := totalProb / float64(validPairCount)
		if verifiedCount > 0 {
			return true, fmt.Sprintf("all %d pairs skipped (%d verified, avg_prob=%.2f)", validPairCount, verifiedCount, avgProb)
		}
		return true, fmt.Sprintf("all %d pairs high HB (avg_prob=%.2f)", validPairCount, avgProb)
	}

	return false, ""
}

func (sm *StageManager) prepareTask(entry *fuzzer.UAFCorpusEntry) *validationTask {
	clone := entry.Clone()
	if clone == nil {
		return nil
	}

	// If TargetVarNamePair is set, only process entries containing that pair
	if sm.cfg.TargetVarNamePair != "" {
		if !entryContainsTargetVarName(clone, sm.cfg.TargetVarNamePair) {
			return nil
		}
		log.Logf(0, "uafvalidate: [debug mode] entry matches target VarName pair %s", sm.cfg.TargetVarNamePair)
	}

	// Pre-check: if all pairs have high HB confidence, skip entire entry
	// Skip this check in debug mode (TargetVarNamePair is set)
	if sm.cfg.TargetVarNamePair == "" {
		if skip, reason := sm.shouldSkipEntry(clone); skip {
			log.Logf(0, "uafvalidate: skipping entry (all pairs high HB): %s", reason)
			return nil
		}
	}

	signature := clone.Profile
	if IsZeroSignature(signature) && clone.PairBasicInfo.UAFPairID() != 0 {
		signature = SignatureFromPair(&clone.PairBasicInfo)
	}
	key := ""
	if !IsZeroSignature(signature) {
		key = SignatureKey(signature)
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.closed {
		return nil
	}
	if key == "" || key == zeroSignatureKey {
		sm.seq++
		key = fmt.Sprintf("anon-%d", sm.seq)
	}
	// Skip if already seen (in pending or previously completed)
	if _, exists := sm.seenKeys[key]; exists {
		return nil
	}
	if _, exists := sm.pending[key]; exists {
		return nil
	}
	task := &validationTask{
		entry:     clone,
		signature: signature,
		key:       key,
	}
	// Pre-compute original TimeDiff for each pair from entry.Pairs
	if len(clone.Pairs) > 0 {
		task.pairOriginalTD = make(map[string]uint64, len(clone.Pairs))
		for _, pair := range clone.Pairs {
			if pair == nil {
				continue
			}
			k := pairKey(*pair)
			task.pairOriginalTD[k] = pair.TimeDiff
		}
	}
	sm.pending[key] = task
	sm.seenKeys[key] = struct{}{}
	return task
}

func (sm *StageManager) dispatch(task *validationTask) {
	if task == nil {
		return
	}
	sm.mu.Lock()
	if sm.tasksClosed {
		log.Logf(0, "uafvalidate: dispatch drop key=%s (tasks closed)", task.key)
		sm.mu.Unlock()
		return
	}
	tasksCh := sm.tasks
	sm.mu.Unlock()
	log.Logf(0, "uafvalidate: dispatch enqueue key=%s", task.key)
	select {
	case tasksCh <- task:
		log.Logf(0, "uafvalidate: dispatch immediate key=%s", task.key)
	default:
		log.Logf(0, "uafvalidate: dispatch blocking key=%s", task.key)
		tasksCh <- task
		log.Logf(0, "uafvalidate: dispatch resumed key=%s", task.key)
	}
}

func (sm *StageManager) complete(task *validationTask) {
	if task == nil {
		return
	}
	sm.mu.Lock()
	delete(sm.pending, task.key)
	log.Logf(0, "uafvalidate: complete key=%s pending=%d closed=%t tasksClosed=%t", task.key, len(sm.pending), sm.closed, sm.tasksClosed)
	sm.maybeCloseTasksLocked()
	sm.mu.Unlock()
}

func (sm *StageManager) maybeCloseTasksLocked() {
	if sm.closed && !sm.tasksClosed && len(sm.pending) == 0 {
		log.Logf(0, "uafvalidate: closing tasks channel")
		close(sm.tasks)
		sm.tasksClosed = true
	}
}

func (sm *StageManager) updateIntersection(task *validationTask, res *ValidationResult) {
	if task == nil || res == nil {
		return
	}
	if !res.Success {
		return
	}
	if task.pairLatest == nil {
		task.pairLatest = make(map[string]ddrd.MayUAFPair)
	}
	if task.pairCounts == nil {
		task.pairCounts = make(map[string]int)
	}
	seen := make(map[string]struct{}, len(res.Pairs))
	for _, pair := range res.Pairs {
		key := pairKey(pair)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		task.pairLatest[key] = pair
		task.pairCounts[key]++
	}
}

func clonePairs(report *ddrd.Report) []ddrd.MayUAFPair {
	if report == nil || len(report.UAFPairs) == 0 {
		return nil
	}
	cloned := make([]ddrd.MayUAFPair, 0, len(report.UAFPairs))
	for _, pair := range report.UAFPairs {
		if pair == nil {
			continue
		}
		cloned = append(cloned, *pair)
	}
	return cloned
}

func collectStablePairs(latest map[string]ddrd.MayUAFPair, counts map[string]int, minCount int, originalPairs []*ddrd.MayUAFPair) []ddrd.MayUAFPair {
	if len(latest) == 0 || len(counts) == 0 {
		return nil
	}
	if minCount <= 1 {
		minCount = 1
	}
	// Build a set of original pair keys for fast lookup
	originalKeys := make(map[string]struct{}, len(originalPairs))
	for _, pair := range originalPairs {
		if pair == nil {
			continue
		}
		originalKeys[pairKey(*pair)] = struct{}{}
	}
	keys := make([]string, 0, len(counts))
	for key, count := range counts {
		if count < minCount {
			continue
		}
		if _, ok := latest[key]; !ok {
			continue
		}
		// Additional condition: pair must exist in original corpus pairs
		if len(originalKeys) > 0 {
			if _, inOriginal := originalKeys[key]; !inOriginal {
				continue
			}
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	stable := make([]ddrd.MayUAFPair, 0, len(keys))
	for _, key := range keys {
		stable = append(stable, latest[key])
	}
	return stable
}

// collectStablePairsWithDelays returns stable pairs with computed delays:
// - StartDelayUs: original TimeDiff in microseconds (same as discovery phase)
// - AccessDelayUs: max(original TimeDiff, runtime TimeDiff) in microseconds
func collectStablePairsWithDelays(
	latest map[string]ddrd.MayUAFPair,
	counts map[string]int,
	originalTD map[string]uint64,
	minCount int,
	originalPairs []*ddrd.MayUAFPair,
) []StablePairWithDelays {
	if len(latest) == 0 || len(counts) == 0 {
		return nil
	}
	if minCount <= 1 {
		minCount = 1
	}
	// Build a set of original pair keys for fast lookup
	originalKeys := make(map[string]struct{}, len(originalPairs))
	for _, pair := range originalPairs {
		if pair == nil {
			continue
		}
		originalKeys[pairKey(*pair)] = struct{}{}
	}
	keys := make([]string, 0, len(counts))
	for key, count := range counts {
		if count < minCount {
			continue
		}
		if _, ok := latest[key]; !ok {
			continue
		}
		// Additional condition: pair must exist in original corpus pairs
		if len(originalKeys) > 0 {
			if _, inOriginal := originalKeys[key]; !inOriginal {
				continue
			}
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	result := make([]StablePairWithDelays, 0, len(keys))
	for _, key := range keys {
		pair := latest[key]
		runtimeTD := pair.TimeDiff // nanoseconds from runtime observation
		origTD := originalTD[key]  // nanoseconds from original corpus entry
		if origTD == 0 {
			origTD = runtimeTD // fallback if not recorded
		}

		// Compute max for access delay
		var maxTD uint64
		if runtimeTD > origTD {
			maxTD = runtimeTD
		} else {
			maxTD = origTD
		}

		// Convert to microseconds (TimeDiff is in nanoseconds)
		// StartDelayUs: use original delay (same as discovery phase)
		// AccessDelayUs: use max(original, runtime) for kernel udelay
		startDelayUs := int64(origTD / 1000)
		accessDelayUs := int64(maxTD / 1000)

		result = append(result, StablePairWithDelays{
			Pair:          pair,
			StartDelayUs:  startDelayUs,
			AccessDelayUs: accessDelayUs,
		})
	}
	return result
}

func pairKey(pair ddrd.MayUAFPair) string {
	return fmt.Sprintf("%016x-%016x-%016x-%016x",
		pair.FreeAccessName,
		pair.UseAccessName,
		pair.FreeCallStack,
		pair.UseCallStack,
	)
}

// entryContainsTargetVarName checks if any pair in the entry matches the target VarName pair.
// targetVarNamePair format: "freeAccessName-useAccessName" (hex without 0x prefix)
func entryContainsTargetVarName(entry *fuzzer.UAFCorpusEntry, targetVarNamePair string) bool {
	if entry == nil || targetVarNamePair == "" {
		return false
	}
	for _, pair := range entry.Pairs {
		if pair == nil {
			continue
		}
		vnKey := VarNamePairKey(pair)
		if vnKey == targetVarNamePair {
			return true
		}
	}
	return false
}

// pairMatchesTargetVarName checks if a pair matches the target VarName pair.
func pairMatchesTargetVarName(pair *ddrd.MayUAFPair, targetVarNamePair string) bool {
	if pair == nil || targetVarNamePair == "" {
		return false
	}
	return VarNamePairKey(pair) == targetVarNamePair
}

func (sm *StageManager) shouldRetry(task *validationTask, res *ValidationResult) bool {
	if task == nil || res == nil {
		return false
	}
	if task.attempts >= sm.cfg.DelayRetryBudget {
		return false
	}
	if res.Err != nil {
		return true
	}
	switch res.CrashTitle {
	case crashLostConnection, crashTimedOut:
		return true
	default:
		return false
	}
}

func requiredStableCount(repeat int) int {
	if repeat <= 1 {
		return 1
	}
	return repeat/2 + 1
}

func (sm *StageManager) runVerificationPhase(ctx context.Context, task *validationTask, stablePairs []ddrd.MayUAFPair) {
	log.Logf(0, "uafvalidate: starting verification phase for key=%s pairs=%d", task.key, len(stablePairs))

	for i, pair := range stablePairs {
		if ctx.Err() != nil {
			return
		}

		fullKey := pairKey(pair)       // Full key (with CallStack)
		vnKey := VarNamePairKey(&pair) // VarName key (without CallStack)

		// ========== Layer 1: Exact match skip ==========
		if sm.isInvalid(fullKey) {
			log.Logf(0, "uafvalidate: L1 skip (exact) pair %d/%d key=%s", i+1, len(stablePairs), task.key)
			continue
		}

		if sm.isValidated(fullKey) {
			log.Logf(0, "uafvalidate: skipping validated pair %d/%d for key=%s", i+1, len(stablePairs), task.key)
			continue
		}

		// ========== Layer 2: VarName probabilistic skip ==========
		if sm.varNameHBStore != nil {
			skip, prob, stats := sm.varNameHBStore.ShouldSkip(&pair, rand.Float64)
			if skip {
				log.Logf(0, "uafvalidate: L2 skip (HB prob) pair %d/%d vnkey=%s conf=%.2f prob=%.2f failures=%d successes=%d",
					i+1, len(stablePairs), vnKey, stats.HBConfidence(), prob, stats.Failures, stats.Successes)
				continue
			}
			if prob > 0 {
				log.Logf(1, "uafvalidate: L2 pass (HB prob) pair %d/%d vnkey=%s conf=%.2f prob=%.2f",
					i+1, len(stablePairs), vnKey, stats.HBConfidence(), prob)
			}
		}

		// ========== Execute verification ==========
		log.Logf(0, "uafvalidate: verifying pair %d/%d for key=%s", i+1, len(stablePairs), task.key)

		pairCopy := pair
		exec, err := sm.factory(ctx)
		if err != nil {
			log.Logf(0, "uafvalidate: failed to create executor for verification: %v", err)
			continue
		}

		req := &ExecutionRequest{
			Entry:         task.entry,
			Delays:        sm.delay.BuildDelays(task.entry),
			TargetPair:    &pairCopy,
			RepeatTimes:   sm.cfg.VerifyRepeatTimes,
			DisableDdrd:   true,
			StopOnSuccess: true,
		}

		execRes, runErr := exec.Run(ctx, req)
		if closer, ok := exec.(interface{ Close() error }); ok {
			closer.Close()
		}

		// Extract crash info
		crashInfo := ""
		if execRes != nil && execRes.Crashed && execRes.CrashTitle != "" {
			crashInfo = fmt.Sprintf(" crash=%q", execRes.CrashTitle)
		}

		if runErr != nil {
			// Log run error with any available crash info
			if crashInfo != "" {
				log.Logf(0, "uafvalidate: verification run failed: %v%s", runErr, crashInfo)
			} else {
				log.Logf(0, "uafvalidate: verification run failed: %v", runErr)
			}
			if execRes != nil && execRes.Crashed && execRes.CrashTitle != "" {
				log.Logf(0, "uafvalidate: crash detected during failed run: %s", execRes.CrashTitle)
				if len(execRes.CrashReport) > 0 {
					reportPreview := string(execRes.CrashReport)
					if len(reportPreview) > 500 {
						reportPreview = reportPreview[:500] + "..."
					}
					log.Logf(0, "uafvalidate: crash report preview:\n%s", reportPreview)
				}
			}
			continue // Execution error, don't update statistics
		}

		// ========== Update statistics ==========
		status := "Not Triggerable"
		if execRes.TriggeredCount >= 2 {
			status = "Stable"
		} else if execRes.TriggeredCount > 0 {
			status = "Not Stable"
		}

		log.Logf(0, "uafvalidate: verification run finished duration=%s crashed=%t%s triggered=%d/%d status=%s",
			execRes.Duration, execRes.Crashed, crashInfo, execRes.TriggeredCount, req.RepeatTimes, status)

		if execRes.TriggeredCount > 0 {
			// ========== Success: proves not HB relationship ==========
			// Serialize the validated entry including triggering programs
			reportData := serializeValidatedEntry(execRes, task.entry)
			sm.markValidated(fullKey, reportData)

			// Update VarName HB statistics (success) and mark as verified
			// This will cause ALL future entries with the same VarName pair to be skipped
			if sm.varNameHBStore != nil {
				sm.varNameHBStore.RecordSuccessWithKey(&pairCopy, task.key)
				stats := sm.varNameHBStore.GetByPair(&pairCopy)
				log.Logf(0, "uafvalidate: pair validated, HB conf updated: vnkey=%s new_conf=%.2f verified=%t",
					vnKey, stats.HBConfidence(), stats.IsVerified())
			}

			// Log a summary (not full data to avoid log flooding)
			reportPreview := string(reportData)
			if len(reportPreview) > 2000 {
				reportPreview = reportPreview[:2000] + "...[truncated]"
			}
			log.Logf(0, "uafvalidate: pair validated after %d attempt(s)\n%s", execRes.TriggeredCount, reportPreview)
			continue
		}

		// ========== Failure: increase HB confidence ==========
		// Layer 1: Mark this exact pair as invalid
		sm.markInvalid(fullKey)

		// Layer 2: Update VarName HB statistics (failure)
		if sm.varNameHBStore != nil {
			sm.varNameHBStore.RecordFailure(&pairCopy)
			stats := sm.varNameHBStore.GetByPair(&pairCopy)
			log.Logf(0, "uafvalidate: pair failed verification, HB conf updated: vnkey=%s new_conf=%.2f skip_prob=%.2f",
				vnKey, stats.HBConfidence(), stats.SkipProbability())
		}
	}

	// Output statistics summary
	if sm.varNameHBStore != nil {
		total, highConf, verified := sm.varNameHBStore.Stats()
		log.Logf(0, "uafvalidate: verification phase complete, VarName HB stats: total=%d high_confidence=%d verified=%d", total, highConf, verified)
	}
}

// runVerificationPhaseWithDelays runs verification using per-pair computed delays:
// - StartDelayUs (original delay, same as discovery) for barrier start delay
// - AccessDelayUs (max of original/runtime) for kernel UAF access delay
func (sm *StageManager) runVerificationPhaseWithDelays(ctx context.Context, task *validationTask, stablePairs []StablePairWithDelays) {
	debugMode := sm.cfg.TargetVarNamePair != ""
	if debugMode {
		log.Logf(0, "uafvalidate: [debug mode] starting verification phase for key=%s pairs=%d target=%s",
			task.key, len(stablePairs), sm.cfg.TargetVarNamePair)
	} else {
		log.Logf(0, "uafvalidate: starting verification phase (with delays) for key=%s pairs=%d", task.key, len(stablePairs))
	}

	for i, spd := range stablePairs {
		if ctx.Err() != nil {
			return
		}

		pair := spd.Pair
		fullKey := pairKey(pair)       // Full key (with CallStack)
		vnKey := VarNamePairKey(&pair) // VarName key (without CallStack)

		// In debug mode, only verify pairs matching the target VarName
		if debugMode {
			if !pairMatchesTargetVarName(&pair, sm.cfg.TargetVarNamePair) {
				log.Logf(1, "uafvalidate: [debug mode] skipping non-target pair %d/%d vnkey=%s", i+1, len(stablePairs), vnKey)
				continue
			}
			log.Logf(0, "uafvalidate: [debug mode] verifying target pair %d/%d vnkey=%s fullkey=%s",
				i+1, len(stablePairs), vnKey, fullKey)
		} else {
			// ========== Normal mode: Layer 1 & 2 skip checks ==========
			// ========== Layer 1: Exact match skip ==========
			if sm.isInvalid(fullKey) {
				log.Logf(0, "uafvalidate: L1 skip (exact) pair %d/%d key=%s", i+1, len(stablePairs), task.key)
				continue
			}

			if sm.isValidated(fullKey) {
				log.Logf(0, "uafvalidate: skipping validated pair %d/%d for key=%s", i+1, len(stablePairs), task.key)
				continue
			}

			// ========== Layer 2: VarName probabilistic skip ==========
			if sm.varNameHBStore != nil {
				skip, prob, stats := sm.varNameHBStore.ShouldSkip(&pair, rand.Float64)
				if skip {
					log.Logf(0, "uafvalidate: L2 skip (HB prob) pair %d/%d vnkey=%s conf=%.2f prob=%.2f failures=%d successes=%d",
						i+1, len(stablePairs), vnKey, stats.HBConfidence(), prob, stats.Failures, stats.Successes)
					continue
				}
				if prob > 0 {
					log.Logf(1, "uafvalidate: L2 pass (HB prob) pair %d/%d vnkey=%s conf=%.2f prob=%.2f",
						i+1, len(stablePairs), vnKey, stats.HBConfidence(), prob)
				}
			}
		}

		// ========== Execute verification ==========
		log.Logf(0, "uafvalidate: verifying pair %d/%d for key=%s start_delay=%dus access_delay=%dus",
			i+1, len(stablePairs), task.key, spd.StartDelayUs, spd.AccessDelayUs)

		// Create a copy of the pair with AccessDelayUs as TimeDiff (for kernel udelay)
		pairCopy := pair
		pairCopy.TimeDiff = uint64(spd.AccessDelayUs) * 1000 // Convert to nanoseconds for ukcDelayMicros

		exec, err := sm.factory(ctx)
		if err != nil {
			log.Logf(0, "uafvalidate: failed to create executor for verification: %v", err)
			continue
		}

		// Build start delays array using spd.StartDelayUs for the first participant
		startDelays := buildStartDelaysFromPair(task.entry, spd.StartDelayUs)

		req := &ExecutionRequest{
			Entry:         task.entry,
			Delays:        startDelays,
			TargetPair:    &pairCopy,
			RepeatTimes:   sm.cfg.VerifyRepeatTimes,
			DisableDdrd:   true,
			StopOnSuccess: true,
			StartDelayUs:  spd.StartDelayUs,
			AccessDelayUs: spd.AccessDelayUs,
		}

		execRes, runErr := exec.Run(ctx, req)
		if closer, ok := exec.(interface{ Close() error }); ok {
			closer.Close()
		}

		// Extract crash info
		crashInfo := ""
		if execRes != nil && execRes.Crashed && execRes.CrashTitle != "" {
			crashInfo = fmt.Sprintf(" crash=%q", execRes.CrashTitle)
		}

		if runErr != nil {
			// Log run error with any available crash info
			if crashInfo != "" {
				log.Logf(0, "uafvalidate: verification run failed: %v%s", runErr, crashInfo)
			} else {
				log.Logf(0, "uafvalidate: verification run failed: %v", runErr)
			}
			if execRes != nil && execRes.Crashed && execRes.CrashTitle != "" {
				log.Logf(0, "uafvalidate: crash detected during failed run: %s", execRes.CrashTitle)
				if len(execRes.CrashReport) > 0 {
					reportPreview := string(execRes.CrashReport)
					if len(reportPreview) > 500 {
						reportPreview = reportPreview[:500] + "..."
					}
					log.Logf(0, "uafvalidate: crash report preview:\n%s", reportPreview)
				}
			}
			continue // Execution error, don't update statistics
		}

		// ========== Update statistics ==========
		status := "Not Triggerable"
		if execRes.TriggeredCount >= 2 {
			status = "Stable"
		} else if execRes.TriggeredCount > 0 {
			status = "Not Stable"
		}

		log.Logf(0, "uafvalidate: verification run finished duration=%s crashed=%t%s triggered=%d/%d status=%s",
			execRes.Duration, execRes.Crashed, crashInfo, execRes.TriggeredCount, req.RepeatTimes, status)

		if execRes.TriggeredCount > 0 {
			// ========== Success: proves not HB relationship ==========
			// Serialize the validated entry including triggering programs
			reportData := serializeValidatedEntry(execRes, task.entry)

			// In debug mode, only log but don't update databases
			if debugMode {
				log.Logf(0, "uafvalidate: [debug mode] SUCCESS vnkey=%s triggered=%d/%d (not updating databases)",
					vnKey, execRes.TriggeredCount, req.RepeatTimes)
				reportPreview := string(reportData)
				if len(reportPreview) > 2000 {
					reportPreview = reportPreview[:2000] + "...[truncated]"
				}
				log.Logf(0, "uafvalidate: [debug mode] report:\n%s", reportPreview)
				continue
			}

			sm.markValidated(fullKey, reportData)

			// Update VarName HB statistics (success) and mark as verified
			// This will cause ALL future entries with the same VarName pair to be skipped
			if sm.varNameHBStore != nil {
				sm.varNameHBStore.RecordSuccessWithKey(&pair, task.key)
				stats := sm.varNameHBStore.GetByPair(&pair)
				log.Logf(0, "uafvalidate: pair validated, HB conf updated: vnkey=%s new_conf=%.2f verified=%t",
					vnKey, stats.HBConfidence(), stats.IsVerified())
			}

			// Log a summary (not full data to avoid log flooding)
			reportPreview := string(reportData)
			if len(reportPreview) > 2000 {
				reportPreview = reportPreview[:2000] + "...[truncated]"
			}
			log.Logf(0, "uafvalidate: pair validated after %d attempt(s)\n%s", execRes.TriggeredCount, reportPreview)
			continue
		}

		// ========== Failure: increase HB confidence ==========
		// In debug mode, only log but don't update databases
		if debugMode {
			log.Logf(0, "uafvalidate: [debug mode] FAILED vnkey=%s triggered=0/%d (not updating databases)",
				vnKey, req.RepeatTimes)
			continue
		}

		// Layer 1: Mark this exact pair as invalid
		sm.markInvalid(fullKey)

		// Layer 2: Update VarName HB statistics (failure)
		if sm.varNameHBStore != nil {
			sm.varNameHBStore.RecordFailure(&pair)
			stats := sm.varNameHBStore.GetByPair(&pair)
			log.Logf(0, "uafvalidate: pair failed verification, HB conf updated: vnkey=%s new_conf=%.2f skip_prob=%.2f",
				vnKey, stats.HBConfidence(), stats.SkipProbability())
		}
	}

	// Output statistics summary
	if sm.varNameHBStore != nil {
		total, highConf, verified := sm.varNameHBStore.Stats()
		log.Logf(0, "uafvalidate: verification phase (with delays) complete, VarName HB stats: total=%d high_confidence=%d verified=%d", total, highConf, verified)
	}
}

// buildStartDelaysFromPair builds barrier start delays array using the given start delay for proc 0
func buildStartDelaysFromPair(entry *fuzzer.UAFCorpusEntry, startDelayUs int64) []int64 {
	if entry == nil {
		return nil
	}
	participants := len(entry.ReplayPlan.DelaysMicros)
	if participants == 0 && entry.Barrier.GroupSize > 0 {
		participants = entry.Barrier.GroupSize
	}
	if participants < 2 {
		return nil
	}
	if participants > defaultMaxBarrierDelays {
		participants = defaultMaxBarrierDelays
	}
	delays := make([]int64, participants)
	delays[0] = startDelayUs
	return delays
}

func (sm *StageManager) isInvalid(key string) bool {
	if sm.invalidDB == nil {
		return false
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	_, ok := sm.invalidDB.Records[key]
	return ok
}

func (sm *StageManager) markInvalid(key string) {
	if sm.invalidDB == nil {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.invalidDB.Save(key, []byte{}, 0)
	if err := sm.invalidDB.Flush(); err != nil {
		log.Logf(0, "uafvalidate: failed to flush invalid db: %v", err)
	}
}

func (sm *StageManager) isValidated(key string) bool {
	if sm.validDB == nil {
		return false
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	_, ok := sm.validDB.Records[key]
	return ok
}

func (sm *StageManager) markValidated(key string, data []byte) {
	if sm.validDB == nil {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.validDB.Save(key, data, 0)
	if err := sm.validDB.Flush(); err != nil {
		log.Logf(0, "uafvalidate: failed to flush validated db: %v", err)
	}
}

func serializeCrashReport(res *ExecutionResult) []byte {
	if res == nil {
		return []byte(crashReportFallback)
	}
	data := res.CrashReport
	if len(data) == 0 {
		data = res.Output
	}
	if len(data) == 0 {
		return []byte(crashReportFallback)
	}
	if len(data) > maxCrashReportSize {
		data = data[:maxCrashReportSize]
	}
	return append([]byte{}, data...)
}

// serializeValidatedEntry serializes the validated entry including the triggering programs.
// Format:
//
//	=== CRASH REPORT ===
//	<crash report content>
//	=== TRIGGERING PROGRAMS ===
//	--- PROGRAM 0 ---
//	<program 0 source>
//	--- PROGRAM 1 ---
//	<program 1 source>
//	...
//	=== BARRIER INFO ===
//	Participants: <mask>
//	GroupID: <id>
//	GroupSize: <size>
//	=== REPLAY PLAN ===
//	Delays: <delays>
func serializeValidatedEntry(res *ExecutionResult, entry *fuzzer.UAFCorpusEntry) []byte {
	var buf bytes.Buffer

	// Section 1: Crash Report
	buf.WriteString("=== CRASH REPORT ===\n")
	reportData := serializeCrashReport(res)
	buf.Write(reportData)
	buf.WriteString("\n")

	if entry == nil {
		return buf.Bytes()
	}

	// Section 2: Triggering Programs
	buf.WriteString("\n=== TRIGGERING PROGRAMS ===\n")
	if len(entry.Programs) > 0 {
		for i, p := range entry.Programs {
			buf.WriteString(fmt.Sprintf("--- PROGRAM %d ---\n", i))
			if p != nil {
				buf.Write(p.Serialize())
			} else {
				buf.WriteString("<nil>\n")
			}
			buf.WriteString("\n")
		}
	} else if entry.Prog != nil {
		// Fallback to single Prog if Programs is empty
		buf.WriteString("--- PROGRAM 0 ---\n")
		buf.Write(entry.Prog.Serialize())
		buf.WriteString("\n")
	} else {
		buf.WriteString("<no programs>\n")
	}

	// Section 3: Barrier Info
	buf.WriteString("\n=== BARRIER INFO ===\n")
	buf.WriteString(fmt.Sprintf("Participants: 0x%x\n", entry.Barrier.Participants))
	buf.WriteString(fmt.Sprintf("GroupID: %d\n", entry.Barrier.GroupID))
	buf.WriteString(fmt.Sprintf("GroupSize: %d\n", entry.Barrier.GroupSize))
	if len(entry.Barrier.ProcList) > 0 {
		buf.WriteString(fmt.Sprintf("ProcList: %v\n", entry.Barrier.ProcList))
	}

	// Section 4: Replay Plan (delays)
	buf.WriteString("\n=== REPLAY PLAN ===\n")
	if len(entry.ReplayPlan.DelaysMicros) > 0 {
		buf.WriteString(fmt.Sprintf("Delays: %v\n", entry.ReplayPlan.DelaysMicros))
	} else {
		buf.WriteString("Delays: <none>\n")
	}

	// Truncate if too large
	result := buf.Bytes()
	if len(result) > maxCrashReportSize*2 {
		result = result[:maxCrashReportSize*2]
	}
	return result
}
