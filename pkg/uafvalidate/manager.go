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
	Entry               *fuzzer.UAFCorpusEntry
	Delays              []int64
	TargetPair          *ddrd.MayUAFPair
	RepeatTimes         int
	DisableDdrd         bool
	StopOnSuccess       bool
	RaceTimeThresholdNs uint64 // Adaptive race detection threshold in nanoseconds
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

	// Threshold controller for adaptive race detection
	thresholdCtrl *ddrd.ThresholdController

	// Corpus-level validation statistics
	processedCorpus uint64 // Number of corpus entries that have completed validation (regardless of result)
	recentProcessed uint64 // Recently processed corpus entries (for threshold calculation)
	lastStatsUpdate time.Time

	// Dirty flags for deferred flush (reduce IO frequency)
	invalidDirty bool
	validDirty   bool
	lastFlush    time.Time

	mu           sync.Mutex
	pending      map[string]*validationTask
	seenKeys     map[string]struct{} // tracks all keys that have been enqueued (including completed)
	processedDB  *db.DB              // persists processed corpus keys (to avoid re-validation after restart)
	processedSet map[string]struct{} // in-memory cache of processed keys
	closed       bool
	seq          uint64
	tasksClosed  bool

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
	entry      *fuzzer.UAFCorpusEntry
	signature  fuzzer.UAFPairProfile
	key        string
	attempts   int
	repeats    int
	pairLatest map[string]ddrd.MayUAFPair
	pairCounts map[string]int
}

func NewStageManager(cfg Config, factory ExecutorFactory) *StageManager {
	cfg = cfg.withDefaults()
	if factory == nil {
		factory = func(context.Context) (Executor, error) {
			return nil, fmt.Errorf("no executor factory configured")
		}
	}
	sm := &StageManager{
		cfg:             cfg,
		delay:           NewDelayManager(defaultMaxBarrierDelays, cfg.DelayRetryBudget),
		factory:         factory,
		tasks:           make(chan *validationTask, cfg.MaxConcurrent*2),
		results:         make(chan *ValidationResult, cfg.MaxConcurrent*2),
		pending:         make(map[string]*validationTask),
		seenKeys:        make(map[string]struct{}),
		processedSet:    make(map[string]struct{}),
		stable:          requiredStableCount(cfg.RepeatCount),
		lastStatsUpdate: time.Now(),
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

		// Processed corpus DB - tracks all corpus entries that have been validated (regardless of result)
		processedPath := filepath.Join(cfg.Workdir, "processed_corpus.db")
		pdb, err := db.Open(processedPath, true)
		if err != nil {
			log.Logf(0, "uafvalidate: failed to open processed corpus db: %v", err)
		} else {
			sm.processedDB = pdb
			// Load existing processed keys into memory
			for key := range pdb.Records {
				sm.processedSet[key] = struct{}{}
			}
			sm.processedCorpus = uint64(len(sm.processedSet))
			log.Logf(0, "uafvalidate: loaded %d processed corpus entries from db", len(pdb.Records))
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

		// Use shared threshold controller if provided, otherwise create a new one
		if cfg.ThresholdCtrl != nil {
			sm.thresholdCtrl = cfg.ThresholdCtrl
			log.Logf(0, "uafvalidate: using shared threshold controller, current threshold: %d ns",
				sm.thresholdCtrl.CurrentThreshold())
		} else {
			thresholdPath := filepath.Join(cfg.Workdir, "threshold_config.json")
			sm.thresholdCtrl = ddrd.NewThresholdController(thresholdPath)
			log.Logf(0, "uafvalidate: created new threshold controller, current threshold: %d ns",
				sm.thresholdCtrl.CurrentThreshold())
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
			// During stable pair collection phase (before verification),
			// use maximum threshold to capture all potential UAF pairs
			execRes, runErr := exec.Run(ctx, &ExecutionRequest{
				Entry:               task.entry,
				Delays:              delays,
				RaceTimeThresholdNs: ddrd.MaxThresholdNs,
			})
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
			result.StablePairs = collectStablePairs(task.pairLatest, task.pairCounts, sm.stable, task.entry.Pairs)
			if len(result.StablePairs) > 0 {
				sm.runVerificationPhase(ctx, task, result.StablePairs)
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

		// Layer 2: VarName HB probability check
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
		return true, fmt.Sprintf("all %d pairs high HB (avg_prob=%.2f)", validPairCount, avgProb)
	}

	return false, ""
}

func (sm *StageManager) prepareTask(entry *fuzzer.UAFCorpusEntry) *validationTask {
	clone := entry.Clone()
	if clone == nil {
		return nil
	}

	// Pre-check: if all pairs have high HB confidence, skip entire entry
	if skip, reason := sm.shouldSkipEntry(clone); skip {
		log.Logf(0, "uafvalidate: skipping entry (all pairs high HB): %s", reason)
		return nil
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
	// Skip if already processed (validated in previous session)
	if _, processed := sm.processedSet[key]; processed {
		return nil
	}
	// Skip if already seen (in pending or previously completed in this session)
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
	// Mark corpus as processed (regardless of validation result)
	sm.markProcessedLocked(task.key)
	// Flush databases when completing a task to ensure data is persisted
	sm.maybeFlushLocked()
	log.Logf(0, "uafvalidate: complete key=%s pending=%d closed=%t tasksClosed=%t processed=%d",
		task.key, len(sm.pending), sm.closed, sm.tasksClosed, sm.processedCorpus)
	sm.maybeCloseTasksLocked()
	sm.mu.Unlock()
}

// markProcessedLocked marks a corpus key as processed and persists to DB.
// Must be called with sm.mu held.
func (sm *StageManager) markProcessedLocked(key string) {
	if _, exists := sm.processedSet[key]; exists {
		return
	}
	sm.processedSet[key] = struct{}{}
	sm.processedCorpus++
	sm.recentProcessed++
	if sm.processedDB != nil {
		sm.processedDB.Save(key, []byte{}, 0)
	}
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

// collectStablePairs filters pairs that:
// 1. Appeared at least minCount times in the repeated executions
// 2. Also exist in the original entry's pairs (originalPairs)
// This ensures we only verify pairs that were in the original corpus entry.
// For each stable pair, the TimeDiff is set to max(original TimeDiff, stable run TimeDiff).
func collectStablePairs(latest map[string]ddrd.MayUAFPair, counts map[string]int, minCount int, originalPairs []*ddrd.MayUAFPair) []ddrd.MayUAFPair {
	if len(latest) == 0 || len(counts) == 0 {
		return nil
	}
	if minCount <= 1 {
		minCount = 1
	}

	// Build a map from key to original pair (to access original TimeDiff)
	originalByKey := make(map[string]*ddrd.MayUAFPair, len(originalPairs))
	for _, p := range originalPairs {
		if p == nil {
			continue
		}
		originalByKey[pairKey(*p)] = p
	}

	keys := make([]string, 0, len(counts))
	for key, count := range counts {
		if count < minCount {
			continue
		}
		if _, ok := latest[key]; !ok {
			continue
		}
		// Only include pairs that exist in the original entry
		if _, inOriginal := originalByKey[key]; !inOriginal {
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	stable := make([]ddrd.MayUAFPair, 0, len(keys))
	for _, key := range keys {
		pair := latest[key]
		// Use max TimeDiff between original and stable run
		if origPair, ok := originalByKey[key]; ok && origPair != nil {
			if origPair.TimeDiff > pair.TimeDiff {
				pair.TimeDiff = origPair.TimeDiff
			}
		}
		stable = append(stable, pair)
	}
	return stable
}

func pairKey(pair ddrd.MayUAFPair) string {
	return fmt.Sprintf("%016x-%016x-%016x-%016x",
		pair.FreeAccessName,
		pair.UseAccessName,
		pair.FreeCallStack,
		pair.UseCallStack,
	)
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
			Entry:               task.entry,
			Delays:              sm.delay.BuildDelays(task.entry),
			TargetPair:          &pairCopy,
			RepeatTimes:         10,
			DisableDdrd:         true,
			StopOnSuccess:       true,
			RaceTimeThresholdNs: sm.CurrentThreshold(),
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

			// Update VarName HB statistics (success)
			if sm.varNameHBStore != nil {
				sm.varNameHBStore.RecordSuccess(&pairCopy)
				stats := sm.varNameHBStore.GetByPair(&pairCopy)
				log.Logf(0, "uafvalidate: pair validated, HB conf updated: vnkey=%s new_conf=%.2f",
					vnKey, stats.HBConfidence())
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
		total, highConf := sm.varNameHBStore.Stats()
		log.Logf(0, "uafvalidate: verification phase complete, VarName HB stats: total=%d high_confidence=%d", total, highConf)
	}
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

// flushInterval is the minimum time between database flushes
const flushInterval = 5 * time.Second

func (sm *StageManager) markInvalid(key string) {
	if sm.invalidDB == nil {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.invalidDB.Save(key, []byte{}, 0)
	sm.invalidDirty = true
	sm.maybeFlushLocked()
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
	sm.validDirty = true
	sm.maybeFlushLocked()
}

// maybeFlushLocked flushes dirty databases if enough time has passed since last flush.
// Must be called with sm.mu held.
func (sm *StageManager) maybeFlushLocked() {
	now := time.Now()
	if now.Sub(sm.lastFlush) < flushInterval {
		return
	}
	sm.lastFlush = now
	if sm.invalidDirty && sm.invalidDB != nil {
		if err := sm.invalidDB.Flush(); err != nil {
			log.Logf(0, "uafvalidate: failed to flush invalid db: %v", err)
		}
		sm.invalidDirty = false
	}
	if sm.validDirty && sm.validDB != nil {
		if err := sm.validDB.Flush(); err != nil {
			log.Logf(0, "uafvalidate: failed to flush validated db: %v", err)
		}
		sm.validDirty = false
	}
	if sm.processedDB != nil {
		if err := sm.processedDB.Flush(); err != nil {
			log.Logf(0, "uafvalidate: failed to flush processed db: %v", err)
		}
	}
}

// FlushDBs forces a flush of all dirty databases.
func (sm *StageManager) FlushDBs() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.invalidDirty && sm.invalidDB != nil {
		if err := sm.invalidDB.Flush(); err != nil {
			log.Logf(0, "uafvalidate: failed to flush invalid db: %v", err)
		}
		sm.invalidDirty = false
	}
	if sm.validDirty && sm.validDB != nil {
		if err := sm.validDB.Flush(); err != nil {
			log.Logf(0, "uafvalidate: failed to flush validated db: %v", err)
		}
		sm.validDirty = false
	}
	if sm.processedDB != nil {
		if err := sm.processedDB.Flush(); err != nil {
			log.Logf(0, "uafvalidate: failed to flush processed db: %v", err)
		}
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

// UpdateThresholdStats updates the threshold controller with current corpus-level statistics.
// Should be called periodically (e.g., every few minutes).
// Parameters:
//   - recentCollected: number of new corpus entries collected since last update (tracked, not used in adjustment)
//   - totalCorpus: total number of corpus entries in the UAF store
func (sm *StageManager) UpdateThresholdStats(recentCollected, totalCorpus uint64) {
	if sm.thresholdCtrl == nil {
		return
	}

	sm.mu.Lock()
	// Get processed corpus count and recent processed since last update
	verifiedCorpus := sm.processedCorpus
	recentVerified := sm.recentProcessed
	sm.recentProcessed = 0 // Reset for next interval
	sm.mu.Unlock()

	// Update threshold controller with corpus-level stats
	sm.thresholdCtrl.UpdateStats(totalCorpus, verifiedCorpus, recentCollected, recentVerified)

	log.Logf(3, "uafvalidate: threshold updated - corpus(total:%d,verified:%d) threshold:%d ns",
		totalCorpus, verifiedCorpus, sm.thresholdCtrl.CurrentThreshold())
}

// CurrentThreshold returns the current race time threshold in nanoseconds.
// Returns the default threshold if controller is not initialized.
func (sm *StageManager) CurrentThreshold() uint64 {
	if sm.thresholdCtrl == nil {
		return ddrd.DefaultThresholdNs
	}
	return sm.thresholdCtrl.CurrentThreshold()
}

// GetVerificationStats returns the current verification statistics at corpus level.
// Returns:
//   - processedCorpus: total number of corpus entries that have been validated
//   - invalidPairs: number of pairs marked as invalid (HB-ordered)
//   - validPairs: number of pairs confirmed as triggerable
func (sm *StageManager) GetVerificationStats() (processedCorpus, invalidPairs, validPairs uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	processedCorpus = sm.processedCorpus
	if sm.validDB != nil {
		validPairs = uint64(len(sm.validDB.Records))
	}
	if sm.invalidDB != nil {
		invalidPairs = uint64(len(sm.invalidDB.Records))
	}
	return
}
