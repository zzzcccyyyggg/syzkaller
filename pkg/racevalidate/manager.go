package uafvalidate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
)

type Executor interface {
	Run(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error)
	// RunBatch executes multiple requests in a single RPC session.
	// This is more efficient than calling Run multiple times as it avoids
	// re-establishing SSH connections and RPC servers for each request.
	// Returns results in the same order as requests.
	RunBatch(ctx context.Context, reqs []*ExecutionRequest) ([]*ExecutionResult, error)
}

type ExecutorFactory func(ctx context.Context) (Executor, error)

type ExecutionRequest struct {
	Entry         *fuzzer.UAFCorpusEntry
	Delays        []int64
	TargetPair    *ddrd.MayUAFPair
	RepeatTimes   int
	DisableDdrd   bool
	StopOnSuccess bool
	// ObserveTargetPairOnly records DDRD target-pair observations without counting
	// them as validation success. Matching crashes still update TriggeredCount.
	ObserveTargetPairOnly bool

	// Per-pair computed delays for verification phase
	// StartDelayUs: original delay - used for barrier start delay (nanosleep in executor), same as discovery phase
	// AccessDelayUs: max(original, runtime) - used for UAF access delay (udelay in kernel)
	StartDelayUs          int64
	AccessDelayUs         int64
	TargetDelaySide       string
	TargetDelaySideKernel int32
	TargetDelayMode       string
	TargetDelayModeKernel int32
}

// StablePairWithDelays extends MayUAFPair with computed delay values for verification
type StablePairWithDelays struct {
	Pair          ddrd.MayUAFPair
	StartDelayUs  int64 // original TimeDiff in microseconds (same as discovery phase)
	AccessDelayUs int64 // max(original TimeDiff, runtime TimeDiff) in microseconds
}

type snSampleStats struct {
	Count         int
	FreeMin       int32
	FreeMax       int32
	UseMin        int32
	UseMax        int32
	FreeTidMin    int32
	FreeTidMax    int32
	UseTidMin     int32
	UseTidMax     int32
	FreeTidValues map[int32]int
	UseTidValues  map[int32]int
}

type ExecutionResult struct {
	Output              []byte
	Duration            time.Duration
	Crashed             bool
	CrashTitle          string
	CrashReport         []byte
	Ddrd                *ddrd.Report
	TriggeredCount      int
	ObservedTargetCount int
}

type ValidationResult struct {
	Entry          *fuzzer.UAFCorpusEntry
	Signature      fuzzer.UAFPairProfile
	Delays         []int64
	Duration       time.Duration
	Output         []byte
	Success        bool
	NoStablePairs  bool
	CrashTitle     string
	Err            error
	Attempt        int
	RepeatIndex    int
	RepeatTotal    int
	Pairs          []ddrd.MayUAFPair
	StablePairs    []ddrd.MayUAFPair
	CollectionOnly bool

	VerificationExecutedPairs         int
	VerificationSkippedPairs          int
	VerificationValidatedPairs        int
	VerificationFailedPairs           int
	VerificationSkippedValidatedPairs int
}

type VerificationSummary struct {
	ExecutedPairs         int
	SkippedPairs          int
	ValidatedPairs        int
	FailedPairs           int
	SkippedValidatedPairs int
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

	// Layer 2: VarName pair validation backoff statistics store
	varNameBackoffDB    *db.DB
	varNameBackoffStore *VarNameBackoffStore

	mu          sync.Mutex
	pending     map[string]*validationTask
	seenKeys    map[string]struct{} // tracks all keys that have been enqueued (including completed)
	closed      bool
	seq         uint64
	tasksClosed bool

	// VarName-based scheduling (when EnableVarNameScheduling is true)
	varNameGroups  map[string][]string        // vnKey → []entryKey (entries containing this VarName)
	entryStore     map[string]*validationTask // entryKey → task (all registered tasks)
	entryVarNames  map[string][]string        // entryKey → []vnKey (VarNames in each entry)
	varNameCounts  map[string]int             // vnKey → count of pending entries
	sortedVarNames []string                   // vnKeys sorted by count (ascending)
	currentVNIndex int                        // round-robin index
	vnScheduleCond *sync.Cond                 // condition variable for task availability

	// ContinueAfterBackoff support: re-test backoff-skipped entries after initial pass.
	backoffSkippedEntries []*fuzzer.UAFCorpusEntry // entries skipped by shouldSkipEntry during the backoff-guided pass
	backoffPhaseComplete  bool                     // true after the initial backoff-guided pass; disables backoff skip for re-enqueued entries

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
	ref            *ValidationEntryRef
	signature      fuzzer.UAFPairProfile
	key            string
	attempts       int
	repeats        int
	historyCount   int                        // number of replay history records
	pairLatest     map[string]ddrd.MayUAFPair // latest runtime pair (with runtime TimeDiff)
	pairCounts     map[string]int
	pairOriginalTD map[string]uint64 // original TimeDiff from entry.Pairs (nanoseconds)
	pairSNSamples  map[string]*snSampleStats
}

func NewStageManager(cfg Config, factory ExecutorFactory) *StageManager {
	cfg = cfg.withDefaults()

	// PriorityLowHistory requires VarName scheduling infrastructure
	if cfg.PriorityLowHistory && !cfg.EnableVarNameScheduling {
		log.Logf(0, "uafvalidate: PriorityLowHistory enabled, automatically enabling VarName scheduling")
		cfg.EnableVarNameScheduling = true
	}

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

	// Initialize VarName scheduling structures
	if cfg.EnableVarNameScheduling {
		sm.varNameGroups = make(map[string][]string)
		sm.entryStore = make(map[string]*validationTask)
		sm.entryVarNames = make(map[string][]string)
		sm.varNameCounts = make(map[string]int)
		sm.vnScheduleCond = sync.NewCond(&sm.mu)
		log.Logf(0, "uafvalidate: VarName-based scheduling enabled")
		if cfg.PriorityLowHistory {
			log.Logf(0, "uafvalidate: PriorityLowHistory enabled (sort by ascending history count)")
		}
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

		// Layer 2: VarName pair validation backoff statistics DB.
		backoffPath := filepath.Join(cfg.Workdir, "varname_backoff_stats.db")
		legacyBackoffPath := filepath.Join(cfg.Workdir, "varname_hb_stats.db")
		statsPath := backoffPath
		if !osutil.IsExist(backoffPath) && osutil.IsExist(legacyBackoffPath) {
			statsPath = legacyBackoffPath
			log.Logf(0, "uafvalidate: using legacy validation backoff stats db: %s", legacyBackoffPath)
		}
		backoffDB, err := db.Open(statsPath, true)
		if err != nil {
			log.Logf(0, "uafvalidate: failed to open validation backoff stats db: %v", err)
		} else {
			sm.varNameBackoffDB = backoffDB
			sm.varNameBackoffStore = NewVarNameBackoffStore(backoffDB)
		}
	}

	return sm
}

func (sm *StageManager) Enqueue(entry *fuzzer.UAFCorpusEntry) bool {
	if entry == nil {
		return false
	}
	task := sm.prepareTask(entry)
	if task == nil {
		return false
	}
	sm.dispatch(task)
	return true
}

func (sm *StageManager) EnqueueRef(ref *ValidationEntryRef) bool {
	if ref == nil || ref.PairKey == "" || ref.CorpusRecordID == "" {
		return false
	}
	task := sm.prepareTaskRef(ref)
	if task == nil {
		return false
	}
	sm.dispatch(task)
	return true
}

func (sm *StageManager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < sm.cfg.MaxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sm.cfg.EnableVarNameScheduling {
				sm.workerVarNameSchedule(ctx)
			} else {
				sm.worker(ctx)
			}
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
		// Wake up VarName workers if they're waiting
		if sm.vnScheduleCond != nil {
			sm.vnScheduleCond.Broadcast()
		}
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
	// Wake up VarName workers if they're waiting
	if sm.vnScheduleCond != nil {
		sm.vnScheduleCond.Broadcast()
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

// workerVarNameSchedule is the worker loop for VarName-based scheduling.
func (sm *StageManager) workerVarNameSchedule(ctx context.Context) {
	for {
		// Check context first
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Try to pick a task
		sm.mu.Lock()
		for {
			// Check if we should exit
			if sm.closed && len(sm.entryStore) == 0 {
				sm.mu.Unlock()
				return
			}

			// Try to pick a task
			task := sm.pickNextVarNameTask()
			if task != nil {
				sm.mu.Unlock()
				sm.handleTask(ctx, task)
				break
			}

			// No task available, wait for signal or check context
			if sm.closed {
				sm.mu.Unlock()
				return
			}

			// Wait for new tasks or close signal
			// Use a goroutine to handle context cancellation while waiting
			done := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					sm.mu.Lock()
					if sm.vnScheduleCond != nil {
						sm.vnScheduleCond.Broadcast()
					}
					sm.mu.Unlock()
				case <-done:
				}
			}()
			sm.vnScheduleCond.Wait()
			close(done)

			// Check context after waking up
			if ctx.Err() != nil {
				sm.mu.Unlock()
				return
			}
		}
	}
}

func (sm *StageManager) handleTask(ctx context.Context, task *validationTask) {
	if task == nil {
		return
	}
	if err := sm.materializeTaskEntry(task); err != nil {
		result := &ValidationResult{
			Entry:     task.lightResultEntry(),
			Signature: task.signature,
			Err:       err,
			Attempt:   task.attempts + 1,
		}
		sm.results <- result
		sm.complete(task)
		return
	}
	if task.entry == nil {
		return
	}
	sm.logReplayAvailability(task)
	sm.handleTaskRepeats(ctx, task)
}

func (sm *StageManager) logReplayAvailability(task *validationTask) {
	if task == nil || task.entry == nil {
		return
	}
	if sm.cfg.EnableReplay && len(task.entry.ReplayHistory) > 0 {
		log.Logf(0, "[history] validate: replay enabled for key=%s, history_count=%d", task.key, len(task.entry.ReplayHistory))
	} else if sm.cfg.EnableReplay {
		log.Logf(0, "[history] validate: no replay history available for key=%s", task.key)
	}
}

func (sm *StageManager) handleTaskRepeats(ctx context.Context, task *validationTask) {
	for task.repeats < sm.cfg.RepeatCount {
		if ctx.Err() != nil {
			sm.complete(task)
			return
		}
		task.attempts++
		// In collection phase, optionally skip delays to let natural timing determine stable pairs
		var delays []int64
		if sm.cfg.DisableCollectionDelay {
			// No delays during collection - run programs with natural timing
			delays = nil
		} else {
			delays = sm.delay.BuildDelays(task.entry)
		}
		log.Logf(0, "uafvalidate: task start key=%s attempt=%d repeat=%d/%d delays=%d", task.key, task.attempts, task.repeats+1, sm.cfg.RepeatCount, len(delays))
		result := &ValidationResult{
			Entry:          task.lightResultEntry(),
			Signature:      task.signature,
			Delays:         append([]int64(nil), delays...),
			Attempt:        task.attempts,
			CollectionOnly: sm.cfg.CollectionOnly,
		}
		exec, err := sm.factory(ctx)
		if err != nil {
			result.Err = err
		} else {
			// Use batch execution to run replay + collection in a single RPC session
			// This avoids SSH reconnection issues between replay and main execution
			execRes, runErr := sm.runBatchReplayAndCollect(ctx, exec, task, delays)
			if closer, ok := exec.(interface{ Close() error }); ok {
				if cerr := closer.Close(); cerr != nil {
					log.Logf(0, "uafvalidate: executor close error key=%s err=%v", task.key, cerr)
				}
			}
			if runErr != nil {
				result.Err = runErr
			} else if execRes != nil {
				result.Duration = execRes.Duration
				result.Output = append([]byte{}, execRes.Output...)
				result.Success = !execRes.Crashed
				result.CrashTitle = execRes.CrashTitle
				if execRes.Ddrd != nil {
					result.Pairs = clonePairs(execRes.Ddrd)
				}
			} else {
				result.Err = fmt.Errorf("batch execution returned nil result")
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
			originMatchMode := sm.cfg.OriginMatchMode
			if normalizeOriginMatchMode(originMatchMode) == OriginMatchModePrimaryVarName {
				originalPairs = primaryOriginPairs(task.entry)
			}
			// skipOriginalCheck: skip if debug mode OR if RequireOriginMatch is disabled
			skipOriginalCheck := sm.cfg.TargetVarNamePair != "" || !sm.cfg.RequireOriginMatch
			result.StablePairs = collectStablePairs(task.pairLatest, task.pairCounts, sm.stable, originalPairs, skipOriginalCheck, originMatchMode, sm.cfg.MaxStablePairsPerOrigin, sm.cfg.MaxStablePairsPerEntry)
			if len(result.StablePairs) > 0 {
				// Compute stable pairs with per-pair delays (min/max of original vs runtime TimeDiff)
				stablePairsWithDelays := collectStablePairsWithDelays(
					task.pairLatest,
					task.pairCounts,
					task.pairOriginalTD,
					sm.stable,
					originalPairs,
					skipOriginalCheck,
					originMatchMode,
					sm.cfg.MaxStablePairsPerOrigin,
					sm.cfg.MaxStablePairsPerEntry,
				)
				if sm.cfg.TargetVarNamePair != "" {
					logTargetCollectionSummary(task, result, originalPairs, stablePairsWithDelays, sm.cfg.TargetVarNamePair, sm.stable, sm.cfg.EnableReplay)
				}
				logSNDriftSummary(task, stablePairsWithDelays, originalPairs, originMatchMode, sm.cfg.SNFallbackRange)
				if sm.cfg.CollectionOnly {
					log.Logf(0, "uafvalidate: collection-only summary key=%s runtime_pairs=%d stable_pairs=%d repeat=%d/%d replay_enabled=%t history=%d",
						task.key, len(result.Pairs), len(result.StablePairs), task.repeats+1, sm.cfg.RepeatCount, sm.cfg.EnableReplay, len(task.entry.ReplayHistory))
				} else {
					summary := sm.runVerificationPhaseWithDelays(ctx, task, stablePairsWithDelays)
					result.VerificationExecutedPairs = summary.ExecutedPairs
					result.VerificationSkippedPairs = summary.SkippedPairs
					result.VerificationValidatedPairs = summary.ValidatedPairs
					result.VerificationFailedPairs = summary.FailedPairs
					result.VerificationSkippedValidatedPairs = summary.SkippedValidatedPairs
				}
			} else {
				if sm.cfg.TargetVarNamePair != "" {
					logTargetCollectionSummary(task, result, originalPairs, nil, sm.cfg.TargetVarNamePair, sm.stable, sm.cfg.EnableReplay)
				}
				result.NoStablePairs = true
				if !sm.cfg.CollectionOnly {
					result.Success = false
					log.Logf(0, "uafvalidate: no stable pairs key=%s runtime_pairs=%d repeat=%d/%d replay_enabled=%t history=%d",
						task.key, len(result.Pairs), task.repeats+1, sm.cfg.RepeatCount, sm.cfg.EnableReplay, len(task.entry.ReplayHistory))
				} else {
					log.Logf(0, "uafvalidate: collection-only summary key=%s runtime_pairs=%d stable_pairs=0 repeat=%d/%d replay_enabled=%t history=%d",
						task.key, len(result.Pairs), task.repeats+1, sm.cfg.RepeatCount, sm.cfg.EnableReplay, len(task.entry.ReplayHistory))
				}
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

func (sm *StageManager) newHistoryMinimizer(task *validationTask, targetPair *ddrd.MayUAFPair,
	delays []int64) *HistoryMinimizer {
	runner := func(ctx context.Context, entry *fuzzer.UAFCorpusEntry) (*ExecutionResult, error) {
		exec, err := sm.factory(ctx)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closer, ok := exec.(interface{ Close() error }); ok {
				if cerr := closer.Close(); cerr != nil {
					log.Logf(0, "uafvalidate: minimizer executor close error key=%s err=%v", task.key, cerr)
				}
			}
		}()

		tempTask := &validationTask{
			entry: entry,
			key:   task.key,
		}
		var pairCopy *ddrd.MayUAFPair
		if targetPair != nil {
			copyVal := *targetPair
			pairCopy = &copyVal
		}
		verifyReq := &ExecutionRequest{
			Entry:         entry,
			Delays:        append([]int64(nil), delays...),
			TargetPair:    pairCopy,
			RepeatTimes:   1,
			DisableDdrd:   true,
			StopOnSuccess: true,
		}
		return sm.runBatchReplayAndSingleVerify(ctx, exec, tempTask, verifyReq)
	}
	return NewHistoryMinimizer(runner, sm.cfg, task.entry)
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

// entryBackoffThreshold is the minimum skip probability for a pair to be considered "skippable".
const entryBackoffThreshold = 0.8

// shouldSkipEntry checks if all pairs in the entry have accumulated a high
// backoff score and should be skipped entirely to avoid unnecessary execution.
func (sm *StageManager) shouldSkipEntry(entry *fuzzer.UAFCorpusEntry) (skip bool, reason string) {
	if sm.varNameBackoffStore == nil {
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
		if sm.varNameBackoffStore.IsVerified(pair) {
			skippedCount++
			verifiedCount++
			totalProb += 1.0
			continue
		}

		// Layer 3: VarName backoff probability check (for repeatedly low-yield pairs)
		stats := sm.varNameBackoffStore.GetByPair(pair)
		prob := stats.SkipProbability()
		totalProb += prob

		// If probability is high enough, count as skippable
		if prob >= entryBackoffThreshold {
			skippedCount++
		}
	}

	// If all pairs would be skipped, skip the entire entry
	if skippedCount == validPairCount && validPairCount > 0 {
		avgProb := totalProb / float64(validPairCount)
		if verifiedCount > 0 {
			return true, fmt.Sprintf("all %d pairs skipped (%d verified, avg_prob=%.2f)", validPairCount, verifiedCount, avgProb)
		}
		return true, fmt.Sprintf("all %d pairs high backoff score (avg_prob=%.2f)", validPairCount, avgProb)
	}

	return false, ""
}

func (sm *StageManager) prepareTask(entry *fuzzer.UAFCorpusEntry) *validationTask {
	// Debug: log incoming entry history status
	if entry != nil {
		log.Logf(1, "[history] prepareTask: incoming entry has %d history records", len(entry.ReplayHistory))
	}

	clone := entry.Clone()
	if clone == nil {
		return nil
	}

	// Debug: log cloned entry history status
	log.Logf(1, "[history] prepareTask: cloned entry has %d history records", len(clone.ReplayHistory))

	// Compute entry key early for TargetCorpusKey filtering
	signature := clone.Profile
	if IsZeroSignature(signature) && clone.PairBasicInfo.UAFPairID() != 0 {
		signature = SignatureFromPair(&clone.PairBasicInfo)
	}
	entryKey := ""
	if !IsZeroSignature(signature) {
		entryKey = SignatureKey(signature)
	}

	// If TargetCorpusKey is set, only process the matching entry. Accept both
	// the stable signature key and the persisted uaf-corpus.db record key so
	// targeted diagnostics can replay an exact saved corpus record.
	if sm.cfg.TargetCorpusKey != "" {
		if !targetCorpusKeyMatches(sm.cfg.TargetCorpusKey, entryKey, clone.CorpusRecordID) {
			return nil
		}
		log.Logf(1, "uafvalidate: [debug mode] entry matches target corpus key %s", sm.cfg.TargetCorpusKey)
	}

	// If TargetVarNamePair is set, only process entries containing that pair
	if sm.cfg.TargetVarNamePair != "" {
		if !entryContainsTargetVarName(clone, sm.cfg.TargetVarNamePair) {
			return nil
		}
		log.Logf(1, "uafvalidate: [debug mode] entry matches target VarName pair %s", sm.cfg.TargetVarNamePair)
	}

	// Pre-check: if all pairs have high backoff score, skip entire entry.
	// Skip this check in debug mode (TargetVarNamePair or TargetCorpusKey is set)
	// Also skip if DisableBackoffSkip is enabled or the backoff phase is already complete (re-enqueue phase).
	sm.mu.Lock()
	backoffDone := sm.backoffPhaseComplete
	sm.mu.Unlock()
	if sm.cfg.TargetVarNamePair == "" && sm.cfg.TargetCorpusKey == "" && !sm.cfg.DisableBackoffSkip && !backoffDone {
		if skip, reason := sm.shouldSkipEntry(clone); skip {
			log.Logf(0, "uafvalidate: skipping entry (all pairs high backoff score): %s", reason)
			if sm.cfg.ContinueAfterBackoff {
				sm.mu.Lock()
				sm.backoffSkippedEntries = append(sm.backoffSkippedEntries, clone)
				sm.mu.Unlock()
			}
			return nil
		}
	}

	key := entryKey
	if clone.CorpusRecordID != "" && (len(clone.ValidateQueueKeys) != 0 || clone.ValidateQueueKey != "") {
		key = "corpus-" + clone.CorpusRecordID
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
		entry:        clone,
		signature:    signature,
		key:          key,
		historyCount: len(clone.ReplayHistory),
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

func (sm *StageManager) prepareTaskRef(ref *ValidationEntryRef) *validationTask {
	if ref == nil {
		return nil
	}
	pair := ref.Pair
	if pair.UAFPairID() == 0 {
		return nil
	}
	signature := SignatureFromPair(&pair)
	entryKey := SignatureKey(signature)
	pairCopy := pair
	lightEntry := &fuzzer.UAFCorpusEntry{
		PairBasicInfo:    pairCopy,
		Pairs:            []*ddrd.MayUAFPair{&pairCopy},
		Profile:          signature,
		ValidateQueueKey: ref.QueueKey,
		ValidateQueueSeq: ref.QueueSeq,
		ValidatePairKey:  ref.PairKey,
		CorpusRecordID:   ref.CorpusRecordID,
	}

	if sm.cfg.TargetCorpusKey != "" {
		if !targetCorpusKeyMatches(sm.cfg.TargetCorpusKey, entryKey, ref.CorpusRecordID) {
			return nil
		}
		log.Logf(1, "uafvalidate: [debug mode] ref matches target corpus key %s", sm.cfg.TargetCorpusKey)
	}
	if sm.cfg.TargetVarNamePair != "" {
		if !entryContainsTargetVarName(lightEntry, sm.cfg.TargetVarNamePair) {
			return nil
		}
		log.Logf(1, "uafvalidate: [debug mode] ref matches target VarName pair %s", sm.cfg.TargetVarNamePair)
	}

	sm.mu.Lock()
	backoffDone := sm.backoffPhaseComplete
	sm.mu.Unlock()
	if sm.cfg.TargetVarNamePair == "" && sm.cfg.TargetCorpusKey == "" && !sm.cfg.DisableBackoffSkip && !backoffDone {
		if skip, reason := sm.shouldSkipEntry(lightEntry); skip {
			log.Logf(0, "uafvalidate: skipping ref (all pairs high backoff score): %s", reason)
			if sm.cfg.ContinueAfterBackoff {
				sm.mu.Lock()
				sm.backoffSkippedEntries = append(sm.backoffSkippedEntries, lightEntry)
				sm.mu.Unlock()
			}
			return nil
		}
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.closed {
		return nil
	}
	key := entryKey
	if key == "" || key == zeroSignatureKey {
		sm.seq++
		key = fmt.Sprintf("anon-%d", sm.seq)
	}
	if _, exists := sm.seenKeys[key]; exists {
		return nil
	}
	if _, exists := sm.pending[key]; exists {
		return nil
	}
	task := &validationTask{
		entry:          lightEntry,
		ref:            ref,
		signature:      signature,
		key:            key,
		historyCount:   ref.HistoryCount,
		pairOriginalTD: map[string]uint64{pairKey(pair): pair.TimeDiff},
	}
	sm.pending[key] = task
	sm.seenKeys[key] = struct{}{}
	return task
}

func (sm *StageManager) materializeTaskEntry(task *validationTask) error {
	if task == nil || task.ref == nil {
		return nil
	}
	if sm.cfg.EntryResolver == nil {
		return fmt.Errorf("validation ref requires an entry resolver")
	}
	entry, err := sm.cfg.EntryResolver.ResolveValidationEntry(task.ref)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("corpus record %s not found for pair %s", task.ref.CorpusRecordID, task.ref.PairKey)
	}
	entry.ValidateQueueKey = task.ref.QueueKey
	entry.ValidateQueueSeq = task.ref.QueueSeq
	entry.ValidatePairKey = task.ref.PairKey
	entry.CorpusRecordID = task.ref.CorpusRecordID
	task.entry = entry
	task.historyCount = len(entry.ReplayHistory)
	return nil
}

func (task *validationTask) lightResultEntry() *fuzzer.UAFCorpusEntry {
	if task == nil {
		return nil
	}
	var pair ddrd.MayUAFPair
	if task.ref != nil {
		pair = task.ref.Pair
	} else if task.entry != nil {
		pair = task.entry.PairBasicInfo
	}
	entry := &fuzzer.UAFCorpusEntry{
		PairBasicInfo: pair,
		Profile:       task.signature,
	}
	if pair.UAFPairID() != 0 {
		pairCopy := pair
		entry.Pairs = []*ddrd.MayUAFPair{&pairCopy}
	}
	if task.ref != nil {
		entry.ValidateQueueKey = task.ref.QueueKey
		entry.ValidateQueueSeq = task.ref.QueueSeq
		entry.ValidatePairKey = task.ref.PairKey
		entry.CorpusRecordID = task.ref.CorpusRecordID
	} else if task.entry != nil {
		entry.ValidateQueueKey = task.entry.ValidateQueueKey
		entry.ValidateQueueSeq = task.entry.ValidateQueueSeq
		entry.ValidatePairKey = task.entry.ValidatePairKey
		if len(task.entry.ValidateQueueKeys) != 0 {
			entry.ValidateQueueKeys = append([]string(nil), task.entry.ValidateQueueKeys...)
		}
		if len(task.entry.ValidatePairKeys) != 0 {
			entry.ValidatePairKeys = append([]string(nil), task.entry.ValidatePairKeys...)
		}
		entry.CorpusRecordID = task.entry.CorpusRecordID
	}
	return entry
}

func (sm *StageManager) dispatch(task *validationTask) {
	if task == nil {
		return
	}

	// Use VarName-based scheduling if enabled
	if sm.cfg.EnableVarNameScheduling {
		sm.dispatchVarNameSchedule(task)
		return
	}

	// Original channel-based dispatch
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

// dispatchVarNameSchedule registers a task for VarName-based round-robin scheduling.
func (sm *StageManager) dispatchVarNameSchedule(task *validationTask) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.closed {
		log.Logf(0, "uafvalidate: dispatch drop key=%s (closed)", task.key)
		return
	}

	// Extract VarName keys from the entry's pairs
	vnKeys := sm.extractVarNameKeys(task.entry)
	if len(vnKeys) == 0 {
		// No pairs, use a fallback key
		vnKeys = []string{"__no_pairs__"}
	}

	// Register task in entryStore
	sm.entryStore[task.key] = task
	sm.entryVarNames[task.key] = vnKeys

	// Add to each VarName group (with optional history-based sorting)
	for _, vnKey := range vnKeys {
		if sm.cfg.PriorityLowHistory {
			// Insert in sorted order by historyCount (ascending)
			sm.varNameGroups[vnKey] = sm.insertSortedByHistory(sm.varNameGroups[vnKey], task.key)
		} else {
			// Default: append to end (FIFO)
			sm.varNameGroups[vnKey] = append(sm.varNameGroups[vnKey], task.key)
		}
		sm.varNameCounts[vnKey]++
	}

	// Rebuild sorted VarNames
	sm.rebuildSortedVarNames()

	log.Logf(1, "uafvalidate: vn-dispatch key=%s vnkeys=%d history=%d total_entries=%d total_vnkeys=%d",
		task.key, len(vnKeys), task.historyCount, len(sm.entryStore), len(sm.sortedVarNames))

	// Signal waiting workers
	if sm.vnScheduleCond != nil {
		sm.vnScheduleCond.Broadcast()
	}
}

// insertSortedByHistory inserts entryKey into the list maintaining ascending historyCount order.
// Must be called with sm.mu held.
func (sm *StageManager) insertSortedByHistory(list []string, entryKey string) []string {
	task := sm.entryStore[entryKey]
	if task == nil {
		return append(list, entryKey)
	}

	// Find insertion point
	insertIdx := len(list)
	for i, key := range list {
		other := sm.entryStore[key]
		if other != nil && task.historyCount < other.historyCount {
			insertIdx = i
			break
		}
	}

	// Insert at position
	list = append(list, "")
	copy(list[insertIdx+1:], list[insertIdx:])
	list[insertIdx] = entryKey
	return list
}

// extractVarNameKeys extracts unique VarName keys from an entry's pairs.
func (sm *StageManager) extractVarNameKeys(entry *fuzzer.UAFCorpusEntry) []string {
	if entry == nil {
		return nil
	}

	seen := make(map[string]struct{})
	var keys []string

	for _, pair := range entry.Pairs {
		if pair == nil {
			continue
		}
		vnKey := VarNamePairKey(pair)
		if _, exists := seen[vnKey]; !exists {
			seen[vnKey] = struct{}{}
			keys = append(keys, vnKey)
		}
	}

	// Also check PairBasicInfo if no pairs in slice
	if len(keys) == 0 && (entry.PairBasicInfo.FreeAccessName != 0 || entry.PairBasicInfo.UseAccessName != 0) {
		vnKey := VarNamePairKey(&entry.PairBasicInfo)
		keys = append(keys, vnKey)
	}

	return keys
}

// rebuildSortedVarNames rebuilds the sorted VarName list by ascending count.
func (sm *StageManager) rebuildSortedVarNames() {
	// Collect VarNames with non-zero counts
	sm.sortedVarNames = make([]string, 0, len(sm.varNameCounts))
	for vnKey, count := range sm.varNameCounts {
		if count > 0 && len(sm.varNameGroups[vnKey]) > 0 {
			sm.sortedVarNames = append(sm.sortedVarNames, vnKey)
		}
	}

	// Sort by count ascending
	sort.Slice(sm.sortedVarNames, func(i, j int) bool {
		return sm.varNameCounts[sm.sortedVarNames[i]] < sm.varNameCounts[sm.sortedVarNames[j]]
	})

	// Reset index if out of range
	if sm.currentVNIndex >= len(sm.sortedVarNames) {
		sm.currentVNIndex = 0
	}
}

// pickNextVarNameTask picks the next task using VarName-based round-robin.
// Must be called with sm.mu held. Returns nil if no tasks available.
func (sm *StageManager) pickNextVarNameTask() *validationTask {
	if len(sm.sortedVarNames) == 0 || len(sm.entryStore) == 0 {
		return nil
	}

	// Try each VarName in round-robin order
	for attempts := 0; attempts < len(sm.sortedVarNames); attempts++ {
		if sm.currentVNIndex >= len(sm.sortedVarNames) {
			sm.currentVNIndex = 0
		}

		vnKey := sm.sortedVarNames[sm.currentVNIndex]
		sm.currentVNIndex++

		entryKeys := sm.varNameGroups[vnKey]
		if len(entryKeys) == 0 {
			continue
		}

		// Find first valid entry in this group
		for len(entryKeys) > 0 {
			entryKey := entryKeys[0]
			entryKeys = entryKeys[1:]
			sm.varNameGroups[vnKey] = entryKeys

			task, ok := sm.entryStore[entryKey]
			if !ok {
				// Entry already processed, skip
				continue
			}

			// Remove entry from all VarName groups
			for _, otherVN := range sm.entryVarNames[entryKey] {
				if otherVN != vnKey {
					sm.removeEntryFromGroup(otherVN, entryKey)
				}
			}

			// Update counts
			for _, vn := range sm.entryVarNames[entryKey] {
				sm.varNameCounts[vn]--
			}

			// Remove from stores
			delete(sm.entryStore, entryKey)
			delete(sm.entryVarNames, entryKey)

			// Rebuild sorted list (counts changed)
			sm.rebuildSortedVarNames()

			log.Logf(0, "uafvalidate: vn-pick key=%s from_vn=%s remaining_entries=%d",
				entryKey, vnKey, len(sm.entryStore))

			return task
		}
	}

	return nil
}

// removeEntryFromGroup removes an entry key from a VarName group.
func (sm *StageManager) removeEntryFromGroup(vnKey, entryKey string) {
	entries := sm.varNameGroups[vnKey]
	for i, key := range entries {
		if key == entryKey {
			sm.varNameGroups[vnKey] = append(entries[:i], entries[i+1:]...)
			return
		}
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
		// ContinueAfterBackoff: re-enqueue backoff-skipped entries before closing
		if sm.cfg.ContinueAfterBackoff && !sm.backoffPhaseComplete && len(sm.backoffSkippedEntries) > 0 {
			sm.backoffPhaseComplete = true
			skipped := sm.backoffSkippedEntries
			sm.backoffSkippedEntries = nil
			// Reset closed so prepareTask() and dispatch() accept new entries
			sm.closed = false
			log.Logf(0, "uafvalidate: backoff phase complete, scheduling %d skipped entries for exhaustive testing", len(skipped))
			// Wake up VarName workers that may be waiting
			if sm.vnScheduleCond != nil {
				sm.vnScheduleCond.Broadcast()
			}
			go sm.reEnqueueBackoffSkipped(skipped)
			return
		}
		log.Logf(0, "uafvalidate: closing tasks channel")
		close(sm.tasks)
		sm.tasksClosed = true
	}
}

// isBackoffPhaseComplete returns true if the initial backoff-guided pass has completed
// and we are now in the exhaustive re-testing phase.
func (sm *StageManager) isBackoffPhaseComplete() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.backoffPhaseComplete
}

// reEnqueueBackoffSkipped re-enqueues entries that were skipped by the entry-level backoff check.
// Entries are shuffled to randomize testing order.
func (sm *StageManager) reEnqueueBackoffSkipped(entries []*fuzzer.UAFCorpusEntry) {
	// Shuffle for random testing order
	rand.Shuffle(len(entries), func(i, j int) {
		entries[i], entries[j] = entries[j], entries[i]
	})

	enqueued := 0
	for _, entry := range entries {
		sm.Enqueue(entry)
		enqueued++
	}
	log.Logf(0, "uafvalidate: re-enqueued %d/%d backoff-skipped entries for exhaustive testing", enqueued, len(entries))

	// Signal close again — no more entries to enqueue
	sm.mu.Lock()
	sm.closed = true
	sm.maybeCloseTasksLocked()
	if sm.vnScheduleCond != nil {
		sm.vnScheduleCond.Broadcast()
	}
	sm.mu.Unlock()
}

// runReplayOnExecutor replays the execution history on a given executor.
// This warms up the kernel state before the main task execution.
// The executor is NOT closed - caller is responsible for closing it.
// DEPRECATED: This creates new RPC server for each Run call, causing SSH reconnection issues.
// Use runBatchReplayAndCollect instead.
func (sm *StageManager) runReplayOnExecutor(ctx context.Context, exec Executor, task *validationTask) error {
	if !sm.cfg.EnableReplay {
		return nil
	}
	historyLen := len(task.entry.ReplayHistory)
	if historyLen == 0 {
		return nil
	}

	log.Logf(0, "[history] replay: starting on same executor key=%s history=%d", task.key, historyLen)
	startTime := time.Now()

	for i, record := range task.entry.ReplayHistory {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if record == nil || len(record.Programs) == 0 {
			continue
		}

		// Create a minimal entry for replay with the recorded program group
		replayEntry := &fuzzer.UAFCorpusEntry{
			Programs: record.Programs,
			Barrier: fuzzer.BarrierSnapshot{
				GroupSize: len(record.Programs),
				GroupID:   record.GroupID,
			},
		}

		// Run in barrier mode but optionally skip race pair collection
		replayReq := &ExecutionRequest{
			Entry:       replayEntry,
			DisableDdrd: !sm.cfg.ReplayCollectPairs,
		}

		_, runErr := exec.Run(ctx, replayReq)
		if runErr != nil {
			log.Logf(1, "[history] replay %d/%d execution error: %v", i+1, historyLen, runErr)
			// Continue with remaining replays - don't abort
		}
	}

	log.Logf(0, "[history] replay: completed key=%s history=%d duration=%s", task.key, historyLen, time.Since(startTime))
	return nil
}

func (sm *StageManager) buildReplayRequests(task *validationTask) []*ExecutionRequest {
	var reqs []*ExecutionRequest
	if task == nil || task.entry == nil {
		return nil
	}
	if !sm.cfg.EnableReplay || len(task.entry.ReplayHistory) == 0 {
		return nil
	}
	history := task.entry.ReplayHistory
	if limit := sm.cfg.MaxReplayHistory; limit > 0 && len(history) > limit {
		history = history[len(history)-limit:]
	}
	for _, record := range history {
		if record == nil || len(record.Programs) == 0 {
			continue
		}
		replayEntry := &fuzzer.UAFCorpusEntry{
			Programs: record.Programs,
			Barrier: fuzzer.BarrierSnapshot{
				GroupSize: len(record.Programs),
				GroupID:   record.GroupID,
			},
		}
		reqs = append(reqs, &ExecutionRequest{
			Entry:       replayEntry,
			DisableDdrd: !sm.cfg.ReplayCollectPairs,
		})
	}
	return reqs
}

// runBatchReplayAndCollect combines replay history + main collection into a single batch execution.
// This uses RunBatch to execute all requests in a single RPC session, avoiding SSH reconnection issues.
// Returns the result of the main (last) request.
func (sm *StageManager) runBatchReplayAndCollect(ctx context.Context, exec Executor, task *validationTask, delays []int64) (*ExecutionResult, error) {
	reqs := sm.buildReplayRequests(task)

	// Add main collection request as the last request
	mainReq := &ExecutionRequest{
		Entry:  task.entry,
		Delays: delays,
	}
	reqs = append(reqs, mainReq)

	log.Logf(0, "[batch] executing key=%s replay=%d main=1 total=%d", task.key, len(reqs)-1, len(reqs))
	startTime := time.Now()

	// Run all requests in a single batch (single RPC session)
	results, err := exec.RunBatch(ctx, reqs)
	if err != nil {
		return nil, err
	}

	log.Logf(0, "[batch] completed key=%s results=%d duration=%s", task.key, len(results), time.Since(startTime))

	// Return the last result (the main collection)
	if len(results) > 0 {
		return results[len(results)-1], nil
	}
	return nil, fmt.Errorf("batch execution produced no results")
}

// runBatchReplayAndVerify combines replay history + verification request(s) into a single batch execution.
// This uses RunBatch to execute all requests in a single RPC session, avoiding SSH reconnection issues.
// If VerifyDelaySweep is enabled, generates multiple verify requests with different delays.
// Returns the aggregated result of the verification request(s).
func (sm *StageManager) runBatchReplayAndVerify(ctx context.Context, exec Executor, task *validationTask, verifyReq *ExecutionRequest) (*ExecutionResult, error) {
	reqs := sm.buildReplayRequests(task)
	replayCount := len(reqs)

	// Build verify requests - with delay sweep if enabled
	verifyCount := 1
	if sm.cfg.VerifyDelaySweep && sm.cfg.VerifyDelaySteps > 1 {
		verifyCount = sm.cfg.VerifyDelaySteps
		maxDelay := sm.cfg.VerifyDelayMaxUs
		power := sm.cfg.VerifyDelayPower

		for i := 0; i < verifyCount; i++ {
			sweepDelay := sweepDelayForStep(i, verifyCount, maxDelay, power)

			// Create a copy of the verify request with updated delay
			verifyReqCopy := *verifyReq
			verifyReqCopy.StartDelayUs = sweepDelay
			verifyReqCopy.Delays = buildStartDelaysFromPair(task.entry, sweepDelay)

			// Also update the TargetPair's TimeDiff if provided
			if verifyReq.TargetPair != nil {
				pairCopy := *verifyReq.TargetPair
				pairCopy.TimeDiff = uint64(sweepDelay) * 1000 // Convert to nanoseconds
				verifyReqCopy.TargetPair = &pairCopy
			}

			reqs = append(reqs, &verifyReqCopy)
		}

		log.Logf(0, "[batch] verify: executing key=%s replay=%d verify=%d (delay_sweep 0-%dµs) total=%d",
			task.key, replayCount, verifyCount, maxDelay, len(reqs))
	} else {
		// No delay sweep - single verify request
		reqs = append(reqs, verifyReq)
		log.Logf(0, "[batch] verify: executing key=%s replay=%d verify=1 total=%d", task.key, replayCount, len(reqs))
	}

	startTime := time.Now()

	// Run all requests in a single batch (single RPC session)
	results, err := exec.RunBatch(ctx, reqs)
	if err != nil {
		return nil, err
	}

	duration := time.Since(startTime)
	log.Logf(0, "[batch] verify: completed key=%s results=%d duration=%s", task.key, len(results), duration)

	// Extract verify results (skip replay results)
	if len(results) <= replayCount {
		return nil, fmt.Errorf("batch verification produced no verify results (got %d, need >%d)", len(results), replayCount)
	}

	verifyResults := results[replayCount:]

	// Aggregate verify results
	return sm.aggregateVerifyResults(verifyResults, duration), nil
}

func (sm *StageManager) runBatchReplayAndSingleVerify(ctx context.Context, exec Executor,
	task *validationTask, verifyReq *ExecutionRequest) (*ExecutionResult, error) {
	reqs := sm.buildReplayRequests(task)
	replayCount := len(reqs)
	reqs = append(reqs, verifyReq)
	log.Logf(0, "[batch] minimize-verify: executing key=%s replay=%d verify=1 total=%d",
		task.key, replayCount, len(reqs))
	startTime := time.Now()
	results, err := exec.RunBatch(ctx, reqs)
	if err != nil {
		return nil, err
	}
	duration := time.Since(startTime)
	log.Logf(0, "[batch] minimize-verify: completed key=%s results=%d duration=%s", task.key, len(results), duration)
	if len(results) <= replayCount {
		return nil, fmt.Errorf("minimize verification produced no verify result (got %d, need >%d)", len(results), replayCount)
	}
	return results[replayCount], nil
}

// aggregateVerifyResults combines multiple verify results into a single result.
func (sm *StageManager) aggregateVerifyResults(results []*ExecutionResult, totalDuration time.Duration) *ExecutionResult {
	if len(results) == 0 {
		return nil
	}

	// For single result, return as-is
	if len(results) == 1 {
		return results[0]
	}

	// Aggregate multiple results
	aggregated := &ExecutionResult{
		Duration:            totalDuration,
		TriggeredCount:      0,
		ObservedTargetCount: 0,
	}

	triggeredDelays := []int64{}
	for i, r := range results {
		if r == nil {
			continue
		}
		if len(r.Output) != 0 {
			aggregated.Output = append(aggregated.Output, r.Output...)
		}
		if r.TriggeredCount > 0 {
			aggregated.TriggeredCount++
			// Record which delay step triggered
			if sm.cfg.VerifyDelaySweep {
				sweepDelay := sweepDelayForStep(i, len(results), sm.cfg.VerifyDelayMaxUs, sm.cfg.VerifyDelayPower)
				triggeredDelays = append(triggeredDelays, sweepDelay)
			}
		}
		if r.ObservedTargetCount > 0 {
			aggregated.ObservedTargetCount++
		}
		// Capture first crash info
		if r.Crashed && aggregated.CrashTitle == "" {
			aggregated.Crashed = true
			aggregated.CrashTitle = r.CrashTitle
			aggregated.CrashReport = r.CrashReport
		}
		// Merge DDRD reports (take first non-nil)
		if r.Ddrd != nil && aggregated.Ddrd == nil {
			aggregated.Ddrd = r.Ddrd
		}
	}

	// Log delay sweep statistics
	if sm.cfg.VerifyDelaySweep && len(results) > 1 {
		if len(triggeredDelays) > 0 {
			log.Logf(0, "[batch] verify: delay sweep triggered %d/%d steps, first at %dµs",
				aggregated.TriggeredCount, len(results), triggeredDelays[0])
		} else {
			log.Logf(0, "[batch] verify: delay sweep triggered 0/%d steps", len(results))
		}
	}

	return aggregated
}

// sweepDelayForStep computes the delay for a given step in the sweep.
// Uses exponential curve: delay(i) = maxDelay * (i/(n-1))^power
func sweepDelayForStep(step, totalSteps int, maxDelayUs int64, power float64) int64 {
	if totalSteps <= 1 {
		return 0
	}
	if step <= 0 {
		return 0
	}
	if step >= totalSteps-1 {
		return maxDelayUs
	}
	ratio := float64(step) / float64(totalSteps-1)
	return int64(float64(maxDelayUs) * math.Pow(ratio, power))
}

// runReplayPhase replays the execution history to reconstruct system state before validation.
// DEPRECATED: This runs each replay in a separate executor, which doesn't achieve the intended effect.
// Use runReplayOnExecutor instead to replay on the same executor that will run the main task.
func (sm *StageManager) runReplayPhase(ctx context.Context, task *validationTask) error {
	historyLen := len(task.entry.ReplayHistory)
	if historyLen == 0 {
		return nil
	}

	log.Logf(0, "uafvalidate: starting replay phase key=%s history=%d", task.key, historyLen)
	startTime := time.Now()

	for i, record := range task.entry.ReplayHistory {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if record == nil || len(record.Programs) == 0 {
			continue
		}

		exec, err := sm.factory(ctx)
		if err != nil {
			log.Logf(0, "uafvalidate: replay %d/%d failed to create executor: %v", i+1, historyLen, err)
			continue
		}

		// Create a minimal entry for replay with the recorded program group
		replayEntry := &fuzzer.UAFCorpusEntry{
			Programs: record.Programs,
			Barrier: fuzzer.BarrierSnapshot{
				GroupSize: len(record.Programs),
				GroupID:   record.GroupID,
			},
		}

		// Run in barrier mode but optionally skip race pair collection
		replayReq := &ExecutionRequest{
			Entry:       replayEntry,
			DisableDdrd: !sm.cfg.ReplayCollectPairs,
		}

		_, runErr := exec.Run(ctx, replayReq)

		// Clean up executor
		if closer, ok := exec.(interface{ Close() error }); ok {
			if cerr := closer.Close(); cerr != nil {
				log.Logf(0, "uafvalidate: replay %d/%d close error: %v", i+1, historyLen, cerr)
			}
		}

		if runErr != nil {
			log.Logf(0, "uafvalidate: replay %d/%d execution failed: %v", i+1, historyLen, runErr)
			// Continue with remaining replays
		}
	}

	log.Logf(0, "uafvalidate: replay phase completed key=%s duration=%s", task.key, time.Since(startTime))
	return nil
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
	if task.pairSNSamples == nil {
		task.pairSNSamples = make(map[string]*snSampleStats)
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
		recordSNSample(task.pairSNSamples, key, pair)
	}
}

func recordSNSample(samples map[string]*snSampleStats, key string, pair ddrd.MayUAFPair) {
	if samples == nil {
		return
	}
	stats := samples[key]
	if stats == nil {
		stats = &snSampleStats{}
		samples[key] = stats
	}
	stats.Count++
	if stats.Count == 1 {
		stats.FreeMin = pair.FreeSN
		stats.FreeMax = pair.FreeSN
		stats.UseMin = pair.UseSN
		stats.UseMax = pair.UseSN
		stats.FreeTidMin = pair.FreeTid
		stats.FreeTidMax = pair.FreeTid
		stats.UseTidMin = pair.UseTid
		stats.UseTidMax = pair.UseTid
	} else {
		stats.FreeMin = minSN(stats.FreeMin, pair.FreeSN)
		stats.FreeMax = maxSN(stats.FreeMax, pair.FreeSN)
		stats.UseMin = minSN(stats.UseMin, pair.UseSN)
		stats.UseMax = maxSN(stats.UseMax, pair.UseSN)
		if pair.FreeTid < stats.FreeTidMin {
			stats.FreeTidMin = pair.FreeTid
		}
		if pair.FreeTid > stats.FreeTidMax {
			stats.FreeTidMax = pair.FreeTid
		}
		if pair.UseTid < stats.UseTidMin {
			stats.UseTidMin = pair.UseTid
		}
		if pair.UseTid > stats.UseTidMax {
			stats.UseTidMax = pair.UseTid
		}
	}
	if stats.FreeTidValues == nil {
		stats.FreeTidValues = make(map[int32]int)
	}
	if stats.UseTidValues == nil {
		stats.UseTidValues = make(map[int32]int)
	}
	stats.FreeTidValues[pair.FreeTid]++
	stats.UseTidValues[pair.UseTid]++
}

func minSN(a, b int32) int32 {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if b < a {
		return b
	}
	return a
}

func maxSN(a, b int32) int32 {
	if b > a {
		return b
	}
	return a
}

func logSNDriftSummary(task *validationTask, stablePairs []StablePairWithDelays, originalPairs []*ddrd.MayUAFPair, originMatchMode string, configuredRange int) {
	if task == nil || len(stablePairs) == 0 || len(task.pairSNSamples) == 0 {
		return
	}

	expectedRepeats := task.repeats + 1
	var (
		withSamples    int
		withOriginal   int
		fullObserved   int
		exactSN        int
		within1        int
		within2        int
		within4        int
		within8        int
		withinConfig   int
		exactTID       int
		stableTID      int
		multiTID       int
		maxFreeTIDVals int
		maxUseTIDVals  int
		maxAbsObserved int32
		detailLogged   int
	)

	for _, spd := range stablePairs {
		pair := spd.Pair
		key := pairKey(pair)
		samples := task.pairSNSamples[key]
		if samples == nil || samples.Count == 0 {
			continue
		}
		withSamples++
		if samples.Count >= expectedRepeats {
			fullObserved++
		}
		original, ok := findOriginalPairForSNDrift(pair, originalPairs, originMatchMode)
		if ok {
			withOriginal++
		}

		maxAbs := pairMaxAbsSNDelta(samples, pair)
		if maxAbs > maxAbsObserved {
			maxAbsObserved = maxAbs
		}
		if pairSNWithin(samples, pair, 0) {
			exactSN++
		}
		if pairSNWithin(samples, pair, 1) {
			within1++
		}
		if pairSNWithin(samples, pair, 2) {
			within2++
		}
		if pairSNWithin(samples, pair, 4) {
			within4++
		}
		if pairSNWithin(samples, pair, 8) {
			within8++
		}
		if configuredRange > 0 && pairSNWithin(samples, pair, configuredRange) {
			withinConfig++
		}
		freeTidVals := len(samples.FreeTidValues)
		useTidVals := len(samples.UseTidValues)
		if freeTidVals > maxFreeTIDVals {
			maxFreeTIDVals = freeTidVals
		}
		if useTidVals > maxUseTIDVals {
			maxUseTIDVals = useTidVals
		}
		if pairTIDExact(samples, pair) {
			exactTID++
		}
		if pairTIDStable(samples) {
			stableTID++
		}
		if freeTidVals > 1 || useTidVals > 1 {
			multiTID++
		}

		if detailLogged < 8 {
			freeLow, freeHigh, freeOK := sideSNDeltaRange(samples.FreeMin, samples.FreeMax, pair.FreeSN)
			useLow, useHigh, useOK := sideSNDeltaRange(samples.UseMin, samples.UseMax, pair.UseSN)
			originField := "n/a"
			if ok {
				originField = fmt.Sprintf("free:%d use:%d", original.FreeSN, original.UseSN)
			}
			log.Logf(1, "uafvalidate: sn-drift pair key=%s vnkey=%s observed=%d/%d ref_sn=(free:%d use:%d) origin_sn=(%s) observed_sn=(free:%d-%d use:%d-%d) delta_from_ref=(free:%s use:%s) ref_tid=(free:%d use:%d) observed_tid=(free:%s use:%s) tid_exact=%t recommend_half_window=%d",
				task.key, VarNamePairKey(&pair), samples.Count, expectedRepeats,
				pair.FreeSN, pair.UseSN, originField, samples.FreeMin, samples.FreeMax, samples.UseMin, samples.UseMax,
				formatSNDeltaRange(freeLow, freeHigh, freeOK), formatSNDeltaRange(useLow, useHigh, useOK),
				pair.FreeTid, pair.UseTid, formatInt32Counts(samples.FreeTidValues), formatInt32Counts(samples.UseTidValues),
				pairTIDExact(samples, pair), maxAbs)
			detailLogged++
		}
	}

	configField := "n/a"
	if configuredRange > 0 {
		configField = fmt.Sprintf("%d", configuredRange)
	}
	log.Logf(0, "uafvalidate: sn-drift summary key=%s stable_pairs=%d samples=%d with_original=%d full_observed=%d/%d repeat=%d stable_threshold=%d exact_sn=%d within_1=%d within_2=%d within_4=%d within_8=%d within_config_range=%d config_range=%s max_abs_delta=%d exact_tid=%d stable_tid=%d multi_tid=%d max_free_tid_values=%d max_use_tid_values=%d",
		task.key, len(stablePairs), withSamples, withOriginal, fullObserved, withSamples,
		expectedRepeats, requiredStableCount(expectedRepeats), exactSN, within1, within2, within4, within8,
		withinConfig, configField, maxAbsObserved, exactTID, stableTID, multiTID, maxFreeTIDVals, maxUseTIDVals)
}

func logTargetCollectionSummary(task *validationTask, result *ValidationResult, originalPairs []*ddrd.MayUAFPair, stablePairs []StablePairWithDelays, target string, stableThreshold int, replayEnabled bool) {
	if task == nil || result == nil || target == "" {
		return
	}
	var storedPairs []*ddrd.MayUAFPair
	historyCount := 0
	if task.entry != nil {
		storedPairs = task.entry.Pairs
		historyCount = len(task.entry.ReplayHistory)
	}
	log.Logf(0, "uafvalidate: target collection summary key=%s corpus_record=%s target=%s stored_target_pairs=%d origin_filter_target_pairs=%d latest_runtime_target_pairs=%d stable_target_pairs=%d stable_pairs=%d pair_keys_seen=%d repeat=%d/%d stable_threshold=%d replay_enabled=%t history=%d",
		task.key,
		func() string {
			if task.entry != nil {
				return task.entry.CorpusRecordID
			}
			return ""
		}(),
		target,
		countTargetPairs(storedPairs, target),
		countTargetPairs(originalPairs, target),
		countTargetPairsFromValues(result.Pairs, target),
		countTargetStablePairs(stablePairs, target),
		len(stablePairs),
		len(task.pairCounts),
		task.repeats+1,
		result.RepeatTotal,
		stableThreshold,
		replayEnabled && historyCount > 0,
		historyCount,
	)
}

func countTargetPairs(pairs []*ddrd.MayUAFPair, target string) int {
	if len(pairs) == 0 || target == "" {
		return 0
	}
	count := 0
	for _, pair := range pairs {
		if pairMatchesTargetVarName(pair, target) {
			count++
		}
	}
	return count
}

func countTargetPairsFromValues(pairs []ddrd.MayUAFPair, target string) int {
	if len(pairs) == 0 || target == "" {
		return 0
	}
	count := 0
	for i := range pairs {
		if pairMatchesTargetVarName(&pairs[i], target) {
			count++
		}
	}
	return count
}

func countTargetStablePairs(pairs []StablePairWithDelays, target string) int {
	if len(pairs) == 0 || target == "" {
		return 0
	}
	count := 0
	for i := range pairs {
		if pairMatchesTargetVarName(&pairs[i].Pair, target) {
			count++
		}
	}
	return count
}

func findOriginalPairForSNDrift(runtime ddrd.MayUAFPair, originalPairs []*ddrd.MayUAFPair, originMatchMode string) (ddrd.MayUAFPair, bool) {
	if len(originalPairs) == 0 {
		return ddrd.MayUAFPair{}, false
	}
	exact := pairKey(runtime)
	for _, pair := range originalPairs {
		if pair != nil && pairKey(*pair) == exact {
			return *pair, true
		}
	}
	origin := originMatchKey(runtime, originMatchMode)
	for _, pair := range originalPairs {
		if pair != nil && originMatchKey(*pair, originMatchMode) == origin {
			return *pair, true
		}
	}
	vn := varNamePairKey(runtime)
	for _, pair := range originalPairs {
		if pair != nil && varNamePairKey(*pair) == vn {
			return *pair, true
		}
	}
	return ddrd.MayUAFPair{}, false
}

func pairSNWithin(samples *snSampleStats, original ddrd.MayUAFPair, halfWindow int) bool {
	if samples == nil {
		return false
	}
	return sideSNWithin(samples.FreeMin, samples.FreeMax, original.FreeSN, halfWindow) &&
		sideSNWithin(samples.UseMin, samples.UseMax, original.UseSN, halfWindow)
}

func pairTIDExact(samples *snSampleStats, ref ddrd.MayUAFPair) bool {
	if samples == nil || samples.Count == 0 {
		return false
	}
	return len(samples.FreeTidValues) == 1 && samples.FreeTidValues[ref.FreeTid] == samples.Count &&
		len(samples.UseTidValues) == 1 && samples.UseTidValues[ref.UseTid] == samples.Count
}

func pairTIDStable(samples *snSampleStats) bool {
	if samples == nil || samples.Count == 0 {
		return false
	}
	return len(samples.FreeTidValues) == 1 && len(samples.UseTidValues) == 1
}

func sideSNWithin(observedMin, observedMax, original int32, halfWindow int) bool {
	if original <= 0 {
		return true
	}
	if observedMin <= 0 || observedMax <= 0 {
		return false
	}
	return int(observedMin) >= int(original)-halfWindow && int(observedMax) <= int(original)+halfWindow
}

func pairMaxAbsSNDelta(samples *snSampleStats, original ddrd.MayUAFPair) int32 {
	var maxAbs int32
	if low, high, ok := sideSNDeltaRange(samples.FreeMin, samples.FreeMax, original.FreeSN); ok {
		maxAbs = max32(maxAbs, abs32(low))
		maxAbs = max32(maxAbs, abs32(high))
	}
	if low, high, ok := sideSNDeltaRange(samples.UseMin, samples.UseMax, original.UseSN); ok {
		maxAbs = max32(maxAbs, abs32(low))
		maxAbs = max32(maxAbs, abs32(high))
	}
	return maxAbs
}

func sideSNDeltaRange(observedMin, observedMax, original int32) (int32, int32, bool) {
	if original <= 0 || observedMin <= 0 || observedMax <= 0 {
		return 0, 0, false
	}
	return observedMin - original, observedMax - original, true
}

func formatSNDeltaRange(low, high int32, ok bool) string {
	if !ok {
		return "n/a"
	}
	if low == high {
		return fmt.Sprintf("%+d", low)
	}
	return fmt.Sprintf("%+d..%+d", low, high)
}

func formatInt32Counts(values map[int32]int) string {
	if len(values) == 0 {
		return "n/a"
	}
	keys := make([]int, 0, len(values))
	for value := range values {
		keys = append(keys, int(value))
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value := int32(key)
		parts = append(parts, fmt.Sprintf("%d:%d", value, values[value]))
	}
	return strings.Join(parts, ",")
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}

func max32(a, b int32) int32 {
	if b > a {
		return b
	}
	return a
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

func collectStablePairs(latest map[string]ddrd.MayUAFPair, counts map[string]int, minCount int, originalPairs []*ddrd.MayUAFPair, skipOriginalCheck bool, originMatchMode string, maxPerOrigin int, maxPerEntry int) []ddrd.MayUAFPair {
	if len(latest) == 0 || len(counts) == 0 {
		return nil
	}
	if minCount <= 1 {
		minCount = 1
	}
	originalKeys, _ := buildOriginalMatchIndexes(originalPairs, originMatchMode)
	keys := make([]string, 0, len(counts))
	for key, count := range counts {
		if count < minCount {
			continue
		}
		pair, ok := latest[key]
		if !ok {
			continue
		}
		// Additional condition: pair must exist in original corpus pairs
		// In debug mode (skipOriginalCheck=true), skip this check to allow any runtime-discovered pairs.
		if !skipOriginalCheck && len(originalKeys) > 0 {
			if _, inOriginal := originalKeys[originMatchKey(pair, originMatchMode)]; !inOriginal {
				continue
			}
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil
	}
	sortStablePairKeys(keys, latest, counts, originalPairs, originMatchMode)
	keys = limitKeysPerOrigin(keys, latest, originMatchMode, maxPerOrigin)
	keys = limitKeysPerEntry(keys, maxPerEntry)
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
	skipOriginalCheck bool,
	originMatchMode string,
	maxPerOrigin int,
	maxPerEntry int,
) []StablePairWithDelays {
	if len(latest) == 0 || len(counts) == 0 {
		return nil
	}
	if minCount <= 1 {
		minCount = 1
	}
	originalKeys, originalTDByMatchKey := buildOriginalMatchIndexes(originalPairs, originMatchMode)
	keys := make([]string, 0, len(counts))
	for key, count := range counts {
		if count < minCount {
			continue
		}
		pair, ok := latest[key]
		if !ok {
			continue
		}
		// Additional condition: pair must exist in original corpus pairs
		// In debug mode (skipOriginalCheck=true), skip this check to allow any runtime-discovered pairs
		if !skipOriginalCheck && len(originalKeys) > 0 {
			if _, inOriginal := originalKeys[originMatchKey(pair, originMatchMode)]; !inOriginal {
				continue
			}
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil
	}
	sortStablePairKeys(keys, latest, counts, originalPairs, originMatchMode)
	keys = limitKeysPerOrigin(keys, latest, originMatchMode, maxPerOrigin)
	keys = limitKeysPerEntry(keys, maxPerEntry)
	result := make([]StablePairWithDelays, 0, len(keys))
	for _, key := range keys {
		pair := latest[key]
		runtimeTD := pair.TimeDiff // nanoseconds from runtime observation
		origTD := originalTD[key]  // nanoseconds from original corpus entry
		if origTD == 0 {
			origTD = originalTDByMatchKey[originMatchKey(pair, originMatchMode)]
		}
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

func varNamePairKey(pair ddrd.MayUAFPair) string {
	return fmt.Sprintf("%016x-%016x", pair.FreeAccessName, pair.UseAccessName)
}

func normalizeOriginMatchMode(mode string) string {
	switch mode {
	case OriginMatchModeVarName, OriginMatchModePrimaryVarName:
		return mode
	default:
		return OriginMatchModeExact
	}
}

func originKeyMode(mode string) string {
	if normalizeOriginMatchMode(mode) == OriginMatchModeExact {
		return OriginMatchModeExact
	}
	return OriginMatchModeVarName
}

func primaryOriginPairs(entry *fuzzer.UAFCorpusEntry) []*ddrd.MayUAFPair {
	if entry == nil {
		return nil
	}
	pair := entry.PairBasicInfo
	if pair.UAFPairID() == 0 && !IsZeroSignature(entry.Profile) {
		pair = ddrd.MayUAFPair{
			FreeAccessName: entry.Profile.FreeAccessName,
			UseAccessName:  entry.Profile.UseAccessName,
			FreeCallStack:  entry.Profile.FreeCallStack,
			UseCallStack:   entry.Profile.UseCallStack,
		}
	}
	if pair.UAFPairID() == 0 {
		return nil
	}
	return []*ddrd.MayUAFPair{&pair}
}

func originMatchKey(pair ddrd.MayUAFPair, mode string) string {
	if originKeyMode(mode) == OriginMatchModeVarName {
		return varNamePairKey(pair)
	}
	return pairKey(pair)
}

func buildOriginalMatchIndexes(originalPairs []*ddrd.MayUAFPair, mode string) (map[string]struct{}, map[string]uint64) {
	keys := make(map[string]struct{}, len(originalPairs))
	timeDiffs := make(map[string]uint64, len(originalPairs))
	for _, pair := range originalPairs {
		if pair == nil {
			continue
		}
		key := originMatchKey(*pair, mode)
		keys[key] = struct{}{}
		if pair.TimeDiff != 0 {
			if cur := timeDiffs[key]; cur == 0 || pair.TimeDiff < cur {
				timeDiffs[key] = pair.TimeDiff
			}
		}
	}
	return keys, timeDiffs
}

func buildExactOriginalIndex(originalPairs []*ddrd.MayUAFPair) map[string]uint64 {
	timeDiffs := make(map[string]uint64, len(originalPairs))
	for _, pair := range originalPairs {
		if pair == nil {
			continue
		}
		key := pairKey(*pair)
		if pair.TimeDiff != 0 {
			if cur := timeDiffs[key]; cur == 0 || pair.TimeDiff < cur {
				timeDiffs[key] = pair.TimeDiff
			}
			continue
		}
		if _, ok := timeDiffs[key]; !ok {
			timeDiffs[key] = 0
		}
	}
	return timeDiffs
}

func sortStablePairKeys(keys []string, latest map[string]ddrd.MayUAFPair, counts map[string]int, originalPairs []*ddrd.MayUAFPair, originMatchMode string) {
	exactOriginalTD := buildExactOriginalIndex(originalPairs)
	_, originalTDByMatchKey := buildOriginalMatchIndexes(originalPairs, originMatchMode)
	sort.Slice(keys, func(i, j int) bool {
		ki, kj := keys[i], keys[j]
		pi, iok := latest[ki]
		pj, jok := latest[kj]
		if iok != jok {
			return iok
		}
		if !iok {
			return ki < kj
		}

		_, exactI := exactOriginalTD[pairKey(pi)]
		_, exactJ := exactOriginalTD[pairKey(pj)]
		if exactI != exactJ {
			return exactI
		}

		if counts[ki] != counts[kj] {
			return counts[ki] > counts[kj]
		}

		di := stablePairTimeDiffDelta(pi, exactOriginalTD, originalTDByMatchKey, originMatchMode)
		dj := stablePairTimeDiffDelta(pj, exactOriginalTD, originalTDByMatchKey, originMatchMode)
		if di != dj {
			return di < dj
		}

		return ki < kj
	})
}

func stablePairTimeDiffDelta(pair ddrd.MayUAFPair, exactOriginalTD map[string]uint64, originalTDByMatchKey map[string]uint64, originMatchMode string) uint64 {
	orig := exactOriginalTD[pairKey(pair)]
	if orig == 0 {
		orig = originalTDByMatchKey[originMatchKey(pair, originMatchMode)]
	}
	if orig == 0 || pair.TimeDiff == 0 {
		return ^uint64(0)
	}
	if pair.TimeDiff > orig {
		return pair.TimeDiff - orig
	}
	return orig - pair.TimeDiff
}

func limitKeysPerOrigin(keys []string, latest map[string]ddrd.MayUAFPair, mode string, maxPerOrigin int) []string {
	if maxPerOrigin <= 0 || len(keys) <= maxPerOrigin {
		return keys
	}
	counts := make(map[string]int)
	limited := make([]string, 0, len(keys))
	for _, key := range keys {
		pair, ok := latest[key]
		if !ok {
			continue
		}
		originKey := originMatchKey(pair, mode)
		if counts[originKey] >= maxPerOrigin {
			continue
		}
		counts[originKey]++
		limited = append(limited, key)
	}
	return limited
}

func limitKeysPerEntry(keys []string, maxPerEntry int) []string {
	if maxPerEntry <= 0 || len(keys) <= maxPerEntry {
		return keys
	}
	return keys[:maxPerEntry]
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

func targetCorpusKeyMatches(target, signatureKey, corpusRecordID string) bool {
	if target == "" {
		return true
	}
	if signatureKey != "" && target == signatureKey {
		return true
	}
	if corpusRecordID == "" {
		return false
	}
	return target == corpusRecordID || target == "corpus-"+corpusRecordID
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

func targetPairForMatchMode(pair ddrd.MayUAFPair, mode string) ddrd.MayUAFPair {
	switch NormalizeTargetMatchMode(mode) {
	case TargetMatchModeSNOnly, TargetMatchModeSNRangeOnly:
		pair.FreeCallStack = 0
		pair.UseCallStack = 0
		pair.FreeSNMin = 0
		pair.FreeSNMax = 0
		pair.UseSNMin = 0
		pair.UseSNMax = 0
		pair.FreeTid = 0
		pair.UseTid = 0
	case TargetMatchModeSiteOnly:
		pair.FreeCallStack = 0
		pair.UseCallStack = 0
		pair.FreeSN = 0
		pair.UseSN = 0
		pair.FreeSNMin = 0
		pair.FreeSNMax = 0
		pair.UseSNMin = 0
		pair.UseSNMax = 0
		pair.FreeTid = 0
		pair.UseTid = 0
	case TargetMatchModeStackOnly:
		pair.FreeSN = 0
		pair.UseSN = 0
		pair.FreeSNMin = 0
		pair.FreeSNMax = 0
		pair.UseSNMin = 0
		pair.UseSNMax = 0
		pair.FreeTid = 0
		pair.UseTid = 0
	default:
		pair.FreeSNMin = 0
		pair.FreeSNMax = 0
		pair.UseSNMin = 0
		pair.UseSNMax = 0
	}
	return pair
}

type targetMatchAttempt struct {
	mode string
	pair ddrd.MayUAFPair
}

func targetMatchAttempts(pair ddrd.MayUAFPair, mode string, cfg Config) []targetMatchAttempt {
	var attempts []targetMatchAttempt
	switch NormalizeTargetMatchMode(mode) {
	case TargetMatchModeStrictSN:
		attempts = []targetMatchAttempt{{mode: TargetMatchModeStrictSN, pair: targetPairForMatchMode(pair, TargetMatchModeStrictSN)}}
	case TargetMatchModeSNRange:
		if rangePair, ok := targetPairForSNRange(pair, cfg.SNFallbackRange); ok {
			attempts = []targetMatchAttempt{{mode: TargetMatchModeSNRange, pair: rangePair}}
			break
		}
		attempts = []targetMatchAttempt{{mode: TargetMatchModeStackOnly, pair: targetPairForMatchMode(pair, TargetMatchModeStackOnly)}}
	case TargetMatchModeSNOnly:
		attempts = []targetMatchAttempt{{mode: TargetMatchModeSNOnly, pair: targetPairForMatchMode(pair, TargetMatchModeSNOnly)}}
	case TargetMatchModeSNRangeOnly:
		if rangePair, ok := targetPairForSNRangeOnly(pair, cfg.SNFallbackRange); ok {
			attempts = []targetMatchAttempt{{mode: TargetMatchModeSNRangeOnly, pair: rangePair}}
			break
		}
		attempts = []targetMatchAttempt{{mode: TargetMatchModeSNOnly, pair: targetPairForMatchMode(pair, TargetMatchModeSNOnly)}}
	case TargetMatchModeStackOnly:
		attempts = []targetMatchAttempt{{mode: TargetMatchModeStackOnly, pair: targetPairForMatchMode(pair, TargetMatchModeStackOnly)}}
	case TargetMatchModeSiteOnly:
		attempts = []targetMatchAttempt{{mode: TargetMatchModeSiteOnly, pair: targetPairForMatchMode(pair, TargetMatchModeSiteOnly)}}
	default:
		attempts = []targetMatchAttempt{{mode: TargetMatchModeStrictSN, pair: targetPairForMatchMode(pair, TargetMatchModeStrictSN)}}
		if rangePair, ok := targetPairForSNRange(pair, cfg.SNFallbackRange); ok {
			attempts = append(attempts, targetMatchAttempt{mode: TargetMatchModeSNRange, pair: rangePair})
		}
		attempts = append(attempts, targetMatchAttempt{mode: TargetMatchModeStackOnly, pair: targetPairForMatchMode(pair, TargetMatchModeStackOnly)})
	}
	return applyTargetTIDPolicy(attempts, cfg)
}

func applyTargetTIDPolicy(attempts []targetMatchAttempt, cfg Config) []targetMatchAttempt {
	if !cfg.WildcardTargetTID {
		return attempts
	}
	for i := range attempts {
		attempts[i].pair.FreeTid = 0
		attempts[i].pair.UseTid = 0
	}
	return attempts
}

func targetPairForSNRange(pair ddrd.MayUAFPair, halfWindow int) (ddrd.MayUAFPair, bool) {
	if halfWindow <= 0 || (pair.FreeSN <= 0 && pair.UseSN <= 0) {
		return ddrd.MayUAFPair{}, false
	}
	pair = targetPairForMatchMode(pair, TargetMatchModeStrictSN)
	pair.FreeTid = 0
	pair.UseTid = 0
	var ok bool
	pair.FreeSNMin, pair.FreeSNMax, ok = snBounds(pair.FreeSN, halfWindow)
	if !ok {
		pair.FreeSN = 0
	}
	pair.UseSNMin, pair.UseSNMax, ok = snBounds(pair.UseSN, halfWindow)
	if !ok {
		pair.UseSN = 0
	}
	return pair, pair.FreeSNMin != 0 || pair.FreeSNMax != 0 || pair.UseSNMin != 0 || pair.UseSNMax != 0
}

func targetPairForSNRangeOnly(pair ddrd.MayUAFPair, halfWindow int) (ddrd.MayUAFPair, bool) {
	pair, ok := targetPairForSNRange(pair, halfWindow)
	if !ok {
		return ddrd.MayUAFPair{}, false
	}
	pair.FreeCallStack = 0
	pair.UseCallStack = 0
	pair.FreeTid = 0
	pair.UseTid = 0
	return pair, true
}

func snBounds(sn int32, halfWindow int) (int32, int32, bool) {
	if sn <= 0 || halfWindow < 0 {
		return 0, 0, false
	}
	min := int(sn) - halfWindow
	if min < 1 {
		min = 1
	}
	max := int(sn) + halfWindow
	if max > math.MaxInt32 {
		max = math.MaxInt32
	}
	return int32(min), int32(max), true
}

func targetMatchAttemptsForLog(req *ExecutionRequest, runs int) int {
	if req == nil || runs <= 0 {
		return 0
	}
	if req.RepeatTimes <= 0 {
		return runs
	}
	return runs * req.RepeatTimes
}

func (sm *StageManager) runVerificationAttempt(ctx context.Context, task *validationTask,
	req *ExecutionRequest, attemptMode string) (*ExecutionResult, error) {
	exec, err := sm.factory(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closer, ok := exec.(interface{ Close() error }); ok {
			if cerr := closer.Close(); cerr != nil {
				log.Logf(0, "uafvalidate: verification executor close error key=%s mode=%s err=%v",
					task.key, attemptMode, cerr)
			}
		}
	}()
	res, runErr := sm.runBatchReplayAndVerify(ctx, exec, task, req)
	logUAFProbeOutput(task.key, attemptMode, res)
	return res, runErr
}

func logUAFProbeOutput(key, attemptMode string, res *ExecutionResult) {
	if res == nil || len(res.Output) == 0 {
		return
	}
	const prefix = "[KCCWF"
	for _, line := range strings.Split(string(res.Output), "\n") {
		if !strings.Contains(line, prefix) {
			continue
		}
		if strings.Contains(line, "UAF_TARGET") || strings.Contains(line, "UAF pair") {
			log.Logf(1, "uafvalidate: kernel target trace key=%s mode=%s %s", key, attemptMode, line)
		}
	}
}

func (sm *StageManager) runVerificationPhase(ctx context.Context, task *validationTask, stablePairs []ddrd.MayUAFPair) VerificationSummary {
	matchMode := NormalizeTargetMatchMode(sm.cfg.TargetMatchMode)
	log.Logf(0, "uafvalidate: starting verification phase for key=%s pairs=%d target_match_mode=%s",
		task.key, len(stablePairs), matchMode)

	var (
		skippedDebug        int
		skippedInvalid      int
		skippedValidated    int
		skippedBackoff      int
		executedPairs       int
		validatedPairs      int
		failedPairs         int
		strictSuccesses     int
		fallbackRuns        int
		fallbackSuccess     int
		snRangeRuns         int
		snRangeSuccess      int
		stackRuns           int
		stackSuccess        int
		siteOnlySuccess     int
		observedTargets     int
		nonblockingObserved int
	)

	for i, pair := range stablePairs {
		if ctx.Err() != nil {
			return VerificationSummary{
				ExecutedPairs:         executedPairs,
				SkippedPairs:          skippedDebug + skippedInvalid + skippedValidated + skippedBackoff,
				ValidatedPairs:        validatedPairs,
				FailedPairs:           failedPairs,
				SkippedValidatedPairs: skippedValidated,
			}
		}

		fullKey := pairKey(pair)       // Full key (with CallStack)
		vnKey := VarNamePairKey(&pair) // VarName key (without CallStack)

		// ========== Layer 1: Exact match skip ==========
		if sm.isInvalid(fullKey) {
			skippedInvalid++
			log.Logf(1, "uafvalidate: L1 skip (exact) pair %d/%d key=%s", i+1, len(stablePairs), task.key)
			continue
		}

		if sm.isValidated(fullKey) {
			skippedValidated++
			log.Logf(1, "uafvalidate: skipping validated pair %d/%d for key=%s", i+1, len(stablePairs), task.key)
			continue
		}

		// ========== Layer 2: VarName probabilistic backoff ==========
		if sm.varNameBackoffStore != nil {
			skip, prob, stats := sm.varNameBackoffStore.ShouldSkip(&pair, rand.Float64)
			if skip {
				skippedBackoff++
				log.Logf(1, "uafvalidate: L2 skip (backoff) pair %d/%d vnkey=%s score=%.2f prob=%.2f failures=%d successes=%d",
					i+1, len(stablePairs), vnKey, stats.BackoffScore(), prob, stats.Failures, stats.Successes)
				continue
			}
			if prob > 0 {
				log.Logf(1, "uafvalidate: L2 pass (backoff) pair %d/%d vnkey=%s score=%.2f prob=%.2f",
					i+1, len(stablePairs), vnKey, stats.BackoffScore(), prob)
			}
		}

		// ========== Execute verification ==========
		log.Logf(1, "uafvalidate: verifying pair %d/%d for key=%s vnkey=%016x-%016x-%016x-%016x",
			i+1, len(stablePairs), task.key,
			pair.FreeAccessName, pair.UseAccessName, pair.FreeCallStack, pair.UseCallStack)

		var (
			pairCopy    ddrd.MayUAFPair
			req         *ExecutionRequest
			execRes     *ExecutionResult
			runErr      error
			attemptMode string
			attemptRuns int
		)
		attempts := targetMatchAttempts(pair, matchMode, sm.cfg)
		for attemptIndex, attempt := range attempts {
			attemptMode = attempt.mode
			pairCopy = attempt.pair
			if sm.cfg.DisableAccessDelay {
				pairCopy.TimeDiff = 0
			}
			req = &ExecutionRequest{
				Entry:                 task.entry,
				Delays:                sm.delay.BuildDelays(task.entry),
				TargetPair:            &pairCopy,
				RepeatTimes:           sm.cfg.VerifyRepeatTimes,
				DisableDdrd:           !sm.cfg.VerifyCollectPairs,
				StopOnSuccess:         true,
				ObserveTargetPairOnly: sm.cfg.VerifyCollectPairs,
				TargetDelaySide:       sm.cfg.TargetDelaySide,
				TargetDelaySideKernel: TargetDelaySideID(sm.cfg.TargetDelaySide),
				TargetDelayMode:       sm.cfg.TargetDelayMode,
				TargetDelayModeKernel: TargetDelayModeID(sm.cfg.TargetDelayMode),
			}
			log.Logf(1, "uafvalidate: target match attempt key=%s mode=%s target_delay_side=%s target_delay_mode=%s stack=(free:%016x use:%016x) sn=(free:%d use:%d) sn_range=(free:%d-%d use:%d-%d) tid=(free:%d use:%d)",
				task.key, attemptMode, req.TargetDelaySide, req.TargetDelayMode, pairCopy.FreeCallStack, pairCopy.UseCallStack,
				pairCopy.FreeSN, pairCopy.UseSN, pairCopy.FreeSNMin, pairCopy.FreeSNMax,
				pairCopy.UseSNMin, pairCopy.UseSNMax, pairCopy.FreeTid, pairCopy.UseTid)
			execRes, runErr = sm.runVerificationAttempt(ctx, task, req, attemptMode)
			attemptRuns++
			if matchMode == TargetMatchModeSNFallback && attemptMode != TargetMatchModeStrictSN {
				fallbackRuns++
			}
			switch attemptMode {
			case TargetMatchModeSNRange:
				snRangeRuns++
			case TargetMatchModeStackOnly:
				stackRuns++
			}
			if runErr != nil || execRes == nil || execRes.TriggeredCount > 0 || attemptIndex == len(attempts)-1 {
				break
			}
			nextMode := attempts[attemptIndex+1].mode
			log.Logf(1, "uafvalidate: target match mode %s missed for key=%s vnkey=%s; retrying %s fallback",
				attemptMode, task.key, vnKey, nextMode)
		}

		// Extract crash info
		crashInfo := ""
		if execRes != nil && execRes.Crashed && execRes.CrashTitle != "" {
			crashInfo = fmt.Sprintf(" crash=%q", execRes.CrashTitle)
		}
		executedPairs++
		if execRes != nil {
			observedTargets += execRes.ObservedTargetCount
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
		statusDetail := ""
		if execRes.TriggeredCount > 0 {
			status = "Triggered"
		} else if execRes.Crashed && execRes.CrashTitle != "" {
			// Crash happened but target pair was not triggered - different race detected
			statusDetail = " (crashed with different race, target pair not matched)"
		}

		totalAttempts := targetMatchAttemptsForLog(req, attemptRuns)
		log.Logf(1, "uafvalidate: verification run finished duration=%s crashed=%t%s triggered=%d/%d observed_target=%d status=%s%s target_match_mode=%s final_attempt_mode=%s",
			execRes.Duration, execRes.Crashed, crashInfo, execRes.TriggeredCount, totalAttempts, execRes.ObservedTargetCount, status, statusDetail,
			matchMode, attemptMode)

		nonblockingEvidence := req != nil &&
			NormalizeTargetDelayMode(req.TargetDelayMode) == TargetDelayModeNonblocking &&
			execRes.TriggeredCount > 0
		if nonblockingEvidence {
			nonblockingObserved++
			log.Logf(0, "uafvalidate: nonblocking target observed after %d trigger(s); treating as candidate evidence only, not validated target_match_mode=%s final_attempt_mode=%s",
				execRes.TriggeredCount, matchMode, attemptMode)
			continue
		}

		if execRes.TriggeredCount > 0 {
			// ========== Success: proves this VarName pair can trigger ==========
			validatedPairs++
			switch {
			case attemptMode == TargetMatchModeStrictSN:
				strictSuccesses++
			case attemptMode == TargetMatchModeSNRange:
				snRangeSuccess++
				if matchMode == TargetMatchModeSNFallback {
					fallbackSuccess++
				}
			case attemptMode == TargetMatchModeStackOnly:
				stackSuccess++
				if matchMode == TargetMatchModeSNFallback {
					fallbackSuccess++
				}
			case attemptMode == TargetMatchModeSiteOnly:
				siteOnlySuccess++
				if matchMode == TargetMatchModeSNFallback {
					fallbackSuccess++
				}
			}

			// Try to minimize history if enabled
			var minimizedHistory []*fuzzer.BarrierExecutionRecord
			if sm.cfg.EnableHistoryMinimization && len(task.entry.ReplayHistory) > 1 {
				log.Logf(0, "uafvalidate: starting history minimization for key=%s", task.key)
				minimizer := sm.newHistoryMinimizer(task, &pairCopy, req.Delays)
				minResult := minimizer.Minimize(ctx)
				if minResult.Success && minResult.MinimalHistory != nil {
					minimizedHistory = minResult.MinimalHistory
					log.Logf(0, "uafvalidate: minimization complete: %d -> %d records",
						minResult.OriginalCount, minResult.MinimalCount)
				} else if minResult.Error != nil {
					log.Logf(0, "uafvalidate: minimization failed: %v", minResult.Error)
				}
			}

			// Serialize the validated entry including triggering programs and minimized history
			reportData := serializeValidatedEntryWithHistory(execRes, task.entry, minimizedHistory)
			sm.markValidated(fullKey, reportData)
			if sm.cfg.PairStatusSink != nil {
				sm.cfg.PairStatusSink.MarkPairValidated(pair, reportData)
			}

			// Update VarName backoff statistics (success) and mark as verified
			// This will cause ALL future entries with the same VarName pair to be skipped
			if sm.varNameBackoffStore != nil {
				sm.varNameBackoffStore.RecordSuccessWithKey(&pair, task.key)
				stats := sm.varNameBackoffStore.GetByPair(&pair)
				log.Logf(0, "uafvalidate: pair validated, backoff score updated: vnkey=%s new_score=%.2f verified=%t",
					vnKey, stats.BackoffScore(), stats.IsVerified())
			}

			// Log a summary (not full data to avoid log flooding)
			reportPreview := string(reportData)
			if len(reportPreview) > 2000 {
				reportPreview = reportPreview[:2000] + "...[truncated]"
			}
			log.Logf(0, "uafvalidate: pair validated after %d trigger(s) target_match_mode=%s final_attempt_mode=%s\n%s",
				execRes.TriggeredCount, matchMode, attemptMode, reportPreview)
			continue
		}

		// ========== Failure: increase backoff score ==========
		failedPairs++
		// Layer 1: Mark this exact pair as invalid
		sm.markInvalid(fullKey)
		if sm.cfg.PairStatusSink != nil {
			sm.cfg.PairStatusSink.MarkPairInvalid(pair)
		}

		// Layer 2: Update VarName backoff statistics (failure)
		if sm.varNameBackoffStore != nil {
			sm.varNameBackoffStore.RecordFailure(&pair)
			stats := sm.varNameBackoffStore.GetByPair(&pair)
			log.Logf(1, "uafvalidate: pair failed verification, backoff score updated: vnkey=%s new_score=%.2f skip_prob=%.2f",
				vnKey, stats.BackoffScore(), stats.SkipProbability())
		}
	}

	skippedPairs := skippedDebug + skippedInvalid + skippedValidated + skippedBackoff
	handledPairs := executedPairs + skippedPairs
	log.Logf(0, "uafvalidate: verification phase summary key=%s target_match_mode=%s pairs=%d handled=%d executed=%d skipped=%d executed_verify_pairs=%d skipped_pairs=%d skipped_debug=%d skipped_invalid=%d skipped_validated=%d skipped_backoff=%d validated=%d failed=%d strict_success=%d fallback_runs=%d fallback_success=%d site_only_success=%d observed_target=%d nonblocking_observed=%d sn_range_runs=%d sn_range_success=%d stack_fallback_runs=%d stack_fallback_success=%d",
		task.key, matchMode, len(stablePairs), handledPairs, executedPairs, skippedPairs,
		executedPairs, skippedPairs, skippedDebug, skippedInvalid, skippedValidated, skippedBackoff,
		validatedPairs, failedPairs, strictSuccesses, fallbackRuns, fallbackSuccess, siteOnlySuccess, observedTargets, nonblockingObserved,
		snRangeRuns, snRangeSuccess, stackRuns, stackSuccess)

	// Output statistics summary
	if sm.varNameBackoffStore != nil {
		total, highScore, verified := sm.varNameBackoffStore.Stats()
		log.Logf(0, "uafvalidate: verification phase complete, VarName backoff stats: total=%d high_score=%d verified=%d", total, highScore, verified)
	}
	return VerificationSummary{
		ExecutedPairs:         executedPairs,
		SkippedPairs:          skippedPairs,
		ValidatedPairs:        validatedPairs,
		FailedPairs:           failedPairs,
		SkippedValidatedPairs: skippedValidated,
	}
}

// runVerificationPhaseWithDelays runs verification using per-pair computed delays:
// - StartDelayUs (original delay, same as discovery) for barrier start delay
// - AccessDelayUs (max of original/runtime) for kernel UAF access delay
func (sm *StageManager) runVerificationPhaseWithDelays(ctx context.Context, task *validationTask, stablePairs []StablePairWithDelays) VerificationSummary {
	debugMode := sm.cfg.TargetVarNamePair != ""
	matchMode := NormalizeTargetMatchMode(sm.cfg.TargetMatchMode)
	if debugMode {
		log.Logf(0, "uafvalidate: [debug mode] starting verification phase for key=%s pairs=%d target=%s target_match_mode=%s",
			task.key, len(stablePairs), sm.cfg.TargetVarNamePair, matchMode)
	} else {
		log.Logf(0, "uafvalidate: starting verification phase (with delays) for key=%s pairs=%d target_match_mode=%s",
			task.key, len(stablePairs), matchMode)
	}

	var (
		skippedDebug        int
		skippedInvalid      int
		skippedValidated    int
		skippedBackoff      int
		executedPairs       int
		validatedPairs      int
		failedPairs         int
		strictSuccesses     int
		fallbackRuns        int
		fallbackSuccess     int
		snRangeRuns         int
		snRangeSuccess      int
		stackRuns           int
		stackSuccess        int
		siteOnlySuccess     int
		observedTargets     int
		nonblockingObserved int
	)

	for i, spd := range stablePairs {
		if ctx.Err() != nil {
			return VerificationSummary{
				ExecutedPairs:         executedPairs,
				SkippedPairs:          skippedDebug + skippedInvalid + skippedValidated + skippedBackoff,
				ValidatedPairs:        validatedPairs,
				FailedPairs:           failedPairs,
				SkippedValidatedPairs: skippedValidated,
			}
		}

		pair := spd.Pair
		fullKey := pairKey(pair)       // Full key (with CallStack)
		vnKey := VarNamePairKey(&pair) // VarName key (without CallStack)

		// In debug mode, only verify pairs matching the target VarName
		if debugMode {
			if !pairMatchesTargetVarName(&pair, sm.cfg.TargetVarNamePair) {
				skippedDebug++
				log.Logf(1, "uafvalidate: [debug mode] skipping non-target pair %d/%d vnkey=%s", i+1, len(stablePairs), vnKey)
				continue
			}
			log.Logf(1, "uafvalidate: [debug mode] verifying target pair %d/%d vnkey=%s fullkey=%s",
				i+1, len(stablePairs), vnKey, fullKey)
		} else if !sm.cfg.DisableBackoffSkip && !sm.isBackoffPhaseComplete() {
			// ========== Normal mode: Layer 1 & 2 skip checks ==========
			// (Skipped when DisableBackoffSkip is enabled or the backoff phase is already complete)
			// ========== Layer 1: Exact match skip ==========
			if sm.isInvalid(fullKey) {
				skippedInvalid++
				log.Logf(1, "uafvalidate: L1 skip (exact) pair %d/%d key=%s", i+1, len(stablePairs), task.key)
				continue
			}

			if sm.isValidated(fullKey) {
				skippedValidated++
				log.Logf(1, "uafvalidate: skipping validated pair %d/%d for key=%s", i+1, len(stablePairs), task.key)
				continue
			}

			// ========== Layer 2: VarName probabilistic backoff ==========
			if sm.varNameBackoffStore != nil {
				skip, prob, stats := sm.varNameBackoffStore.ShouldSkip(&pair, rand.Float64)
				if skip {
					skippedBackoff++
					log.Logf(1, "uafvalidate: L2 skip (backoff) pair %d/%d vnkey=%s score=%.2f prob=%.2f failures=%d successes=%d",
						i+1, len(stablePairs), vnKey, stats.BackoffScore(), prob, stats.Failures, stats.Successes)
					continue
				}
				if prob > 0 {
					log.Logf(1, "uafvalidate: L2 pass (backoff) pair %d/%d vnkey=%s score=%.2f prob=%.2f",
						i+1, len(stablePairs), vnKey, stats.BackoffScore(), prob)
				}
			}
		}

		// Build start delays array using spd.StartDelayUs for the first participant
		startDelays := buildStartDelaysFromPair(task.entry, spd.StartDelayUs)

		// If DisableVerifyDelay is enabled, disable start delays in verification phase
		actualStartDelayUs := spd.StartDelayUs
		if sm.cfg.DisableVerifyDelay {
			startDelays = nil
			actualStartDelayUs = 0
		}
		actualAccessDelayUs := verificationAccessDelayUs(spd.AccessDelayUs, sm.cfg)

		// ========== Execute verification ==========
		log.Logf(1, "uafvalidate: verifying pair %d/%d for key=%s vnkey=%016x-%016x-%016x-%016x start_delay=%dus access_delay=%dus",
			i+1, len(stablePairs), task.key,
			pair.FreeAccessName, pair.UseAccessName, pair.FreeCallStack, pair.UseCallStack,
			actualStartDelayUs, actualAccessDelayUs)

		var (
			pairCopy    ddrd.MayUAFPair
			req         *ExecutionRequest
			execRes     *ExecutionResult
			runErr      error
			attemptMode string
			attemptRuns int
		)
		attempts := targetMatchAttempts(pair, matchMode, sm.cfg)
		for attemptIndex, attempt := range attempts {
			attemptMode = attempt.mode
			pairCopy = attempt.pair
			pairCopy.TimeDiff = uint64(actualAccessDelayUs) * 1000 // Convert to nanoseconds for ukcDelayMicros

			req = &ExecutionRequest{
				Entry:                 task.entry,
				Delays:                startDelays,
				TargetPair:            &pairCopy,
				RepeatTimes:           sm.cfg.VerifyRepeatTimes,
				DisableDdrd:           !sm.cfg.VerifyCollectPairs,
				StopOnSuccess:         true,
				ObserveTargetPairOnly: sm.cfg.VerifyCollectPairs,
				StartDelayUs:          actualStartDelayUs,
				AccessDelayUs:         actualAccessDelayUs,
				TargetDelaySide:       sm.cfg.TargetDelaySide,
				TargetDelaySideKernel: TargetDelaySideID(sm.cfg.TargetDelaySide),
				TargetDelayMode:       sm.cfg.TargetDelayMode,
				TargetDelayModeKernel: TargetDelayModeID(sm.cfg.TargetDelayMode),
			}
			log.Logf(1, "uafvalidate: target match attempt key=%s mode=%s target_delay_side=%s target_delay_mode=%s stack=(free:%016x use:%016x) sn=(free:%d use:%d) sn_range=(free:%d-%d use:%d-%d) tid=(free:%d use:%d)",
				task.key, attemptMode, req.TargetDelaySide, req.TargetDelayMode, pairCopy.FreeCallStack, pairCopy.UseCallStack,
				pairCopy.FreeSN, pairCopy.UseSN, pairCopy.FreeSNMin, pairCopy.FreeSNMax,
				pairCopy.UseSNMin, pairCopy.UseSNMax, pairCopy.FreeTid, pairCopy.UseTid)
			execRes, runErr = sm.runVerificationAttempt(ctx, task, req, attemptMode)
			attemptRuns++
			if matchMode == TargetMatchModeSNFallback && attemptMode != TargetMatchModeStrictSN {
				fallbackRuns++
			}
			switch attemptMode {
			case TargetMatchModeSNRange:
				snRangeRuns++
			case TargetMatchModeStackOnly:
				stackRuns++
			}
			if runErr != nil || execRes == nil || execRes.TriggeredCount > 0 || attemptIndex == len(attempts)-1 {
				break
			}
			nextMode := attempts[attemptIndex+1].mode
			log.Logf(1, "uafvalidate: target match mode %s missed for key=%s vnkey=%s; retrying %s fallback",
				attemptMode, task.key, vnKey, nextMode)
		}

		// Extract crash info
		crashInfo := ""
		if execRes != nil && execRes.Crashed && execRes.CrashTitle != "" {
			crashInfo = fmt.Sprintf(" crash=%q", execRes.CrashTitle)
		}
		executedPairs++
		if execRes != nil {
			observedTargets += execRes.ObservedTargetCount
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
		// Determine total attempts (delay sweep steps or repeat times)
		totalAttempts := targetMatchAttemptsForLog(req, attemptRuns)
		if sm.cfg.VerifyDelaySweep && sm.cfg.VerifyDelaySteps > 1 {
			totalAttempts = attemptRuns * sm.cfg.VerifyDelaySteps
		}

		status := "Not Triggerable"
		statusDetail := ""
		if execRes.TriggeredCount > 0 {
			status = "Triggered"
		} else if execRes.Crashed && execRes.CrashTitle != "" {
			// Crash happened but target pair was not triggered - different race detected
			statusDetail = " (crashed with different race, target pair not matched)"
		}

		if sm.cfg.VerifyDelaySweep && sm.cfg.VerifyDelaySteps > 1 {
			log.Logf(1, "uafvalidate: verification run finished duration=%s crashed=%t%s triggered=%d/%d observed_target=%d (delay_sweep) status=%s%s target_match_mode=%s final_attempt_mode=%s",
				execRes.Duration, execRes.Crashed, crashInfo, execRes.TriggeredCount, totalAttempts, execRes.ObservedTargetCount, status, statusDetail,
				matchMode, attemptMode)
		} else {
			log.Logf(1, "uafvalidate: verification run finished duration=%s crashed=%t%s triggered=%d/%d observed_target=%d status=%s%s target_match_mode=%s final_attempt_mode=%s",
				execRes.Duration, execRes.Crashed, crashInfo, execRes.TriggeredCount, totalAttempts, execRes.ObservedTargetCount, status, statusDetail,
				matchMode, attemptMode)
		}

		nonblockingEvidence := req != nil &&
			NormalizeTargetDelayMode(req.TargetDelayMode) == TargetDelayModeNonblocking &&
			execRes.TriggeredCount > 0
		if nonblockingEvidence {
			nonblockingObserved++
			log.Logf(0, "uafvalidate: nonblocking target observed after %d trigger(s); treating as candidate evidence only, not validated target_match_mode=%s final_attempt_mode=%s",
				execRes.TriggeredCount, matchMode, attemptMode)
			continue
		}

		if execRes.TriggeredCount > 0 {
			// ========== Success: proves this VarName pair can trigger ==========
			validatedPairs++
			switch {
			case attemptMode == TargetMatchModeStrictSN:
				strictSuccesses++
			case attemptMode == TargetMatchModeSNRange:
				snRangeSuccess++
				if matchMode == TargetMatchModeSNFallback {
					fallbackSuccess++
				}
			case attemptMode == TargetMatchModeStackOnly:
				stackSuccess++
				if matchMode == TargetMatchModeSNFallback {
					fallbackSuccess++
				}
			case attemptMode == TargetMatchModeSiteOnly:
				siteOnlySuccess++
				if matchMode == TargetMatchModeSNFallback {
					fallbackSuccess++
				}
			}

			// Try to minimize history if enabled
			var minimizedHistory []*fuzzer.BarrierExecutionRecord
			if sm.cfg.EnableHistoryMinimization && len(task.entry.ReplayHistory) > 1 {
				log.Logf(0, "uafvalidate: starting history minimization for key=%s", task.key)
				minimizer := sm.newHistoryMinimizer(task, &pairCopy, req.Delays)
				minResult := minimizer.Minimize(ctx)
				if minResult.Success && minResult.MinimalHistory != nil {
					minimizedHistory = minResult.MinimalHistory
					log.Logf(0, "uafvalidate: minimization complete: %d -> %d records",
						minResult.OriginalCount, minResult.MinimalCount)
				} else if minResult.Error != nil {
					log.Logf(0, "uafvalidate: minimization failed: %v", minResult.Error)
				}
			}

			// Serialize the validated entry including triggering programs and minimized history
			reportData := serializeValidatedEntryWithHistory(execRes, task.entry, minimizedHistory)

			// In debug mode, only log but don't update databases
			if debugMode {
				log.Logf(1, "uafvalidate: [debug mode] SUCCESS vnkey=%s triggered=%d/%d (not updating databases)",
					vnKey, execRes.TriggeredCount, totalAttempts)
				reportPreview := string(reportData)
				if len(reportPreview) > 2000 {
					reportPreview = reportPreview[:2000] + "...[truncated]"
				}
				log.Logf(1, "uafvalidate: [debug mode] report:\n%s", reportPreview)
				continue
			}

			sm.markValidated(fullKey, reportData)
			if sm.cfg.PairStatusSink != nil {
				sm.cfg.PairStatusSink.MarkPairValidated(pair, reportData)
			}

			// Update VarName backoff statistics (success) and mark as verified
			// This will cause ALL future entries with the same VarName pair to be skipped
			if sm.varNameBackoffStore != nil {
				sm.varNameBackoffStore.RecordSuccessWithKey(&pair, task.key)
				stats := sm.varNameBackoffStore.GetByPair(&pair)
				log.Logf(1, "uafvalidate: pair validated, backoff score updated: vnkey=%s new_score=%.2f verified=%t",
					vnKey, stats.BackoffScore(), stats.IsVerified())
			}

			// Log a summary (not full data to avoid log flooding)
			reportPreview := string(reportData)
			if len(reportPreview) > 2000 {
				reportPreview = reportPreview[:2000] + "...[truncated]"
			}
			log.Logf(0, "uafvalidate: pair validated after %d trigger(s) target_match_mode=%s final_attempt_mode=%s\n%s",
				execRes.TriggeredCount, matchMode, attemptMode, reportPreview)
			continue
		}

		// ========== Failure: increase backoff score ==========
		failedPairs++
		// In debug mode, only log but don't update databases
		if debugMode {
			log.Logf(1, "uafvalidate: [debug mode] FAILED vnkey=%s triggered=0/%d (not updating databases)",
				vnKey, req.RepeatTimes)
			continue
		}

		// Layer 1: Mark this exact pair as invalid
		sm.markInvalid(fullKey)
		if sm.cfg.PairStatusSink != nil {
			sm.cfg.PairStatusSink.MarkPairInvalid(pair)
		}

		// Layer 2: Update VarName backoff statistics (failure)
		if sm.varNameBackoffStore != nil {
			sm.varNameBackoffStore.RecordFailure(&pair)
			stats := sm.varNameBackoffStore.GetByPair(&pair)
			log.Logf(1, "uafvalidate: pair failed verification, backoff score updated: vnkey=%s new_score=%.2f skip_prob=%.2f",
				vnKey, stats.BackoffScore(), stats.SkipProbability())
		}
	}

	skippedPairs := skippedDebug + skippedInvalid + skippedValidated + skippedBackoff
	handledPairs := executedPairs + skippedPairs
	log.Logf(0, "uafvalidate: verification phase summary key=%s target_match_mode=%s pairs=%d handled=%d executed=%d skipped=%d executed_verify_pairs=%d skipped_pairs=%d skipped_debug=%d skipped_invalid=%d skipped_validated=%d skipped_backoff=%d validated=%d failed=%d strict_success=%d fallback_runs=%d fallback_success=%d site_only_success=%d observed_target=%d nonblocking_observed=%d sn_range_runs=%d sn_range_success=%d stack_fallback_runs=%d stack_fallback_success=%d",
		task.key, matchMode, len(stablePairs), handledPairs, executedPairs, skippedPairs,
		executedPairs, skippedPairs, skippedDebug, skippedInvalid, skippedValidated, skippedBackoff,
		validatedPairs, failedPairs, strictSuccesses, fallbackRuns, fallbackSuccess, siteOnlySuccess, observedTargets, nonblockingObserved,
		snRangeRuns, snRangeSuccess, stackRuns, stackSuccess)

	// Output statistics summary
	if sm.varNameBackoffStore != nil {
		total, highScore, verified := sm.varNameBackoffStore.Stats()
		log.Logf(0, "uafvalidate: verification phase (with delays) complete, VarName backoff stats: total=%d high_score=%d verified=%d", total, highScore, verified)
	}
	return VerificationSummary{
		ExecutedPairs:         executedPairs,
		SkippedPairs:          skippedPairs,
		ValidatedPairs:        validatedPairs,
		FailedPairs:           failedPairs,
		SkippedValidatedPairs: skippedValidated,
	}
}

func verificationAccessDelayUs(accessDelayUs int64, cfg Config) int64 {
	if cfg.VerifyAccessDelayMinUs > 0 && accessDelayUs < cfg.VerifyAccessDelayMinUs {
		accessDelayUs = cfg.VerifyAccessDelayMinUs
	}
	if cfg.DisableAccessDelay {
		return 0
	}
	return accessDelayUs
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
//	=== REPLAY HISTORY ===
//	HistoryCount: <count>
//	--- HISTORY 0 ---
//	GroupID: <id>
//	Timestamp: <time>
//	-- HISTORY PROGRAM 0 --
//	<program source>
//	...
func serializeValidatedEntry(res *ExecutionResult, entry *fuzzer.UAFCorpusEntry) []byte {
	return serializeValidatedEntryWithHistory(res, entry, nil)
}

// serializeValidatedEntryWithHistory serializes the validated entry with optional minimized history.
// If minimizedHistory is nil, uses entry.ReplayHistory.
func serializeValidatedEntryWithHistory(res *ExecutionResult, entry *fuzzer.UAFCorpusEntry, minimizedHistory []*fuzzer.BarrierExecutionRecord) []byte {
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

	// Section 5: Replay History
	history := minimizedHistory
	if history == nil {
		history = entry.ReplayHistory
	}
	buf.WriteString("\n=== REPLAY HISTORY ===\n")
	if len(history) > 0 {
		buf.WriteString(fmt.Sprintf("HistoryCount: %d\n", len(history)))
		if minimizedHistory != nil {
			buf.WriteString(fmt.Sprintf("OriginalCount: %d\n", len(entry.ReplayHistory)))
			buf.WriteString("Minimized: true\n")
		}
		for i, record := range history {
			buf.WriteString(fmt.Sprintf("--- HISTORY %d ---\n", i))
			buf.WriteString(fmt.Sprintf("GroupID: %d\n", record.GroupID))
			buf.WriteString(fmt.Sprintf("Timestamp: %s\n", record.Timestamp.Format("2006-01-02T15:04:05.000000")))
			buf.WriteString(fmt.Sprintf("VMIndex: %d\n", record.VMIndex))
			for j, p := range record.Programs {
				buf.WriteString(fmt.Sprintf("-- HISTORY PROGRAM %d --\n", j))
				if p != nil {
					buf.Write(p.Serialize())
				} else {
					buf.WriteString("<nil>\n")
				}
			}
			buf.WriteString("\n")
		}
	} else {
		buf.WriteString("HistoryCount: 0\n")
	}

	// Truncate if too large (increase limit to accommodate history)
	result := buf.Bytes()
	maxSize := maxCrashReportSize * 4 // Increase limit for history
	if len(result) > maxSize {
		result = result[:maxSize]
	}
	return result
}
