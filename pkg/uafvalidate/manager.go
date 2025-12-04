package uafvalidate

import (
	"context"
	"errors"
	"fmt"
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

	mu          sync.Mutex
	pending     map[string]*validationTask
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
		cfg:     cfg,
		delay:   NewDelayManager(defaultMaxBarrierDelays, cfg.DelayRetryBudget),
		factory: factory,
		tasks:   make(chan *validationTask, cfg.MaxConcurrent*2),
		results: make(chan *ValidationResult, cfg.MaxConcurrent*2),
		pending: make(map[string]*validationTask),
		stable:  requiredStableCount(cfg.RepeatCount),
	}

	if cfg.Workdir != "" {
		dbPath := filepath.Join(cfg.Workdir, "invalid_uaf.db")
		d, err := db.Open(dbPath, true)
		if err != nil {
			log.Logf(0, "uafvalidate: failed to open invalid pair db: %v", err)
		} else {
			sm.invalidDB = d
			log.Logf(0, "uafvalidate: loaded %d invalid pairs from db", len(d.Records))
		}
		validPath := filepath.Join(cfg.Workdir, "validated_uaf.db")
		vd, err := db.Open(validPath, true)
		if err != nil {
			log.Logf(0, "uafvalidate: failed to open validated pair db: %v", err)
		} else {
			sm.validDB = vd
			log.Logf(0, "uafvalidate: loaded %d validated pairs from db", len(vd.Records))
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

func (sm *StageManager) Close() {
	sm.closeOnce.Do(func() {
		sm.mu.Lock()
		sm.closed = true
		sm.maybeCloseTasksLocked()
		sm.mu.Unlock()
	})
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
			result.StablePairs = collectStablePairs(task.pairLatest, task.pairCounts, sm.stable)
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

func (sm *StageManager) prepareTask(entry *fuzzer.UAFCorpusEntry) *validationTask {
	clone := entry.Clone()
	if clone == nil {
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
	if _, exists := sm.pending[key]; exists {
		return nil
	}
	task := &validationTask{
		entry:     clone,
		signature: signature,
		key:       key,
	}
	sm.pending[key] = task
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
	sm.maybeCloseTasksLocked()
	sm.mu.Unlock()
}

func (sm *StageManager) maybeCloseTasksLocked() {
	if sm.closed && !sm.tasksClosed && len(sm.pending) == 0 {
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

func collectStablePairs(latest map[string]ddrd.MayUAFPair, counts map[string]int, minCount int) []ddrd.MayUAFPair {
	if len(latest) == 0 || len(counts) == 0 {
		return nil
	}
	if minCount <= 1 {
		minCount = 1
	}
	keys := make([]string, 0, len(counts))
	for key, count := range counts {
		if count < minCount {
			continue
		}
		if _, ok := latest[key]; !ok {
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
		stable = append(stable, latest[key])
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

		key := pairKey(pair)
		if sm.isInvalid(key) {
			log.Logf(0, "uafvalidate: skipping known invalid pair %d/%d for key=%s", i+1, len(stablePairs), task.key)
			continue
		}

		log.Logf(0, "uafvalidate: verifying pair %d/%d for key=%s", i+1, len(stablePairs), task.key)
		if sm.isValidated(key) {
			log.Logf(0, "uafvalidate: skipping validated pair %d/%d for key=%s", i+1, len(stablePairs), task.key)
			continue
		}

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
			RepeatTimes:   3,
			DisableDdrd:   true,
			StopOnSuccess: true,
		}

		execRes, runErr := exec.Run(ctx, req)
		if closer, ok := exec.(interface{ Close() error }); ok {
			closer.Close()
		}

		if runErr != nil {
			log.Logf(0, "uafvalidate: verification run failed: %v", runErr)
		} else {
			status := "Not Triggerable"
			if execRes.TriggeredCount >= 2 {
				status = "Stable"
			} else if execRes.TriggeredCount > 0 {
				status = "Not Stable"
			}
			log.Logf(0, "uafvalidate: verification run finished duration=%s crashed=%t triggered=%d/%d status=%s",
				execRes.Duration, execRes.Crashed, execRes.TriggeredCount, req.RepeatTimes, status)
			if execRes.TriggeredCount > 0 {
				reportData := serializeCrashReport(execRes)
				sm.markValidated(key, reportData)
				log.Logf(0, "uafvalidate: pair validated after %d attempt(s)\n%s", execRes.TriggeredCount, string(reportData))
				continue
			}

			if execRes.TriggeredCount == 0 {
				sm.markInvalid(key)
			}
		}
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
