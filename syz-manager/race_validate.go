package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	uafvalidate "github.com/google/syzkaller/pkg/racevalidate"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
)

type validationEntryResolver struct {
	workdir string
	target  *prog.Target
}

func (r *validationEntryResolver) ResolveValidationEntry(ref *uafvalidate.ValidationEntryRef) (*fuzzer.UAFCorpusEntry, error) {
	if r == nil || ref == nil {
		return nil, nil
	}
	corpusPath := filepath.Join(r.workdir, "uaf-corpus.db")
	reader := manager.NewStreamingUAFCorpusReader(corpusPath, r.target)
	entry, _, err := reader.LoadEntryByKey(ref.CorpusRecordID, &ref.Pair)
	return entry, err
}

func (mgr *Manager) runUAFValidateMode(ctx context.Context) {
	cfg := mgr.cfg.Experimental.UAFValidate

	if cfg.ContinuousMode && mgr.uafValidateQueue != nil {
		mgr.runUAFValidateQueueMode(ctx)
		return
	}

	// Check if streaming mode is enabled (bypasses uafStore requirement)
	if cfg.StreamingLoad {
		mgr.runUAFValidateModeStreaming(ctx)
		return
	}

	// Non-streaming mode requires uafStore to be loaded
	if mgr.uafStore == nil {
		log.Fatalf("uaf validation requires persisted corpus store")
	}

	// Check if continuous mode is enabled
	if cfg.ContinuousMode {
		mgr.runUAFValidateContinuousMode(ctx)
		return
	}

	// Original one-shot mode (load all entries at once)
	entries, err := mgr.uafStore.Entries()
	if err != nil {
		log.Fatalf("failed to load persisted uaf entries: %v", err)
	}
	if len(entries) == 0 {
		log.Logf(0, "uaf validation: no persisted entries available")
		mgr.exit("uaf-validate")
		return
	}

	// Apply max_entries limit if configured
	if cfg.MaxEntries > 0 && len(entries) > cfg.MaxEntries {
		log.Logf(0, "uaf validation: limiting entries from %d to %d", len(entries), cfg.MaxEntries)
		entries = entries[:cfg.MaxEntries]
	}

	if cfg.EnableReplay {
		// Debug: check entries history after loading
		for i, entry := range entries {
			if entry != nil && len(entry.ReplayHistory) > 0 {
				log.Logf(0, "[history] race_validate: loaded entry %d (ptr=%p) has %d history records", i, entry, len(entry.ReplayHistory))
			}
		}
	}

	validatorCfg := uafvalidate.Config{
		MaxConcurrent:             cfg.MaxConcurrent,
		DelayRetryBudget:          cfg.DelayRetryBudget,
		ExecutionTimeout:          time.Duration(cfg.TimeoutSeconds) * time.Second,
		MaxBatchTimeout:           time.Duration(cfg.MaxBatchTimeoutSeconds) * time.Second,
		Debug:                     *flagDebug,
		RepeatCount:               cfg.RepeatCount,
		VerifyRepeatTimes:         cfg.VerifyRepeatTimes,
		Workdir:                   mgr.cfg.Workdir,
		TargetVarNamePair:         cfg.TargetVarNamePair,
		TargetCorpusKey:           cfg.TargetCorpusKey,
		DisableAsyncSplit:         cfg.DisableAsyncSplit,
		DisableCollectionDelay:    cfg.DisableCollectionDelay,
		DisableVerifyDelay:        cfg.DisableVerifyDelay,
		DisableAccessDelay:        cfg.DisableAccessDelay,
		VerifyAccessDelayMinUs:    cfg.VerifyAccessDelayMinUs,
		TargetMatchMode:           cfg.TargetMatchMode,
		SNFallbackRange:           cfg.SNFallbackRange,
		TargetDelaySide:           cfg.TargetDelaySide,
		TargetDelayMode:           cfg.TargetDelayMode,
		WildcardTargetTID:         cfg.WildcardTargetTID,
		VerifyDelaySweep:          cfg.VerifyDelaySweep,
		VerifyDelaySteps:          cfg.VerifyDelaySteps,
		VerifyDelayMaxUs:          cfg.VerifyDelayMaxUs,
		VerifyDelayPower:          cfg.VerifyDelayPower,
		EnableReplay:              cfg.EnableReplay,
		ReplayCollectPairs:        cfg.ReplayCollectPairs,
		VerifyCollectPairs:        cfg.VerifyCollectPairs,
		MaxReplayHistory:          cfg.MaxReplayHistory,
		EnableVarNameScheduling:   cfg.EnableVarNameScheduling,
		PriorityLowHistory:        cfg.PriorityLowHistory,
		RequireOriginMatch:        cfg.RequireOriginMatch,
		OriginMatchMode:           cfg.OriginMatchMode,
		MaxStablePairsPerOrigin:   cfg.MaxStablePairsPerOrigin,
		MaxStablePairsPerEntry:    cfg.MaxStablePairsPerEntry,
		CollectionOnly:            cfg.CollectionOnly,
		DisableBackoffSkip:        cfg.DisableBackoffSkip,
		ContinueAfterBackoff:      cfg.ContinueAfterBackoff,
		EnableHistoryMinimization: cfg.EnableHistoryMinimization,
		MinimizationMaxAttempts:   cfg.MinimizationMaxAttempts,
		MinimizationStrategy:      cfg.MinimizationStrategy,
		EntryResolver:             &validationEntryResolver{workdir: mgr.uafSharedWorkdir, target: mgr.target},
		PairStatusSink:            mgr.uafPairIndex,
	}
	if validatorCfg.MaxConcurrent > mgr.vmPool.Count() {
		validatorCfg.MaxConcurrent = mgr.vmPool.Count()
	}
	if validatorCfg.MaxConcurrent <= 0 {
		validatorCfg.MaxConcurrent = 1
	}

	stage := uafvalidate.NewStageManager(validatorCfg, mgr.selectExecutorFactory(cfg, validatorCfg))

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultsDone := make(chan struct{})
	go func() {
		for res := range stage.Results() {
			mgr.handleValidationResult(res)
		}
		close(resultsDone)
	}()

	runDone := make(chan struct{})
	go func() {
		stage.Run(runCtx)
		close(runDone)
	}()

	for i, entry := range entries {
		if cfg.EnableReplay {
			log.Logf(0, "[history] race_validate: enqueueing entry %d (ptr=%p) history=%d", i, entry, len(entry.ReplayHistory))
		}
		stage.Enqueue(entry)
	}
	stage.Close()
	<-runDone
	<-resultsDone
	mgr.exit("uaf-validate")
}

func (mgr *Manager) newUAFValidatorConfig(cfg *mgrconfig.UAFValidateConfig) uafvalidate.Config {
	validatorCfg := uafvalidate.Config{
		MaxConcurrent:             cfg.MaxConcurrent,
		DelayRetryBudget:          cfg.DelayRetryBudget,
		ExecutionTimeout:          time.Duration(cfg.TimeoutSeconds) * time.Second,
		MaxBatchTimeout:           time.Duration(cfg.MaxBatchTimeoutSeconds) * time.Second,
		Debug:                     *flagDebug,
		RepeatCount:               cfg.RepeatCount,
		VerifyRepeatTimes:         cfg.VerifyRepeatTimes,
		Workdir:                   mgr.cfg.Workdir,
		TargetVarNamePair:         cfg.TargetVarNamePair,
		TargetCorpusKey:           cfg.TargetCorpusKey,
		DisableAsyncSplit:         cfg.DisableAsyncSplit,
		DisableCollectionDelay:    cfg.DisableCollectionDelay,
		DisableVerifyDelay:        cfg.DisableVerifyDelay,
		DisableAccessDelay:        cfg.DisableAccessDelay,
		VerifyAccessDelayMinUs:    cfg.VerifyAccessDelayMinUs,
		TargetMatchMode:           cfg.TargetMatchMode,
		SNFallbackRange:           cfg.SNFallbackRange,
		TargetDelaySide:           cfg.TargetDelaySide,
		TargetDelayMode:           cfg.TargetDelayMode,
		WildcardTargetTID:         cfg.WildcardTargetTID,
		VerifyDelaySweep:          cfg.VerifyDelaySweep,
		VerifyDelaySteps:          cfg.VerifyDelaySteps,
		VerifyDelayMaxUs:          cfg.VerifyDelayMaxUs,
		VerifyDelayPower:          cfg.VerifyDelayPower,
		EnableReplay:              cfg.EnableReplay,
		ReplayCollectPairs:        cfg.ReplayCollectPairs,
		VerifyCollectPairs:        cfg.VerifyCollectPairs,
		MaxReplayHistory:          cfg.MaxReplayHistory,
		EnableVarNameScheduling:   cfg.EnableVarNameScheduling,
		PriorityLowHistory:        cfg.PriorityLowHistory,
		RequireOriginMatch:        cfg.RequireOriginMatch,
		OriginMatchMode:           cfg.OriginMatchMode,
		MaxStablePairsPerOrigin:   cfg.MaxStablePairsPerOrigin,
		MaxStablePairsPerEntry:    cfg.MaxStablePairsPerEntry,
		CollectionOnly:            cfg.CollectionOnly,
		DisableBackoffSkip:        cfg.DisableBackoffSkip,
		ContinueAfterBackoff:      cfg.ContinueAfterBackoff,
		EnableHistoryMinimization: cfg.EnableHistoryMinimization,
		MinimizationMaxAttempts:   cfg.MinimizationMaxAttempts,
		MinimizationStrategy:      cfg.MinimizationStrategy,
		EntryResolver:             &validationEntryResolver{workdir: mgr.uafSharedWorkdir, target: mgr.target},
		PairStatusSink:            mgr.uafPairIndex,
	}
	if validatorCfg.MaxConcurrent > mgr.vmPool.Count() {
		validatorCfg.MaxConcurrent = mgr.vmPool.Count()
	}
	if validatorCfg.MaxConcurrent <= 0 {
		validatorCfg.MaxConcurrent = 1
	}
	return validatorCfg
}

func (mgr *Manager) runUAFValidateQueueMode(ctx context.Context) {
	cfg := mgr.cfg.Experimental.UAFValidate
	if mgr.uafValidateQueue == nil {
		log.Fatalf("uaf validation queue mode requires validate queue store")
	}

	pollInterval := time.Duration(cfg.IdleReloadSeconds) * time.Second
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}

	validatorCfg := mgr.newUAFValidatorConfig(cfg)
	stage := uafvalidate.NewStageManager(validatorCfg, mgr.selectExecutorFactory(cfg, validatorCfg))

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var validatorProcessed int32
	var validatorSuccess int32

	resultsDone := make(chan struct{})
	go func() {
		for res := range stage.Results() {
			mgr.handleValidationResult(res)
			repeatTotal := res.RepeatTotal
			if repeatTotal <= 0 {
				repeatTotal = 1
			}
			if res.RepeatIndex+1 >= repeatTotal {
				atomic.AddInt32(&validatorProcessed, 1)
				if validationResultSucceededForStats(res) {
					atomic.AddInt32(&validatorSuccess, 1)
				}
				if res.Entry != nil {
					if mgr.uafPairIndex != nil {
						for _, pairKey := range validationPairKeys(res.Entry) {
							if err := mgr.uafPairIndex.MarkProcessed(pairKey); err != nil {
								log.Errorf("uaf validation queue: failed to mark processed %s: %v", pairKey, err)
							}
						}
					}
					for _, queueKey := range validationQueueKeys(res.Entry) {
						if err := mgr.uafValidateQueue.Ack(queueKey); err != nil {
							log.Errorf("uaf validation queue: failed to ack %s: %v", queueKey, err)
						}
					}
				}
			}
		}
		close(resultsDone)
	}()

	runDone := make(chan struct{})
	go func() {
		stage.Run(runCtx)
		close(runDone)
	}()

	mgr.logRaceValidationStorageState("validate-start")
	lastSeq, accepted, acked, err := mgr.loadValidationQueueEntries(stage, 0)
	if err != nil {
		log.Errorf("uaf validation queue: initial load failed: %v", err)
	} else {
		log.Logf(0, "uaf validation queue: initial load accepted=%d acked=%d pending=%d seq=%d",
			accepted, acked, stage.PendingCount(), lastSeq)
		if accepted != 0 || acked != 0 {
			mgr.logRaceValidationStorageState("validate-initial")
		}
	}
	if accepted == 0 && acked == 0 && mgr.uafStore != nil {
		bootstrapQueued, err := mgr.bootstrapValidationQueueFromCorpus(stage)
		if err != nil {
			log.Errorf("uaf validation queue: corpus bootstrap failed: %v", err)
		} else if bootstrapQueued != 0 {
			log.Logf(0, "uaf validation queue: bootstrapped %d legacy corpus entries", bootstrapQueued)
		}
	}

	statsStartTime := time.Now()
	statsTicker := time.NewTicker(15 * time.Second)
	defer statsTicker.Stop()

	pollTicker := time.NewTicker(pollInterval)
	defer pollTicker.Stop()

	log.Logf(0, "uaf validation queue: continuous mode started (poll=%v)", pollInterval)

	for {
		select {
		case <-ctx.Done():
			log.Logf(0, "uaf validation queue: context cancelled, shutting down")
			stage.Shutdown()
			<-runDone
			<-resultsDone
			mgr.exit("uaf-validate")
			return

		case <-statsTicker.C:
			processed := int(atomic.LoadInt32(&validatorProcessed))
			success := int(atomic.LoadInt32(&validatorSuccess))
			pending := stage.PendingCount()
			idle := !stage.HasPending()
			var rate float64
			if processed > 0 {
				rate = float64(processed) / time.Since(statsStartTime).Minutes()
			}
			_ = ddrd.WriteValidatorStats(mgr.uafSharedWorkdir, ddrd.ValidatorStats{
				PendingCount:       pending,
				ProcessedCount:     processed,
				SuccessCount:       success,
				ProcessingRatePerM: rate,
				LastUpdate:         time.Now(),
				Idle:               idle,
			})
			log.Logf(1, "uaf validation queue: status pending=%d processed=%d success=%d rate_per_min=%.2f idle=%t",
				pending, processed, success, rate, idle)

		case <-pollTicker.C:
			newLastSeq, newAccepted, newAcked, err := mgr.loadValidationQueueEntries(stage, lastSeq)
			if err != nil {
				log.Errorf("uaf validation queue: poll failed: %v", err)
				continue
			}
			lastSeq = newLastSeq
			if newAccepted != 0 || newAcked != 0 {
				log.Logf(0, "uaf validation queue: poll accepted=%d acked=%d pending=%d seq=%d",
					newAccepted, newAcked, stage.PendingCount(), lastSeq)
				mgr.logRaceValidationStorageState("validate-poll")
			}
		}
	}
}

func (mgr *Manager) loadValidationQueueEntries(stage *uafvalidate.StageManager, sinceSeq uint64) (uint64, int, int, error) {
	if mgr.uafValidateQueue == nil || stage == nil {
		return sinceSeq, 0, 0, nil
	}
	if err := mgr.uafValidateQueue.Reload(); err != nil {
		return sinceSeq, 0, 0, err
	}
	if mgr.uafPairIndex != nil {
		if err := mgr.uafPairIndex.Reload(); err != nil {
			return sinceSeq, 0, 0, err
		}
	}

	groups, maxSeq, err := mgr.uafValidateQueue.EntriesSinceGroupedByCorpus(sinceSeq)
	if err != nil {
		return sinceSeq, 0, 0, err
	}

	accepted := 0
	acked := 0
	malformed := 0
	skipped := 0
	maxHistory := 0
	groupedPairs := 0
	for _, group := range groups {
		if group == nil || group.CorpusRecordID == "" || len(group.Items) == 0 {
			malformed++
			continue
		}
		groupedPairs += len(group.PairKeys)
		if group.HistoryCount > maxHistory {
			maxHistory = group.HistoryCount
		}
		entry, materializeErr := mgr.materializeValidationGroup(group)
		if materializeErr != nil {
			return sinceSeq, accepted, acked, materializeErr
		}
		if entry == nil {
			malformed++
			for _, queueKey := range group.QueueKeys {
				if queueKey == "" {
					continue
				}
				if err := mgr.uafValidateQueue.Ack(queueKey); err != nil {
					log.Errorf("uaf validation queue: failed to ack malformed item %s: %v", queueKey, err)
				} else {
					acked++
				}
			}
			continue
		}
		if stage.Enqueue(entry) {
			if mgr.uafPairIndex != nil {
				for _, pairKey := range group.PairKeys {
					if err := mgr.uafPairIndex.MarkProcessing(pairKey); err != nil {
						log.Errorf("uaf validation queue: failed to mark processing %s: %v", pairKey, err)
					}
				}
			}
			accepted++
			continue
		}
		skipped++
		if mgr.uafPairIndex != nil {
			for _, pairKey := range group.PairKeys {
				if err := mgr.uafPairIndex.MarkProcessed(pairKey); err != nil {
					log.Errorf("uaf validation queue: failed to mark skipped pair %s processed: %v", pairKey, err)
				}
			}
		}
		for _, queueKey := range group.QueueKeys {
			if err := mgr.uafValidateQueue.Ack(queueKey); err != nil {
				log.Errorf("uaf validation queue: failed to ack skipped item %s: %v", queueKey, err)
			} else {
				acked++
			}
		}
	}
	if len(groups) != 0 {
		log.Logf(1, "uaf validation queue: loaded groups=%d grouped_pairs=%d accepted=%d skipped=%d malformed=%d acked=%d max_history=%d since_seq=%d max_seq=%d",
			len(groups), groupedPairs, accepted, skipped, malformed, acked, maxHistory, sinceSeq, maxSeq)
	}

	return maxSeq, accepted, acked, nil
}

func (mgr *Manager) materializeValidationGroup(group *manager.QueuedUAFCorpusGroup) (*fuzzer.UAFCorpusEntry, error) {
	if mgr == nil || group == nil || group.CorpusRecordID == "" {
		return nil, nil
	}
	reader := manager.NewStreamingUAFCorpusReader(filepath.Join(mgr.uafSharedWorkdir, "uaf-corpus.db"), mgr.target)
	entry, _, err := reader.LoadEntryByKey(group.CorpusRecordID, nil)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	filterValidationGroupPairs(entry, group)
	entry.ValidateQueueKey = firstString(group.QueueKeys)
	entry.ValidateQueueSeq = group.FirstSeq
	entry.ValidatePairKey = firstString(group.PairKeys)
	entry.ValidateQueueKeys = append([]string(nil), group.QueueKeys...)
	entry.ValidatePairKeys = append([]string(nil), group.PairKeys...)
	entry.CorpusRecordID = group.CorpusRecordID
	return entry, nil
}

func filterValidationGroupPairs(entry *fuzzer.UAFCorpusEntry, group *manager.QueuedUAFCorpusGroup) {
	if entry == nil || group == nil {
		return
	}
	targetPairs := make(map[string]ddrd.MayUAFPair, len(group.Pairs))
	for _, pair := range group.Pairs {
		if pair.UAFPairID() == 0 {
			continue
		}
		targetPairs[ddrd.RacePairKeyString(&pair)] = pair
	}
	filtered := make([]*ddrd.MayUAFPair, 0, len(targetPairs))
	for _, pair := range entry.Pairs {
		if pair == nil {
			continue
		}
		key := ddrd.RacePairKeyString(pair)
		if _, ok := targetPairs[key]; !ok {
			continue
		}
		copyPair := *pair
		filtered = append(filtered, &copyPair)
		delete(targetPairs, key)
	}
	for _, pair := range targetPairs {
		copyPair := pair
		filtered = append(filtered, &copyPair)
	}
	if len(filtered) == 0 {
		return
	}
	entry.Pairs = filtered
	entry.PairBasicInfo = *filtered[0]
	entry.Signals = ddrd.FromUAFPairs(entry.Pairs, ddrd.UAFSignalPrioHigh)
	entry.Profile = fuzzer.UAFPairProfile{
		FreeAccessName: filtered[0].FreeAccessName,
		UseAccessName:  filtered[0].UseAccessName,
		FreeCallStack:  filtered[0].FreeCallStack,
		UseCallStack:   filtered[0].UseCallStack,
	}
}

func validationPairKeys(entry *fuzzer.UAFCorpusEntry) []string {
	if entry == nil {
		return nil
	}
	if len(entry.ValidatePairKeys) != 0 {
		return dedupeStrings(entry.ValidatePairKeys)
	}
	if entry.ValidatePairKey == "" {
		return nil
	}
	return []string{entry.ValidatePairKey}
}

func validationQueueKeys(entry *fuzzer.UAFCorpusEntry) []string {
	if entry == nil {
		return nil
	}
	if len(entry.ValidateQueueKeys) != 0 {
		return dedupeStrings(entry.ValidateQueueKeys)
	}
	if entry.ValidateQueueKey == "" {
		return nil
	}
	return []string{entry.ValidateQueueKey}
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func firstString(values []string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (mgr *Manager) bootstrapValidationQueueFromCorpus(stage *uafvalidate.StageManager) (int, error) {
	if mgr.uafStore == nil || stage == nil {
		return 0, nil
	}

	entries, err := mgr.uafStore.Entries()
	if err != nil {
		return 0, err
	}

	queued := 0
	for _, entry := range entries {
		if stage.Enqueue(entry) {
			queued++
		}
	}
	return queued, nil
}

// selectExecutorFactory chooses between snapshot-enabled and standard executor factory
// based on the EnableVMSnapshot configuration option.
func (mgr *Manager) selectExecutorFactory(cfg *mgrconfig.UAFValidateConfig, validatorCfg uafvalidate.Config) uafvalidate.ExecutorFactory {
	if cfg.EnableVMSnapshot {
		// Validate QEMU configuration for snapshot support
		if err := mgr.validateQEMUSnapshotConfig(); err != nil {
			log.Logf(0, "uafvalidate: VM snapshot disabled: %v", err)
			log.Logf(0, "uafvalidate: falling back to standard VM restart mode")
			return mgr.validatorExecutorFactory(validatorCfg)
		}

		// IMPORTANT: When using snapshot mode with shared disk images (e.g., floppy drives
		// specified in qemu_args), running multiple VMs can cause conflicts because all VMs
		// write snapshots to the same disk file. This can cause QEMU to crash on loadvm.
		//
		// Recommended: Set vm.count = 1 when using snapshot mode, or ensure each VM has
		// its own copy of all disk images.
		vmCount := mgr.vmPool.Count()
		if vmCount > 1 {
			log.Logf(0, "uafvalidate: WARNING: snapshot mode with %d VMs may cause conflicts if disk images are shared", vmCount)
			log.Logf(0, "uafvalidate: if you see loadvm crashes, try setting vm.count = 1 in your config")
		}

		log.Logf(0, "uafvalidate: using VM snapshot mode for faster validation")
		return mgr.validatorExecutorFactoryWithSnapshot(validatorCfg)
	}
	return mgr.validatorExecutorFactory(validatorCfg)
}

// qemuVMConfig is a minimal struct to parse QEMU-specific VM configuration.
type qemuVMConfig struct {
	Snapshot bool `json:"snapshot"`
}

// validateQEMUSnapshotConfig checks if the QEMU configuration is compatible with VM snapshots.
// For savevm/loadvm to work, the -snapshot flag must NOT be used.
func (mgr *Manager) validateQEMUSnapshotConfig() error {
	if mgr.cfg.Type != "qemu" {
		return fmt.Errorf("VM snapshot is only supported for QEMU VMs (current type: %s)", mgr.cfg.Type)
	}

	// Parse the VM configuration to check snapshot setting
	var vmCfg qemuVMConfig
	if err := json.Unmarshal(mgr.cfg.VM, &vmCfg); err != nil {
		// If we can't parse it, assume default which is snapshot=true
		log.Logf(1, "uafvalidate: unable to parse VM config: %v, assuming snapshot=true", err)
		vmCfg.Snapshot = true
	}

	// For savevm/loadvm to work, QEMU's -snapshot flag must be disabled
	if vmCfg.Snapshot {
		return fmt.Errorf("QEMU 'snapshot' option must be set to false in VM config for savevm/loadvm to work. " +
			"Add '\"snapshot\": false' to your vm config section. " +
			"Note: this will modify the disk image, so use a dedicated image for validation")
	}

	// Check that image exists and is writable (required when snapshot=false)
	if mgr.cfg.Image != "" && mgr.cfg.Image != "9p" {
		if _, err := os.Stat(mgr.cfg.Image); os.IsNotExist(err) {
			return fmt.Errorf("image file '%s' does not exist", mgr.cfg.Image)
		}
		// Check if image is writable
		f, err := os.OpenFile(mgr.cfg.Image, os.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("image file '%s' is not writable (required when snapshot=false): %v", mgr.cfg.Image, err)
		}
		f.Close()
	}

	return nil
}

func (mgr *Manager) validatorExecutorFactory(cfg uafvalidate.Config) uafvalidate.ExecutorFactory {
	vmCount := mgr.vmPool.Count()
	if vmCount == 0 {
		return func(context.Context) (uafvalidate.Executor, error) {
			return nil, fmt.Errorf("uaf validation: vm pool is empty")
		}
	}

	// Use a channel-based pool to properly manage VM index allocation.
	// This ensures that each VM index is only used by one executor at a time.
	availableVMs := make(chan int, vmCount)
	for i := 0; i < vmCount; i++ {
		availableVMs <- i
	}

	return func(ctx context.Context) (uafvalidate.Executor, error) {
		// Wait for an available VM index
		var index int
		select {
		case index = <-availableVMs:
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		vmInst, err := mgr.vmPool.Create(ctx, index)
		if err != nil {
			// Return the index to the pool on failure
			availableVMs <- index
			return nil, err
		}
		if *flagDebug {
			log.Logf(0, "uafvalidate: acquired vm index=%d/%d for validation", index, vmCount)
		}
		execInst, err := instance.SetupExecProg(vmInst, mgr.cfg, mgr.reporter, nil)
		if err != nil {
			vmInst.Close()
			availableVMs <- index
			return nil, err
		}
		if *flagDebug {
			log.Logf(0, "uafvalidate: vm index=%d ready executor=%p", index, execInst)
		}
		// Wrap the adapter to return the VM index when closed
		return &pooledExecutorAdapter{
			ExecutorAdapter: uafvalidate.NewExecutorAdapter(execInst, cfg),
			releaseVM:       func() { availableVMs <- index },
		}, nil
	}
}

// snapshotVMState holds the state for a single VM with snapshot support.
type snapshotVMState struct {
	vm           *vm.Instance
	imagePath    string // path to the copied image
	snapshotName string // name of the saved snapshot
	ready        bool   // whether snapshot has been saved
	// Cached binary paths in VM to avoid re-copying on restore
	execprogBin string // path to syz-execprog inside VM
	executorBin string // path to syz-executor inside VM
}

// snapshotVMPool manages VMs with snapshot support for faster reset.
type snapshotVMPool struct {
	mgr          *Manager
	cfg          uafvalidate.Config
	validateCfg  *mgrconfig.UAFValidateConfig
	states       map[int]*snapshotVMState
	mu           sync.Mutex
	availableVMs chan int
	vmCount      int
}

func (mgr *Manager) validatorExecutorFactoryWithSnapshot(cfg uafvalidate.Config) uafvalidate.ExecutorFactory {
	vmCount := mgr.vmPool.Count()
	if vmCount == 0 {
		return func(context.Context) (uafvalidate.Executor, error) {
			return nil, fmt.Errorf("uaf validation: vm pool is empty")
		}
	}

	pool := &snapshotVMPool{
		mgr:          mgr,
		cfg:          cfg,
		validateCfg:  mgr.cfg.Experimental.UAFValidate,
		states:       make(map[int]*snapshotVMState),
		availableVMs: make(chan int, vmCount),
		vmCount:      vmCount,
	}

	for i := 0; i < vmCount; i++ {
		pool.availableVMs <- i
	}

	return pool.createExecutor
}

func (pool *snapshotVMPool) createExecutor(ctx context.Context) (uafvalidate.Executor, error) {
	// Wait for an available VM index
	var index int
	select {
	case index = <-pool.availableVMs:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	pool.mu.Lock()
	state := pool.states[index]
	pool.mu.Unlock()

	if state != nil && state.ready {
		// Restore from snapshot
		exec, err := pool.restoreFromSnapshot(ctx, index, state)
		if err != nil {
			log.Logf(0, "uafvalidate: snapshot restore failed for vm %d: %v, recreating", index, err)
			// Cleanup and recreate
			pool.cleanupState(index, state)
			state = nil
		} else {
			return exec, nil
		}
	}

	// First time or recovery: create new VM with snapshot
	exec, err := pool.createNewVMWithSnapshot(ctx, index)
	if err != nil {
		pool.availableVMs <- index
		return nil, err
	}
	return exec, nil
}

func (pool *snapshotVMPool) createNewVMWithSnapshot(ctx context.Context, index int) (uafvalidate.Executor, error) {
	mgr := pool.mgr

	// Step 1: Copy image to workdir
	imagePath, err := pool.copyImage(index)
	if err != nil {
		return nil, fmt.Errorf("failed to copy image: %w", err)
	}
	log.Logf(0, "uafvalidate: vm %d image copied to %s", index, imagePath)

	// Step 2: Create VM with the copied image (snapshot disabled)
	// We need to temporarily modify the config to use our copied image
	vmInst, err := pool.createVMWithImage(ctx, index, imagePath)
	if err != nil {
		os.Remove(imagePath)
		return nil, fmt.Errorf("failed to create VM: %w", err)
	}

	// Step 3: Setup executor (this waits for SSH to be ready)
	execInst, err := instance.SetupExecProg(vmInst, mgr.cfg, mgr.reporter, nil)
	if err != nil {
		vmInst.Close()
		os.Remove(imagePath)
		return nil, fmt.Errorf("failed to setup executor: %w", err)
	}

	// Step 4: Save snapshot
	snapshotName := fmt.Sprintf("uaf-validate-%d", index)
	if err := vmInst.SaveVMSnapshot(snapshotName); err != nil {
		log.Logf(0, "uafvalidate: vm %d failed to save snapshot: %v (continuing without snapshot)", index, err)
		// Continue without snapshot support - fallback to normal mode
		return &snapshotExecutorAdapter{
			ExecutorAdapter: uafvalidate.NewExecutorAdapter(execInst, pool.cfg),
			pool:            pool,
			index:           index,
		}, nil
	}

	log.Logf(0, "uafvalidate: vm %d snapshot saved as '%s'", index, snapshotName)

	// Step 5: Save state including executor binary paths for later reuse
	state := &snapshotVMState{
		vm:           vmInst,
		imagePath:    imagePath,
		snapshotName: snapshotName,
		ready:        true,
		execprogBin:  execInst.ExecprogBin(),
		executorBin:  execInst.ExecutorBin(),
	}
	log.Logf(1, "uafvalidate: vm %d saved executor paths: execprog=%s, executor=%s", index, state.execprogBin, state.executorBin)
	pool.mu.Lock()
	pool.states[index] = state
	pool.mu.Unlock()

	return &snapshotExecutorAdapter{
		ExecutorAdapter: uafvalidate.NewExecutorAdapter(execInst, pool.cfg),
		pool:            pool,
		index:           index,
	}, nil
}

func (pool *snapshotVMPool) restoreFromSnapshot(ctx context.Context, index int, state *snapshotVMState) (uafvalidate.Executor, error) {
	restoreStart := time.Now()
	log.Logf(1, "uafvalidate: vm %d restoring from snapshot '%s' with image '%s' (cold restart with -loadvm)", index, state.snapshotName, state.imagePath)

	// Cold restart approach: close the current VM and create a new one with -loadvm flag
	// This is much faster than booting and then calling loadvm via QMP

	// Step 1: Close the current VM
	closeStart := time.Now()
	if state.vm != nil {
		log.Logf(1, "uafvalidate: vm %d closing current VM before snapshot restore", index)
		state.vm.Close()
		state.vm = nil
		// Wait for ports to be released by the OS - reduced from 1s to 500ms
		time.Sleep(500 * time.Millisecond)
	}
	log.Logf(1, "uafvalidate: vm %d close step took %v", index, time.Since(closeStart))

	// Step 2: Create a new VM instance with snapshot loading on boot
	// Use the same image that was used when the snapshot was saved
	startTime := time.Now()
	vmInst, err := pool.mgr.vmPool.CreateWithSnapshotAndImage(ctx, index, state.snapshotName, state.imagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM with snapshot restore: %w", err)
	}
	log.Logf(1, "uafvalidate: vm %d CreateWithSnapshotAndImage took %v", index, time.Since(startTime))

	// Step 3: Setup executor using cached binary paths (skip SCP copy)
	execStart := time.Now()
	var execInst *instance.ExecProgInstance
	if state.execprogBin != "" && state.executorBin != "" {
		// Use cached paths - much faster as we skip SCP
		log.Logf(1, "uafvalidate: vm %d using cached binary paths: execprog=%s, executor=%s", index, state.execprogBin, state.executorBin)
		execInst, err = instance.SetupExecProgWithBinaries(vmInst, pool.mgr.cfg, pool.mgr.reporter, state.execprogBin, state.executorBin, nil)
	} else {
		// Fallback: copy binaries (slower)
		log.Logf(1, "uafvalidate: vm %d no cached binary paths, will copy binaries", index)
		execInst, err = instance.SetupExecProg(vmInst, pool.mgr.cfg, pool.mgr.reporter, nil)
	}
	if err != nil {
		vmInst.Close()
		return nil, fmt.Errorf("failed to setup executor after snapshot restore: %w", err)
	}
	log.Logf(1, "uafvalidate: vm %d executor setup took %v", index, time.Since(execStart))

	// Update state with new VM instance
	state.vm = vmInst

	log.Logf(1, "uafvalidate: vm %d restored from snapshot successfully (total time: %v)", index, time.Since(restoreStart))

	return &snapshotExecutorAdapter{
		ExecutorAdapter: uafvalidate.NewExecutorAdapter(execInst, pool.cfg),
		pool:            pool,
		index:           index,
	}, nil
}

func (pool *snapshotVMPool) copyImage(index int) (string, error) {
	srcImage := pool.mgr.cfg.Image
	if srcImage == "" {
		return "", fmt.Errorf("no image configured")
	}

	// Create destination path in workdir
	// Use standalone qcow2 file (not overlay) for reliable savevm/loadvm support
	dstImage := filepath.Join(pool.mgr.cfg.Workdir, fmt.Sprintf("validate-vm-%d.qcow2", index))

	// Check if destination already exists and is valid
	if _, err := os.Stat(dstImage); err == nil {
		log.Logf(1, "uafvalidate: reusing existing image copy %s", dstImage)
		return dstImage, nil
	}

	// Always use full conversion to qcow2 for reliable snapshot support
	// Overlay mode has issues with savevm not writing to the overlay file
	log.Logf(0, "uafvalidate: converting image to standalone qcow2: %s -> %s (this may take a while)", srcImage, dstImage)

	// Use qemu-img convert to create a standalone qcow2 image
	cmd := osutil.Command("qemu-img", "convert", "-O", "qcow2", srcImage, dstImage)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Logf(0, "uafvalidate: qemu-img convert failed: %v, output: %s", err, output)
		return "", fmt.Errorf("failed to convert image: %v", err)
	}

	log.Logf(0, "uafvalidate: image converted successfully: %s", dstImage)
	return dstImage, nil
}

func (pool *snapshotVMPool) createVMWithImage(ctx context.Context, index int, imagePath string) (*vm.Instance, error) {
	// Create VM with the overlay image so snapshots are saved to the correct file
	vmInst, err := pool.mgr.vmPool.CreateWithImage(ctx, index, imagePath)
	if err != nil {
		return nil, err
	}
	return vmInst, nil
}

func (pool *snapshotVMPool) cleanupState(index int, state *snapshotVMState) {
	pool.mu.Lock()
	delete(pool.states, index)
	pool.mu.Unlock()

	if state != nil && state.vm != nil {
		// Use recover to catch any panic from closing already-closed resources
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Logf(1, "uafvalidate: recovered from panic during VM cleanup: %v", r)
				}
			}()
			state.vm.Close()
		}()
		state.vm = nil
	}
	// Don't delete the image - it might be reused
}

func (pool *snapshotVMPool) Close() {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for index, state := range pool.states {
		if state.vm != nil {
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Logf(1, "uafvalidate: recovered from panic during pool cleanup: %v", r)
					}
				}()
				state.vm.Close()
			}()
		}
		if state.imagePath != "" {
			os.Remove(state.imagePath)
		}
		delete(pool.states, index)
	}
}

// snapshotExecutorAdapter wraps ExecutorAdapter for snapshot-enabled VMs.
type snapshotExecutorAdapter struct {
	*uafvalidate.ExecutorAdapter
	pool   *snapshotVMPool
	index  int
	closed bool
}

func (s *snapshotExecutorAdapter) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true

	// Close only the executor connections (RPC, SSH), but NOT the VM
	// We want to keep the VM running so we can restore from snapshot
	if s.ExecutorAdapter != nil {
		s.ExecutorAdapter.CloseExecutorOnly()
	}

	// Return the VM index to the pool (don't close the VM, it will be reused)
	s.pool.availableVMs <- s.index

	return nil
}

// pooledExecutorAdapter wraps ExecutorAdapter and returns the VM index to the pool on close.
type pooledExecutorAdapter struct {
	*uafvalidate.ExecutorAdapter
	releaseVM func()
	closed    bool
}

func (p *pooledExecutorAdapter) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	err := p.ExecutorAdapter.Close()
	if p.releaseVM != nil {
		p.releaseVM()
	}
	return err
}

func (mgr *Manager) handleValidationResult(res *uafvalidate.ValidationResult) {
	if res == nil {
		return
	}
	repeatTotal := res.RepeatTotal
	if repeatTotal <= 0 {
		repeatTotal = 1
	}
	runIndex := res.RepeatIndex + 1
	signatureKey := uafvalidate.SignatureKey(res.Signature)
	if runIndex < repeatTotal {
		switch {
		case res.Err != nil:
			log.Errorf("uaf validation: run %d/%d for %s errored: %v", runIndex, repeatTotal, signatureKey, res.Err)
		case res.Success:
			log.Logf(0, "uaf validation: run %d/%d for %s succeeded (pairs=%d)", runIndex, repeatTotal, signatureKey, len(res.Pairs))
		default:
			log.Logf(0, "uaf validation: run %d/%d for %s crashed (%s)", runIndex, repeatTotal, signatureKey, res.CrashTitle)
		}
		return
	}

	if res.CollectionOnly {
		if res.Err != nil {
			log.Errorf("uaf validation: collection-only executor error for %s: %v", signatureKey, res.Err)
			mgr.statUAFFailed.Add(1)
			return
		}
		if res.Success {
			log.Logf(0, "uaf validation: collection-only result for %s succeeded runtime_pairs=%d stable_pairs=%d",
				signatureKey, len(res.Pairs), len(res.StablePairs))
		} else {
			log.Logf(0, "uaf validation: collection-only result for %s crashed (%s)", signatureKey, res.CrashTitle)
		}
		return
	}

	confirmed := false
	if res.Err != nil {
		log.Errorf("uaf validation: executor error: %v", res.Err)
	} else if res.NoStablePairs {
		log.Logf(0, "uaf validation: no stable pair for %s runtime_pairs=%d",
			signatureKey, len(res.Pairs))
	} else if len(res.StablePairs) > 0 {
		confirmed = res.VerificationValidatedPairs > 0
		log.Logf(0, "uaf validation: runtime candidate pair %s", signatureKey)
		log.Logf(0, "uaf validation: runtime candidate intersection for %s count=%d", signatureKey, len(res.StablePairs))
		for idx, pair := range res.StablePairs {
			log.Logf(1, "uaf validation: runtime candidate pair %s[%d]: free_access=%016x use_access=%016x free_stack=%016x use_stack=%016x signal=%016x time_diff=%dns free_sn=%d use_sn=%d lock_type=%d use_access_type=%d",
				signatureKey,
				idx,
				pair.FreeAccessName,
				pair.UseAccessName,
				pair.FreeCallStack,
				pair.UseCallStack,
				pair.Signal,
				pair.TimeDiff,
				pair.FreeSN,
				pair.UseSN,
				pair.LockType,
				pair.UseAccessType,
			)
		}
		log.Logf(0, "uaf validation: verify outcome for %s executed=%d skipped=%d skipped_validated=%d validated=%d failed=%d",
			signatureKey,
			res.VerificationExecutedPairs,
			res.VerificationSkippedPairs,
			res.VerificationSkippedValidatedPairs,
			res.VerificationValidatedPairs,
			res.VerificationFailedPairs)
		if confirmed {
			log.Logf(0, "uaf validation: target race validated for %s", signatureKey)
		} else {
			log.Logf(0, "uaf validation: no target race validated for %s", signatureKey)
		}
	} else {
		log.Logf(0, "uaf validation: pair %s crashed (%s)", signatureKey, res.CrashTitle)
	}

	if confirmed {
		mgr.statUAFValidated.Add(1)
	} else {
		mgr.statUAFFailed.Add(1)
	}
}

func validationResultSucceededForStats(res *uafvalidate.ValidationResult) bool {
	if res == nil {
		return false
	}
	if res.CollectionOnly {
		return res.Success
	}
	return res.VerificationValidatedPairs > 0
}

func cloneMayPairs(pairs []ddrd.MayUAFPair) []ddrd.MayUAFPair {
	if len(pairs) == 0 {
		return nil
	}
	cloned := make([]ddrd.MayUAFPair, len(pairs))
	copy(cloned, pairs)
	return cloned
}

// runUAFValidateContinuousMode runs the validation in continuous mode with incremental corpus reloading.
func (mgr *Manager) runUAFValidateContinuousMode(ctx context.Context) {
	cfg := mgr.cfg.Experimental.UAFValidate

	// Set up reload intervals with defaults
	reloadInterval := time.Duration(cfg.IncrementalReloadMinutes) * time.Minute
	if reloadInterval <= 0 {
		reloadInterval = 10 * time.Minute
	}
	idleReloadInterval := time.Duration(cfg.IdleReloadSeconds) * time.Second
	if idleReloadInterval <= 0 {
		idleReloadInterval = 30 * time.Second
	}

	validatorCfg := uafvalidate.Config{
		MaxConcurrent:             cfg.MaxConcurrent,
		DelayRetryBudget:          cfg.DelayRetryBudget,
		ExecutionTimeout:          time.Duration(cfg.TimeoutSeconds) * time.Second,
		MaxBatchTimeout:           time.Duration(cfg.MaxBatchTimeoutSeconds) * time.Second,
		Debug:                     *flagDebug,
		RepeatCount:               cfg.RepeatCount,
		VerifyRepeatTimes:         cfg.VerifyRepeatTimes,
		Workdir:                   mgr.cfg.Workdir,
		TargetVarNamePair:         cfg.TargetVarNamePair,
		TargetCorpusKey:           cfg.TargetCorpusKey,
		DisableAsyncSplit:         cfg.DisableAsyncSplit,
		DisableCollectionDelay:    cfg.DisableCollectionDelay,
		DisableVerifyDelay:        cfg.DisableVerifyDelay,
		DisableAccessDelay:        cfg.DisableAccessDelay,
		VerifyAccessDelayMinUs:    cfg.VerifyAccessDelayMinUs,
		TargetMatchMode:           cfg.TargetMatchMode,
		SNFallbackRange:           cfg.SNFallbackRange,
		TargetDelaySide:           cfg.TargetDelaySide,
		TargetDelayMode:           cfg.TargetDelayMode,
		WildcardTargetTID:         cfg.WildcardTargetTID,
		VerifyDelaySweep:          cfg.VerifyDelaySweep,
		VerifyDelaySteps:          cfg.VerifyDelaySteps,
		VerifyDelayMaxUs:          cfg.VerifyDelayMaxUs,
		VerifyDelayPower:          cfg.VerifyDelayPower,
		EnableReplay:              cfg.EnableReplay,
		ReplayCollectPairs:        cfg.ReplayCollectPairs,
		VerifyCollectPairs:        cfg.VerifyCollectPairs,
		MaxReplayHistory:          cfg.MaxReplayHistory,
		EnableVarNameScheduling:   cfg.EnableVarNameScheduling,
		PriorityLowHistory:        cfg.PriorityLowHistory,
		RequireOriginMatch:        cfg.RequireOriginMatch,
		OriginMatchMode:           cfg.OriginMatchMode,
		MaxStablePairsPerOrigin:   cfg.MaxStablePairsPerOrigin,
		MaxStablePairsPerEntry:    cfg.MaxStablePairsPerEntry,
		CollectionOnly:            cfg.CollectionOnly,
		DisableBackoffSkip:        cfg.DisableBackoffSkip,
		ContinueAfterBackoff:      cfg.ContinueAfterBackoff,
		EnableHistoryMinimization: cfg.EnableHistoryMinimization,
		MinimizationMaxAttempts:   cfg.MinimizationMaxAttempts,
		MinimizationStrategy:      cfg.MinimizationStrategy,
		EntryResolver:             &validationEntryResolver{workdir: mgr.uafSharedWorkdir, target: mgr.target},
		PairStatusSink:            mgr.uafPairIndex,
	}
	if validatorCfg.MaxConcurrent > mgr.vmPool.Count() {
		validatorCfg.MaxConcurrent = mgr.vmPool.Count()
	}
	if validatorCfg.MaxConcurrent <= 0 {
		validatorCfg.MaxConcurrent = 1
	}

	stage := uafvalidate.NewStageManager(validatorCfg, mgr.selectExecutorFactory(cfg, validatorCfg))

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Atomic counters for validator stats reporting (dynamic threshold coordination)
	var validatorProcessed int32
	var validatorSuccess int32

	// Start result handler
	resultsDone := make(chan struct{})
	go func() {
		for res := range stage.Results() {
			mgr.handleValidationResult(res)
			// Track counts for dynamic threshold coordination
			repeatTotal := res.RepeatTotal
			if repeatTotal <= 0 {
				repeatTotal = 1
			}
			if res.RepeatIndex+1 >= repeatTotal {
				atomic.AddInt32(&validatorProcessed, 1)
				if validationResultSucceededForStats(res) {
					atomic.AddInt32(&validatorSuccess, 1)
				}
			}
		}
		close(resultsDone)
	}()

	// Start workers
	runDone := make(chan struct{})
	go func() {
		stage.Run(runCtx)
		close(runDone)
	}()

	// Initial load
	var lastSeq uint64 = 0
	entries, newSeq, err := mgr.uafStore.EntriesSince(0)
	if err != nil {
		log.Errorf("uaf validation: failed to load initial entries: %v", err)
	} else {
		lastSeq = newSeq
		enqueued := 0
		withHistory := 0
		for _, entry := range entries {
			if entry != nil && len(entry.ReplayHistory) > 0 {
				withHistory++
			}
			stage.Enqueue(entry)
			enqueued++
		}
		log.Logf(0, "uaf validation: initial load enqueued %d entries (seq=%d, with_history=%d)", enqueued, lastSeq, withHistory)
	}

	// Periodic reload ticker
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()

	// Idle check ticker (more frequent)
	idleTicker := time.NewTicker(idleReloadInterval)
	defer idleTicker.Stop()

	log.Logf(0, "uaf validation: continuous mode started (reload=%v, idle_reload=%v)", reloadInterval, idleReloadInterval)

	// Start periodic validator stats reporter for dynamic threshold coordination
	validatorStartTime := time.Now()
	statsReportInterval := 15 * time.Second
	statsTicker := time.NewTicker(statsReportInterval)
	defer statsTicker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-statsTicker.C:
				processed := int(atomic.LoadInt32(&validatorProcessed))
				success := int(atomic.LoadInt32(&validatorSuccess))
				pending := stage.PendingCount()
				idle := !stage.HasPending()
				var rate float64
				if processed > 0 {
					rate = float64(processed) / time.Since(validatorStartTime).Minutes()
				}
				_ = ddrd.WriteValidatorStats(mgr.uafSharedWorkdir, ddrd.ValidatorStats{
					PendingCount:       pending,
					ProcessedCount:     processed,
					SuccessCount:       success,
					ProcessingRatePerM: rate,
					LastUpdate:         time.Now(),
					Idle:               idle,
				})
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			log.Logf(0, "uaf validation: context cancelled, shutting down")
			stage.Shutdown()
			<-runDone
			<-resultsDone
			mgr.exit("uaf-validate")
			return

		case <-ticker.C:
			// Periodic incremental reload - first reload DB from disk to pick up changes from fuzzer process
			if err := mgr.uafStore.Reload(); err != nil {
				log.Errorf("uaf validation: periodic db reload failed: %v", err)
			}
			newEntries, newSeq, err := mgr.uafStore.EntriesSince(lastSeq)
			if err != nil {
				log.Errorf("uaf validation: periodic reload failed: %v", err)
				continue
			}
			if len(newEntries) > 0 {
				lastSeq = newSeq
				enqueued := 0
				withHistory := 0
				for _, entry := range newEntries {
					if entry != nil && len(entry.ReplayHistory) > 0 {
						withHistory++
					}
					stage.Enqueue(entry)
					enqueued++
				}
				log.Logf(0, "uaf validation: periodic reload enqueued %d new entries (seq=%d, pending=%d, seen=%d, with_history=%d)",
					enqueued, lastSeq, stage.PendingCount(), stage.SeenCount(), withHistory)
			}

		case <-idleTicker.C:
			// Check if idle (no pending tasks)
			if !stage.HasPending() {
				// Reload DB from disk to pick up changes from fuzzer process
				if err := mgr.uafStore.Reload(); err != nil {
					log.Errorf("uaf validation: idle db reload failed: %v", err)
				}
				newEntries, newSeq, err := mgr.uafStore.EntriesSince(lastSeq)
				if err != nil {
					log.Errorf("uaf validation: idle reload failed: %v", err)
					continue
				}
				if len(newEntries) > 0 {
					lastSeq = newSeq
					enqueued := 0
					withHistory := 0
					for _, entry := range newEntries {
						if entry != nil && len(entry.ReplayHistory) > 0 {
							withHistory++
						}
						stage.Enqueue(entry)
						enqueued++
					}
					log.Logf(0, "uaf validation: idle reload enqueued %d new entries (seq=%d, pending=%d, seen=%d, with_history=%d)",
						enqueued, lastSeq, stage.PendingCount(), stage.SeenCount(), withHistory)
				} else {
					log.Logf(1, "uaf validation: idle, no new entries available (seq=%d, seen=%d)",
						lastSeq, stage.SeenCount())
				}
			}
		}
	}
}

// runUAFValidateModeStreaming runs validation with memory-efficient streaming load.
// This is designed for large uaf-corpus.db files (>1GB) that would otherwise cause OOM.
// It supports co-start with fuzz: if the corpus file does not yet exist, it waits
// until fuzz creates it, then enters a continuous polling loop to pick up new entries.
func (mgr *Manager) runUAFValidateModeStreaming(ctx context.Context) {
	cfg := mgr.cfg.Experimental.UAFValidate
	log.Logf(0, "uaf validation: entering streaming mode...")

	// Determine corpus path
	corpusPath := filepath.Join(mgr.uafSharedWorkdir, "uaf-corpus.db")
	log.Logf(0, "uaf validation: checking corpus file: %s", corpusPath)

	// Wait for corpus file to appear (supports co-start with fuzz).
	const corpusWaitInterval = 10 * time.Second
	for {
		if _, err := os.Stat(corpusPath); err == nil {
			break
		}
		log.Logf(0, "uaf validation: corpus file %s not yet available, waiting %v for fuzz to create it...", corpusPath, corpusWaitInterval)
		select {
		case <-ctx.Done():
			log.Logf(0, "uaf validation: context cancelled while waiting for corpus")
			mgr.exit("uaf-validate")
			return
		case <-time.After(corpusWaitInterval):
		}
	}

	// Get file size for progress reporting
	fi, err := os.Stat(corpusPath)
	if err != nil {
		log.Fatalf("uaf validation: failed to stat corpus file: %v", err)
	}
	fileSizeMB := fi.Size() / (1024 * 1024)
	log.Logf(0, "uaf validation: streaming mode enabled for %s (%d MB)", corpusPath, fileSizeMB)

	// Determine batch size
	batchSize := cfg.StreamingBatchSize
	if batchSize <= 0 {
		batchSize = 500
	}
	log.Logf(0, "uaf validation: using batch size %d", batchSize)

	// Determine reload intervals
	reloadInterval := time.Duration(cfg.IncrementalReloadMinutes) * time.Minute
	if reloadInterval <= 0 {
		reloadInterval = 10 * time.Minute
	}
	idleReloadInterval := time.Duration(cfg.IdleReloadSeconds) * time.Second
	if idleReloadInterval <= 0 {
		idleReloadInterval = 30 * time.Second
	}

	// Setup validator
	validatorCfg := uafvalidate.Config{
		MaxConcurrent:             cfg.MaxConcurrent,
		DelayRetryBudget:          cfg.DelayRetryBudget,
		ExecutionTimeout:          time.Duration(cfg.TimeoutSeconds) * time.Second,
		MaxBatchTimeout:           time.Duration(cfg.MaxBatchTimeoutSeconds) * time.Second,
		Debug:                     *flagDebug,
		RepeatCount:               cfg.RepeatCount,
		VerifyRepeatTimes:         cfg.VerifyRepeatTimes,
		Workdir:                   mgr.cfg.Workdir,
		TargetVarNamePair:         cfg.TargetVarNamePair,
		TargetCorpusKey:           cfg.TargetCorpusKey,
		DisableAsyncSplit:         cfg.DisableAsyncSplit,
		DisableCollectionDelay:    cfg.DisableCollectionDelay,
		DisableVerifyDelay:        cfg.DisableVerifyDelay,
		DisableAccessDelay:        cfg.DisableAccessDelay,
		VerifyAccessDelayMinUs:    cfg.VerifyAccessDelayMinUs,
		TargetMatchMode:           cfg.TargetMatchMode,
		SNFallbackRange:           cfg.SNFallbackRange,
		TargetDelaySide:           cfg.TargetDelaySide,
		TargetDelayMode:           cfg.TargetDelayMode,
		WildcardTargetTID:         cfg.WildcardTargetTID,
		VerifyDelaySweep:          cfg.VerifyDelaySweep,
		VerifyDelaySteps:          cfg.VerifyDelaySteps,
		VerifyDelayMaxUs:          cfg.VerifyDelayMaxUs,
		VerifyDelayPower:          cfg.VerifyDelayPower,
		EnableReplay:              cfg.EnableReplay,
		ReplayCollectPairs:        cfg.ReplayCollectPairs,
		VerifyCollectPairs:        cfg.VerifyCollectPairs,
		MaxReplayHistory:          cfg.MaxReplayHistory,
		EnableVarNameScheduling:   cfg.EnableVarNameScheduling,
		PriorityLowHistory:        cfg.PriorityLowHistory,
		RequireOriginMatch:        cfg.RequireOriginMatch,
		OriginMatchMode:           cfg.OriginMatchMode,
		MaxStablePairsPerOrigin:   cfg.MaxStablePairsPerOrigin,
		MaxStablePairsPerEntry:    cfg.MaxStablePairsPerEntry,
		CollectionOnly:            cfg.CollectionOnly,
		DisableBackoffSkip:        cfg.DisableBackoffSkip,
		ContinueAfterBackoff:      cfg.ContinueAfterBackoff,
		EnableHistoryMinimization: cfg.EnableHistoryMinimization,
		MinimizationMaxAttempts:   cfg.MinimizationMaxAttempts,
		MinimizationStrategy:      cfg.MinimizationStrategy,
		EntryResolver:             &validationEntryResolver{workdir: mgr.uafSharedWorkdir, target: mgr.target},
		PairStatusSink:            mgr.uafPairIndex,
	}
	if validatorCfg.MaxConcurrent > mgr.vmPool.Count() {
		validatorCfg.MaxConcurrent = mgr.vmPool.Count()
	}
	if validatorCfg.MaxConcurrent <= 0 {
		validatorCfg.MaxConcurrent = 1
	}

	stage := uafvalidate.NewStageManager(validatorCfg, mgr.selectExecutorFactory(cfg, validatorCfg))

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start result handler
	resultsDone := make(chan struct{})
	go func() {
		for res := range stage.Results() {
			mgr.handleValidationResult(res)
		}
		close(resultsDone)
	}()

	// Start workers
	runDone := make(chan struct{})
	go func() {
		stage.Run(runCtx)
		close(runDone)
	}()

	maxEntries := cfg.MaxEntries

	// Helper: do one streaming scan and enqueue new entries.
	// Returns the new maxSeq and cumulative enqueue count.
	streamOnce := func(sinceSeq uint64, totalEnqueued int) (uint64, int) {
		reader := manager.NewStreamingUAFCorpusReader(corpusPath, mgr.target)
		batchEnqueued := 0
		withHistory := 0
		lastBatchLog := time.Now()
		limitHit := false

		newMaxSeq, err := reader.IterateEntriesBatched(sinceSeq, batchSize, func(entries []*fuzzer.UAFCorpusEntry, seqs []uint64) bool {
			for _, entry := range entries {
				if maxEntries > 0 && totalEnqueued+batchEnqueued >= maxEntries {
					log.Logf(0, "uaf validation: reached max_entries limit (%d)", maxEntries)
					limitHit = true
					return false
				}
				if entry != nil && len(entry.ReplayHistory) > 0 {
					withHistory++
				}
				stage.Enqueue(entry)
				batchEnqueued++
			}
			if time.Since(lastBatchLog) > 3*time.Second || batchEnqueued <= batchSize {
				log.Logf(0, "uaf validation: enqueued %d entries (total=%d, with_history=%d)",
					batchEnqueued, totalEnqueued+batchEnqueued, withHistory)
				lastBatchLog = time.Now()
			}
			return !limitHit
		})
		if err != nil {
			log.Logf(0, "uaf validation: streaming scan error: %v", err)
		}
		if newMaxSeq < sinceSeq {
			newMaxSeq = sinceSeq
		}
		if batchEnqueued > 0 {
			log.Logf(0, "uaf validation: scan complete - enqueued %d new entries (total=%d, seq=%d)",
				batchEnqueued, totalEnqueued+batchEnqueued, newMaxSeq)
		}
		return newMaxSeq, totalEnqueued + batchEnqueued
	}

	// Initial scan
	log.Logf(0, "uaf validation: starting initial streaming scan...")
	var lastSeq uint64
	totalEnqueued := 0
	lastSeq, totalEnqueued = streamOnce(0, 0)
	log.Logf(0, "uaf validation: initial scan done - enqueued %d entries (seq=%d)", totalEnqueued, lastSeq)

	// Continuous polling loop: periodically re-read corpus for new entries from fuzz.
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()
	idleTicker := time.NewTicker(idleReloadInterval)
	defer idleTicker.Stop()

	log.Logf(0, "uaf validation: entering continuous streaming loop (reload=%v, idle_reload=%v)", reloadInterval, idleReloadInterval)

	for {
		select {
		case <-ctx.Done():
			log.Logf(0, "uaf validation: context cancelled, shutting down")
			stage.Shutdown()
			<-runDone
			<-resultsDone
			mgr.exit("uaf-validate")
			return

		case <-ticker.C:
			newSeq, newTotal := streamOnce(lastSeq, totalEnqueued)
			lastSeq = newSeq
			totalEnqueued = newTotal

		case <-idleTicker.C:
			if !stage.HasPending() {
				newSeq, newTotal := streamOnce(lastSeq, totalEnqueued)
				lastSeq = newSeq
				totalEnqueued = newTotal
			}
		}
	}
}
