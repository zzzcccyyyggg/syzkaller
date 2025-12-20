package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/uafvalidate"
)

func (mgr *Manager) runUAFValidateMode(ctx context.Context) {
	if mgr.uafStore == nil {
		log.Fatalf("uaf validation requires persisted corpus store")
	}

	cfg := mgr.cfg.Experimental.UAFValidate

	// Check if continuous mode is enabled
	if cfg.ContinuousMode {
		mgr.runUAFValidateContinuousMode(ctx)
		return
	}

	// Original one-shot mode
	entries, err := mgr.uafStore.Entries()
	if err != nil {
		log.Fatalf("failed to load persisted uaf entries: %v", err)
	}
	if len(entries) == 0 {
		log.Logf(0, "uaf validation: no persisted entries available")
		mgr.exit("uaf-validate")
		return
	}

	validatorCfg := uafvalidate.Config{
		MaxConcurrent:    cfg.MaxConcurrent,
		DelayRetryBudget: cfg.DelayRetryBudget,
		ExecutionTimeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
		Debug:            *flagDebug,
		RepeatCount:      cfg.RepeatCount,
		Workdir:          mgr.cfg.Workdir,
	}
	if validatorCfg.MaxConcurrent > mgr.vmPool.Count() {
		validatorCfg.MaxConcurrent = mgr.vmPool.Count()
	}
	if validatorCfg.MaxConcurrent <= 0 {
		validatorCfg.MaxConcurrent = 1
	}

	stage := uafvalidate.NewStageManager(validatorCfg, mgr.validatorExecutorFactory(validatorCfg))

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

	for _, entry := range entries {
		stage.Enqueue(entry)
	}
	stage.Close()
	<-runDone
	<-resultsDone
	mgr.exit("uaf-validate")
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
	var outcome manager.UAFValidationOutcome = manager.OutcomeFailed
	note := res.CrashTitle
	if res.Err != nil {
		note = res.Err.Error()
		log.Errorf("uaf validation: executor error: %v", res.Err)
	} else if res.Success {
		outcome = manager.OutcomeConfirmed
		note = ""
		log.Logf(0, "uaf validation: confirmed pair %s", signatureKey)
		log.Logf(0, "uaf validation: stable intersection for %s count=%d", signatureKey, len(res.StablePairs))
		for idx, pair := range res.StablePairs {
			log.Logf(0, "uaf validation: stable pair %s[%d]: free_access=%016x use_access=%016x free_stack=%016x use_stack=%016x signal=%016x time_diff=%dns free_sn=%d use_sn=%d lock_type=%d use_access_type=%d",
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
	} else {
		log.Logf(0, "uaf validation: pair %s crashed (%s)", signatureKey, res.CrashTitle)
	}

	if outcome == manager.OutcomeConfirmed {
		mgr.statUAFValidated.Add(1)
	} else {
		mgr.statUAFFailed.Add(1)
	}

	if mgr.uafValidatedStore == nil || uafvalidate.IsZeroSignature(res.Signature) || res.Entry == nil {
		return
	}
	entry := &manager.UAFValidationEntry{
		Profile:     res.Signature,
		Barrier:     res.Entry.Barrier,
		ReplayPlan:  res.Entry.ReplayPlan,
		Outcome:     outcome,
		Attempts:    normalizeAttempts(res.Attempt),
		LastAttempt: time.Now(),
		Notes:       note,
		RepeatCount: repeatTotal,
		StablePairs: cloneMayPairs(res.StablePairs),
		LastPairs:   cloneMayPairs(res.Pairs),
	}
	if err := mgr.uafValidatedStore.Upsert(entry); err != nil {
		log.Errorf("uaf validation: failed to persist result: %v", err)
	}
}

func normalizeAttempts(attempt int) int {
	if attempt <= 0 {
		return 1
	}
	return attempt
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
		MaxConcurrent:    cfg.MaxConcurrent,
		DelayRetryBudget: cfg.DelayRetryBudget,
		ExecutionTimeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
		Debug:            *flagDebug,
		RepeatCount:      cfg.RepeatCount,
		Workdir:          mgr.cfg.Workdir,
	}
	if validatorCfg.MaxConcurrent > mgr.vmPool.Count() {
		validatorCfg.MaxConcurrent = mgr.vmPool.Count()
	}
	if validatorCfg.MaxConcurrent <= 0 {
		validatorCfg.MaxConcurrent = 1
	}

	stage := uafvalidate.NewStageManager(validatorCfg, mgr.validatorExecutorFactory(validatorCfg))

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

	// Initial load
	var lastSeq uint64 = 0
	entries, newSeq, err := mgr.uafStore.EntriesSince(0)
	if err != nil {
		log.Errorf("uaf validation: failed to load initial entries: %v", err)
	} else {
		lastSeq = newSeq
		enqueued := 0
		for _, entry := range entries {
			stage.Enqueue(entry)
			enqueued++
		}
		log.Logf(0, "uaf validation: initial load enqueued %d entries (seq=%d)", enqueued, lastSeq)
	}

	// Periodic reload ticker
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()

	// Idle check ticker (more frequent)
	idleTicker := time.NewTicker(idleReloadInterval)
	defer idleTicker.Stop()

	log.Logf(0, "uaf validation: continuous mode started (reload=%v, idle_reload=%v)", reloadInterval, idleReloadInterval)

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
				for _, entry := range newEntries {
					stage.Enqueue(entry)
					enqueued++
				}
				log.Logf(0, "uaf validation: periodic reload enqueued %d new entries (seq=%d, pending=%d, seen=%d)",
					enqueued, lastSeq, stage.PendingCount(), stage.SeenCount())
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
					for _, entry := range newEntries {
						stage.Enqueue(entry)
						enqueued++
					}
					log.Logf(0, "uaf validation: idle reload enqueued %d new entries (seq=%d, pending=%d, seen=%d)",
						enqueued, lastSeq, stage.PendingCount(), stage.SeenCount())
				} else {
					log.Logf(1, "uaf validation: idle, no new entries available (seq=%d, seen=%d)",
						lastSeq, stage.SeenCount())
				}
			}
		}
	}
}
