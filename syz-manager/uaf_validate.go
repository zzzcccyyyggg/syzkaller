package main

import (
	"context"
	"fmt"
	"sync"
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
	entries, err := mgr.uafStore.Entries()
	if err != nil {
		log.Fatalf("failed to load persisted uaf entries: %v", err)
	}
	if len(entries) == 0 {
		log.Logf(0, "uaf validation: no persisted entries available")
		mgr.exit("uaf-validate")
		return
	}
	cfg := mgr.cfg.Experimental.UAFValidate
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
	var mu sync.Mutex
	nextIndex := 0
	return func(ctx context.Context) (uafvalidate.Executor, error) {
		mu.Lock()
		index := nextIndex % vmCount
		nextIndex++
		mu.Unlock()
		vmInst, err := mgr.vmPool.Create(ctx, index)
		if err != nil {
			return nil, err
		}
		if *flagDebug {
			log.Logf(0, "uafvalidate: acquired vm index=%d/%d for validation", index, vmCount)
		}
		execInst, err := instance.SetupExecProg(vmInst, mgr.cfg, mgr.reporter, nil)
		if err != nil {
			vmInst.Close()
			return nil, err
		}
		if *flagDebug {
			log.Logf(0, "uafvalidate: vm index=%d ready executor=%p", index, execInst)
		}
		return uafvalidate.NewExecutorAdapter(execInst, cfg), nil
	}
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
