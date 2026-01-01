package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/uafvalidate"
	"github.com/google/syzkaller/vm"
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
		MaxConcurrent:     cfg.MaxConcurrent,
		DelayRetryBudget:  cfg.DelayRetryBudget,
		ExecutionTimeout:  time.Duration(cfg.TimeoutSeconds) * time.Second,
		Debug:             *flagDebug,
		RepeatCount:       cfg.RepeatCount,
		VerifyRepeatTimes: cfg.VerifyRepeatTimes,
		Workdir:           mgr.cfg.Workdir,
		TargetVarNamePair: cfg.TargetVarNamePair,
		DisableAsyncSplit: cfg.DisableAsyncSplit,
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

	for _, entry := range entries {
		stage.Enqueue(entry)
	}
	stage.Close()
	<-runDone
	<-resultsDone
	mgr.exit("uaf-validate")
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
	execprogBin  string // path to syz-execprog inside VM
	executorBin  string // path to syz-executor inside VM
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
			vmInst:          vmInst,
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
		vmInst:          vmInst,
	}, nil
}

func (pool *snapshotVMPool) restoreFromSnapshot(ctx context.Context, index int, state *snapshotVMState) (uafvalidate.Executor, error) {
	restoreStart := time.Now()
	log.Logf(0, "uafvalidate: vm %d restoring from snapshot '%s' with image '%s' (cold restart with -loadvm)", index, state.snapshotName, state.imagePath)

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
	log.Logf(0, "uafvalidate: vm %d CreateWithSnapshotAndImage took %v", index, time.Since(startTime))

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

	log.Logf(0, "uafvalidate: vm %d restored from snapshot successfully (total time: %v)", index, time.Since(restoreStart))

	return &snapshotExecutorAdapter{
		ExecutorAdapter: uafvalidate.NewExecutorAdapter(execInst, pool.cfg),
		pool:            pool,
		index:           index,
		vmInst:          vmInst,
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
	vmInst *vm.Instance
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

	confirmed := false
	if res.Err != nil {
		log.Errorf("uaf validation: executor error: %v", res.Err)
	} else if res.Success {
		confirmed = true
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

	if confirmed {
		mgr.statUAFValidated.Add(1)
	} else {
		mgr.statUAFFailed.Add(1)
	}
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
		MaxConcurrent:     cfg.MaxConcurrent,
		DelayRetryBudget:  cfg.DelayRetryBudget,
		ExecutionTimeout:  time.Duration(cfg.TimeoutSeconds) * time.Second,
		Debug:             *flagDebug,
		RepeatCount:       cfg.RepeatCount,
		VerifyRepeatTimes: cfg.VerifyRepeatTimes,
		Workdir:           mgr.cfg.Workdir,
		TargetVarNamePair: cfg.TargetVarNamePair,
		DisableAsyncSplit: cfg.DisableAsyncSplit,
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
