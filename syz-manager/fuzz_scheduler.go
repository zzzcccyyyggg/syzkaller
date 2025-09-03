// ===============DDRD====================
// Fuzz Mode Control System for Syzkaller
// 支持三种模式: auto (两阶段智能切换), normal (仅正常测试), concurrency (仅并发测试)
//
// 架构说明:
// - FuzzScheduler: 核心调度器，管理模式切换逻辑
// - ModeTransitionManager: 重启管理器，通过关闭所有fuzzer并重启实现模式切换
// - 事件驱动设计: 基于信号变化和时间触发模式切换
// ===============DDRD====================

package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

// FuzzPhase represents the current fuzzing phase
type FuzzPhase int

// Fuzzing phases
const (
	PhaseNormalFuzz FuzzPhase = iota // Normal syzkaller fuzzing
	PhaseRaceFuzz                    // Race-focused concurrent fuzzing
)

// FuzzMode represents the fuzzing execution mode
type FuzzMode string

// Supported fuzzing modes
const (
	FuzzModeAuto        FuzzMode = "auto"        // Automatic two-phase mode
	FuzzModeNormal      FuzzMode = "normal"      // Normal fuzzing only
	FuzzModeConcurrency FuzzMode = "concurrency" // Concurrency testing only
)

// ModeTransitionManager manages restart-based mode transitions.
// It shuts down all current fuzzers and restarts them in the new mode.
type ModeTransitionManager struct {
	mu              sync.Mutex
	isTransitioning bool
	targetPhase     FuzzPhase
	transitionID    string // Unique identifier for each transition

	// Manager reference for fuzzer control
	manager *Manager

	// Restart configuration
	restartTimeout time.Duration // Maximum time to wait for shutdown (30 seconds)

	// Callbacks
	onTransitionStart func(FuzzPhase)
	onTransitionDone  func(FuzzPhase, bool) // phase, success
}

// NewModeTransitionManager creates a new mode transition manager for restart-based switching.
func NewModeTransitionManager(manager *Manager) *ModeTransitionManager {
	return &ModeTransitionManager{
		manager:        manager,
		restartTimeout: 30 * time.Second,
	}
}

// ===============DDRD====================

// FuzzScheduler manages two-phase fuzzing scheduling with synchronization support.
// It coordinates between normal fuzzing and race detection phases.
type FuzzScheduler struct {
	mu sync.Mutex

	// Runtime mode configuration
	fuzzMode FuzzMode

	// Current phase state
	currentPhase   FuzzPhase
	phaseStartTime time.Time

	// Normal fuzzing phase state
	lastSignalCount   int
	lastSignalUpdate  time.Time
	normalFuzzEnabled bool

	// Race fuzzing phase state
	lastRaceSignalCount  int
	lastRaceSignalUpdate time.Time
	raceFuzzEnabled      bool

	// Configuration parameters
	maxPhaseTime time.Duration // Maximum runtime per phase

	// Event callbacks
	onPhaseChange func(newPhase FuzzPhase)

	// Restart transition management
	transitionMgr *ModeTransitionManager
}

// ===============DDRD====================

// StartTransition initiates a restart-based phase transition.
// All current fuzzers are shut down and new ones are started in the target phase.
func (mtm *ModeTransitionManager) StartTransition(targetPhase FuzzPhase) error {
	mtm.mu.Lock()
	defer mtm.mu.Unlock()

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] StartTransition called: targetPhase=%v, isTransitioning=%v",
			targetPhase, mtm.isTransitioning)
	}

	if mtm.isTransitioning {
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] StartTransition rejected: transition already in progress (ID=%s, phase=%v)",
				mtm.transitionID, mtm.targetPhase)
		}
		return fmt.Errorf("transition already in progress")
	}

	// Generate unique transition ID
	mtm.transitionID = fmt.Sprintf("transition_%d", time.Now().UnixNano())
	mtm.isTransitioning = true
	mtm.targetPhase = targetPhase

	log.Logf(0, "Starting restart-based mode transition %s to phase %v",
		mtm.transitionID, targetPhase)

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] Restart transition initialized: ID=%s, targetPhase=%v",
			mtm.transitionID, targetPhase)
	}

	// Notify callback
	if mtm.onTransitionStart != nil {
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Calling onTransitionStart callback for phase %v", targetPhase)
		}
		mtm.onTransitionStart(targetPhase)
	}

	// Start async restart process
	go mtm.performRestartTransition()

	return nil
}

func (mtm *ModeTransitionManager) performRestartTransition() {
	startTime := time.Now()

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] performRestartTransition started: transitionID=%s, restartTimeout=%v",
			mtm.transitionID, mtm.restartTimeout)
	}

	// Step 1: Signal all VMs to stop
	log.Logf(0, "Transition %s: Shutting down all fuzzer VMs", mtm.transitionID)
	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] Signaling VM shutdown for transition %s", mtm.transitionID)
	}

	// Send stop signal to all VMs
	mtm.signalVMShutdown()

	// Step 2: Wait for shutdown with timeout
	shutdownSuccess := mtm.waitForShutdown()

	if !shutdownSuccess {
		log.Logf(0, "Transition %s: Shutdown timeout, forcing restart", mtm.transitionID)
	}

	// Step 3: Complete transition
	mtm.mu.Lock()
	success := true // We consider forced restart as success too
	mtm.completeTransition(success)
	mtm.mu.Unlock()

	totalTime := time.Since(startTime)
	log.Logf(0, "Transition %s completed in %v", mtm.transitionID, totalTime)

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] performRestartTransition completed: success=%v, totalTime=%v",
			success, totalTime)
	}
}

func (mtm *ModeTransitionManager) signalVMShutdown() {
	if mtm.manager == nil {
		log.Logf(0, "CRITICAL: Manager reference not set in ModeTransitionManager")
		return
	}

	// Send shutdown signal to VM pool
	// This will cause all running fuzzer instances to terminate
	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] Sending vmStop signal to terminate all fuzzers")
	}

	select {
	case mtm.manager.vmStop <- true:
		log.Logf(1, "VM shutdown signal sent successfully")
	default:
		log.Logf(1, "VM shutdown signal already pending")
	}
}

func (mtm *ModeTransitionManager) waitForShutdown() bool {
	timeout := time.NewTimer(mtm.restartTimeout)
	defer timeout.Stop()

	checkTicker := time.NewTicker(2 * time.Second)
	defer checkTicker.Stop()

	for {
		select {
		case <-timeout.C:
			log.Logf(0, "VM shutdown timeout reached (%v)", mtm.restartTimeout)
			return false

		case <-checkTicker.C:
			// Check if all fuzzers have stopped
			numFuzzing := atomic.LoadUint32(&mtm.manager.numFuzzing)
			if log.V(1) {
				log.Logf(1, "[DDRD-DEBUG] Shutdown check: numFuzzing=%d", numFuzzing)
			}

			if numFuzzing == 0 {
				log.Logf(1, "All fuzzers have shut down successfully")
				return true
			}

			log.Logf(1, "Waiting for %d fuzzers to shut down", numFuzzing)
		}
	}
}

func (mtm *ModeTransitionManager) completeTransition(success bool) {
	// 调用者已持有锁
	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] completeTransition called: transitionID=%s, success=%v, targetPhase=%v",
			mtm.transitionID, success, mtm.targetPhase)
	}

	mtm.isTransitioning = false

	if success {
		log.Logf(0, "Restart transition %s completed successfully", mtm.transitionID)
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Successful restart transition to phase %v", mtm.targetPhase)
		}
	} else {
		log.Logf(0, "Restart transition %s completed with issues", mtm.transitionID)
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Failed restart transition to phase %v", mtm.targetPhase)
		}
	}

	// 通知回调完成切换
	if mtm.onTransitionDone != nil {
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Calling onTransitionDone callback: success=%v, phase=%v",
				success, mtm.targetPhase)
		}
		go mtm.onTransitionDone(mtm.targetPhase, success)
	}
}

// GetTransitionInfo returns current transition status information.
func (mtm *ModeTransitionManager) GetTransitionInfo() (bool, string, FuzzPhase) {
	mtm.mu.Lock()
	defer mtm.mu.Unlock()

	if log.V(2) {
		log.Logf(2, "[DDRD-DEBUG] GetTransitionInfo: isTransitioning=%v, ID=%s, targetPhase=%v",
			mtm.isTransitioning, mtm.transitionID, mtm.targetPhase)
	}

	return mtm.isTransitioning, mtm.transitionID, mtm.targetPhase
}

// NewFuzzScheduler creates a new fuzzing scheduler with the specified mode.
// If mode is empty, defaults to auto mode. The scheduler requires proper
// initialization via SetupTransitionManager() before use.
func NewFuzzScheduler(mode FuzzMode) *FuzzScheduler {
	if mode == "" {
		mode = FuzzModeAuto // Default to auto mode
	}

	var initialPhase FuzzPhase
	var normalEnabled, raceEnabled bool

	switch mode {
	case FuzzModeNormal:
		initialPhase = PhaseNormalFuzz
		normalEnabled = true
		raceEnabled = false
	case FuzzModeConcurrency:
		initialPhase = PhaseRaceFuzz
		normalEnabled = false
		raceEnabled = true
	default: // FuzzModeAuto
		initialPhase = PhaseNormalFuzz
		normalEnabled = true
		raceEnabled = false
	}

	log.Logf(1, "Fuzz Scheduler initialized with mode: %s, initial phase: %v", mode, initialPhase)

	scheduler := &FuzzScheduler{
		fuzzMode:             mode,
		currentPhase:         initialPhase,
		phaseStartTime:       time.Now(),
		lastSignalUpdate:     time.Now(),
		lastRaceSignalUpdate: time.Now(),
		normalFuzzEnabled:    normalEnabled,
		raceFuzzEnabled:      raceEnabled,
		maxPhaseTime:         2 * time.Minute, // 2 minutes per phase for testing
	}

	return scheduler
}

// SetPhaseChangeCallback 设置阶段变化回调
func (fs *FuzzScheduler) SetPhaseChangeCallback(callback func(newPhase FuzzPhase)) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.onPhaseChange = callback
}

// GetCurrentPhase 获取当前阶段
func (fs *FuzzScheduler) GetCurrentPhase() FuzzPhase {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.currentPhase
}

// GetFuzzMode 获取当前fuzz模式
func (fs *FuzzScheduler) GetFuzzMode() FuzzMode {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.fuzzMode
}

// IsNormalFuzzEnabled 检查是否启用正常fuzz
func (fs *FuzzScheduler) IsNormalFuzzEnabled() bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.normalFuzzEnabled
}

// IsRaceFuzzEnabled 检查是否启用race fuzz
func (fs *FuzzScheduler) IsRaceFuzzEnabled() bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.raceFuzzEnabled
}

// UpdateSignalCount 更新正常fuzz的signal计数
func (fs *FuzzScheduler) UpdateSignalCount(newCount int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.currentPhase != PhaseNormalFuzz {
		return
	}

	// 检查signal是否增长
	if newCount > fs.lastSignalCount {
		fs.lastSignalCount = newCount
		fs.lastSignalUpdate = time.Now()
		log.Logf(1, "Normal fuzz signal updated: %d", newCount)
	}

	// 检查是否需要切换阶段
	fs.checkPhaseSwitch()
}

// UpdateRaceSignalCount 更新race fuzz的signal计数
func (fs *FuzzScheduler) UpdateRaceSignalCount(newCount int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.currentPhase != PhaseRaceFuzz {
		return
	}

	// 检查race signal是否增长
	if newCount > fs.lastRaceSignalCount {
		fs.lastRaceSignalCount = newCount
		fs.lastRaceSignalUpdate = time.Now()
		log.Logf(1, "Race fuzz signal updated: %d", newCount)
	}

	// 检查是否需要切换阶段
	fs.checkPhaseSwitch()
}

// UpdateRacePairSignal 更新race pair覆盖率signal
func (fs *FuzzScheduler) UpdateRacePairSignal(newSignal uint64) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.currentPhase != PhaseRaceFuzz {
		return
	}

	// 检查race pair signal是否增长
	if newSignal > uint64(fs.lastRaceSignalCount) {
		fs.lastRaceSignalCount = int(newSignal)
		fs.lastRaceSignalUpdate = time.Now()
		log.Logf(1, "Race pair signal updated: %d", newSignal)
	}

	// 检查是否需要切换阶段
	fs.checkPhaseSwitch()
}

// checkPhaseSwitch evaluates whether a phase transition should occur (internal function, requires mutex lock).
func (fs *FuzzScheduler) checkPhaseSwitch() {
	// Fixed modes don't perform phase transitions
	if fs.fuzzMode == FuzzModeNormal || fs.fuzzMode == FuzzModeConcurrency {
		return
	}

	// Only AUTO mode performs automatic transitions
	if fs.fuzzMode != FuzzModeAuto {
		return
	}

	now := time.Now()
	phaseRunTime := now.Sub(fs.phaseStartTime)

	// Time-based switching for auto mode
	if phaseRunTime >= fs.maxPhaseTime {
		reason := fmt.Sprintf("auto mode: %v phase max time reached", fs.currentPhase)
		log.Logf(0, "Phase switch triggered: %s", reason)
		fs.switchPhase(reason)
	}
}

// switchPhase initiates a coordinated phase switch (internal function, requires mutex lock).
func (fs *FuzzScheduler) switchPhase(reason string) {
	if fs.transitionMgr == nil {
		log.Logf(0, "CRITICAL: Transition manager not initialized. Call SetupTransitionManager() first.")
		panic("FuzzScheduler transition manager not initialized")
	}

	// Start synchronized switch process
	fs.startSynchronizedSwitch(reason)
}

// switchPhaseImmediate performs the actual phase switch without synchronization.
// This is called after all fuzzers have been coordinated via the transition manager.
func (fs *FuzzScheduler) switchPhaseImmediate(reason string) {
	oldPhase := fs.currentPhase
	oldTime := fs.phaseStartTime

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] switchPhaseImmediate called: oldPhase=%v, reason='%s', phaseRuntime=%v",
			oldPhase, reason, time.Since(oldTime))
	}

	// Switch to next phase
	switch fs.currentPhase {
	case PhaseNormalFuzz:
		fs.currentPhase = PhaseRaceFuzz
		fs.normalFuzzEnabled = false
		fs.raceFuzzEnabled = true
		log.Logf(0, "Switching to race fuzz phase: %s", reason)

		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Phase switch executed: NORMAL->RACE, normalEnabled=%v, raceEnabled=%v",
				fs.normalFuzzEnabled, fs.raceFuzzEnabled)
		}

	case PhaseRaceFuzz:
		fs.currentPhase = PhaseNormalFuzz
		fs.normalFuzzEnabled = true
		fs.raceFuzzEnabled = false
		log.Logf(0, "Switching to normal fuzz phase: %s", reason)

		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Phase switch executed: RACE->NORMAL, normalEnabled=%v, raceEnabled=%v",
				fs.normalFuzzEnabled, fs.raceFuzzEnabled)
		}
	}

	// Reset phase state
	fs.phaseStartTime = time.Now()

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] Phase state reset: newStartTime=%v", fs.phaseStartTime)
	}

	// Trigger callback
	if fs.onPhaseChange != nil {
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Triggering onPhaseChange callback for phase %v", fs.currentPhase)
		}
		go fs.onPhaseChange(fs.currentPhase)
	}

	log.Logf(0, "Phase switched from %v to %v", oldPhase, fs.currentPhase)

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] switchPhaseImmediate completed: %v->%v, runtime was %v",
			oldPhase, fs.currentPhase, time.Since(oldTime))
	}
}

// startSynchronizedSwitch initiates a coordinated phase transition.
func (fs *FuzzScheduler) startSynchronizedSwitch(reason string) {
	oldPhase := fs.currentPhase
	var newPhase FuzzPhase

	switch fs.currentPhase {
	case PhaseNormalFuzz:
		newPhase = PhaseRaceFuzz
	case PhaseRaceFuzz:
		newPhase = PhaseNormalFuzz
	}

	log.Logf(0, "Starting synchronized phase switch from %v to %v: %s",
		oldPhase, newPhase, reason)

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] startSynchronizedSwitch: oldPhase=%v, newPhase=%v, reason='%s'",
			oldPhase, newPhase, reason)
	}

	// Start restart transition process
	if err := fs.transitionMgr.StartTransition(newPhase); err != nil {
		log.Logf(0, "CRITICAL: Failed to start restart transition: %v", err)
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] StartTransition failed: error=%v", err)
		}
		// Don't fall back to immediate switch - this indicates a serious problem
		panic(fmt.Sprintf("restart transition failed: %v", err))
	}

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] StartTransition succeeded, restarting all fuzzers")
	}
}

// SetupTransitionManager initializes the restart-based transition manager.
// This method must be called before the scheduler can perform phase switches.
func (fs *FuzzScheduler) SetupTransitionManager(manager *Manager) {
	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] SetupTransitionManager called")
	}

	fs.transitionMgr = NewModeTransitionManager(manager)

	// Setup completion callback
	fs.transitionMgr.onTransitionDone = func(phase FuzzPhase, success bool) {
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] onTransitionDone callback: phase=%v, success=%v", phase, success)
		}

		fs.mu.Lock()
		defer fs.mu.Unlock()

		if success {
			// Execute actual phase switch after successful restart
			if log.V(1) {
				log.Logf(1, "[DDRD-DEBUG] Executing phase switch after successful restart")
			}
			fs.switchPhaseImmediate("restart transition completed")
		} else {
			log.Logf(0, "Restart transition failed, keeping current phase")
			if log.V(1) {
				log.Logf(1, "[DDRD-DEBUG] Restart transition failed, keeping phase %v", fs.currentPhase)
			}
		}

		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Restart transition completed successfully")
		}
	}

	log.Logf(1, "Restart transition manager initialized for scheduler")

	// Start periodic checking for auto mode
	if fs.fuzzMode == FuzzModeAuto {
		fs.StartPeriodicCheck()
		log.Logf(1, "Started periodic phase checking for auto mode")
	}

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] SetupTransitionManager completed successfully")
	}
}

// ===============DDRD====================

// ForcePhaseSwitch 强制切换阶段
func (fs *FuzzScheduler) ForcePhaseSwitch() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] ForcePhaseSwitch called: currentPhase=%v", fs.currentPhase)
	}

	fs.switchPhase("manually triggered")
}

// GetStatus 获取调度器状态信息
func (fs *FuzzScheduler) GetStatus() map[string]interface{} {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	now := time.Now()
	return map[string]interface{}{
		"fuzz_mode":           fs.fuzzMode,
		"current_phase":       fs.currentPhase,
		"phase_start_time":    fs.phaseStartTime,
		"phase_runtime":       now.Sub(fs.phaseStartTime),
		"normal_fuzz_enabled": fs.normalFuzzEnabled,
		"race_fuzz_enabled":   fs.raceFuzzEnabled,
		"last_signal_count":   fs.lastSignalCount,
		"last_signal_update":  fs.lastSignalUpdate,
		"race_signal_count":   fs.lastRaceSignalCount,
		"race_signal_update":  fs.lastRaceSignalUpdate,
	}
}

// GetPhaseStats returns phase statistics for HTML page display.
func (fs *FuzzScheduler) GetPhaseStats() map[string]interface{} {
	return fs.GetStatus()
}

// StartPeriodicCheck begins periodic phase switch evaluation.
func (fs *FuzzScheduler) StartPeriodicCheck() {
	go func() {
		ticker := time.NewTicker(10 * time.Second) // Check every 10 seconds for testing
		defer ticker.Stop()
		log.Logf(1, "Periodic phase checker started")

		for range ticker.C {
			fs.mu.Lock()
			fs.checkPhaseSwitch()
			fs.mu.Unlock()
		}
	}()
}

// IsTransitionInProgress returns whether a phase transition is currently in progress.
func (fs *FuzzScheduler) IsTransitionInProgress() bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.transitionMgr == nil {
		return false
	}
	isTransitioning, _, _ := fs.transitionMgr.GetTransitionInfo()
	return isTransitioning
}

// GetTransitionManager returns the transition manager for direct RPC access.
func (fs *FuzzScheduler) GetTransitionManager() *ModeTransitionManager {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.transitionMgr
}

// ===============DDRD====================
