// ===============DDRD====================
// Fuzz Mode Control System for Syzkaller
// 支持三种模式: auto (两阶段智能切换), normal (仅正常测试), concurrency (仅并发测试)
//
// 架构说明:
// - FuzzScheduler: 核心调度器，管理模式切换逻辑
// - ModeTransitionManager: 同步管理器，确保所有fuzzer协调切换
// - 事件驱动设计: 基于信号变化和时间触发模式切换
// ===============DDRD====================

package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

// getMapKeys returns string slice of map keys for debugging
func getMapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// getPendingFuzzers returns list of fuzzers that are active but not ready
func getPendingFuzzers(active, ready map[string]bool) []string {
	pending := make([]string, 0)
	for fuzzer := range active {
		if !ready[fuzzer] {
			pending = append(pending, fuzzer)
		}
	}
	return pending
}

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

// ModeTransitionManager manages synchronization mechanism for mode transitions.
// It ensures all fuzzers coordinate during phase switches using a two-phase commit pattern.
type ModeTransitionManager struct {
	mu              sync.Mutex
	isTransitioning bool
	targetPhase     FuzzPhase
	transitionID    string // Unique identifier for each transition

	// Fuzzer state tracking
	activeFuzzers map[string]bool // Active fuzzer list
	readyFuzzers  map[string]bool // Ready fuzzer list

	// Synchronization configuration
	maxWaitTime   time.Duration // Maximum wait time (30 seconds)
	checkInterval time.Duration // Check interval (1 second)

	// Callbacks
	onTransitionStart func(FuzzPhase)
	onTransitionDone  func(FuzzPhase, bool) // phase, success
}

// NewModeTransitionManager creates a new mode transition manager with default settings.
func NewModeTransitionManager() *ModeTransitionManager {
	mgr := &ModeTransitionManager{
		activeFuzzers: make(map[string]bool),
		readyFuzzers:  make(map[string]bool),
		maxWaitTime:   30 * time.Second,
		checkInterval: 1 * time.Second,
	}

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] ModeTransitionManager created: maxWaitTime=%v, checkInterval=%v",
			mgr.maxWaitTime, mgr.checkInterval)
	}

	return mgr
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
	maxPhaseTime     time.Duration // Maximum runtime per phase (1 hour)
	signalStableTime time.Duration // Signal stability threshold (5 minutes)

	// Event callbacks
	onPhaseChange func(newPhase FuzzPhase)

	// Synchronization management (required)
	transitionMgr *ModeTransitionManager

	// Transition state tracking
	isWaitingForSync bool
	pendingPhase     FuzzPhase
}

// ===============DDRD====================

// StartTransition initiates a coordinated phase transition across all active fuzzers.
// Returns error if another transition is already in progress.
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

	// Reset fuzzer readiness state
	mtm.readyFuzzers = make(map[string]bool)

	log.Logf(0, "Starting mode transition %s to phase %v with %d active fuzzers",
		mtm.transitionID, targetPhase, len(mtm.activeFuzzers))

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] Transition state initialized: ID=%s, targetPhase=%v, activeFuzzers=%v",
			mtm.transitionID, targetPhase, getMapKeys(mtm.activeFuzzers))
	}

	// Notify callback
	if mtm.onTransitionStart != nil {
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Calling onTransitionStart callback for phase %v", targetPhase)
		}
		mtm.onTransitionStart(targetPhase)
	}

	// Start async waiting process
	go mtm.waitForAllFuzzersReady()

	return nil
}

func (mtm *ModeTransitionManager) waitForAllFuzzersReady() {
	startTime := time.Now()
	ticker := time.NewTicker(mtm.checkInterval)
	defer ticker.Stop()

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] waitForAllFuzzersReady started: transitionID=%s, maxWaitTime=%v",
			mtm.transitionID, mtm.maxWaitTime)
	}

	for {
		select {
		case <-ticker.C:
			mtm.mu.Lock()
			ready := len(mtm.readyFuzzers)
			total := len(mtm.activeFuzzers)
			elapsed := time.Since(startTime)

			log.Logf(1, "Transition %s: %d/%d fuzzers ready (%.1fs elapsed)",
				mtm.transitionID, ready, total, elapsed.Seconds())

			if log.V(1) {
				log.Logf(1, "[DDRD-DEBUG] Fuzzer readiness state: ready=%v, pending=%v",
					getMapKeys(mtm.readyFuzzers), getPendingFuzzers(mtm.activeFuzzers, mtm.readyFuzzers))
			}

			// 检查是否所有fuzzer都准备好了
			if ready == total {
				if log.V(1) {
					log.Logf(1, "[DDRD-DEBUG] All fuzzers ready, completing transition %s", mtm.transitionID)
				}
				mtm.completeTransition(true)
				mtm.mu.Unlock()
				return
			}

			// 检查是否超时
			if elapsed >= mtm.maxWaitTime {
				log.Logf(0, "Transition %s timeout: only %d/%d fuzzers ready",
					mtm.transitionID, ready, total)
				if log.V(1) {
					log.Logf(1, "[DDRD-DEBUG] Transition timeout details: elapsed=%v, maxWaitTime=%v, pending=%v",
						elapsed, mtm.maxWaitTime, getPendingFuzzers(mtm.activeFuzzers, mtm.readyFuzzers))
				}
				mtm.completeTransition(false)
				mtm.mu.Unlock()
				return
			}

			mtm.mu.Unlock()
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
		log.Logf(0, "Transition %s completed successfully", mtm.transitionID)
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Successful transition: all %d fuzzers coordinated for phase %v",
				len(mtm.activeFuzzers), mtm.targetPhase)
		}
	} else {
		log.Logf(0, "Transition %s completed with timeout", mtm.transitionID)
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Failed transition: only %d/%d fuzzers ready, missing=%v",
				len(mtm.readyFuzzers), len(mtm.activeFuzzers),
				getPendingFuzzers(mtm.activeFuzzers, mtm.readyFuzzers))
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

// RegisterFuzzer adds a fuzzer to the active fuzzer list for transition coordination.
func (mtm *ModeTransitionManager) RegisterFuzzer(name string) {
	mtm.mu.Lock()
	defer mtm.mu.Unlock()

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] RegisterFuzzer called: name=%s, currentActive=%v",
			name, getMapKeys(mtm.activeFuzzers))
	}

	mtm.activeFuzzers[name] = true
	log.Logf(1, "Fuzzer %s registered for mode transitions", name)

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] Fuzzer registered: name=%s, totalActive=%d, activeFuzzers=%v",
			name, len(mtm.activeFuzzers), getMapKeys(mtm.activeFuzzers))
	}
}

// UnregisterFuzzer removes a fuzzer from transition coordination.
func (mtm *ModeTransitionManager) UnregisterFuzzer(name string) {
	mtm.mu.Lock()
	defer mtm.mu.Unlock()

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] UnregisterFuzzer called: name=%s, wasActive=%v, wasReady=%v",
			name, mtm.activeFuzzers[name], mtm.readyFuzzers[name])
	}

	delete(mtm.activeFuzzers, name)
	delete(mtm.readyFuzzers, name)
	log.Logf(1, "Fuzzer %s unregistered from mode transitions", name)

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] Fuzzer unregistered: name=%s, totalActive=%d, activeFuzzers=%v",
			name, len(mtm.activeFuzzers), getMapKeys(mtm.activeFuzzers))
	}
}

// MarkFuzzerReady marks a fuzzer as ready for the current transition.
// Returns true if the fuzzer was successfully marked as ready.
func (mtm *ModeTransitionManager) MarkFuzzerReady(name string, transitionID string) bool {
	mtm.mu.Lock()
	defer mtm.mu.Unlock()

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] MarkFuzzerReady called: name=%s, providedID=%s, currentID=%s, isTransitioning=%v",
			name, transitionID, mtm.transitionID, mtm.isTransitioning)
	}

	// Check if transition ID matches
	if transitionID != mtm.transitionID {
		log.Logf(1, "Fuzzer %s sent outdated transition ID %s (current: %s)",
			name, transitionID, mtm.transitionID)
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Transition ID mismatch: fuzzer=%s, provided=%s, expected=%s",
				name, transitionID, mtm.transitionID)
		}
		return false
	}

	// Check if fuzzer is registered
	if !mtm.activeFuzzers[name] {
		log.Logf(1, "Unknown fuzzer %s trying to mark ready", name)
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Unknown fuzzer attempted ready: name=%s, activeFuzzers=%v",
				name, getMapKeys(mtm.activeFuzzers))
		}
		return false
	}

	mtm.readyFuzzers[name] = true
	log.Logf(1, "Fuzzer %s marked ready for transition %s", name, transitionID)

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] Fuzzer marked ready: name=%s, readyCount=%d/%d, readyFuzzers=%v",
			name, len(mtm.readyFuzzers), len(mtm.activeFuzzers), getMapKeys(mtm.readyFuzzers))
	}

	return true
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

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] FuzzScheduler configuration: mode=%s, initialPhase=%v, normalEnabled=%v, raceEnabled=%v",
			mode, initialPhase, normalEnabled, raceEnabled)
	}

	scheduler := &FuzzScheduler{
		fuzzMode:             mode,
		currentPhase:         initialPhase,
		phaseStartTime:       time.Now(),
		lastSignalUpdate:     time.Now(),
		lastRaceSignalUpdate: time.Now(),
		normalFuzzEnabled:    normalEnabled,
		raceFuzzEnabled:      raceEnabled,
		maxPhaseTime:         30 * time.Minute, // 5 minutes per phase
		signalStableTime:     30 * time.Second, // 30 seconds stability for testing
	}

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] FuzzScheduler created: maxPhaseTime=%v, signalStableTime=%v, phaseStartTime=%v",
			scheduler.maxPhaseTime, scheduler.signalStableTime, scheduler.phaseStartTime)
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

	if log.V(2) {
		log.Logf(2, "[DDRD-DEBUG] UpdateSignalCount called: newCount=%d, currentPhase=%v, lastCount=%d",
			newCount, fs.currentPhase, fs.lastSignalCount)
	}

	if fs.currentPhase != PhaseNormalFuzz {
		if log.V(2) {
			log.Logf(2, "[DDRD-DEBUG] UpdateSignalCount ignored: not in normal fuzz phase (current=%v)",
				fs.currentPhase)
		}
		return
	}

	// 检查signal是否增长
	if newCount > fs.lastSignalCount {
		oldCount := fs.lastSignalCount
		oldUpdate := fs.lastSignalUpdate
		fs.lastSignalCount = newCount
		fs.lastSignalUpdate = time.Now()

		log.Logf(1, "Normal fuzz signal updated: %d", newCount)
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Normal signal growth: %d -> %d (+%d), lastUpdate: %v -> %v",
				oldCount, newCount, newCount-oldCount, oldUpdate, fs.lastSignalUpdate)
		}
	} else if log.V(2) {
		log.Logf(2, "[DDRD-DEBUG] Normal signal no change: %d (no growth)", newCount)
	}

	// 检查是否需要切换阶段
	fs.checkPhaseSwitch()
}

// UpdateRaceSignalCount 更新race fuzz的signal计数
func (fs *FuzzScheduler) UpdateRaceSignalCount(newCount int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if log.V(2) {
		log.Logf(2, "[DDRD-DEBUG] UpdateRaceSignalCount called: newCount=%d, currentPhase=%v, lastCount=%d",
			newCount, fs.currentPhase, fs.lastRaceSignalCount)
	}

	if fs.currentPhase != PhaseRaceFuzz {
		if log.V(2) {
			log.Logf(2, "[DDRD-DEBUG] UpdateRaceSignalCount ignored: not in race fuzz phase (current=%v)",
				fs.currentPhase)
		}
		return
	}

	// 检查race signal是否增长
	if newCount > fs.lastRaceSignalCount {
		oldCount := fs.lastRaceSignalCount
		oldUpdate := fs.lastRaceSignalUpdate
		fs.lastRaceSignalCount = newCount
		fs.lastRaceSignalUpdate = time.Now()

		log.Logf(1, "Race fuzz signal updated: %d", newCount)
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Race signal growth: %d -> %d (+%d), lastUpdate: %v -> %v",
				oldCount, newCount, newCount-oldCount, oldUpdate, fs.lastRaceSignalUpdate)
		}
	} else if log.V(2) {
		log.Logf(2, "[DDRD-DEBUG] Race signal no change: %d (no growth)", newCount)
	}

	// 检查是否需要切换阶段
	fs.checkPhaseSwitch()
}

// UpdateRacePairSignal 更新race pair覆盖率signal
func (fs *FuzzScheduler) UpdateRacePairSignal(newSignal uint64) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if log.V(2) {
		log.Logf(2, "[DDRD-DEBUG] UpdateRacePairSignal called: newSignal=%d, currentPhase=%v, lastCount=%d",
			newSignal, fs.currentPhase, fs.lastRaceSignalCount)
	}

	if fs.currentPhase != PhaseRaceFuzz {
		if log.V(2) {
			log.Logf(2, "[DDRD-DEBUG] UpdateRacePairSignal ignored: not in race fuzz phase (current=%v)",
				fs.currentPhase)
		}
		return
	}

	// 检查race pair signal是否增长
	if newSignal > uint64(fs.lastRaceSignalCount) {
		oldCount := fs.lastRaceSignalCount
		oldUpdate := fs.lastRaceSignalUpdate
		fs.lastRaceSignalCount = int(newSignal)
		fs.lastRaceSignalUpdate = time.Now()

		log.Logf(1, "Race pair signal updated: %d", newSignal)
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Race pair signal growth: %d -> %d (+%d), lastUpdate: %v -> %v",
				oldCount, int(newSignal), int(newSignal)-oldCount, oldUpdate, fs.lastRaceSignalUpdate)
		}
	} else if log.V(2) {
		log.Logf(2, "[DDRD-DEBUG] Race pair signal no change: %d (no growth)", newSignal)
	}

	// 检查是否需要切换阶段
	fs.checkPhaseSwitch()
}

// checkPhaseSwitch evaluates whether a phase transition should occur (internal function, requires mutex lock).
func (fs *FuzzScheduler) checkPhaseSwitch() {
	if log.V(2) {
		log.Logf(2, "[DDRD-DEBUG] checkPhaseSwitch called: currentPhase=%v, fuzzMode=%s",
			fs.currentPhase, fs.fuzzMode)
	}

	// Fixed modes don't perform phase transitions
	if fs.fuzzMode == FuzzModeNormal || fs.fuzzMode == FuzzModeConcurrency {
		if log.V(2) {
			log.Logf(2, "[DDRD-DEBUG] checkPhaseSwitch skipped: fixed mode %s", fs.fuzzMode)
		}
		return
	}

	now := time.Now()
	phaseRunTime := now.Sub(fs.phaseStartTime)

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] Phase timing check: currentPhase=%v, runtime=%v, maxPhaseTime=%v",
			fs.currentPhase, phaseRunTime, fs.maxPhaseTime)
	}

	var shouldSwitch bool
	var reason string

	switch fs.currentPhase {
	case PhaseNormalFuzz:
		// Only check transition conditions in AUTO mode
		if fs.fuzzMode == FuzzModeAuto {
			if log.V(1) {
				log.Logf(1, "[DDRD-DEBUG] Normal phase evaluation: runtime=%v, maxTime=%v, shouldSwitch=%v",
					phaseRunTime, fs.maxPhaseTime, phaseRunTime >= fs.maxPhaseTime)
			}

			if phaseRunTime >= fs.maxPhaseTime {
				shouldSwitch = true
				reason = "auto mode: normal fuzz max time reached (1 hour)"
				if log.V(1) {
					log.Logf(1, "[DDRD-DEBUG] Normal phase switch decision: SWITCH due to time limit")
				}
			} else if log.V(1) {
				log.Logf(1, "[DDRD-DEBUG] Normal phase switch decision: CONTINUE (time remaining: %v)",
					fs.maxPhaseTime-phaseRunTime)
			}
			// Signal stability check removed, only time-based switching
		} else if log.V(2) {
			log.Logf(2, "[DDRD-DEBUG] Normal phase evaluation skipped: mode is %s", fs.fuzzMode)
		}

	case PhaseRaceFuzz:
		// Only check transition conditions in AUTO mode
		if fs.fuzzMode == FuzzModeAuto {
			if log.V(1) {
				log.Logf(1, "[DDRD-DEBUG] Race phase evaluation: runtime=%v, maxTime=%v, shouldSwitch=%v",
					phaseRunTime, fs.maxPhaseTime, phaseRunTime >= fs.maxPhaseTime)
			}

			if phaseRunTime >= fs.maxPhaseTime {
				shouldSwitch = true
				reason = "auto mode: race fuzz max time reached (1 hour)"
				if log.V(1) {
					log.Logf(1, "[DDRD-DEBUG] Race phase switch decision: SWITCH due to time limit")
				}
			} else if log.V(1) {
				log.Logf(1, "[DDRD-DEBUG] Race phase switch decision: CONTINUE (time remaining: %v)",
					fs.maxPhaseTime-phaseRunTime)
			}
			// Signal stability check removed, only time-based switching
		} else if log.V(2) {
			log.Logf(2, "[DDRD-DEBUG] Race phase evaluation skipped: mode is %s", fs.fuzzMode)
		}
	}

	if shouldSwitch {
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Phase switch triggered: reason='%s', from=%v", reason, fs.currentPhase)
		}
		fs.switchPhase(reason)
	} else if log.V(2) {
		log.Logf(2, "[DDRD-DEBUG] No phase switch needed")
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
		log.Logf(1, "[DDRD-DEBUG] startSynchronizedSwitch: oldPhase=%v, newPhase=%v, reason='%s', isWaiting=%v",
			oldPhase, newPhase, reason, fs.isWaitingForSync)
	}

	// Set waiting state
	fs.isWaitingForSync = true
	fs.pendingPhase = newPhase

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] Synchronization state set: isWaiting=%v, pendingPhase=%v",
			fs.isWaitingForSync, fs.pendingPhase)
	}

	// Start synchronized transition process
	if err := fs.transitionMgr.StartTransition(newPhase); err != nil {
		log.Logf(0, "CRITICAL: Failed to start synchronized transition: %v", err)
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] StartTransition failed: error=%v, resetting waiting state", err)
		}
		fs.isWaitingForSync = false
		// Don't fall back to immediate switch - this indicates a serious problem
		panic(fmt.Sprintf("synchronized transition failed: %v", err))
	}

	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] StartTransition succeeded, waiting for fuzzer coordination")
	}
}

// SetupTransitionManager initializes the synchronization manager for coordinated phase transitions.
// This method must be called before the scheduler can perform phase switches.
func (fs *FuzzScheduler) SetupTransitionManager() {
	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] SetupTransitionManager called")
	}

	fs.transitionMgr = NewModeTransitionManager()

	// Setup completion callback
	fs.transitionMgr.onTransitionDone = func(phase FuzzPhase, success bool) {
		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] onTransitionDone callback: phase=%v, success=%v", phase, success)
		}

		fs.mu.Lock()
		defer fs.mu.Unlock()

		if success {
			// Execute actual phase switch after successful synchronization
			if log.V(1) {
				log.Logf(1, "[DDRD-DEBUG] Executing phase switch after successful synchronization")
			}
			fs.switchPhaseImmediate("synchronized transition completed")
		} else {
			log.Logf(0, "Mode transition failed, keeping current phase")
			if log.V(1) {
				log.Logf(1, "[DDRD-DEBUG] Mode transition failed, keeping phase %v", fs.currentPhase)
			}
		}
		fs.isWaitingForSync = false

		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Transition completed, isWaitingForSync=%v", fs.isWaitingForSync)
		}
	}

	log.Logf(1, "Transition manager initialized for scheduler")

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
	status := map[string]interface{}{
		"fuzz_mode":               fs.fuzzMode,
		"current_phase":           fs.currentPhase,
		"phase_start_time":        fs.phaseStartTime,
		"phase_runtime":           now.Sub(fs.phaseStartTime),
		"normal_fuzz_enabled":     fs.normalFuzzEnabled,
		"race_fuzz_enabled":       fs.raceFuzzEnabled,
		"last_signal_count":       fs.lastSignalCount,
		"last_signal_update":      fs.lastSignalUpdate,
		"signal_stable_time":      now.Sub(fs.lastSignalUpdate),
		"last_race_signal_count":  fs.lastRaceSignalCount,
		"last_race_signal_update": fs.lastRaceSignalUpdate,
		"race_signal_stable_time": now.Sub(fs.lastRaceSignalUpdate),
	}

	if log.V(2) {
		log.Logf(2, "[DDRD-DEBUG] GetStatus: phase=%v, runtime=%v, normalEnabled=%v, raceEnabled=%v",
			fs.currentPhase, now.Sub(fs.phaseStartTime), fs.normalFuzzEnabled, fs.raceFuzzEnabled)
	}

	return status
}

// GetPhaseStats returns phase statistics for HTML page display.
func (fs *FuzzScheduler) GetPhaseStats() map[string]interface{} {
	return fs.GetStatus()
}

// StartPeriodicCheck begins periodic phase switch evaluation.
func (fs *FuzzScheduler) StartPeriodicCheck() {
	if log.V(1) {
		log.Logf(1, "[DDRD-DEBUG] StartPeriodicCheck called, starting background checker")
	}

	go func() {
		ticker := time.NewTicker(60 * time.Second) // Check every 60 seconds
		defer ticker.Stop()

		if log.V(1) {
			log.Logf(1, "[DDRD-DEBUG] Periodic checker started with 5s interval")
		}

		for range ticker.C {
			if log.V(2) {
				log.Logf(2, "[DDRD-DEBUG] Periodic check triggered")
			}

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
	return fs.isWaitingForSync
}

// GetTransitionManager returns the transition manager for direct RPC access.
func (fs *FuzzScheduler) GetTransitionManager() *ModeTransitionManager {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.transitionMgr
}

// ===============DDRD====================
