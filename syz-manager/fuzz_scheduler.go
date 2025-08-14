// ===============DDRD====================
// Fuzz Mode Control System for Syzkaller
// 支持三种模式: auto (两阶段智能切换), normal (仅正常测试), concurrency (仅并发测试)
// ===============DDRD====================

package main

import (
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

// FuzzPhase 表示当前的fuzz阶段
type FuzzPhase int

const (
	PhaseNormalFuzz FuzzPhase = iota // 正常syzkaller fuzz
	PhaseRaceFuzz                    // 并发race fuzz
)

// FuzzMode 表示fuzz执行模式
type FuzzMode string

const (
	FuzzModeAuto        FuzzMode = "auto"        // 自动两阶段模式
	FuzzModeNormal      FuzzMode = "normal"      // 仅正常fuzz
	FuzzModeConcurrency FuzzMode = "concurrency" // 仅并发测试
)

// FuzzScheduler 管理两阶段fuzz的调度
type FuzzScheduler struct {
	mu sync.Mutex

	// 运行模式
	fuzzMode FuzzMode

	// 当前阶段
	currentPhase   FuzzPhase
	phaseStartTime time.Time

	// 正常fuzz阶段状态
	lastSignalCount   int
	lastSignalUpdate  time.Time
	normalFuzzEnabled bool

	// Race fuzz阶段状态
	lastRaceSignalCount  int
	lastRaceSignalUpdate time.Time
	raceFuzzEnabled      bool

	// 配置参数
	maxPhaseTime     time.Duration // 每个阶段最大运行时间（1小时）
	signalStableTime time.Duration // signal稳定时间（5分钟）

	// 回调函数
	onPhaseChange func(newPhase FuzzPhase)
}

// NewFuzzScheduler 创建新的fuzz调度器
func NewFuzzScheduler(mode FuzzMode) *FuzzScheduler {
	if mode == "" {
		mode = FuzzModeAuto // 默认自动模式
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

	return &FuzzScheduler{
		fuzzMode:             mode,
		currentPhase:         initialPhase,
		phaseStartTime:       time.Now(),
		lastSignalUpdate:     time.Now(),
		lastRaceSignalUpdate: time.Now(),
		normalFuzzEnabled:    normalEnabled,
		raceFuzzEnabled:      raceEnabled,
		maxPhaseTime:         time.Hour,       // 1小时
		signalStableTime:     5 * time.Minute, // 5分钟
	}
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

// checkPhaseSwitch 检查是否需要切换阶段（内部函数，调用前需要持有锁）
func (fs *FuzzScheduler) checkPhaseSwitch() {
	// 如果是固定模式，不进行阶段切换
	if fs.fuzzMode == FuzzModeNormal || fs.fuzzMode == FuzzModeConcurrency {
		return
	}

	now := time.Now()
	phaseRunTime := now.Sub(fs.phaseStartTime)

	var shouldSwitch bool
	var reason string

	switch fs.currentPhase {
	case PhaseNormalFuzz:
		// 只有在AUTO模式下才检查切换条件，其他模式保持当前阶段
		if fs.fuzzMode == FuzzModeAuto {
			if phaseRunTime >= fs.maxPhaseTime {
				shouldSwitch = true
				reason = "auto mode: normal fuzz max time reached (1 hour)"
			}
			// 移除signal稳定性检查，只按时间切换
		}

	case PhaseRaceFuzz:
		// 只有在AUTO模式下才检查切换条件，其他模式保持当前阶段
		if fs.fuzzMode == FuzzModeAuto {
			if phaseRunTime >= fs.maxPhaseTime {
				shouldSwitch = true
				reason = "auto mode: race fuzz max time reached (1 hour)"
			}
			// 移除signal稳定性检查，只按时间切换
		}
	}

	if shouldSwitch {
		fs.switchPhase(reason)
	}
}

// switchPhase 切换阶段（内部函数，调用前需要持有锁）
func (fs *FuzzScheduler) switchPhase(reason string) {
	oldPhase := fs.currentPhase

	// 切换到下一个阶段
	switch fs.currentPhase {
	case PhaseNormalFuzz:
		fs.currentPhase = PhaseRaceFuzz
		fs.normalFuzzEnabled = false
		fs.raceFuzzEnabled = true
		log.Logf(0, "Switching to race fuzz phase: %s", reason)

	case PhaseRaceFuzz:
		fs.currentPhase = PhaseNormalFuzz
		fs.normalFuzzEnabled = true
		fs.raceFuzzEnabled = false
		log.Logf(0, "Switching to normal fuzz phase: %s", reason)
	}

	// 重置阶段状态
	fs.phaseStartTime = time.Now()

	// 调用回调函数
	if fs.onPhaseChange != nil {
		go fs.onPhaseChange(fs.currentPhase)
	}

	log.Logf(0, "Phase switched from %v to %v", oldPhase, fs.currentPhase)
}

// ForcePhaseSwitch 强制切换阶段
func (fs *FuzzScheduler) ForcePhaseSwitch() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.switchPhase("manually triggered")
}

// GetStatus 获取调度器状态信息
func (fs *FuzzScheduler) GetStatus() map[string]interface{} {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	now := time.Now()
	return map[string]interface{}{
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
}

// GetPhaseStats 获取阶段统计信息 (用于HTML页面显示)
func (fs *FuzzScheduler) GetPhaseStats() map[string]interface{} {
	return fs.GetStatus()
}

// StartPeriodicCheck 启动定期检查
func (fs *FuzzScheduler) StartPeriodicCheck() {
	go func() {
		ticker := time.NewTicker(30 * time.Second) // 每30秒检查一次
		defer ticker.Stop()

		for range ticker.C {
			fs.mu.Lock()
			fs.checkPhaseSwitch()
			fs.mu.Unlock()
		}
	}()
}

// ===============DDRD====================
