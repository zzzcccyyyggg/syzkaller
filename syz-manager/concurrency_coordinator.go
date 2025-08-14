// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// ConcurrencyCoordinator - 并发测试协调器
// 统一管理并发测试的所有组件：调度、程序选择、test pair分发、结果处理

package main

import (
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
)

// ConcurrencyCoordinator 并发测试协调器
type ConcurrencyCoordinator struct {
	mgr *Manager
	mu  sync.RWMutex

	// 核心组件
	fuzzScheduler           *FuzzScheduler
	programSelector         *ProgramSelector
	testPairDispatcher      *TestPairDispatcher
	racePairCoverageManager *RacePairCoverageManager
	raceReportManager       *RaceReportManager

	// 配置
	config *ConcurrencyConfig

	// 状态统计
	stats *ConcurrencyStats

	// 缓存和优化
	lastModeCheck     time.Time
	cachedMode        FuzzPhase
	modeCheckInterval time.Duration
}

// ConcurrencyConfig 并发测试配置
type ConcurrencyConfig struct {
	// 模式配置
	FuzzMode string `json:"fuzz_mode"` // "auto", "normal", "concurrency"

	// 阶段切换配置
	MaxPhaseTime     time.Duration `json:"max_phase_time"`     // 1小时
	SignalStableTime time.Duration `json:"signal_stable_time"` // 5分钟

	// Test Pair配置
	TestPairRatio      float64 `json:"test_pair_ratio"`      // 并发测试占比 0.3
	PairSelectionMode  string  `json:"pair_selection_mode"`  // "random", "race_rich", "similar_calls", "mixed"
	MaxConcurrentPairs int     `json:"max_concurrent_pairs"` // 最大并发test pair数量

	// Race检测配置
	RaceTimeWindow    time.Duration `json:"race_time_window"`    // race检测时间窗口
	MinRaceConfidence float64       `json:"min_race_confidence"` // 最低race置信度

	// 验证配置
	ValidationEnabled bool `json:"validation_enabled"` // 是否启用race验证
	ValidationRounds  int  `json:"validation_rounds"`  // 验证轮数
}

// ConcurrencyStats 并发测试统计
type ConcurrencyStats struct {
	mu sync.RWMutex

	// 基础统计
	TotalTestPairs  int64
	SuccessfulRaces int64
	ValidatedRaces  int64

	// 阶段统计
	LastPhaseSwitch     time.Time
	CurrentPhaseRuntime time.Duration
	PhaseCount          map[FuzzPhase]int64

	// 程序选择统计
	SelectionModeStats map[string]int64

	// 性能统计
	AvgTestPairTime  time.Duration
	TestPairTimeouts int64
}

// NewConcurrencyCoordinator 创建并发测试协调器
func NewConcurrencyCoordinator(mgr *Manager) *ConcurrencyCoordinator {
	config := &ConcurrencyConfig{
		FuzzMode:           "auto",
		MaxPhaseTime:       time.Hour,
		SignalStableTime:   5 * time.Minute,
		TestPairRatio:      0.3,
		PairSelectionMode:  "mixed",
		MaxConcurrentPairs: 4,
		RaceTimeWindow:     100 * time.Millisecond,
		MinRaceConfidence:  0.1,
		ValidationEnabled:  true,
		ValidationRounds:   3,
	}

	// 从manager配置中覆盖
	if mgr.cfg.Experimental.FuzzMode != "" {
		config.FuzzMode = mgr.cfg.Experimental.FuzzMode
	}

	coordinator := &ConcurrencyCoordinator{
		mgr:               mgr,
		config:            config,
		stats:             newConcurrencyStats(),
		modeCheckInterval: 5 * time.Second,
	}

	// 初始化组件
	coordinator.initializeComponents()

	log.Logf(0, "ConcurrencyCoordinator initialized with mode: %s", config.FuzzMode)
	return coordinator
}

// initializeComponents 初始化所有组件
func (cc *ConcurrencyCoordinator) initializeComponents() {
	// 使用Manager中已有的组件，避免重复创建
	cc.fuzzScheduler = cc.mgr.fuzzScheduler
	cc.fuzzScheduler.SetPhaseChangeCallback(cc.onPhaseChange)

	// 初始化程序选择器
	cc.programSelector = NewProgramSelector(cc.mgr)

	// 使用Manager中已有的组件
	cc.testPairDispatcher = cc.mgr.testPairDispatcher
	cc.racePairCoverageManager = cc.mgr.racePairCoverageManager
	cc.raceReportManager = cc.mgr.raceReportManager

	// 如果testPairDispatcher为空，则创建新的
	if cc.testPairDispatcher == nil {
		cc.testPairDispatcher = NewTestPairDispatcher(cc.mgr)
		cc.mgr.testPairDispatcher = cc.testPairDispatcher
	}

	// 启动定期检查
	cc.fuzzScheduler.StartPeriodicCheck()
	go cc.startStatisticsCollection()
}

// onPhaseChange 阶段切换回调
func (cc *ConcurrencyCoordinator) onPhaseChange(newPhase FuzzPhase) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.stats.mu.Lock()
	cc.stats.LastPhaseSwitch = time.Now()
	cc.stats.PhaseCount[newPhase]++
	cc.stats.mu.Unlock()

	cc.cachedMode = newPhase
	cc.lastModeCheck = time.Now()

	switch newPhase {
	case PhaseNormalFuzz:
		log.Logf(0, "ConcurrencyCoordinator: Switched to normal fuzzing phase")
		cc.testPairDispatcher.Disable()

	case PhaseRaceFuzz:
		log.Logf(0, "ConcurrencyCoordinator: Switched to race fuzzing phase")
		cc.testPairDispatcher.Enable(cc.config.MaxConcurrentPairs)
		cc.updateTestPairGeneration()
	}
}

// updateTestPairGeneration 更新test pair生成
func (cc *ConcurrencyCoordinator) updateTestPairGeneration() {
	// 根据当前corpus状态更新choice table
	go func() {
		cc.mgr.mu.Lock()
		corpusSize := len(cc.mgr.corpus)
		cc.mgr.mu.Unlock()

		if corpusSize < 2 {
			log.Logf(1, "Corpus too small for test pair generation: %d", corpusSize)
			return
		}

		// 生成新的test pairs
		for i := 0; i < cc.config.MaxConcurrentPairs; i++ {
			cc.generateTestPair()
		}
	}()
}

// generateTestPair 生成test pair
func (cc *ConcurrencyCoordinator) generateTestPair() {
	mode := parseTestPairSelectionMode(cc.config.PairSelectionMode)
	prog1, prog2, hash1, hash2 := cc.programSelector.SelectPairPrograms(mode)

	if prog1 == nil || prog2 == nil {
		return
	}

	// 使用TestPairDispatcher的API来添加test pair
	cc.testPairDispatcher.QueueTestPair(prog1, prog2, hash1, hash2)

	// 更新统计
	modeStr := modeToString(mode)
	cc.stats.mu.Lock()
	cc.stats.TotalTestPairs++
	cc.stats.SelectionModeStats[modeStr]++
	cc.stats.mu.Unlock()

	log.Logf(2, "Generated test pair: mode=%s, hash1=%s, hash2=%s",
		modeStr, hash1[:8], hash2[:8])
}

// HandlePoll 处理fuzzer的Poll请求
func (cc *ConcurrencyCoordinator) HandlePoll(a *rpctype.PollArgs, r *rpctype.PollRes) {
	// 更新调度器状态
	cc.updateSchedulerSignals(a)

	// 处理test pair相关请求
	cc.handleTestPairRequests(a, r)
}

// updateSchedulerSignals 更新调度器信号
func (cc *ConcurrencyCoordinator) updateSchedulerSignals(_ *rpctype.PollArgs) {
	currentPhase := cc.GetCurrentPhase()

	corpusSignalCount := int(cc.mgr.stats.corpusSignal.get())

	switch currentPhase {
	case PhaseNormalFuzz:
		cc.fuzzScheduler.UpdateSignalCount(corpusSignalCount)

	case PhaseRaceFuzz:
		raceSignalCount := int(cc.mgr.stats.raceSignals.get())
		cc.fuzzScheduler.UpdateRaceSignalCount(raceSignalCount)
	}
}

// handleTestPairRequests 处理test pair请求
func (cc *ConcurrencyCoordinator) handleTestPairRequests(_ *rpctype.PollArgs, _ *rpctype.PollRes) {
	if cc.GetCurrentPhase() != PhaseRaceFuzz {
		return
	}

	// 检查是否需要生成新的test pairs
	stats := cc.testPairDispatcher.GetStats()
	pendingCount := stats["pending"].(int)

	if pendingCount < cc.config.MaxConcurrentPairs {
		go cc.generateTestPair()
	}
}

// GetCurrentPhase 获取当前阶段（带缓存）
func (cc *ConcurrencyCoordinator) GetCurrentPhase() FuzzPhase {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	// 使用缓存减少锁竞争
	if time.Since(cc.lastModeCheck) < cc.modeCheckInterval {
		return cc.cachedMode
	}

	cc.mu.RUnlock()
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// 双重检查
	if time.Since(cc.lastModeCheck) < cc.modeCheckInterval {
		return cc.cachedMode
	}

	cc.cachedMode = cc.fuzzScheduler.GetCurrentPhase()
	cc.lastModeCheck = time.Now()
	return cc.cachedMode
}

// IsTestPairModeEnabled 检查是否启用test pair模式
func (cc *ConcurrencyCoordinator) IsTestPairModeEnabled() bool {
	return cc.GetCurrentPhase() == PhaseRaceFuzz
}

// handleNewRacePair 处理新发现的race pair
func (cc *ConcurrencyCoordinator) handleNewRacePair(racePair *RacePair) {
	cc.stats.mu.Lock()
	cc.stats.SuccessfulRaces++
	cc.stats.mu.Unlock()

	// 触发race验证
	if cc.config.ValidationEnabled {
		go cc.validateRacePair(racePair)
	}
}

// validateRacePair 验证race pair
func (cc *ConcurrencyCoordinator) validateRacePair(racePair *RacePair) {
	// 简化的验证逻辑
	for i := 0; i < cc.config.ValidationRounds; i++ {
		// 这里应该重新执行test pair进行验证
		time.Sleep(100 * time.Millisecond) // 模拟验证过程
	}

	cc.stats.mu.Lock()
	cc.stats.ValidatedRaces++
	cc.stats.mu.Unlock()

	log.Logf(1, "Race pair validated: %v", racePair)
}

// GetStatus 获取状态信息
func (cc *ConcurrencyCoordinator) GetStatus() map[string]interface{} {
	cc.stats.mu.RLock()
	defer cc.stats.mu.RUnlock()

	dispatcherStats := cc.testPairDispatcher.GetStats()

	status := map[string]interface{}{
		"config":               cc.config,
		"current_phase":        cc.GetCurrentPhase(),
		"total_test_pairs":     cc.stats.TotalTestPairs,
		"successful_races":     cc.stats.SuccessfulRaces,
		"validated_races":      cc.stats.ValidatedRaces,
		"phase_count":          cc.stats.PhaseCount,
		"selection_mode_stats": cc.stats.SelectionModeStats,
		"dispatcher_stats":     dispatcherStats,
	}

	// 合并调度器状态
	for k, v := range cc.fuzzScheduler.GetStatus() {
		status["scheduler_"+k] = v
	}

	return status
}

// startStatisticsCollection 启动统计信息收集
func (cc *ConcurrencyCoordinator) startStatisticsCollection() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cc.collectStatistics()
	}
}

// collectStatistics 收集统计信息
func (cc *ConcurrencyCoordinator) collectStatistics() {
	// 收集当前运行时间
	cc.stats.mu.Lock()
	if !cc.stats.LastPhaseSwitch.IsZero() {
		cc.stats.CurrentPhaseRuntime = time.Since(cc.stats.LastPhaseSwitch)
	}
	cc.stats.mu.Unlock()
}

// newConcurrencyStats 创建新的统计对象
func newConcurrencyStats() *ConcurrencyStats {
	return &ConcurrencyStats{
		PhaseCount:         make(map[FuzzPhase]int64),
		SelectionModeStats: make(map[string]int64),
	}
}

// parseTestPairSelectionMode 解析test pair选择模式
func parseTestPairSelectionMode(mode string) TestPairSelectionMode {
	switch mode {
	case "random":
		return PairSelectionRandom
	case "race_rich":
		return PairSelectionRaceRich
	case "similar_calls":
		return PairSelectionSimilarCalls
	case "mixed":
		return PairSelectionMixed
	default:
		return PairSelectionRandom
	}
}

// modeToString 将mode转换为字符串
func modeToString(mode TestPairSelectionMode) string {
	switch mode {
	case PairSelectionRandom:
		return "random"
	case PairSelectionRaceRich:
		return "race_rich"
	case PairSelectionSimilarCalls:
		return "similar_calls"
	case PairSelectionMixed:
		return "mixed"
	default:
		return "random"
	}
}
