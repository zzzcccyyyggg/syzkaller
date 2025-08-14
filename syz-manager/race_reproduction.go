// ===============DDRD====================
// Race Reproduction System for Syzkaller
// 专门用于复现已发现的race pairs的系统
// ===============DDRD====================

package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/prog"
)

// RaceReproductionMode 竞争复现模式
type RaceReproductionMode int

const (
	ReproModeNoLock   RaceReproductionMode = iota // 无锁竞争复现
	ReproModeOneSided                             // 单边锁竞争复现
	ReproModeBothLock                             // 双边锁竞争复现
	ReproModeDisabled                             // 禁用复现模式
)

// RaceAccessType 内存访问类型
type RaceAccessType int

const (
	AccessTypeNoLock   RaceAccessType = iota // 无锁访问
	AccessTypeWithLock                       // 有锁访问
	AccessTypeUnknown                        // 未知类型
)

// RaceAccessInfo 竞争访问信息
type RaceAccessInfo struct {
	VarName       uint64         `json:"var_name"`        // 变量名哈希
	CallStackHash uint64         `json:"call_stack_hash"` // 调用栈哈希
	AccessType    RaceAccessType `json:"access_type"`     // 访问类型
	ThreadID      uint32         `json:"thread_id"`       // 线程ID
	Program       *prog.Prog     `json:"-"`               // 相关程序
}

// RacePairInfo 竞争对信息
type RacePairInfo struct {
	ID           string               `json:"id"`
	FirstAccess  RaceAccessInfo       `json:"first_access"`
	SecondAccess RaceAccessInfo       `json:"second_access"`
	ReproMode    RaceReproductionMode `json:"repro_mode"`
	Priority     int                  `json:"priority"`     // 复现优先级
	Attempts     int                  `json:"attempts"`     // 尝试次数
	Success      bool                 `json:"success"`      // 是否成功复现
	LastAttempt  time.Time            `json:"last_attempt"` // 最后尝试时间
}

// RaceReproductionManager 竞争复现管理器
type RaceReproductionManager struct {
	mu sync.RWMutex

	enabled bool
	mode    RaceReproductionMode

	// 待复现的race pairs队列
	reproQueue     []*RacePairInfo
	activeRepros   map[string]*RacePairInfo // 正在复现的pairs
	completedPairs map[string]*RacePairInfo // 已完成的pairs

	// 配置参数
	maxConcurrentRepros int           // 最大并发复现数
	reproTimeout        time.Duration // 复现超时时间
	maxAttempts         int           // 最大尝试次数

	// 统计信息
	stats RaceReproStats
}

// RaceReproStats 复现统计信息
type RaceReproStats struct {
	TotalPairs       int `json:"total_pairs"`
	SuccessfulRepros int `json:"successful_repros"`
	FailedRepros     int `json:"failed_repros"`
	PendingRepros    int `json:"pending_repros"`

	// 按类型分类
	NoLockPairs   int `json:"no_lock_pairs"`
	OneSidedPairs int `json:"one_sided_pairs"`
	BothLockPairs int `json:"both_lock_pairs"`
}

// NewRaceReproductionManager creates a new race reproduction manager
func NewRaceReproductionManager(enabledStr, workdir string) *RaceReproductionManager {
	// Default is enabled if not specified
	enabled := true
	if enabledStr == "disabled" || enabledStr == "false" {
		enabled = false
	}

	return &RaceReproductionManager{
		enabled:             enabled,
		mode:                ReproModeNoLock, // This will be dynamically determined per race pair
		reproQueue:          make([]*RacePairInfo, 0),
		activeRepros:        make(map[string]*RacePairInfo),
		completedPairs:      make(map[string]*RacePairInfo),
		maxConcurrentRepros: 4,                // Default concurrent reproduction limit
		reproTimeout:        time.Minute * 10, // 10 minutes timeout
		maxAttempts:         3,                // Max 3 attempts per pair
		stats:               RaceReproStats{},
	}
}

// AddNewRacePairForReproduction adds a newly detected race pair to the reproduction queue
// The reproduction strategy is automatically determined based on lock status
func (mgr *RaceReproductionManager) AddNewRacePairForReproduction(first, second RaceAccessInfo) string {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if !mgr.enabled {
		return ""
	}

	// Generate unique ID for this race pair
	pairID := fmt.Sprintf("race_%d_%d_%d", first.VarName, second.VarName, time.Now().UnixNano())

	// Create race pair info
	racePair := &RacePairInfo{
		ID:           pairID,
		FirstAccess:  first,
		SecondAccess: second,
		Priority:     50, // Will be calculated after determining reproduction mode
		Attempts:     0,
		Success:      false,
		LastAttempt:  time.Time{},
	}

	// Automatically determine reproduction strategy based on lock status
	racePair.ReproMode = mgr.DetermineReproductionStrategy(racePair)

	// Calculate priority based on the race pair characteristics
	racePair.Priority = mgr.calculatePriority(racePair)

	// Add to reproduction queue
	mgr.reproQueue = append(mgr.reproQueue, racePair)
	mgr.stats.TotalPairs++

	log.Printf("DDRD Race Repro: Added race pair %s for reproduction with strategy %v",
		pairID, racePair.ReproMode)

	return pairID
}

// Enable 启用竞争复现模式
func (rrm *RaceReproductionManager) Enable(mode RaceReproductionMode) {
	rrm.mu.Lock()
	defer rrm.mu.Unlock()

	rrm.enabled = true
	rrm.mode = mode

	log.Printf("Race Reproduction模式已启用: mode=%v, maxConcurrent=%d",
		mode, rrm.maxConcurrentRepros)
}

// Disable 禁用竞争复现模式
func (rrm *RaceReproductionManager) Disable() {
	rrm.mu.Lock()
	defer rrm.mu.Unlock()

	rrm.enabled = false
	rrm.mode = ReproModeDisabled

	log.Printf("Race Reproduction模式已禁用")
}

// DetermineReproductionStrategy automatically determines the best reproduction strategy
// based on the lock status of both accesses in the race pair
func (mgr *RaceReproductionManager) DetermineReproductionStrategy(pair *RacePairInfo) RaceReproductionMode {
	access1 := pair.FirstAccess.AccessType
	access2 := pair.SecondAccess.AccessType

	// Determine strategy based on lock status combination
	switch {
	case access1 == AccessTypeNoLock && access2 == AccessTypeNoLock:
		// Both accesses are lock-free -> NoLock strategy
		log.Printf("DDRD Race Repro: Detected NoLock race pair %s (both accesses lock-free)", pair.ID)
		return ReproModeNoLock

	case access1 == AccessTypeWithLock && access2 == AccessTypeNoLock:
		// One side locked, one side unlocked -> OneSided strategy
		log.Printf("DDRD Race Repro: Detected OneSided race pair %s (first=locked, second=unlocked)", pair.ID)
		return ReproModeOneSided

	case access1 == AccessTypeNoLock && access2 == AccessTypeWithLock:
		// One side unlocked, one side locked -> OneSided strategy
		log.Printf("DDRD Race Repro: Detected OneSided race pair %s (first=unlocked, second=locked)", pair.ID)
		return ReproModeOneSided

	case access1 == AccessTypeWithLock && access2 == AccessTypeWithLock:
		// Both sides locked -> BothLock strategy
		log.Printf("DDRD Race Repro: Detected BothLock race pair %s (both accesses locked)", pair.ID)
		return ReproModeBothLock

	default:
		// Unknown or mixed access types -> fallback to NoLock
		log.Printf("DDRD Race Repro: Unknown access types for race pair %s, using NoLock strategy", pair.ID)
		return ReproModeNoLock
	}
}

// IsEnabled 检查是否启用
func (rrm *RaceReproductionManager) IsEnabled() bool {
	rrm.mu.RLock()
	defer rrm.mu.RUnlock()
	return rrm.enabled
}

// AddRacePairForReproduction 添加race pair到复现队列
func (rrm *RaceReproductionManager) AddRacePairForReproduction(pair *RacePairInfo) {
	rrm.mu.Lock()
	defer rrm.mu.Unlock()

	if !rrm.enabled {
		return
	}

	// 分类race pair并设置复现模式
	pair.ReproMode = rrm.classifyRacePair(pair)
	pair.Priority = rrm.calculatePriority(pair)

	// 添加到队列
	rrm.reproQueue = append(rrm.reproQueue, pair)
	rrm.stats.TotalPairs++

	// 更新分类统计
	switch pair.ReproMode {
	case ReproModeNoLock:
		rrm.stats.NoLockPairs++
	case ReproModeOneSided:
		rrm.stats.OneSidedPairs++
	case ReproModeBothLock:
		rrm.stats.BothLockPairs++
	}

	log.Printf("添加race pair到复现队列: id=%s, mode=%v, priority=%d",
		pair.ID, pair.ReproMode, pair.Priority)
}

// classifyRacePair 分类race pair
func (rrm *RaceReproductionManager) classifyRacePair(pair *RacePairInfo) RaceReproductionMode {
	first := pair.FirstAccess.AccessType
	second := pair.SecondAccess.AccessType

	if first == AccessTypeNoLock && second == AccessTypeNoLock {
		return ReproModeNoLock
	} else if (first == AccessTypeNoLock && second == AccessTypeWithLock) ||
		(first == AccessTypeWithLock && second == AccessTypeNoLock) {
		return ReproModeOneSided
	} else if first == AccessTypeWithLock && second == AccessTypeWithLock {
		return ReproModeBothLock
	}

	return ReproModeNoLock // 默认无锁模式
}

// calculatePriority 计算复现优先级
func (rrm *RaceReproductionManager) calculatePriority(pair *RacePairInfo) int {
	priority := 50 // 基础优先级

	// 根据复现模式调整优先级
	switch pair.ReproMode {
	case ReproModeNoLock:
		priority += 30 // 无锁竞争优先级最高
	case ReproModeOneSided:
		priority += 20 // 单边锁竞争优先级中等
	case ReproModeBothLock:
		priority += 10 // 双边锁竞争优先级较低
	}

	// 根据尝试次数降低优先级
	priority -= pair.Attempts * 5

	if priority < 0 {
		priority = 0
	}

	return priority
}

// GetNextRacePairToReproduce 获取下一个要复现的race pair
func (rrm *RaceReproductionManager) GetNextRacePairToReproduce() *RacePairInfo {
	rrm.mu.Lock()
	defer rrm.mu.Unlock()

	if !rrm.enabled || len(rrm.reproQueue) == 0 {
		return nil
	}

	// 检查并发限制
	if len(rrm.activeRepros) >= rrm.maxConcurrentRepros {
		return nil
	}

	// 按优先级排序并选择最高优先级的pair
	var selectedIndex int = -1
	var maxPriority int = -1

	for i, pair := range rrm.reproQueue {
		if pair.Priority > maxPriority && pair.Attempts < rrm.maxAttempts {
			maxPriority = pair.Priority
			selectedIndex = i
		}
	}

	if selectedIndex == -1 {
		return nil
	}

	// 移除选中的pair并添加到活跃列表
	pair := rrm.reproQueue[selectedIndex]
	rrm.reproQueue = append(rrm.reproQueue[:selectedIndex], rrm.reproQueue[selectedIndex+1:]...)
	rrm.activeRepros[pair.ID] = pair

	return pair
}

// StartReproduction 开始复现指定的race pair
func (rrm *RaceReproductionManager) StartReproduction(pair *RacePairInfo) error {
	log.Printf("开始复现race pair: id=%s, mode=%v", pair.ID, pair.ReproMode)

	pair.Attempts++
	pair.LastAttempt = time.Now()

	switch pair.ReproMode {
	case ReproModeNoLock:
		return rrm.reproduceNoLockRace(pair)
	case ReproModeOneSided:
		return rrm.reproduceOneSidedRace(pair)
	case ReproModeBothLock:
		return rrm.reproduceBothLockRace(pair)
	default:
		return fmt.Errorf("未知的复现模式: %v", pair.ReproMode)
	}
}

// reproduceNoLockRace 复现无锁竞争
func (rrm *RaceReproductionManager) reproduceNoLockRace(pair *RacePairInfo) error {
	log.Printf("执行无锁竞争复现策略: %s", pair.ID)

	// 设置内核模块为无锁复现模式
	// 这里需要调用内核模块接口
	kernelInfo := NoLockReproduceInfo{
		VarName:   pair.FirstAccess.VarName,
		StackHash: pair.FirstAccess.CallStackHash,
		TID:       int(pair.FirstAccess.ThreadID),
		SN:        pair.Attempts,
	}

	// 模拟调用内核接口设置复现信息
	err := rrm.setKernelNoLockReproduceInfo(kernelInfo)
	if err != nil {
		return fmt.Errorf("设置内核无锁复现信息失败: %v", err)
	}

	// 启动无锁复现模式
	err = rrm.startKernelNoLockReproduceMode()
	if err != nil {
		return fmt.Errorf("启动内核无锁复现模式失败: %v", err)
	}

	// 同时执行两个程序
	return rrm.executeProgramsPair(pair)
}

// reproduceOneSidedRace 复现单边锁竞争
func (rrm *RaceReproductionManager) reproduceOneSidedRace(pair *RacePairInfo) error {
	log.Printf("执行单边锁竞争复现策略: %s", pair.ID)

	// 识别哪一边有锁，哪一边无锁
	var noLockAccess, lockAccess *RaceAccessInfo
	if pair.FirstAccess.AccessType == AccessTypeNoLock {
		noLockAccess = &pair.FirstAccess
		lockAccess = &pair.SecondAccess
	} else {
		noLockAccess = &pair.SecondAccess
		lockAccess = &pair.FirstAccess
	}

	// 设置内核模块为单边锁复现模式
	kernelInfo := OneSidedReproduceInfo{
		VarName:     noLockAccess.VarName,
		StackHash:   noLockAccess.CallStackHash,
		NoLockTID:   int(noLockAccess.ThreadID),
		WithLockTID: int(lockAccess.ThreadID),
		SN:          pair.Attempts,
	}

	err := rrm.setKernelOneSidedReproduceInfo(kernelInfo)
	if err != nil {
		return fmt.Errorf("设置内核单边锁复现信息失败: %v", err)
	}

	// 启动单边锁复现模式
	err = rrm.startKernelOneSidedReproduceMode()
	if err != nil {
		return fmt.Errorf("启动内核单边锁复现模式失败: %v", err)
	}

	// 让无锁的线程先执行
	log.Printf("让无锁线程(%d)先执行，有锁线程(%d)等待",
		noLockAccess.ThreadID, lockAccess.ThreadID)

	return rrm.executeProgramsPair(pair)
}

// reproduceBothLockRace 复现双边锁竞争
func (rrm *RaceReproductionManager) reproduceBothLockRace(pair *RacePairInfo) error {
	log.Printf("执行双边锁竞争复现策略: %s", pair.ID)

	// 对于双边锁的情况，交替让两边先执行
	var firstAccess, secondAccess *RaceAccessInfo
	if pair.Attempts%2 == 1 {
		firstAccess = &pair.FirstAccess
		secondAccess = &pair.SecondAccess
	} else {
		firstAccess = &pair.SecondAccess
		secondAccess = &pair.FirstAccess
	}

	log.Printf("尝试 %d: 让线程(%d)先执行，线程(%d)后执行",
		pair.Attempts, firstAccess.ThreadID, secondAccess.ThreadID)

	// 这里可以使用类似单边锁的策略，但交替执行顺序
	kernelInfo := OneSidedReproduceInfo{
		VarName:     firstAccess.VarName,
		StackHash:   firstAccess.CallStackHash,
		NoLockTID:   int(firstAccess.ThreadID),  // 先执行的线程
		WithLockTID: int(secondAccess.ThreadID), // 后执行的线程
		SN:          pair.Attempts,
	}

	err := rrm.setKernelOneSidedReproduceInfo(kernelInfo)
	if err != nil {
		return fmt.Errorf("设置内核双边锁复现信息失败: %v", err)
	}

	err = rrm.startKernelOneSidedReproduceMode()
	if err != nil {
		return fmt.Errorf("启动内核双边锁复现模式失败: %v", err)
	}

	return rrm.executeProgramsPair(pair)
}

// executeProgramsPair 执行程序对
func (rrm *RaceReproductionManager) executeProgramsPair(pair *RacePairInfo) error {
	// 创建执行选项，启用race复现标志
	opts := &ipc.ExecOpts{
		Flags: ipc.FlagCollectSignal | ipc.FlagCollectCover | ipc.FlagCollectRace,
	}

	// 创建结果通道
	result1Chan := make(chan error, 1)
	result2Chan := make(chan error, 1)

	// 并发执行两个程序
	go func() {
		result1Chan <- rrm.executeProgram(pair.FirstAccess.Program, opts)
	}()

	go func() {
		result2Chan <- rrm.executeProgram(pair.SecondAccess.Program, opts)
	}()

	// 等待执行完成
	timeout := time.After(rrm.reproTimeout)
	var err1, err2 error
	completed := 0

	for completed < 2 {
		select {
		case err1 = <-result1Chan:
			completed++
		case err2 = <-result2Chan:
			completed++
		case <-timeout:
			return fmt.Errorf("执行超时")
		}
	}

	if err1 != nil || err2 != nil {
		return fmt.Errorf("程序执行失败: err1=%v, err2=%v", err1, err2)
	}

	return nil
}

// executeProgram 执行单个程序（简化实现）
func (rrm *RaceReproductionManager) executeProgram(prog *prog.Prog, opts *ipc.ExecOpts) error {
	// 这里应该调用实际的executor
	// 现在做简化模拟
	log.Printf("执行程序: %s", prog.String())
	time.Sleep(100 * time.Millisecond) // 模拟执行时间
	return nil
}

// CompleteReproduction 完成复现
func (rrm *RaceReproductionManager) CompleteReproduction(pairID string, success bool, result string) {
	rrm.mu.Lock()
	defer rrm.mu.Unlock()

	pair, exists := rrm.activeRepros[pairID]
	if !exists {
		log.Printf("警告: 尝试完成不存在的复现任务: %s", pairID)
		return
	}

	// 从活跃列表移除
	delete(rrm.activeRepros, pairID)

	// 添加到完成列表
	pair.Success = success
	rrm.completedPairs[pairID] = pair

	// 更新统计
	if success {
		rrm.stats.SuccessfulRepros++
		log.Printf("成功复现race pair: %s, 结果: %s", pairID, result)
	} else {
		rrm.stats.FailedRepros++

		// 如果失败且未达到最大尝试次数，重新加入队列
		if pair.Attempts < rrm.maxAttempts {
			pair.Priority -= 10 // 降低优先级
			rrm.reproQueue = append(rrm.reproQueue, pair)
			delete(rrm.completedPairs, pairID)
			log.Printf("复现失败，重新加入队列: %s, 尝试次数: %d/%d",
				pairID, pair.Attempts, rrm.maxAttempts)
		} else {
			log.Printf("复现失败，已达到最大尝试次数: %s", pairID)
		}
	}
}

// GetStats 获取统计信息
func (rrm *RaceReproductionManager) GetStats() RaceReproStats {
	rrm.mu.RLock()
	defer rrm.mu.RUnlock()

	stats := rrm.stats
	stats.PendingRepros = len(rrm.reproQueue) + len(rrm.activeRepros)
	return stats
}

// GetReproQueue 获取复现队列（用于调试）
func (rrm *RaceReproductionManager) GetReproQueue() []*RacePairInfo {
	rrm.mu.RLock()
	defer rrm.mu.RUnlock()

	// 返回副本以避免并发问题
	queue := make([]*RacePairInfo, len(rrm.reproQueue))
	copy(queue, rrm.reproQueue)
	return queue
}

// GetActiveRepros 获取活跃复现任务（用于调试）
func (rrm *RaceReproductionManager) GetActiveRepros() map[string]*RacePairInfo {
	rrm.mu.RLock()
	defer rrm.mu.RUnlock()

	// 返回副本以避免并发问题
	active := make(map[string]*RacePairInfo)
	for k, v := range rrm.activeRepros {
		active[k] = v
	}
	return active
}

// 内核接口相关结构体和函数
type NoLockReproduceInfo struct {
	VarName   uint64
	StackHash uint64
	TID       int
	SN        int
}

type OneSidedReproduceInfo struct {
	VarName     uint64
	StackHash   uint64
	NoLockTID   int
	WithLockTID int
	SN          int
}

// 模拟内核接口函数
func (rrm *RaceReproductionManager) setKernelNoLockReproduceInfo(info NoLockReproduceInfo) error {
	log.Printf("设置内核无锁复现信息: VarName=0x%x, StackHash=0x%x, TID=%d",
		info.VarName, info.StackHash, info.TID)
	return nil
}

func (rrm *RaceReproductionManager) startKernelNoLockReproduceMode() error {
	log.Printf("启动内核无锁复现模式")
	return nil
}

func (rrm *RaceReproductionManager) setKernelOneSidedReproduceInfo(info OneSidedReproduceInfo) error {
	log.Printf("设置内核单边锁复现信息: VarName=0x%x, NoLockTID=%d, WithLockTID=%d",
		info.VarName, info.NoLockTID, info.WithLockTID)
	return nil
}

func (rrm *RaceReproductionManager) startKernelOneSidedReproduceMode() error {
	log.Printf("启动内核单边锁复现模式")
	return nil
}

// ===============DDRD====================
