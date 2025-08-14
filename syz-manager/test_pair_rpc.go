// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Test Pair RPC execution system for Manager

// ===============DDRD====================
// Test Pair RPC Execution for Syzkaller Race Detection
// Handles test pair distribution via RPC to fuzzers
// ===============DDRD====================
package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// CheckTestPairMode 检查是否处于test pair模式
func (mgr *Manager) CheckTestPairMode(args *rpctype.CheckModeArgs, res *rpctype.CheckModeRes) error {
	if mgr.testPairDispatcher == nil {
		log.Logf(2, "CheckTestPairMode: testPairDispatcher为空，返回false")
		res.IsTestPairMode = false
		return nil
	}
	enabled := mgr.testPairDispatcher.IsEnabled()
	log.Logf(2, "CheckTestPairMode: dispatcher enabled=%v", enabled)
	res.IsTestPairMode = enabled
	return nil
}

// TestPairSelectionMode defines the mode for selecting test pairs
type TestPairSelectionMode int

const (
	PairSelectionRandom TestPairSelectionMode = iota
	// PairSelectionRaceRich selects programs more likely to contain races
	PairSelectionRaceRich
	// PairSelectionSimilarCalls selects programs with similar system calls
	PairSelectionSimilarCalls
	// PairSelectionMixed mixes different selection strategies
	PairSelectionMixed
)

// TestPairDispatcher manages test pair distribution to fuzzers via RPC
type TestPairDispatcher struct {
	mgr           *Manager
	pendingTasks  []rpctype.TestPairTask
	activeTasks   map[string]*TestPairInfo // ID -> TestPairInfo
	taskQueue     chan rpctype.TestPairTask
	resultQueue   chan rpctype.TestPairResult
	mu            sync.Mutex
	enabled       bool
	maxConcurrent int
	taskCounter   uint64 // Counter for unique task IDs
}

// TestPairInfo tracks active test pair execution
type TestPairInfo struct {
	Task       rpctype.TestPairTask
	FuzzerName string
	StartTime  time.Time
	Timeout    time.Duration
}

// NewTestPairDispatcher creates a new test pair dispatcher
func NewTestPairDispatcher(mgr *Manager) *TestPairDispatcher {
	return &TestPairDispatcher{
		mgr:           mgr,
		pendingTasks:  make([]rpctype.TestPairTask, 0),
		activeTasks:   make(map[string]*TestPairInfo),
		taskQueue:     make(chan rpctype.TestPairTask, 100),
		resultQueue:   make(chan rpctype.TestPairResult, 100),
		maxConcurrent: 10,
	}
}

// Enable enables the test pair dispatcher
func (tpd *TestPairDispatcher) Enable(maxConcurrent int) {
	tpd.mu.Lock()
	defer tpd.mu.Unlock()

	tpd.enabled = true
	tpd.maxConcurrent = maxConcurrent
}

// Disable disables the test pair dispatcher
func (tpd *TestPairDispatcher) Disable() {
	tpd.mu.Lock()
	defer tpd.mu.Unlock()

	tpd.enabled = false
}

// IsEnabled checks if the dispatcher is enabled
func (tpd *TestPairDispatcher) IsEnabled() bool {
	tpd.mu.Lock()
	defer tpd.mu.Unlock()
	return tpd.enabled
}

// QueueTestPair adds a test pair task to the queue
func (tpd *TestPairDispatcher) QueueTestPair(prog1, prog2 *prog.Prog, hash1, hash2 string) {
	tpd.mu.Lock()
	defer tpd.mu.Unlock()

	if !tpd.enabled {
		return
	}

	// Create test pair task
	tpd.taskCounter++
	taskID := fmt.Sprintf("pair_%d_%s_%s", tpd.taskCounter, hash1[:8], hash2[:8])

	task := rpctype.TestPairTask{
		ID:    taskID,
		Prog1: prog1.Serialize(),
		Prog2: prog2.Serialize(),
		Hash1: hash1,
		Hash2: hash2,
		Opts: &ipc.ExecOpts{
			Flags: ipc.FlagCollectSignal | ipc.FlagCollectCover, // 移除可能有问题的标志
		},
		Priority: 1,
	}

	tpd.pendingTasks = append(tpd.pendingTasks, task)
	log.Logf(0, "Test Pair %s 已加入队列 (程序: %s + %s)", taskID, hash1[:8], hash2[:8])
}

// GetTasksForFuzzer returns available tasks for a fuzzer
func (tpd *TestPairDispatcher) GetTasksForFuzzer(fuzzerName string, capacity int) []rpctype.TestPairTask {
	tpd.mu.Lock()
	defer tpd.mu.Unlock()

	if !tpd.enabled || len(tpd.pendingTasks) == 0 {
		return nil
	}

	// Determine how many tasks to send
	available := len(tpd.pendingTasks)
	toSend := capacity
	if toSend > available {
		toSend = available
	}
	if toSend > 1 { // 减少到每次最多1个任务，降低负载
		toSend = 1
	}

	// Extract tasks
	tasks := make([]rpctype.TestPairTask, toSend)
	copy(tasks, tpd.pendingTasks[:toSend])

	// Update pending tasks
	tpd.pendingTasks = tpd.pendingTasks[toSend:]

	// Track active tasks
	for _, task := range tasks {
		tpd.activeTasks[task.ID] = &TestPairInfo{
			Task:       task,
			FuzzerName: fuzzerName,
			StartTime:  time.Now(),
			Timeout:    60 * time.Second, // 增加到60秒超时
		}
	}

	return tasks
}

// HandleTestPairResults processes results from fuzzers
func (tpd *TestPairDispatcher) HandleTestPairResults(fuzzerName string, results []rpctype.TestPairResult) {
	tpd.mu.Lock()
	defer tpd.mu.Unlock()

	for _, result := range results {
		if taskInfo, exists := tpd.activeTasks[result.ID]; exists {
			// Remove from active tasks
			delete(tpd.activeTasks, result.ID)

			// Process result
			tpd.processResult(taskInfo, result)
		}
	}
}

// processResult processes a single test pair result
func (tpd *TestPairDispatcher) processResult(taskInfo *TestPairInfo, result rpctype.TestPairResult) {
	execTime := time.Duration(result.ExecTime)

	if result.Success {
		log.Logf(0, "Test Pair %s 执行完成: 用时=%v, races=%d, 新races=%d",
			result.ID, execTime, len(result.Races), len(result.Races))

		// Process race detection results
		if len(result.Races) > 0 {
			// Convert RPC race info to internal format and process
			for _, race := range result.Races {
				log.Logf(0, "检测到竞争: %s vs %s (%s)",
					race.Syscall1, race.Syscall2, race.LockType)
			}
		}

		// Process execution info
		if result.Info1 != nil {
			signal1 := tpd.processExecutionResult(result.Info1)
			// Record signal for corpus update
			log.Logf(0, "程序1执行信号长度: %d", len(signal1))
		}

		if result.Info2 != nil {
			signal2 := tpd.processExecutionResult(result.Info2)
			// Record signal for corpus update
			log.Logf(0, "程序2执行信号长度: %d", len(signal2))
		}
	} else {
		log.Logf(0, "Test Pair %s 执行失败: %s", result.ID, result.Error)
	}
}

// processExecutionResult converts ProgInfo to signal
func (tpd *TestPairDispatcher) processExecutionResult(info *ipc.ProgInfo) signal.Signal {
	if info == nil {
		return nil
	}

	allSignals := signal.FromRaw([]uint32{}, 1)
	if allSignals == nil {
		allSignals = make(signal.Signal)
	}

	for _, call := range info.Calls {
		if len(call.Signal) > 0 {
			callSignal := signal.FromRaw(call.Signal, 1)
			for elem, prio := range callSignal {
				allSignals[elem] = prio
			}
		}
	}

	return allSignals
}

// CleanupTimeoutTasks removes tasks that have timed out
func (tpd *TestPairDispatcher) CleanupTimeoutTasks() {
	tpd.mu.Lock()
	defer tpd.mu.Unlock()

	now := time.Now()
	for taskID, taskInfo := range tpd.activeTasks {
		if now.Sub(taskInfo.StartTime) > taskInfo.Timeout {
			log.Logf(0, "Test Pair %s 执行超时，从活跃任务中移除", taskID)
			delete(tpd.activeTasks, taskID)
		}
	}
}

// GetStats returns dispatcher statistics
func (tpd *TestPairDispatcher) GetStats() map[string]interface{} {
	tpd.mu.Lock()
	defer tpd.mu.Unlock()

	return map[string]interface{}{
		"enabled":       tpd.enabled,
		"pending":       len(tpd.pendingTasks),
		"active":        len(tpd.activeTasks),
		"maxConcurrent": tpd.maxConcurrent,
		"totalCreated":  tpd.taskCounter,
	}
}

// ===============DDRD====================
