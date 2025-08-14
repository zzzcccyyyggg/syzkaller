// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// ===============DDRD====================
// Race coverage helper methods for Manager - 重构使用RacePairCoverageManager
// ===============DDRD====================

package main

// GetRaceCoverageStats 获取race pair覆盖率统计信息
func (mgr *Manager) GetRaceCoverageStats() map[string]interface{} {
	return mgr.racePairCoverageManager.GetStatistics()
}

// GetRacePairCoverageSignal 获取race pair覆盖率信号数量
func (mgr *Manager) GetRacePairCoverageSignal() uint64 {
	return mgr.racePairCoverageManager.GetCoverageSignal()
}

// GetRecentRacePairs 获取最近发现的race pairs
func (mgr *Manager) GetRecentRacePairs() []*RacePair {
	return mgr.racePairCoverageManager.GetRecentRacePairs()
}

// GetAllRacePairs 获取所有已发现的race pairs
func (mgr *Manager) GetAllRacePairs() []*RacePair {
	return mgr.racePairCoverageManager.GetAllRacePairs()
}

// GetRacePairsByLockStatus 获取按锁状态分类的race pairs
func (mgr *Manager) GetRacePairsByLockStatus(status LockStatus) []*RacePair {
	return mgr.racePairCoverageManager.GetRacePairsByLockStatus(status)
}

// IsRacePairCoverageEnabled 检查race pair覆盖率是否启用
func (mgr *Manager) IsRacePairCoverageEnabled() bool {
	return mgr.racePairCoverageManager.IsEnabled()
}

// ClearRacePairCoverage 清空race pair覆盖率数据（用于测试）
func (mgr *Manager) ClearRacePairCoverage() {
	mgr.racePairCoverageManager.Clear()
}

// GetNewRacePairSignalSinceLastCheck 获取自上次检查以来的新race pair信号
func (mgr *Manager) GetNewRacePairSignalSinceLastCheck() uint64 {
	return mgr.racePairCoverageManager.GetNewSignalSinceLastCheck()
}

// 注意：移除了基于signal.Signal的方法，因为RacePairCoverageManager
// 处理的是AccessInfo和RacePair结构，提供了更丰富的race检测信息

// ===============DDRD====================
