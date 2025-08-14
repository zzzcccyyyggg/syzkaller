// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Test Pair program selection strategies
// 实现不同的程序选择策略来创建test pairs

// ===============DDRD====================

package main

import (
	"math/rand"
	"strings"

	"github.com/google/syzkaller/prog"
)

// ProgramSelector 程序选择器，用于为test pair选择程序
type ProgramSelector struct {
	mgr *Manager
}

// NewProgramSelector 创建程序选择器
func NewProgramSelector(mgr *Manager) *ProgramSelector {
	return &ProgramSelector{mgr: mgr}
}

// SelectPairPrograms 根据指定策略选择一对程序
func (ps *ProgramSelector) SelectPairPrograms(mode TestPairSelectionMode) (*prog.Prog, *prog.Prog, string, string) {
	switch mode {
	case PairSelectionRandom:
		return ps.selectRandomPair()
	case PairSelectionRaceRich:
		return ps.selectRaceRichPair()
	case PairSelectionSimilarCalls:
		return ps.selectSimilarCallsPair()
	case PairSelectionMixed:
		// 混合策略：随机选择一种方法
		modes := []TestPairSelectionMode{
			PairSelectionRandom,
			PairSelectionRaceRich,
			PairSelectionSimilarCalls,
		}
		selectedMode := modes[rand.Intn(len(modes))]
		return ps.SelectPairPrograms(selectedMode)
	default:
		return ps.selectRandomPair()
	}
}

// selectRandomPair 随机选择两个程序
func (ps *ProgramSelector) selectRandomPair() (*prog.Prog, *prog.Prog, string, string) {
	ps.mgr.mu.Lock()
	defer ps.mgr.mu.Unlock()

	if len(ps.mgr.corpus) < 2 {
		return nil, nil, "", ""
	}

	// 获取corpus中的所有程序
	var corpusItems []CorpusItem
	var hashes []string

	for hash, item := range ps.mgr.corpus {
		corpusItems = append(corpusItems, item)
		hashes = append(hashes, hash)
	}

	// 随机选择两个不同的程序
	idx1 := rand.Intn(len(corpusItems))
	idx2 := rand.Intn(len(corpusItems))

	// 确保选择不同的程序
	for idx2 == idx1 && len(corpusItems) > 1 {
		idx2 = rand.Intn(len(corpusItems))
	}

	prog1, err1 := ps.mgr.target.Deserialize(corpusItems[idx1].Prog, prog.NonStrict)
	prog2, err2 := ps.mgr.target.Deserialize(corpusItems[idx2].Prog, prog.NonStrict)

	if err1 != nil || err2 != nil {
		return nil, nil, "", ""
	}

	return prog1, prog2, hashes[idx1], hashes[idx2]
}

// selectRaceRichPair 选择可能产生race pairs的程序对
func (ps *ProgramSelector) selectRaceRichPair() (*prog.Prog, *prog.Prog, string, string) {
	// 基于最近的race pairs来选择相关程序
	recentPairs := ps.mgr.GetRecentRacePairs()

	if len(recentPairs) < 2 {
		// 如果没有足够的race pair信息，回退到随机选择
		return ps.selectRandomPair()
	}

	// 从最近的race pairs中获取程序信息，选择相关程序
	// 这里简化为随机选择，实际可以根据race pair的程序信息做更智能的选择
	return ps.selectRandomPair()
}

// selectSimilarCallsPair 选择使用相似系统调用的程序对
func (ps *ProgramSelector) selectSimilarCallsPair() (*prog.Prog, *prog.Prog, string, string) {
	ps.mgr.mu.Lock()
	defer ps.mgr.mu.Unlock()

	if len(ps.mgr.corpus) < 2 {
		return ps.selectRandomPair()
	}

	// 按系统调用分组程序
	callGroups := make(map[string][]CorpusItemWithHash)

	for hash, item := range ps.mgr.corpus {
		// 提取主要系统调用名称
		mainCall := ps.extractMainSyscall(item.Call)
		if mainCall != "" {
			callGroups[mainCall] = append(callGroups[mainCall], CorpusItemWithHash{item, hash})
		}
	}

	// 查找有多个程序的调用组
	var validGroups []string
	for call, items := range callGroups {
		if len(items) >= 2 {
			validGroups = append(validGroups, call)
		}
	}

	if len(validGroups) == 0 {
		ps.mgr.mu.Unlock()
		return ps.selectRandomPair()
	}

	// 随机选择一个调用组
	selectedCall := validGroups[rand.Intn(len(validGroups))]
	groupItems := callGroups[selectedCall]

	// 从该组中选择两个程序
	idx1 := rand.Intn(len(groupItems))
	idx2 := rand.Intn(len(groupItems))

	for idx2 == idx1 && len(groupItems) > 1 {
		idx2 = rand.Intn(len(groupItems))
	}

	prog1, err1 := ps.mgr.target.Deserialize(groupItems[idx1].Item.Prog, prog.NonStrict)
	prog2, err2 := ps.mgr.target.Deserialize(groupItems[idx2].Item.Prog, prog.NonStrict)

	if err1 != nil || err2 != nil {
		ps.mgr.mu.Unlock()
		return ps.selectRandomPair()
	}

	return prog1, prog2, groupItems[idx1].Hash, groupItems[idx2].Hash
}

// extractMainSyscall 从调用字符串中提取主要系统调用名称
func (ps *ProgramSelector) extractMainSyscall(callStr string) string {
	if callStr == "" {
		return ""
	}

	// 提取第一个单词作为主要系统调用
	parts := strings.Split(callStr, "$")
	if len(parts) > 0 {
		return parts[0]
	}

	// 如果没有$分隔符，直接返回整个字符串
	return callStr
}

// CorpusItemWithHash 带hash的corpus item
type CorpusItemWithHash struct {
	Item CorpusItem
	Hash string
}

// CanCreateTestPair 检查是否可以创建test pair
func (ps *ProgramSelector) CanCreateTestPair() bool {
	ps.mgr.mu.Lock()
	defer ps.mgr.mu.Unlock()

	return len(ps.mgr.corpus) >= 2
}

// GetCorpusSize 获取corpus大小
func (ps *ProgramSelector) GetCorpusSize() int {
	ps.mgr.mu.Lock()
	defer ps.mgr.mu.Unlock()

	return len(ps.mgr.corpus)
}

// GetRaceRichProgramCount 获取包含race的程序数量
func (ps *ProgramSelector) GetRaceRichProgramCount() int {
	// 基于race pair coverage manager获取统计信息
	recentPairs := ps.mgr.GetRecentRacePairs()
	return len(recentPairs)
}

// SelectTargetedPair 为特定目标选择程序对（例如特定的竞争条件）
func (ps *ProgramSelector) SelectTargetedPair(targetSyscalls []string) (*prog.Prog, *prog.Prog, string, string) {
	ps.mgr.mu.Lock()
	defer ps.mgr.mu.Unlock()

	// 查找包含目标系统调用的程序
	var candidates []CorpusItemWithHash

	for hash, item := range ps.mgr.corpus {
		for _, targetCall := range targetSyscalls {
			if strings.Contains(item.Call, targetCall) {
				candidates = append(candidates, CorpusItemWithHash{item, hash})
				break
			}
		}
	}

	if len(candidates) < 2 {
		ps.mgr.mu.Unlock()
		return ps.selectRandomPair()
	}

	// 随机选择两个候选程序
	idx1 := rand.Intn(len(candidates))
	idx2 := rand.Intn(len(candidates))

	for idx2 == idx1 && len(candidates) > 1 {
		idx2 = rand.Intn(len(candidates))
	}

	prog1, err1 := ps.mgr.target.Deserialize(candidates[idx1].Item.Prog, prog.NonStrict)
	prog2, err2 := ps.mgr.target.Deserialize(candidates[idx2].Item.Prog, prog.NonStrict)

	if err1 != nil || err2 != nil {
		ps.mgr.mu.Unlock()
		return ps.selectRandomPair()
	}

	return prog1, prog2, candidates[idx1].Hash, candidates[idx2].Hash
}

// ===============DDRD====================
