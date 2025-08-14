// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package ddrd provides race coverage extraction and analysis utilities
// ===============DDRD====================
package ddrd

import (
	"encoding/binary"
	"fmt"
)

// ExtractRacePairsFromRpcInfo 从RPC返回的race信息中提取RacePair
func ExtractRacePairsFromRpcInfo(races []MayRacePair) []*MayRacePair {
	var racePairs []*MayRacePair

	for _, race := range races {
		rp := &MayRacePair{
			// Core information
			Syscall1: race.Syscall1,
			Syscall2: race.Syscall2,

			// Extended metadata from executor
			VarName1:   race.VarName1,
			VarName2:   race.VarName2,
			CallStack1: race.CallStack1,
			CallStack2: race.CallStack2,
			Signal:     race.Signal,

			// Access and timing information
			AccessType1: race.AccessType1,
			AccessType2: race.AccessType2,
			TimeDiff:    race.TimeDiff,

			// Lock information
			LockType: race.LockType,
		}

		racePairs = append(racePairs, rp)
	}

	return racePairs
}

// ExtractRacePairsFromExecutorData 从executor传输的完整race data中提取race pairs
// 处理包含signal、varname、callstack hash等完整信息的数据
func ExtractRacePairsFromExecutorData(mappingData []byte, syscall1, syscall2 string) []*MayRacePair {
	var racePairs []*MayRacePair

	// 解析mapping data中的完整race pair信息
	if len(mappingData) > 0 {
		// 使用内置的解析函数处理完整的race pair数据
		pairsFromMapping := ParseRacePairInfoFromMappingData(mappingData)

		for _, pairInfo := range pairsFromMapping {
			// 如果syscall信息为空，则使用传入的参数
			if pairInfo.Syscall1 == "" {
				pairInfo.Syscall1 = syscall1
			}
			if pairInfo.Syscall2 == "" {
				pairInfo.Syscall2 = syscall2
			}

			// 设置默认的锁类型
			if pairInfo.LockType == "" {
				pairInfo.LockType = "none"
			}

			racePairs = append(racePairs, &pairInfo)
		}
	}

	return racePairs
}

// ParseRacePairInfoFromMappingData extracts MayRacePair structures from executor mapping data
func ParseRacePairInfoFromMappingData(mappingData []byte) []MayRacePair {
	var racePairs []MayRacePair

	if len(mappingData) < 4 {
		return racePairs
	}

	// Read race pair count
	offset := 0
	count := binary.LittleEndian.Uint32(mappingData[offset : offset+4])
	offset += 4

	// Parse each race pair
	for i := uint32(0); i < count && i < 1000; i++ { // limit to 1000 race pairs
		if offset+64 > len(mappingData) { // minimum size check
			break
		}

		rp := MayRacePair{}

		// Signal (8 bytes)
		rp.Signal = binary.LittleEndian.Uint64(mappingData[offset : offset+8])
		offset += 8

		// VarName1 length and data
		if offset+4 > len(mappingData) {
			break
		}
		varname1Len := binary.LittleEndian.Uint32(mappingData[offset : offset+4])
		offset += 4

		if varname1Len > 0 && varname1Len < 256 && offset+int(varname1Len) <= len(mappingData) {
			rp.VarName1 = string(mappingData[offset : offset+int(varname1Len)])
			offset += int(varname1Len)
		}

		// VarName2 length and data
		if offset+4 > len(mappingData) {
			break
		}
		varname2Len := binary.LittleEndian.Uint32(mappingData[offset : offset+4])
		offset += 4

		if varname2Len > 0 && varname2Len < 256 && offset+int(varname2Len) <= len(mappingData) {
			rp.VarName2 = string(mappingData[offset : offset+int(varname2Len)])
			offset += int(varname2Len)
		}

		// CallStack hashes (16 bytes)
		if offset+16 > len(mappingData) {
			break
		}
		rp.CallStack1 = binary.LittleEndian.Uint64(mappingData[offset : offset+8])
		rp.CallStack2 = binary.LittleEndian.Uint64(mappingData[offset+8 : offset+16])
		offset += 16

		// Access types (2 bytes)
		if offset+2 > len(mappingData) {
			break
		}
		rp.AccessType1 = mappingData[offset]
		rp.AccessType2 = mappingData[offset+1]
		offset += 2

		// Time difference (8 bytes)
		if offset+8 > len(mappingData) {
			break
		}
		rp.TimeDiff = binary.LittleEndian.Uint64(mappingData[offset : offset+8])
		offset += 8

		// Align to 8-byte boundary
		for offset%8 != 0 && offset < len(mappingData) {
			offset++
		}

		racePairs = append(racePairs, rp)
	}

	return racePairs
}

// MergeRacePairs 合并多个race pair列表，去除重复
func MergeRacePairs(lists ...[]*MayRacePair) []*MayRacePair {
	seen := make(map[uint64]*MayRacePair)

	for _, list := range lists {
		for _, rp := range list {
			id := rp.RacePairID()
			if _, exists := seen[id]; !exists {
				seen[id] = rp
			}
		}
	}

	result := make([]*MayRacePair, 0, len(seen))
	for _, rp := range seen {
		result = append(result, rp)
	}

	return result
}

// FilterRacePairsBySyscalls 根据系统调用过滤race pairs
func FilterRacePairsBySyscalls(racePairs []*MayRacePair, allowedSyscalls []string) []*MayRacePair {
	if len(allowedSyscalls) == 0 {
		return racePairs
	}

	syscallSet := make(map[string]bool)
	for _, syscall := range allowedSyscalls {
		syscallSet[syscall] = true
	}

	var filtered []*MayRacePair
	for _, rp := range racePairs {
		if syscallSet[rp.Syscall1] || syscallSet[rp.Syscall2] {
			filtered = append(filtered, rp)
		}
	}

	return filtered
}

// FilterRacePairsByLockType 根据锁类型过滤race pairs
func FilterRacePairsByLockType(racePairs []*MayRacePair, lockTypes []string) []*MayRacePair {
	if len(lockTypes) == 0 {
		return racePairs
	}

	lockTypeSet := make(map[string]bool)
	for _, lockType := range lockTypes {
		lockTypeSet[lockType] = true
	}

	var filtered []*MayRacePair
	for _, rp := range racePairs {
		if lockTypeSet[rp.LockType] {
			filtered = append(filtered, rp)
		}
	}

	return filtered
}

// GroupRacePairsBySyscalls 根据系统调用组合对race pairs进行分组
func GroupRacePairsBySyscalls(racePairs []*MayRacePair) map[string][]*MayRacePair {
	groups := make(map[string][]*MayRacePair)

	for _, rp := range racePairs {
		key := fmt.Sprintf("%s+%s", rp.Syscall1, rp.Syscall2)
		groups[key] = append(groups[key], rp)
	}

	return groups
}
