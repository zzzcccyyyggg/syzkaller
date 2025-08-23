// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package ddrd provides race coverage extraction and analysis utilities
// ===============DDRD====================
package ddrd

// ExtractRacePairsFromRpcInfo 从RPC返回的race信息中提取RacePair
func ExtractRacePairsFromRpcInfo(races []MayRacePair) []*MayRacePair {
	var racePairs []*MayRacePair

	for _, race := range races {
		rp := &MayRacePair{
			// Core information - using index and num fields
			Syscall1Idx: race.Syscall1Idx,
			Syscall2Idx: race.Syscall2Idx,
			Syscall1Num: race.Syscall1Num,
			Syscall2Num: race.Syscall2Num,

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
