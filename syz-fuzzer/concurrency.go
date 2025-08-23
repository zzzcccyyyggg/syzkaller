// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// ===============DDRD====================
// Package main provides race detection and pair testing support for syz-fuzzer
// ===============DDRD====================
package main

import (
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
)

// ===============DDRD====================
// RacePairManager handles race pair generation and management
// Simplified interface focused on race detection
// ===============DDRD====================
type RacePairManager struct {
	fuzzer *Fuzzer

	// Runtime state
	isActive      bool
	lastModeCheck time.Time
}

// NewRacePairManager creates a new race pair manager
func NewRacePairManager(fuzzer *Fuzzer) *RacePairManager {
	return &RacePairManager{
		fuzzer: fuzzer,
	}
}

// IsRacePairMode checks if the fuzzer should operate in race pair testing mode
func (rpm *RacePairManager) IsRacePairMode() bool {
	// Cache mode check to avoid frequent RPC calls
	if time.Since(rpm.lastModeCheck) < 5*time.Second {
		return rpm.isActive
	}

	rpm.lastModeCheck = time.Now()

	// Check with manager
	args := &rpctype.CheckModeArgs{}
	res := &rpctype.CheckModeRes{}

	if err := rpm.fuzzer.manager.Call("Manager.CheckTestPairMode", args, res); err != nil {
		log.Logf(1, "CheckTestPairMode RPC failed: %v, defaulting to normal mode", err)
		rpm.isActive = false
		return false
	}

	if res.IsTestPairMode != rpm.isActive {
		log.Logf(1, "Race pair mode changed: %v -> %v", rpm.isActive, res.IsTestPairMode)
		rpm.isActive = res.IsTestPairMode

		if rpm.isActive {
			rpm.onEnterRacePairMode()
		} else {
			rpm.onExitRacePairMode()
		}
	}

	return rpm.isActive
}

// onEnterRacePairMode handles entering race pair testing mode
func (rpm *RacePairManager) onEnterRacePairMode() {
	log.Logf(0, "Entering race pair testing mode")
	// Generate initial corpus pairs
	rpm.fuzzer.generateTestPairsFromCorpus(50)
}

// onExitRacePairMode handles exiting race pair testing mode
func (rpm *RacePairManager) onExitRacePairMode() {
	log.Logf(0, "Exiting race pair testing mode")
	// No cleanup needed for now
}

// // reportNewRacePairs reports newly discovered race pairs to the manager
// func (rpm *RacePairManager) reportNewRacePairs(pair *WorkRacePair, races []*ddrd.MayRacePair, output []byte) {
// 	// Prepare race data for manager
// 	raceData := make([]rpctype.RacePairData, len(races))
// 	for i, race := range races {
// 		raceData[i] = rpctype.RacePairData{
// 			Syscall1:    race.Syscall1,
// 			Syscall2:    race.Syscall2,
// 			VarName1:    race.VarName1,
// 			VarName2:    race.VarName2,
// 			CallStack1:  race.CallStack1,
// 			CallStack2:  race.CallStack2,
// 			Signal:      race.Signal,
// 			LockType:    race.LockType,
// 			AccessType1: race.AccessType1,
// 			AccessType2: race.AccessType2,
// 			TimeDiff:    race.TimeDiff,
// 		}
// 	}

// 	// Send to manager
// 	req := &rpctype.NewRacePairArgs{
// 		Name:      rpm.fuzzer.name,
// 		PairID:    pair.pairID,
// 		Prog1Data: pair.p1.Serialize(),
// 		Prog2Data: pair.p2.Serialize(),
// 		Races:     raceData,
// 		Output:    output,
// 	}

// 	var res rpctype.NewRacePairRes
// 	if err := rpm.fuzzer.manager.Call("Manager.NewRacePair", req, &res); err != nil {
// 		log.Logf(1, "failed to report new race pairs: %v", err)
// 	} else {
// 		log.Logf(1, "reported %d new race pairs to manager", len(races))
// 	}
// }
