// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ddrd

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
)

// RacePairID generates a unique identifier for a race pair
// Uses the executor-generated signal as the primary identifier when available
// And use the hash of all relevant fields if the signal is unavailable

// RacePairID generates a unique identifier for a race pair
// Uses the executor-generated signal as the primary identifier when available
// And use the hash of all relevant fields if the signal is unavailable
func (rp *MayRacePair) RacePairID() uint64 {
	// If executor provided a signal (based on varname1+varname2+callstack hashes), use it
	if rp.Signal != 0 {
		return rp.Signal
	}
	// Fallback: generate hash from available fields
	h := sha256.New()
	buf := make([]byte, 8)

	// Include syscall indices and numbers
	binary.LittleEndian.PutUint32(buf[:4], uint32(rp.Syscall1Idx))
	h.Write(buf[:4])
	binary.LittleEndian.PutUint32(buf[:4], uint32(rp.Syscall2Idx))
	h.Write(buf[:4])
	binary.LittleEndian.PutUint32(buf[:4], uint32(rp.Syscall1Num))
	h.Write(buf[:4])
	binary.LittleEndian.PutUint32(buf[:4], uint32(rp.Syscall2Num))
	h.Write(buf[:4])

	// Include variable name identifiers
	binary.LittleEndian.PutUint64(buf, rp.VarName1)
	h.Write(buf)
	binary.LittleEndian.PutUint64(buf, rp.VarName2)
	h.Write(buf)

	// Include access types and lock type
	h.Write([]byte{rp.AccessType1})
	h.Write([]byte{rp.AccessType2})
	h.Write([]byte{rp.LockType})

	// Include callstack hashes
	binary.LittleEndian.PutUint64(buf, rp.CallStack1)
	h.Write(buf)
	binary.LittleEndian.PutUint64(buf, rp.CallStack2)
	h.Write(buf)

	// Include time difference
	binary.LittleEndian.PutUint64(buf, rp.TimeDiff)
	h.Write(buf)

	hash := h.Sum(nil)
	return binary.LittleEndian.Uint64(hash[:8])
}

// String returns a human-readable representation of the race pair
func (rp *MayRacePair) String() string {
	return fmt.Sprintf("RacePair{syscall_%d(%d) vs syscall_%d(%d), lock=%d, vars=0x%x,0x%x, access=%d,%d, signal=0x%x, stacks=0x%x,0x%x, timediff=%d}",
		rp.Syscall1Num, rp.Syscall1Idx, rp.Syscall2Num, rp.Syscall2Idx, rp.LockType,
		rp.VarName1, rp.VarName2, rp.AccessType1, rp.AccessType2,
		rp.Signal, rp.CallStack1, rp.CallStack2, rp.TimeDiff)
}

// RaceCover maintains coverage of detected race pairs
// Similar to normal coverage but for race conditions
type RaceCover map[uint64]*MayRacePair

// Merge adds new race pairs to the coverage
func (rc *RaceCover) Merge(racePairs []*MayRacePair) {
	c := *rc
	if c == nil {
		c = make(RaceCover)
		*rc = c
	}
	for _, rp := range racePairs {
		id := rp.RacePairID()
		c[id] = rp
	}
}

// MergeDiff adds new race pairs and returns newly discovered race pairs
func (rc *RaceCover) MergeDiff(racePairs []*MayRacePair) []*MayRacePair {
	c := *rc
	if c == nil {
		c = make(RaceCover)
		*rc = c
	}

	var newRaces []*MayRacePair
	for _, rp := range racePairs {
		id := rp.RacePairID()
		if _, exists := c[id]; !exists {
			c[id] = rp
			newRaces = append(newRaces, rp)
		}
	}
	return newRaces
}

// Serialize returns all race pairs as a slice
func (rc RaceCover) Serialize() []*MayRacePair {
	result := make([]*MayRacePair, 0, len(rc))
	for _, rp := range rc {
		result = append(result, rp)
	}

	// Sort for consistent output
	sort.Slice(result, func(i, j int) bool {
		return result[i].RacePairID() < result[j].RacePairID()
	})

	return result
}

// Len returns the number of unique race pairs covered
func (rc RaceCover) Len() int {
	return len(rc)
}

// Contains checks if a specific race pair is already covered
func (rc RaceCover) Contains(rp *MayRacePair) bool {
	if rc == nil {
		return false
	}
	_, exists := rc[rp.RacePairID()]
	return exists
}

// GetBySyscalls returns all race pairs involving specific syscall numbers
func (rc RaceCover) GetBySyscalls(syscall1Num, syscall2Num int32) []*MayRacePair {
	var result []*MayRacePair
	for _, rp := range rc {
		if (rp.Syscall1Num == syscall1Num && rp.Syscall2Num == syscall2Num) ||
			(rp.Syscall1Num == syscall2Num && rp.Syscall2Num == syscall1Num) {
			result = append(result, rp)
		}
	}
	return result
}

// GetByType returns all race pairs of a specific lock type
func (rc RaceCover) GetByType(lockType uint8) []*MayRacePair {
	var result []*MayRacePair
	for _, rp := range rc {
		if rp.LockType == lockType {
			result = append(result, rp)
		}
	}
	return result
}

// RaceCoverageStats returns statistics about the race coverage
type RaceCoverageStats struct {
	TotalRacePairs    int
	UniqueSyscalls    int
	UniqueVariables   int
	LockTypeBreakdown map[uint8]int
}

// GetStats returns detailed statistics about the race coverage
func (rc RaceCover) GetStats() RaceCoverageStats {
	stats := RaceCoverageStats{
		TotalRacePairs:    len(rc),
		LockTypeBreakdown: make(map[uint8]int),
	}

	syscallSet := make(map[int32]struct{})
	variableSet := make(map[uint64]struct{})

	for _, rp := range rc {
		// Count unique syscalls
		syscallSet[rp.Syscall1Num] = struct{}{}
		syscallSet[rp.Syscall2Num] = struct{}{}

		// Count unique variables
		if rp.VarName1 != 0 {
			variableSet[rp.VarName1] = struct{}{}
		}
		if rp.VarName2 != 0 {
			variableSet[rp.VarName2] = struct{}{}
		}

		// Count lock types
		stats.LockTypeBreakdown[rp.LockType]++
	}

	stats.UniqueSyscalls = len(syscallSet)
	stats.UniqueVariables = len(variableSet)

	return stats
}

// Clear removes all race pairs from coverage
func (rc *RaceCover) Clear() {
	*rc = make(RaceCover)
}

// Copy creates a deep copy of the race coverage
func (rc RaceCover) Copy() RaceCover {
	if rc == nil {
		return nil
	}

	result := make(RaceCover, len(rc))
	for id, rp := range rc {
		// Create a copy of the race pair
		newRP := &MayRacePair{
			Syscall1Idx: rp.Syscall1Idx,
			Syscall2Idx: rp.Syscall2Idx,
			Syscall1Num: rp.Syscall1Num,
			Syscall2Num: rp.Syscall2Num,
			VarName1:    rp.VarName1,
			VarName2:    rp.VarName2,
			CallStack1:  rp.CallStack1,
			CallStack2:  rp.CallStack2,
			Signal:      rp.Signal,
			LockType:    rp.LockType,
			AccessType1: rp.AccessType1,
			AccessType2: rp.AccessType2,
			TimeDiff:    rp.TimeDiff,
		}
		result[id] = newRP
	}

	return result
}
