// ===============DDRD====================
// Package main implements race pair coverage tracking
// Race pairs represent potential racing memory accesses, not actual data races
// Based on DDRD (Dynamic Data Race Detection) algorithm
// ===============DDRD====================
package main

import (
	"sync"
	"time"
)

// LockStatus represents the synchronization status between two accesses
type LockStatus int

const (
	NoLocks LockStatus = iota
	OneSidedLock
	UnsyncLocks
	SyncWithCommonLock
)

func (ls LockStatus) String() string {
	switch ls {
	case NoLocks:
		return "No Locks"
	case OneSidedLock:
		return "One-Sided Lock"
	case UnsyncLocks:
		return "Unsynchronized Locks"
	case SyncWithCommonLock:
		return "Synchronized (Common Lock)"
	default:
		return "Unknown"
	}
}

// AccessInfo represents a memory access record
type AccessInfo struct {
	TID           int        `json:"tid"`
	VarName       uint64     `json:"var_name"`
	Address       uint64     `json:"address"`
	AccessType    byte       `json:"access_type"` // 'R', 'W', 'F'
	Size          uint64     `json:"size"`
	CallStackHash uint64     `json:"call_stack_hash"`
	AccessTime    uint64     `json:"access_time"`
	SN            int        `json:"sn"`
	HeldLocks     []LockInfo `json:"held_locks"`
}

// LockInfo represents a held lock
type LockInfo struct {
	Name string `json:"name"`
	Ptr  uint64 `json:"ptr"`
	Attr int    `json:"attr"`
}

// RaceKey uniquely identifies a race pair for deduplication
type RaceKey struct {
	Var1  uint64 `json:"var1"`
	Var2  uint64 `json:"var2"`
	Hash1 uint64 `json:"hash1"`
	Hash2 uint64 `json:"hash2"`
}

// NewRaceKey creates a normalized race key with consistent ordering
func NewRaceKey(var1, var2, hash1, hash2 uint64) RaceKey {
	key := RaceKey{}

	if var1 <= var2 {
		key.Var1, key.Var2 = var1, var2
	} else {
		key.Var1, key.Var2 = var2, var1
	}

	if hash1 <= hash2 {
		key.Hash1, key.Hash2 = hash1, hash2
	} else {
		key.Hash1, key.Hash2 = hash2, hash1
	}

	return key
}

// RacePair represents a potential racing access pair
type RacePair struct {
	First          AccessInfo `json:"first"`
	Second         AccessInfo `json:"second"`
	AccessTimeDiff uint64     `json:"access_time_diff"`
	TriggerCounts  int        `json:"trigger_counts"`
	LockStatus     LockStatus `json:"lock_status"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
}

// RacePairCoverageManager manages race pair discovery and coverage
type RacePairCoverageManager struct {
	mu                     sync.RWMutex
	enabled                bool
	racePairs              map[RaceKey]*RacePair // All discovered race pairs
	lockStatusStats        map[LockStatus]int    // Statistics by lock status
	totalSignal            uint64                // Total coverage signal
	newPairsSinceLastCheck uint64                // New pairs since last signal check
	lastSignalTime         time.Time             // Last time signal was updated

	// Configuration
	timeThreshold uint64 // Maximum time difference for potential races

	// Callback for notifying new race pair discovery
	onNewRacePairCallback func(AccessInfo, AccessInfo)
}

// NewRacePairCoverageManager creates a new race pair coverage manager
func NewRacePairCoverageManager() *RacePairCoverageManager {
	return &RacePairCoverageManager{
		enabled:         false,
		racePairs:       make(map[RaceKey]*RacePair),
		lockStatusStats: make(map[LockStatus]int),
		timeThreshold:   10000000000, // 10us in nanoseconds
		lastSignalTime:  time.Now(),
	}
}

// SetEnabled enables or disables race pair tracking
func (rpcm *RacePairCoverageManager) SetEnabled(enabled bool) {
	rpcm.mu.Lock()
	defer rpcm.mu.Unlock()
	rpcm.enabled = enabled
}

// SetNewRacePairCallback sets the callback function for new race pair discovery
func (rpcm *RacePairCoverageManager) SetNewRacePairCallback(callback func(AccessInfo, AccessInfo)) {
	rpcm.mu.Lock()
	defer rpcm.mu.Unlock()
	rpcm.onNewRacePairCallback = callback
}

// IsEnabled returns whether race pair tracking is enabled
func (rpcm *RacePairCoverageManager) IsEnabled() bool {
	rpcm.mu.RLock()
	defer rpcm.mu.RUnlock()
	return rpcm.enabled
}

// AddAccessRecords processes a batch of access records and discovers new race pairs
func (rpcm *RacePairCoverageManager) AddAccessRecords(records []AccessInfo) uint64 {
	rpcm.mu.Lock()
	defer rpcm.mu.Unlock()

	if !rpcm.enabled {
		return 0
	}

	newPairs := rpcm.analyzeRacePairs(records)
	return newPairs
}

// analyzeRacePairs implements the race pair detection algorithm from DDRD
func (rpcm *RacePairCoverageManager) analyzeRacePairs(records []AccessInfo) uint64 {
	newPairsCount := uint64(0)
	n := len(records)

	// Build free operation index for same valid interval checking
	freeOps := rpcm.buildFreeOperationIndex(records)

	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			a := &records[i]
			b := &records[j]

			// Skip same thread accesses
			if a.TID == b.TID {
				continue
			}

			// At least one must be a write operation
			if !(a.AccessType == 'W' || b.AccessType == 'W') {
				continue
			}

			// Check address overlap
			if !rpcm.addressesOverlap(a, b) {
				continue
			}

			// Check time threshold
			timeDiff := rpcm.getTimeDifference(a.AccessTime, b.AccessTime)
			if timeDiff > rpcm.timeThreshold {
				continue
			}

			// Check if in same valid interval (not separated by free operations)
			if !rpcm.inSameValidInterval(a, b, freeOps) {
				continue
			}

			// Determine lock status
			lockStatus := rpcm.determineLockStatus(a, b)

			// Create race key for deduplication
			first, second := rpcm.orderAccesses(a, b)
			key := NewRaceKey(first.VarName, second.VarName, first.CallStackHash, second.CallStackHash)

			// Check if this race pair already exists
			if existingPair, exists := rpcm.racePairs[key]; exists {
				existingPair.TriggerCounts++
				existingPair.LastSeen = time.Now()
			} else {
				// New race pair discovered!
				newPair := &RacePair{
					First:          *first,
					Second:         *second,
					AccessTimeDiff: timeDiff,
					TriggerCounts:  1,
					LockStatus:     lockStatus,
					FirstSeen:      time.Now(),
					LastSeen:       time.Now(),
				}

				rpcm.racePairs[key] = newPair
				rpcm.lockStatusStats[lockStatus]++
				rpcm.totalSignal++
				rpcm.newPairsSinceLastCheck++
				newPairsCount++

				// Notify about new race pair discovery
				if rpcm.onNewRacePairCallback != nil {
					rpcm.onNewRacePairCallback(*first, *second)
				}
			}
		}
	}

	return newPairsCount
}

// Helper functions

func (rpcm *RacePairCoverageManager) buildFreeOperationIndex(records []AccessInfo) map[uint64][]AccessInfo {
	freeOps := make(map[uint64][]AccessInfo)
	for _, record := range records {
		if record.AccessType == 'F' {
			addr := record.Address
			freeOps[addr] = append(freeOps[addr], record)
		}
	}
	return freeOps
}

func (rpcm *RacePairCoverageManager) addressesOverlap(a, b *AccessInfo) bool {
	return (a.Address < b.Address+b.Size) && (b.Address < a.Address+a.Size)
}

func (rpcm *RacePairCoverageManager) getTimeDifference(t1, t2 uint64) uint64 {
	if t1 > t2 {
		return t1 - t2
	}
	return t2 - t1
}

func (rpcm *RacePairCoverageManager) inSameValidInterval(a, b *AccessInfo, freeOps map[uint64][]AccessInfo) bool {
	minTime := a.AccessTime
	maxTime := b.AccessTime
	if minTime > maxTime {
		minTime, maxTime = maxTime, minTime
	}

	// Check if any free operation between the two accesses affects their address ranges
	for _, freeOpList := range freeOps {
		for _, freeOp := range freeOpList {
			if freeOp.AccessTime > minTime && freeOp.AccessTime < maxTime {
				// Check if free operation overlaps with either access
				if rpcm.addressesOverlap(a, &freeOp) || rpcm.addressesOverlap(b, &freeOp) {
					return false
				}
			}
		}
	}

	return true
}

func (rpcm *RacePairCoverageManager) determineLockStatus(a, b *AccessInfo) LockStatus {
	locksA := a.HeldLocks
	locksB := b.HeldLocks

	if len(locksA) == 0 && len(locksB) == 0 {
		return NoLocks
	}

	if len(locksA) == 0 || len(locksB) == 0 {
		return OneSidedLock
	}

	// Check for common locks
	lockPtrsA := make(map[uint64]bool)
	for _, lock := range locksA {
		lockPtrsA[lock.Ptr] = true
	}

	for _, lock := range locksB {
		if lockPtrsA[lock.Ptr] {
			return SyncWithCommonLock
		}
	}

	return UnsyncLocks
}

func (rpcm *RacePairCoverageManager) orderAccesses(a, b *AccessInfo) (*AccessInfo, *AccessInfo) {
	if a.AccessTime <= b.AccessTime {
		return a, b
	}
	return b, a
}

// GetCoverageSignal returns the current coverage signal count
func (rpcm *RacePairCoverageManager) GetCoverageSignal() uint64 {
	rpcm.mu.RLock()
	defer rpcm.mu.RUnlock()
	return rpcm.totalSignal
}

// GetNewSignalSinceLastCheck returns new signal count and resets the counter
func (rpcm *RacePairCoverageManager) GetNewSignalSinceLastCheck() uint64 {
	rpcm.mu.Lock()
	defer rpcm.mu.Unlock()

	newSignal := rpcm.newPairsSinceLastCheck
	rpcm.newPairsSinceLastCheck = 0
	rpcm.lastSignalTime = time.Now()
	return newSignal
}

// GetRecentRacePairs returns recently discovered race pairs (within the last minute)
func (rpcm *RacePairCoverageManager) GetRecentRacePairs() []*RacePair {
	rpcm.mu.RLock()
	defer rpcm.mu.RUnlock()

	var recentPairs []*RacePair
	cutoffTime := time.Now().Add(-1 * time.Minute) // Last minute

	for _, pair := range rpcm.racePairs {
		if pair.LastSeen.After(cutoffTime) {
			recentPairs = append(recentPairs, pair)
		}
	}

	return recentPairs
}

// GetStatistics returns coverage statistics
func (rpcm *RacePairCoverageManager) GetStatistics() map[string]interface{} {
	rpcm.mu.RLock()
	defer rpcm.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_race_pairs"] = len(rpcm.racePairs)
	stats["total_signal"] = rpcm.totalSignal
	stats["enabled"] = rpcm.enabled

	// Lock status breakdown
	lockStats := make(map[string]int)
	for status, count := range rpcm.lockStatusStats {
		lockStats[status.String()] = count
	}
	stats["lock_status_stats"] = lockStats

	return stats
}

// GetRacePairsByLockStatus returns race pairs filtered by lock status
func (rpcm *RacePairCoverageManager) GetRacePairsByLockStatus(status LockStatus) []*RacePair {
	rpcm.mu.RLock()
	defer rpcm.mu.RUnlock()

	var result []*RacePair
	for _, pair := range rpcm.racePairs {
		if pair.LockStatus == status {
			result = append(result, pair)
		}
	}
	return result
}

// GetAllRacePairs returns all discovered race pairs
func (rpcm *RacePairCoverageManager) GetAllRacePairs() []*RacePair {
	rpcm.mu.RLock()
	defer rpcm.mu.RUnlock()

	var result []*RacePair
	for _, pair := range rpcm.racePairs {
		result = append(result, pair)
	}
	return result
}

// Clear removes all race pairs (useful for testing)
func (rpcm *RacePairCoverageManager) Clear() {
	rpcm.mu.Lock()
	defer rpcm.mu.Unlock()

	rpcm.racePairs = make(map[RaceKey]*RacePair)
	rpcm.lockStatusStats = make(map[LockStatus]int)
	rpcm.totalSignal = 0
	rpcm.newPairsSinceLastCheck = 0
}

// ===============DDRD====================
