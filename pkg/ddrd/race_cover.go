// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ddrd

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ============================================================================
// Core Race Coverage Data Structures
// ============================================================================

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

	// Include access types and lock type (convert uint32 to bytes)
	binary.LittleEndian.PutUint32(buf[:4], rp.AccessType1)
	h.Write(buf[:4])
	binary.LittleEndian.PutUint32(buf[:4], rp.AccessType2)
	h.Write(buf[:4])
	binary.LittleEndian.PutUint32(buf[:4], rp.LockType)
	h.Write(buf[:4])

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
func (rc RaceCover) GetByType(lockType uint32) []*MayRacePair {
	var result []*MayRacePair
	for _, rp := range rc {
		if rp.LockType == lockType {
			result = append(result, rp)
		}
	}
	return result
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
			Sn1:         rp.Sn1,
			Sn2:         rp.Sn2,
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

// ============================================================================
// Race Coverage Statistics
// ============================================================================

// RaceCoverageStats returns statistics about the race coverage
type RaceCoverageStats struct {
	TotalRacePairs    int
	UniqueSyscalls    int
	UniqueVariables   int
	LockTypeBreakdown map[uint32]int
}

// GetStats returns detailed statistics about the race coverage
func (rc RaceCover) GetStats() RaceCoverageStats {
	stats := RaceCoverageStats{
		TotalRacePairs:    len(rc),
		LockTypeBreakdown: make(map[uint32]int),
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

// ============================================================================
// Race Coverage Persistence
// ============================================================================

// RaceCoverageRecord represents a serializable race coverage record
type RaceCoverageRecord struct {
	Version    string                  `json:"version"`
	Timestamp  time.Time               `json:"timestamp"`
	TotalPairs int                     `json:"total_pairs"`
	Pairs      map[string]*MayRacePair `json:"pairs"`
	Stats      RaceCoverageStats       `json:"stats"`
}

// SaveToFile persists the race coverage to a file
func (rc RaceCover) SaveToFile(filePath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Create the record
	record := RaceCoverageRecord{
		Version:    "1.0",
		Timestamp:  time.Now(),
		TotalPairs: len(rc),
		Pairs:      make(map[string]*MayRacePair),
		Stats:      rc.GetStats(),
	}

	// Convert race pairs to string keys for JSON serialization
	for id, rp := range rc {
		key := fmt.Sprintf("%016x", id)
		record.Pairs[key] = rp
	}

	// Write to temporary file first
	tempPath := filePath + ".tmp"
	file, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create temp file %s: %w", tempPath, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(record); err != nil {
		return fmt.Errorf("failed to encode race coverage: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, filePath); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// LoadRaceCoverFromFile loads race coverage from a file
func LoadRaceCoverFromFile(filePath string) (RaceCover, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return make(RaceCover), nil // Return empty coverage if file doesn't exist
		}
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	var record RaceCoverageRecord
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("failed to decode race coverage: %w", err)
	}

	// Convert string keys back to uint64 IDs
	coverage := make(RaceCover)
	for key, rp := range record.Pairs {
		var id uint64
		if _, err := fmt.Sscanf(key, "%016x", &id); err != nil {
			return nil, fmt.Errorf("failed to parse race pair ID %s: %w", key, err)
		}
		coverage[id] = rp
	}

	return coverage, nil
}

// Export exports race coverage to a writer in the specified format
func (rc RaceCover) Export(writer io.Writer, format string) error {
	switch format {
	case "json":
		return rc.exportJSON(writer)
	case "csv":
		return rc.exportCSV(writer)
	case "text":
		return rc.exportText(writer)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

// exportJSON exports coverage in JSON format
func (rc RaceCover) exportJSON(writer io.Writer) error {
	record := RaceCoverageRecord{
		Version:    "1.0",
		Timestamp:  time.Now(),
		TotalPairs: len(rc),
		Pairs:      make(map[string]*MayRacePair),
		Stats:      rc.GetStats(),
	}

	for id, rp := range rc {
		key := fmt.Sprintf("%016x", id)
		record.Pairs[key] = rp
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(record)
}

// exportCSV exports coverage in CSV format
func (rc RaceCover) exportCSV(writer io.Writer) error {
	// CSV header
	fmt.Fprintln(writer, "ID,Syscall1Idx,Syscall2Idx,Syscall1Num,Syscall2Num,VarName1,VarName2,CallStack1,CallStack2,Sn1,Sn2,Signal,LockType,AccessType1,AccessType2,TimeDiff")

	// Sort pairs by ID for consistent output
	pairs := rc.Serialize()
	for _, rp := range pairs {
		fmt.Fprintf(writer, "%016x,%d,%d,%d,%d,%016x,%016x,%016x,%016x,%d,%d,%016x,%d,%d,%d,%d\n",
			rp.RacePairID(), rp.Syscall1Idx, rp.Syscall2Idx, rp.Syscall1Num, rp.Syscall2Num,
			rp.VarName1, rp.VarName2, rp.CallStack1, rp.CallStack2,
			rp.Sn1, rp.Sn2, rp.Signal, rp.LockType, rp.AccessType1, rp.AccessType2, rp.TimeDiff)
	}

	return nil
}

// exportText exports coverage in human-readable text format
func (rc RaceCover) exportText(writer io.Writer) error {
	stats := rc.GetStats()

	fmt.Fprintf(writer, "Race Coverage Report\n")
	fmt.Fprintf(writer, "===================\n")
	fmt.Fprintf(writer, "Total Race Pairs: %d\n", stats.TotalRacePairs)
	fmt.Fprintf(writer, "Unique Syscalls: %d\n", stats.UniqueSyscalls)
	fmt.Fprintf(writer, "Unique Variables: %d\n", stats.UniqueVariables)
	fmt.Fprintf(writer, "\nLock Type Breakdown:\n")

	for lockType, count := range stats.LockTypeBreakdown {
		fmt.Fprintf(writer, "  Type %d: %d pairs\n", lockType, count)
	}

	fmt.Fprintf(writer, "\nRace Pairs:\n")
	fmt.Fprintf(writer, "===========\n")

	pairs := rc.Serialize()
	for i, rp := range pairs {
		fmt.Fprintf(writer, "%d. %s\n", i+1, rp.String())
	}

	return nil
}

// ============================================================================
// Persistent Storage
// ============================================================================

// RaceCoverageDB manages persistent storage of race coverage
type RaceCoverageDB struct {
	mu       sync.RWMutex
	coverage RaceCover
	filePath string
	dirty    bool
	lastSave time.Time
}

// NewRaceCoverageDB creates a new race coverage database
func NewRaceCoverageDB(filePath string) *RaceCoverageDB {
	db := &RaceCoverageDB{
		coverage: make(RaceCover),
		filePath: filePath,
		lastSave: time.Now(),
	}

	// Try to load existing data
	if err := db.Load(); err != nil {
		// Log error but continue with empty coverage
		fmt.Printf("Warning: Failed to load race coverage from %s: %v\n", filePath, err)
	}

	return db
}

// Save persists the race coverage to disk
func (db *RaceCoverageDB) Save() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if !db.dirty {
		return nil // No changes to save
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(db.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Create the record
	record := RaceCoverageRecord{
		Version:    "1.0",
		Timestamp:  time.Now(),
		TotalPairs: len(db.coverage),
		Pairs:      make(map[string]*MayRacePair),
		Stats:      db.coverage.GetStats(),
	}

	// Convert race pairs to string keys for JSON serialization
	for id, rp := range db.coverage {
		key := fmt.Sprintf("%016x", id)
		record.Pairs[key] = rp
	}

	// Write to temporary file first
	tempPath := db.filePath + ".tmp"
	file, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create temp file %s: %w", tempPath, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(record); err != nil {
		return fmt.Errorf("failed to encode race coverage: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, db.filePath); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	db.dirty = false
	db.lastSave = time.Now()
	return nil
}

// Load reads the race coverage from disk
func (db *RaceCoverageDB) Load() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	file, err := os.Open(db.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist yet, start with empty coverage
		}
		return fmt.Errorf("failed to open file %s: %w", db.filePath, err)
	}
	defer file.Close()

	var record RaceCoverageRecord
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&record); err != nil {
		return fmt.Errorf("failed to decode race coverage: %w", err)
	}

	// Convert string keys back to uint64 IDs
	db.coverage = make(RaceCover)
	for key, rp := range record.Pairs {
		var id uint64
		if _, err := fmt.Sscanf(key, "%016x", &id); err != nil {
			return fmt.Errorf("failed to parse race pair ID %s: %w", key, err)
		}
		db.coverage[id] = rp
	}

	db.dirty = false
	return nil
}

// AddRacePairs adds new race pairs and returns newly discovered ones
func (db *RaceCoverageDB) AddRacePairs(pairs []*MayRacePair) []*MayRacePair {
	db.mu.Lock()
	defer db.mu.Unlock()

	var newPairs []*MayRacePair
	for _, rp := range pairs {
		id := rp.RacePairID()
		if _, exists := db.coverage[id]; !exists {
			db.coverage[id] = rp
			newPairs = append(newPairs, rp)
			db.dirty = true
		}
	}

	return newPairs
}

// GetCoverage returns a copy of the current coverage
func (db *RaceCoverageDB) GetCoverage() RaceCover {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.coverage.Copy()
}

// GetStats returns current coverage statistics
func (db *RaceCoverageDB) GetStats() RaceCoverageStats {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.coverage.GetStats()
}

// Len returns the number of unique race pairs
func (db *RaceCoverageDB) Len() int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return len(db.coverage)
}

// AutoSave starts a goroutine that periodically saves the coverage
func (db *RaceCoverageDB) AutoSave(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			if err := db.Save(); err != nil {
				fmt.Printf("Error auto-saving race coverage: %v\n", err)
			}
		}
	}()
}

// Export exports race coverage to a different format
func (db *RaceCoverageDB) Export(writer io.Writer, format string) error {
	db.mu.RLock()
	defer db.mu.RUnlock()

	switch format {
	case "json":
		return db.exportJSON(writer)
	case "csv":
		return db.exportCSV(writer)
	case "text":
		return db.exportText(writer)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

// exportJSON exports coverage in JSON format
func (db *RaceCoverageDB) exportJSON(writer io.Writer) error {
	record := RaceCoverageRecord{
		Version:    "1.0",
		Timestamp:  time.Now(),
		TotalPairs: len(db.coverage),
		Pairs:      make(map[string]*MayRacePair),
		Stats:      db.coverage.GetStats(),
	}

	for id, rp := range db.coverage {
		key := fmt.Sprintf("%016x", id)
		record.Pairs[key] = rp
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(record)
}

// exportCSV exports coverage in CSV format
func (db *RaceCoverageDB) exportCSV(writer io.Writer) error {
	// CSV header
	fmt.Fprintln(writer, "ID,Syscall1Idx,Syscall2Idx,Syscall1Num,Syscall2Num,VarName1,VarName2,CallStack1,CallStack2,Sn1,Sn2,Signal,LockType,AccessType1,AccessType2,TimeDiff")

	// Sort pairs by ID for consistent output
	pairs := db.coverage.Serialize()
	for _, rp := range pairs {
		fmt.Fprintf(writer, "%016x,%d,%d,%d,%d,%016x,%016x,%016x,%016x,%d,%d,%016x,%d,%d,%d,%d\n",
			rp.RacePairID(), rp.Syscall1Idx, rp.Syscall2Idx, rp.Syscall1Num, rp.Syscall2Num,
			rp.VarName1, rp.VarName2, rp.CallStack1, rp.CallStack2,
			rp.Sn1, rp.Sn2, rp.Signal, rp.LockType, rp.AccessType1, rp.AccessType2, rp.TimeDiff)
	}

	return nil
}

// exportText exports coverage in human-readable text format
func (db *RaceCoverageDB) exportText(writer io.Writer) error {
	stats := db.coverage.GetStats()

	fmt.Fprintf(writer, "Race Coverage Report\n")
	fmt.Fprintf(writer, "===================\n")
	fmt.Fprintf(writer, "Total Race Pairs: %d\n", stats.TotalRacePairs)
	fmt.Fprintf(writer, "Unique Syscalls: %d\n", stats.UniqueSyscalls)
	fmt.Fprintf(writer, "Unique Variables: %d\n", stats.UniqueVariables)
	fmt.Fprintf(writer, "\nLock Type Breakdown:\n")

	for lockType, count := range stats.LockTypeBreakdown {
		fmt.Fprintf(writer, "  Type %d: %d pairs\n", lockType, count)
	}

	fmt.Fprintf(writer, "\nRace Pairs:\n")
	fmt.Fprintf(writer, "===========\n")

	pairs := db.coverage.Serialize()
	for i, rp := range pairs {
		fmt.Fprintf(writer, "%d. %s\n", i+1, rp.String())
	}

	return nil
}

// Close saves the coverage and releases resources
func (db *RaceCoverageDB) Close() error {
	return db.Save()
}
