// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ddrd

import (
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
// Core UAF Coverage Data Structures
// ============================================================================

// UAFPairID generates a unique identifier for a UAF pair
// Uses the executor-generated signal as the primary identifier when available
// And use the hash of all relevant fields if the signal is unavailable
func (uaf *MayUAFPair) UAFPairID() uint64 {
	// If executor provided a signal (based on access names + callstack hashes), use it
	if uaf.Signal != 0 {
		return uaf.Signal
	}
	return 0
}

// String returns a human-readable representation of the UAF pair
func (uaf *MayUAFPair) String() string {
	return fmt.Sprintf("UAFPair{lock=%d, accesses=0x%x->0x%x, type=%d, signal=0x%x, stacks=0x%x,0x%x, timediff=%dns, sn=%d->%d}",
		uaf.LockType, uaf.FreeAccessName, uaf.UseAccessName, uaf.UseAccessType,
		uaf.Signal, uaf.FreeCallStack, uaf.UseCallStack, uaf.TimeDiff, uaf.FreeSN, uaf.UseSN)
}

// UAFCover maintains coverage of detected UAF pairs
// Similar to normal coverage but for use-after-free conditions
type UAFCover map[uint64]*MayUAFPair

// Merge adds new UAF pairs to the coverage
func (uc *UAFCover) Merge(uafPairs []*MayUAFPair) {
	c := *uc
	if c == nil {
		c = make(UAFCover)
		*uc = c
	}
	for _, uaf := range uafPairs {
		id := uaf.UAFPairID()
		c[id] = uaf
	}
}

// MergeDiff adds new UAF pairs and returns newly discovered UAF pairs
func (uc *UAFCover) MergeDiff(uafPairs []*MayUAFPair) []*MayUAFPair {
	c := *uc
	if c == nil {
		c = make(UAFCover)
		*uc = c
	}

	var newUAFs []*MayUAFPair
	for _, uaf := range uafPairs {
		id := uaf.UAFPairID()
		if _, exists := c[id]; !exists {
			c[id] = uaf
			newUAFs = append(newUAFs, uaf)
		}
	}
	return newUAFs
}

// Serialize returns all UAF pairs as a slice
func (uc UAFCover) Serialize() []*MayUAFPair {
	result := make([]*MayUAFPair, 0, len(uc))
	for _, uaf := range uc {
		result = append(result, uaf)
	}

	// Sort for consistent output
	sort.Slice(result, func(i, j int) bool {
		return result[i].UAFPairID() < result[j].UAFPairID()
	})

	return result
}

// Len returns the number of unique UAF pairs covered
func (uc UAFCover) Len() int {
	return len(uc)
}

// Contains checks if a specific UAF pair is already covered
func (uc UAFCover) Contains(uaf *MayUAFPair) bool {
	if uc == nil {
		return false
	}
	_, exists := uc[uaf.UAFPairID()]
	return exists
}

// GetByType returns all UAF pairs of a specific lock type
func (uc UAFCover) GetByType(lockType uint32) []*MayUAFPair {
	var result []*MayUAFPair
	for _, uaf := range uc {
		if uaf.LockType == lockType {
			result = append(result, uaf)
		}
	}
	return result
}

// GetByAccessType returns all UAF pairs of a specific access type
func (uc UAFCover) GetByAccessType(accessType uint32) []*MayUAFPair {
	var result []*MayUAFPair
	for _, uaf := range uc {
		if uaf.UseAccessType == accessType {
			result = append(result, uaf)
		}
	}
	return result
}

// GetByTimeDiffRange returns UAF pairs within a specific time difference range
func (uc UAFCover) GetByTimeDiffRange(minNanos, maxNanos uint64) []*MayUAFPair {
	var result []*MayUAFPair
	for _, uaf := range uc {
		if uaf.TimeDiff >= minNanos && uaf.TimeDiff <= maxNanos {
			result = append(result, uaf)
		}
	}
	return result
}

// Clear removes all UAF pairs from coverage
func (uc *UAFCover) Clear() {
	*uc = make(UAFCover)
}

// Copy creates a deep copy of the UAF coverage
func (uc UAFCover) Copy() UAFCover {
	if uc == nil {
		return nil
	}

	result := make(UAFCover, len(uc))
	for id, uaf := range uc {
		// Create a copy of the UAF pair
		newUAF := &MayUAFPair{
			FreeAccessName: uaf.FreeAccessName,
			UseAccessName:  uaf.UseAccessName,
			FreeCallStack:  uaf.FreeCallStack,
			UseCallStack:   uaf.UseCallStack,
			Signal:         uaf.Signal,
			TimeDiff:       uaf.TimeDiff,
			FreeSN:         uaf.FreeSN,
			UseSN:          uaf.UseSN,
			LockType:       uaf.LockType,
			UseAccessType:  uaf.UseAccessType,
		}
		result[id] = newUAF
	}

	return result
}

// ============================================================================
// UAF Coverage Statistics
// ============================================================================

// UAFCoverageStats returns statistics about the UAF coverage
type UAFCoverageStats struct {
	TotalUAFPairs       int
	UniqueAccesses      int
	LockTypeBreakdown   map[uint32]int
	AccessTypeBreakdown map[uint32]int
	TimeDiffStats       TimeDiffStats
}

// TimeDiffStats contains statistics about time differences in UAF pairs
type TimeDiffStats struct {
	MinTimeDiff    uint64
	MaxTimeDiff    uint64
	AvgTimeDiff    uint64
	MedianTimeDiff uint64
}

// GetStats returns detailed statistics about the UAF coverage
func (uc UAFCover) GetStats() UAFCoverageStats {
	stats := UAFCoverageStats{
		TotalUAFPairs:       len(uc),
		LockTypeBreakdown:   make(map[uint32]int),
		AccessTypeBreakdown: make(map[uint32]int),
	}

	accessSet := make(map[uint64]struct{})
	var timeDiffs []uint64

	for _, uaf := range uc {
		// Count unique accesses
		if uaf.FreeAccessName != 0 {
			accessSet[uaf.FreeAccessName] = struct{}{}
		}
		if uaf.UseAccessName != 0 {
			accessSet[uaf.UseAccessName] = struct{}{}
		}

		// Count lock types
		stats.LockTypeBreakdown[uaf.LockType]++

		// Count access types
		stats.AccessTypeBreakdown[uaf.UseAccessType]++

		// Collect time differences
		timeDiffs = append(timeDiffs, uaf.TimeDiff)
	}

	stats.UniqueAccesses = len(accessSet)

	// Calculate time diff statistics
	if len(timeDiffs) > 0 {
		sort.Slice(timeDiffs, func(i, j int) bool { return timeDiffs[i] < timeDiffs[j] })

		stats.TimeDiffStats.MinTimeDiff = timeDiffs[0]
		stats.TimeDiffStats.MaxTimeDiff = timeDiffs[len(timeDiffs)-1]
		stats.TimeDiffStats.MedianTimeDiff = timeDiffs[len(timeDiffs)/2]

		var sum uint64
		for _, td := range timeDiffs {
			sum += td
		}
		stats.TimeDiffStats.AvgTimeDiff = sum / uint64(len(timeDiffs))
	}

	return stats
}

// ============================================================================
// UAF Coverage Persistence
// ============================================================================

// UAFCoverageRecord represents a serializable UAF coverage record
type UAFCoverageRecord struct {
	Version    string                 `json:"version"`
	Timestamp  time.Time              `json:"timestamp"`
	TotalPairs int                    `json:"total_pairs"`
	Pairs      map[string]*MayUAFPair `json:"pairs"`
	Stats      UAFCoverageStats       `json:"stats"`
}

// SaveToFile persists the UAF coverage to a file
func (uc UAFCover) SaveToFile(filePath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Create the record
	record := UAFCoverageRecord{
		Version:    "1.0",
		Timestamp:  time.Now(),
		TotalPairs: len(uc),
		Pairs:      make(map[string]*MayUAFPair),
		Stats:      uc.GetStats(),
	}

	// Convert UAF pairs to string keys for JSON serialization
	for id, uaf := range uc {
		key := fmt.Sprintf("%016x", id)
		record.Pairs[key] = uaf
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
		return fmt.Errorf("failed to encode UAF coverage: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, filePath); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// LoadUAFCoverFromFile loads UAF coverage from a file
func LoadUAFCoverFromFile(filePath string) (UAFCover, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return make(UAFCover), nil // Return empty coverage if file doesn't exist
		}
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	var record UAFCoverageRecord
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("failed to decode UAF coverage: %w", err)
	}

	// Convert string keys back to uint64 IDs
	coverage := make(UAFCover)
	for key, uaf := range record.Pairs {
		var id uint64
		if _, err := fmt.Sscanf(key, "%016x", &id); err != nil {
			return nil, fmt.Errorf("failed to parse UAF pair ID %s: %w", key, err)
		}
		coverage[id] = uaf
	}

	return coverage, nil
}

// Export exports UAF coverage to a writer in the specified format
func (uc UAFCover) Export(writer io.Writer, format string) error {
	switch format {
	case "json":
		return uc.exportJSON(writer)
	case "csv":
		return uc.exportCSV(writer)
	case "text":
		return uc.exportText(writer)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

// exportJSON exports coverage in JSON format
func (uc UAFCover) exportJSON(writer io.Writer) error {
	record := UAFCoverageRecord{
		Version:    "1.0",
		Timestamp:  time.Now(),
		TotalPairs: len(uc),
		Pairs:      make(map[string]*MayUAFPair),
		Stats:      uc.GetStats(),
	}

	for id, uaf := range uc {
		key := fmt.Sprintf("%016x", id)
		record.Pairs[key] = uaf
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(record)
}

// exportCSV exports coverage in CSV format
func (uc UAFCover) exportCSV(writer io.Writer) error {
	// CSV header
	fmt.Fprintln(writer, "ID,FreeAccessName,UseAccessName,FreeCallStack,UseCallStack,Signal,TimeDiff,FreeSN,UseSN,LockType,UseAccessType")

	// Sort pairs by ID for consistent output
	pairs := uc.Serialize()
	for _, uaf := range pairs {
		fmt.Fprintf(writer, "%016x,%016x,%016x,%016x,%016x,%016x,%d,%d,%d,%d,%d\n",
			uaf.UAFPairID(), uaf.FreeAccessName, uaf.UseAccessName, uaf.FreeCallStack, uaf.UseCallStack,
			uaf.Signal, uaf.TimeDiff, uaf.FreeSN, uaf.UseSN, uaf.LockType, uaf.UseAccessType)
	}

	return nil
}

// exportText exports coverage in human-readable text format
func (uc UAFCover) exportText(writer io.Writer) error {
	stats := uc.GetStats()

	fmt.Fprintf(writer, "UAF Coverage Report\n")
	fmt.Fprintf(writer, "==================\n")
	fmt.Fprintf(writer, "Total UAF Pairs: %d\n", stats.TotalUAFPairs)
	fmt.Fprintf(writer, "Unique Accesses: %d\n", stats.UniqueAccesses)

	fmt.Fprintf(writer, "\nTime Difference Statistics:\n")
	fmt.Fprintf(writer, "  Min: %d ns\n", stats.TimeDiffStats.MinTimeDiff)
	fmt.Fprintf(writer, "  Max: %d ns\n", stats.TimeDiffStats.MaxTimeDiff)
	fmt.Fprintf(writer, "  Avg: %d ns\n", stats.TimeDiffStats.AvgTimeDiff)
	fmt.Fprintf(writer, "  Median: %d ns\n", stats.TimeDiffStats.MedianTimeDiff)

	fmt.Fprintf(writer, "\nLock Type Breakdown:\n")
	for lockType, count := range stats.LockTypeBreakdown {
		fmt.Fprintf(writer, "  Type %d: %d pairs\n", lockType, count)
	}

	fmt.Fprintf(writer, "\nAccess Type Breakdown:\n")
	for accessType, count := range stats.AccessTypeBreakdown {
		accessTypeStr := "read"
		if accessType == 1 {
			accessTypeStr = "write"
		}
		fmt.Fprintf(writer, "  %s (%d): %d pairs\n", accessTypeStr, accessType, count)
	}

	fmt.Fprintf(writer, "\nUAF Pairs:\n")
	fmt.Fprintf(writer, "==========\n")

	pairs := uc.Serialize()
	for i, uaf := range pairs {
		fmt.Fprintf(writer, "%d. %s\n", i+1, uaf.String())
	}

	return nil
}

// ============================================================================
// Persistent Storage
// ============================================================================

// UAFCoverageDB manages persistent storage of UAF coverage
type UAFCoverageDB struct {
	mu       sync.RWMutex
	coverage UAFCover
	filePath string
	dirty    bool
	lastSave time.Time
}

// NewUAFCoverageDB creates a new UAF coverage database
func NewUAFCoverageDB(filePath string) *UAFCoverageDB {
	db := &UAFCoverageDB{
		coverage: make(UAFCover),
		filePath: filePath,
		lastSave: time.Now(),
	}

	// Try to load existing data
	if err := db.Load(); err != nil {
		// Log error but continue with empty coverage
		fmt.Printf("Warning: Failed to load UAF coverage from %s: %v\n", filePath, err)
	}

	return db
}

// Save persists the UAF coverage to disk
func (db *UAFCoverageDB) Save() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if !db.dirty {
		return nil // No changes to save
	}

	if err := db.coverage.SaveToFile(db.filePath); err != nil {
		return err
	}

	db.dirty = false
	db.lastSave = time.Now()
	return nil
}

// Load reads the UAF coverage from disk
func (db *UAFCoverageDB) Load() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	coverage, err := LoadUAFCoverFromFile(db.filePath)
	if err != nil {
		return err
	}

	db.coverage = coverage
	db.dirty = false
	return nil
}

// AddUAFPairs adds new UAF pairs and returns newly discovered ones
func (db *UAFCoverageDB) AddUAFPairs(pairs []*MayUAFPair) []*MayUAFPair {
	db.mu.Lock()
	defer db.mu.Unlock()

	var newPairs []*MayUAFPair
	for _, uaf := range pairs {
		id := uaf.UAFPairID()
		if _, exists := db.coverage[id]; !exists {
			db.coverage[id] = uaf
			newPairs = append(newPairs, uaf)
			db.dirty = true
		}
	}

	return newPairs
}

// GetCoverage returns a copy of the current coverage
func (db *UAFCoverageDB) GetCoverage() UAFCover {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.coverage.Copy()
}

// GetStats returns current coverage statistics
func (db *UAFCoverageDB) GetStats() UAFCoverageStats {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.coverage.GetStats()
}

// Len returns the number of unique UAF pairs
func (db *UAFCoverageDB) Len() int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return len(db.coverage)
}

// AutoSave starts a goroutine that periodically saves the coverage
func (db *UAFCoverageDB) AutoSave(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			if err := db.Save(); err != nil {
				fmt.Printf("Error auto-saving UAF coverage: %v\n", err)
			}
		}
	}()
}

// Export exports UAF coverage to a different format
func (db *UAFCoverageDB) Export(writer io.Writer, format string) error {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.coverage.Export(writer, format)
}

// Close saves the coverage and releases resources
func (db *UAFCoverageDB) Close() error {
	return db.Save()
}
