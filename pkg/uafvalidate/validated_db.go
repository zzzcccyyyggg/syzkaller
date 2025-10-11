// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package uafvalidate

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
)

// ValidatedRecord represents a record of a validated race pair
type ValidatedRecord struct {
	PairID          uint64    `json:"pair_id"`
	ValidationTime  time.Time `json:"validation_time"`
	IsValid         bool      `json:"is_valid"`         // true if the race was successfully validated
	ValidationCount int       `json:"validation_count"` // number of times this pair was validated
	LastError       string    `json:"last_error"`       // last validation error if any
	OriginalSource  string    `json:"original_source"`  // which fuzzer originally found this race
}

// ValidatedDB manages the database of validated race pairs
type ValidatedDB struct {
	db   *db.DB
	path string
}

// OpenValidatedDB opens or creates the race validation database
func OpenValidatedDB(workdir string) (*ValidatedDB, error) {
	dbPath := filepath.Join(workdir, "race_validated.db")

	database, err := db.Open(dbPath, true) // repair if corrupted
	if err != nil {
		return nil, fmt.Errorf("failed to open validated race database: %v", err)
	}

	vdb := &ValidatedDB{
		db:   database,
		path: dbPath,
	}

	log.Logf(1, "Opened race validation database: %s (%d existing records)",
		dbPath, len(database.Records))

	return vdb, nil
}

// IsValidated checks if a race pair has been validated
func (vdb *ValidatedDB) IsValidated(pairID uint64) bool {
	key := formatPairID(pairID)
	_, exists := vdb.db.Records[key]
	return exists
}

// GetValidatedRecord retrieves the validation record for a race pair
func (vdb *ValidatedDB) GetValidatedRecord(pairID uint64) (*ValidatedRecord, error) {
	key := formatPairID(pairID)
	record, exists := vdb.db.Records[key]
	if !exists {
		return nil, fmt.Errorf("validation record not found for pair %x", pairID)
	}

	var vRecord ValidatedRecord
	if err := json.Unmarshal(record.Val, &vRecord); err != nil {
		return nil, fmt.Errorf("failed to unmarshal validation record: %v", err)
	}

	return &vRecord, nil
}

// MarkAsValidated records a successful validation
func (vdb *ValidatedDB) MarkAsValidated(pairID uint64, originalSource string) error {
	return vdb.recordValidation(pairID, true, "", originalSource)
}

// MarkAsInvalid records a failed validation
func (vdb *ValidatedDB) MarkAsInvalid(pairID uint64, validationError string, originalSource string) error {
	return vdb.recordValidation(pairID, false, validationError, originalSource)
}

// recordValidation records the validation result
func (vdb *ValidatedDB) recordValidation(pairID uint64, isValid bool, validationError string, originalSource string) error {
	key := formatPairID(pairID)
	now := time.Now()

	var vRecord ValidatedRecord

	// Check if record already exists
	if existingRecord, exists := vdb.db.Records[key]; exists {
		// Update existing record
		if err := json.Unmarshal(existingRecord.Val, &vRecord); err != nil {
			log.Logf(0, "Failed to unmarshal existing validation record for %x, creating new: %v", pairID, err)
			vRecord = ValidatedRecord{}
		}
		vRecord.ValidationCount++
	} else {
		// Create new record
		vRecord = ValidatedRecord{
			ValidationCount: 1,
		}
	}

	// Update record fields
	vRecord.PairID = pairID
	vRecord.ValidationTime = now
	vRecord.IsValid = isValid
	vRecord.LastError = validationError
	if vRecord.OriginalSource == "" {
		vRecord.OriginalSource = originalSource
	}

	// Serialize and save
	data, err := json.Marshal(vRecord)
	if err != nil {
		return fmt.Errorf("failed to marshal validation record: %v", err)
	}

	vdb.db.Save(key, data, 0)

	// Immediately flush to disk for persistence
	if err := vdb.db.Flush(); err != nil {
		return fmt.Errorf("failed to flush validation record to disk: %v", err)
	}

	log.Logf(2, "Recorded validation result for pair %x: valid=%v, count=%d (persisted to disk)",
		pairID, isValid, vRecord.ValidationCount)

	return nil
}

// GetUnvalidatedPairs returns a list of pair IDs from corpus that haven't been validated
func (vdb *ValidatedDB) GetUnvalidatedPairs(corpusDB *db.DB) []uint64 {
	var unvalidated []uint64

	for key := range corpusDB.Records {
		// Parse the corpus key (should be hex format)
		pairID, err := strconv.ParseUint(key, 16, 64)
		if err != nil {
			log.Logf(1, "Skipping invalid corpus key format: %s", key)
			continue
		}

		// Check if already validated
		if !vdb.IsValidated(pairID) {
			unvalidated = append(unvalidated, pairID)
		}
	}

	log.Logf(1, "Found %d unvalidated race pairs out of %d total corpus items",
		len(unvalidated), len(corpusDB.Records))

	return unvalidated
}

// GetValidationStats returns statistics about validated pairs
func (vdb *ValidatedDB) GetValidationStats() (total, valid, invalid int, err error) {
	for _, record := range vdb.db.Records {
		var vRecord ValidatedRecord
		if err := json.Unmarshal(record.Val, &vRecord); err != nil {
			log.Logf(1, "Failed to unmarshal validation record, skipping: %v", err)
			continue
		}

		total++
		if vRecord.IsValid {
			valid++
		} else {
			invalid++
		}
	}

	return total, valid, invalid, nil
}

// Flush ensures all pending data is written to disk
func (vdb *ValidatedDB) Flush() error {
	return vdb.db.Flush()
}

// Close closes the validation database
func (vdb *ValidatedDB) Close() error {
	if err := vdb.db.Flush(); err != nil {
		log.Logf(0, "Failed to flush validation database before closing: %v", err)
	}
	// Note: db.DB doesn't have a Close method, just ensure it's flushed
	return nil
}

// formatPairID formats a pair ID as a hex string key
func formatPairID(pairID uint64) string {
	return fmt.Sprintf("%016x", pairID)
}

// GetRecentlyValidated returns pairs validated in the last duration
func (vdb *ValidatedDB) GetRecentlyValidated(since time.Duration) []uint64 {
	var recent []uint64
	cutoff := time.Now().Add(-since)

	for _, record := range vdb.db.Records {
		var vRecord ValidatedRecord
		if err := json.Unmarshal(record.Val, &vRecord); err != nil {
			continue
		}

		if vRecord.ValidationTime.After(cutoff) {
			recent = append(recent, vRecord.PairID)
		}
	}

	return recent
}
