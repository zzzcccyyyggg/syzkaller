// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package uafvalidate

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/log"
)

// Bayesian model parameters for Happens-Before confidence estimation
const (
	alphaPrior      = 0.5  // Beta distribution prior α (Jeffrey's prior)
	betaPrior       = 0.5  // Beta distribution prior β
	successWeight   = 2.0  // Success weight (success is stronger counter-evidence)
	noiseRate       = 0.15 // Assume 15% of failures are noise (non-HB reasons)
	explorationRate = 0.05 // Minimum 5% verification probability
	maxSkipProb     = 0.90 // Maximum 90% skip probability
)

// VarNamePairKey creates a key from FreeAccessName and UseAccessName only (no CallStack)
func VarNamePairKey(pair *ddrd.MayUAFPair) string {
	if pair == nil {
		return ""
	}
	return fmt.Sprintf("%016x-%016x", pair.FreeAccessName, pair.UseAccessName)
}

// VarNameHBStats records Happens-Before statistics for a VarNamePair
type VarNameHBStats struct {
	FreeAccessName uint64    `json:"free_access_name"`
	UseAccessName  uint64    `json:"use_access_name"`
	Failures       int       `json:"failures"`       // Verification failure count (TriggeredCount=0)
	Successes      int       `json:"successes"`      // Verification success count (TriggeredCount>0)
	TotalAttempts  int       `json:"total_attempts"` // Total verification attempts
	LastAttempt    time.Time `json:"last_attempt"`   // Last verification time
	LastSuccess    time.Time `json:"last_success,omitempty"`
	Created        time.Time `json:"created"`
}

// HBConfidence calculates Happens-Before confidence (0.0 - 1.0)
// Uses asymmetric weighting + noise correction Bayesian model
func (s *VarNameHBStats) HBConfidence() float64 {
	if s.TotalAttempts == 0 {
		return 0.5 // Return uncertain when no data
	}

	// Only successes, no failures = definitely not HB
	if s.Successes > 0 && s.Failures == 0 {
		return 0.0
	}

	// Noise correction: some failures may be non-HB reasons
	effectiveFailures := float64(s.Failures) * (1.0 - noiseRate)

	// Higher weight for successes: success is stronger counter-evidence
	effectiveSuccesses := float64(s.Successes) * successWeight

	// Beta distribution posterior mean
	alpha := effectiveFailures + alphaPrior
	beta := effectiveSuccesses + betaPrior

	return alpha / (alpha + beta)
}

// SkipProbability calculates skip probability (0.0 - maxSkipProb)
func (s *VarNameHBStats) SkipProbability() float64 {
	// First attempt must verify
	if s.TotalAttempts == 0 {
		return 0.0
	}

	conf := s.HBConfidence()

	// Apply exploration factor: guarantee minimum verification probability
	skipProb := conf * (1.0 - explorationRate)

	// Limit maximum skip probability
	if skipProb > maxSkipProb {
		return maxSkipProb
	}

	return skipProb
}

// RecordFailure records a verification failure
func (s *VarNameHBStats) RecordFailure() {
	s.Failures++
	s.TotalAttempts++
	s.LastAttempt = time.Now()
}

// RecordSuccess records a verification success
func (s *VarNameHBStats) RecordSuccess() {
	s.Successes++
	s.TotalAttempts++
	now := time.Now()
	s.LastAttempt = now
	s.LastSuccess = now
}

// VarNameHBStore manages VarNamePair HB statistics storage
type VarNameHBStore struct {
	mu    sync.RWMutex
	db    *db.DB
	cache map[string]*VarNameHBStats
}

// NewVarNameHBStore creates a new HB statistics store
func NewVarNameHBStore(database *db.DB) *VarNameHBStore {
	store := &VarNameHBStore{
		db:    database,
		cache: make(map[string]*VarNameHBStats),
	}

	// Load existing data from DB into cache
	if database != nil {
		for key, rec := range database.Records {
			var stats VarNameHBStats
			if err := json.Unmarshal(rec.Val, &stats); err != nil {
				log.Logf(0, "varname_hb: failed to parse stats for %s: %v", key, err)
				continue
			}
			store.cache[key] = &stats
		}
		log.Logf(0, "varname_hb: loaded %d VarNamePair stats from db", len(store.cache))
	}

	return store
}

// Get retrieves statistics for a specified VarNamePair
func (s *VarNameHBStore) Get(key string) *VarNameHBStats {
	s.mu.RLock()
	stats, ok := s.cache[key]
	s.mu.RUnlock()

	if ok {
		return stats
	}

	// Return new empty statistics
	return &VarNameHBStats{
		Created: time.Now(),
	}
}

// GetByPair retrieves statistics via MayUAFPair
func (s *VarNameHBStore) GetByPair(pair *ddrd.MayUAFPair) *VarNameHBStats {
	if pair == nil {
		return &VarNameHBStats{Created: time.Now()}
	}

	key := VarNamePairKey(pair)
	stats := s.Get(key)

	// Fill in VarName info
	if stats.FreeAccessName == 0 {
		stats.FreeAccessName = pair.FreeAccessName
		stats.UseAccessName = pair.UseAccessName
	}

	return stats
}

// RecordFailure records verification failure
func (s *VarNameHBStore) RecordFailure(pair *ddrd.MayUAFPair) {
	if pair == nil {
		return
	}

	key := VarNamePairKey(pair)

	s.mu.Lock()
	defer s.mu.Unlock()

	stats, ok := s.cache[key]
	if !ok {
		stats = &VarNameHBStats{
			FreeAccessName: pair.FreeAccessName,
			UseAccessName:  pair.UseAccessName,
			Created:        time.Now(),
		}
		s.cache[key] = stats
	}

	stats.RecordFailure()
	s.saveLocked(key, stats)

	log.Logf(1, "varname_hb: recorded failure key=%s failures=%d successes=%d conf=%.2f",
		key, stats.Failures, stats.Successes, stats.HBConfidence())
}

// RecordSuccess records verification success
func (s *VarNameHBStore) RecordSuccess(pair *ddrd.MayUAFPair) {
	if pair == nil {
		return
	}

	key := VarNamePairKey(pair)

	s.mu.Lock()
	defer s.mu.Unlock()

	stats, ok := s.cache[key]
	if !ok {
		stats = &VarNameHBStats{
			FreeAccessName: pair.FreeAccessName,
			UseAccessName:  pair.UseAccessName,
			Created:        time.Now(),
		}
		s.cache[key] = stats
	}

	stats.RecordSuccess()
	s.saveLocked(key, stats)

	log.Logf(1, "varname_hb: recorded success key=%s failures=%d successes=%d conf=%.2f",
		key, stats.Failures, stats.Successes, stats.HBConfidence())
}

// ShouldSkip determines whether verification should be skipped
func (s *VarNameHBStore) ShouldSkip(pair *ddrd.MayUAFPair, randFloat func() float64) (skip bool, prob float64, stats *VarNameHBStats) {
	if pair == nil {
		return false, 0, nil
	}

	key := VarNamePairKey(pair)

	s.mu.RLock()
	cachedStats, ok := s.cache[key]
	s.mu.RUnlock()

	if !ok {
		// No history, must verify
		return false, 0, &VarNameHBStats{Created: time.Now()}
	}

	prob = cachedStats.SkipProbability()
	if prob <= 0 {
		return false, 0, cachedStats
	}

	// Probabilistic skip
	if randFloat() < prob {
		return true, prob, cachedStats
	}

	return false, prob, cachedStats
}

// Stats returns statistics summary
func (s *VarNameHBStore) Stats() (total, highConfidence int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total = len(s.cache)
	for _, stats := range s.cache {
		if stats.HBConfidence() >= 0.8 {
			highConfidence++
		}
	}
	return
}

func (s *VarNameHBStore) saveLocked(key string, stats *VarNameHBStats) {
	if s.db == nil {
		return
	}

	data, err := json.Marshal(stats)
	if err != nil {
		log.Logf(0, "varname_hb: failed to marshal stats: %v", err)
		return
	}

	s.db.Save(key, data, 0)
	if err := s.db.Flush(); err != nil {
		log.Logf(0, "varname_hb: failed to flush db: %v", err)
	}
}

// Close closes the store
func (s *VarNameHBStore) Close() error {
	// db.DB is managed externally, don't close here
	return nil
}
