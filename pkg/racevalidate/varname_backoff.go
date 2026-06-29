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

// Bayesian model parameters for validation backoff scoring.
const (
	alphaPrior      = 0.5  // Beta distribution prior α (Jeffrey's prior)
	betaPrior       = 0.5  // Beta distribution prior β
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

// VarNameBackoffStats records validation outcomes used to probabilistically
// back off repeated verification attempts for a VarName pair.
type VarNameBackoffStats struct {
	FreeAccessName uint64    `json:"free_access_name"`
	UseAccessName  uint64    `json:"use_access_name"`
	Failures       int       `json:"failures"`       // Non-triggering verification attempts (TriggeredCount=0)
	Successes      int       `json:"successes"`      // Triggering verification attempts (TriggeredCount>0)
	TotalAttempts  int       `json:"total_attempts"` // Total verification attempts
	LastAttempt    time.Time `json:"last_attempt"`   // Last verification time
	LastSuccess    time.Time `json:"last_success,omitempty"`
	Created        time.Time `json:"created"`

	// Verified indicates this VarName pair has been successfully validated
	// Once verified, all other entries with the same VarName pair can be skipped
	Verified    bool   `json:"verified"`
	VerifiedKey string `json:"verified_key,omitempty"` // The entry key that was successfully verified
}

// BackoffScore returns a smoothed score (0.0 - 1.0) describing how strongly
// past results suggest future verification attempts are likely to be low-yield.
// Successes are handled by the Verified flag (full skip); this formula only
// tracks failures, matching the paper formula exactly.
func (s *VarNameBackoffStats) BackoffScore() float64 {
	if s.TotalAttempts == 0 {
		return 0.5 // Neutral score when no data is available
	}

	// Beta distribution posterior mean: only failures count here.
	// Successful verification sets Verified=true and skips all future attempts.
	alpha := float64(s.Failures) + alphaPrior
	beta := betaPrior

	return alpha / (alpha + beta)
}

// SkipProbability converts the backoff score into a probabilistic skip rate.
func (s *VarNameBackoffStats) SkipProbability() float64 {
	// First attempt must verify
	if s.TotalAttempts == 0 {
		return 0.0
	}

	score := s.BackoffScore()

	// Apply exploration factor: guarantee minimum verification probability
	skipProb := score * (1.0 - explorationRate)

	// Limit maximum skip probability
	if skipProb > maxSkipProb {
		return maxSkipProb
	}

	return skipProb
}

// RecordFailure records a non-triggering verification attempt.
func (s *VarNameBackoffStats) RecordFailure() {
	s.Failures++
	s.TotalAttempts++
	s.LastAttempt = time.Now()
}

// RecordSuccess records a triggering verification attempt.
func (s *VarNameBackoffStats) RecordSuccess() {
	s.Successes++
	s.TotalAttempts++
	now := time.Now()
	s.LastAttempt = now
	s.LastSuccess = now
}

// MarkVerified marks this VarName pair as successfully verified
// Once verified, all other entries with the same VarName pair should be skipped
func (s *VarNameBackoffStats) MarkVerified(entryKey string) {
	s.Verified = true
	s.VerifiedKey = entryKey
}

// IsVerified returns true if this VarName pair has been verified
func (s *VarNameBackoffStats) IsVerified() bool {
	return s.Verified
}

// VarNameBackoffStore manages VarName pair backoff statistics storage.
type VarNameBackoffStore struct {
	mu    sync.RWMutex
	db    *db.DB
	cache map[string]*VarNameBackoffStats
}

// NewVarNameBackoffStore creates a new validation backoff statistics store.
func NewVarNameBackoffStore(database *db.DB) *VarNameBackoffStore {
	store := &VarNameBackoffStore{
		db:    database,
		cache: make(map[string]*VarNameBackoffStats),
	}

	// Load existing data from DB into cache
	if database != nil {
		for key, rec := range database.Records {
			var stats VarNameBackoffStats
			if err := json.Unmarshal(rec.Val, &stats); err != nil {
				log.Logf(0, "varname_backoff: failed to parse stats for %s: %v", key, err)
				continue
			}
			store.cache[key] = &stats
		}
		log.Logf(0, "varname_backoff: loaded %d VarNamePair stats from db", len(store.cache))
	}

	return store
}

// Get retrieves statistics for a specified VarNamePair
func (s *VarNameBackoffStore) Get(key string) *VarNameBackoffStats {
	s.mu.RLock()
	stats, ok := s.cache[key]
	s.mu.RUnlock()

	if ok {
		return stats
	}

	// Return new empty statistics
	return &VarNameBackoffStats{
		Created: time.Now(),
	}
}

// GetByPair retrieves statistics via MayUAFPair
func (s *VarNameBackoffStore) GetByPair(pair *ddrd.MayUAFPair) *VarNameBackoffStats {
	if pair == nil {
		return &VarNameBackoffStats{Created: time.Now()}
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

// RecordFailure records a non-triggering validation attempt.
func (s *VarNameBackoffStore) RecordFailure(pair *ddrd.MayUAFPair) {
	if pair == nil {
		return
	}

	key := VarNamePairKey(pair)

	s.mu.Lock()
	defer s.mu.Unlock()

	stats, ok := s.cache[key]
	if !ok {
		stats = &VarNameBackoffStats{
			FreeAccessName: pair.FreeAccessName,
			UseAccessName:  pair.UseAccessName,
			Created:        time.Now(),
		}
		s.cache[key] = stats
	}

	stats.RecordFailure()
	s.saveLocked(key, stats)

	log.Logf(1, "varname_backoff: recorded failure key=%s failures=%d successes=%d score=%.2f",
		key, stats.Failures, stats.Successes, stats.BackoffScore())
}

// RecordSuccess records verification success
func (s *VarNameBackoffStore) RecordSuccess(pair *ddrd.MayUAFPair) {
	s.RecordSuccessWithKey(pair, "")
}

// RecordSuccessWithKey records verification success and marks the VarName pair as verified
// entryKey is the key of the entry that was successfully verified, used for tracking
func (s *VarNameBackoffStore) RecordSuccessWithKey(pair *ddrd.MayUAFPair, entryKey string) {
	if pair == nil {
		return
	}

	key := VarNamePairKey(pair)

	s.mu.Lock()
	defer s.mu.Unlock()

	stats, ok := s.cache[key]
	if !ok {
		stats = &VarNameBackoffStats{
			FreeAccessName: pair.FreeAccessName,
			UseAccessName:  pair.UseAccessName,
			Created:        time.Now(),
		}
		s.cache[key] = stats
	}

	stats.RecordSuccess()
	// Mark as verified - all future entries with same VarName pair will be skipped
	if !stats.Verified {
		stats.MarkVerified(entryKey)
		log.Logf(0, "varname_backoff: VarName pair VERIFIED key=%s entry=%s (future entries will be skipped)",
			key, entryKey)
	}
	s.saveLocked(key, stats)

	log.Logf(1, "varname_backoff: recorded success key=%s failures=%d successes=%d score=%.2f verified=%t",
		key, stats.Failures, stats.Successes, stats.BackoffScore(), stats.Verified)
}

// IsVerified checks if a VarName pair has already been successfully verified
func (s *VarNameBackoffStore) IsVerified(pair *ddrd.MayUAFPair) bool {
	if pair == nil {
		return false
	}

	key := VarNamePairKey(pair)

	s.mu.RLock()
	stats, ok := s.cache[key]
	s.mu.RUnlock()

	return ok && stats.Verified
}

// ShouldSkip determines whether verification should be skipped
func (s *VarNameBackoffStore) ShouldSkip(pair *ddrd.MayUAFPair, randFloat func() float64) (skip bool, prob float64, stats *VarNameBackoffStats) {
	if pair == nil {
		return false, 0, nil
	}

	key := VarNamePairKey(pair)

	s.mu.RLock()
	cachedStats, ok := s.cache[key]
	s.mu.RUnlock()

	if !ok {
		// No history, must verify
		return false, 0, &VarNameBackoffStats{Created: time.Now()}
	}

	// If already verified, always skip
	if cachedStats.Verified {
		return true, 1.0, cachedStats
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

// Stats returns a summary of persisted backoff statistics.
func (s *VarNameBackoffStore) Stats() (total, highScore, verified int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total = len(s.cache)
	for _, stats := range s.cache {
		if stats.Verified {
			verified++
		}
		if stats.BackoffScore() >= 0.8 {
			highScore++
		}
	}
	return
}

func (s *VarNameBackoffStore) saveLocked(key string, stats *VarNameBackoffStats) {
	if s.db == nil {
		return
	}

	data, err := json.Marshal(stats)
	if err != nil {
		log.Logf(0, "varname_backoff: failed to marshal stats: %v", err)
		return
	}

	s.db.Save(key, data, 0)
	if err := s.db.Flush(); err != nil {
		log.Logf(0, "varname_backoff: failed to flush db: %v", err)
	}
}

// Close closes the store
func (s *VarNameBackoffStore) Close() error {
	// db.DB is managed externally, don't close here
	return nil
}
