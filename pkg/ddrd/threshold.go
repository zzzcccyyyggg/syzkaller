// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package ddrd provides DDRD (Data-race/UAF Detection) related utilities.
package ddrd

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

// Threshold constants (in nanoseconds)
const (
	DefaultThresholdNs = MinThresholdNs // Start with tightest threshold, grow as needed
	MinThresholdNs     = 427_00         // 0.427 ms - tightest
	MaxThresholdNs     = 427_000_000    // 427 ms - loosest
)

// ThresholdState holds the current threshold and statistics for adaptive adjustment.
type ThresholdState struct {
	CurrentThresholdNs uint64                  `json:"current_threshold_ns"`
	LastUpdated        time.Time               `json:"last_updated"`
	Stats              ThresholdStats          `json:"stats"`
	History            []ThresholdHistoryEntry `json:"history,omitempty"`
}

// ThresholdStats contains the statistics used for threshold calculation.
// Now tracks corpus-level statistics instead of pair-level.
type ThresholdStats struct {
	TotalCorpus     uint64 `json:"total_corpus"`     // Total corpus entries collected
	VerifiedCorpus  uint64 `json:"verified_corpus"`  // Corpus entries that have been validated (regardless of result)
	RecentCollected uint64 `json:"recent_collected"` // Recently collected corpus entries
	RecentVerified  uint64 `json:"recent_verified"`  // Recently verified corpus entries
	WindowMinutes   int    `json:"window_minutes"`
}

// ThresholdHistoryEntry records historical threshold changes.
type ThresholdHistoryEntry struct {
	Time      time.Time `json:"time"`
	Threshold uint64    `json:"threshold"`
	Reason    string    `json:"reason,omitempty"`
}

// ThresholdController manages adaptive race detection threshold.
type ThresholdController struct {
	mu       sync.RWMutex
	state    ThresholdState
	workdir  string
	filePath string

	// Configuration
	maxAdjustUp   float64 // Maximum upward adjustment per update (e.g., 1.5 = 50% increase)
	maxAdjustDown float64 // Maximum downward adjustment per update (e.g., 0.5 = 50% decrease)
	maxHistory    int     // Maximum history entries to keep

	// Cache control for cross-process communication
	lastReload     time.Time
	reloadInterval time.Duration
}

// NewThresholdController creates a new threshold controller.
// If the config file doesn't exist, it saves the default state to disk.
func NewThresholdController(configPath string) *ThresholdController {
	tc := &ThresholdController{
		filePath:       configPath,
		maxAdjustUp:    1.2, // Conservative: max 20% increase per update
		maxAdjustDown:  0.5, // Aggressive: up to 50% decrease per update
		maxHistory:     100,
		reloadInterval: 30 * time.Second, // Reload from file every 30 seconds for cross-process sync
		lastReload:     time.Now(),
		state: ThresholdState{
			CurrentThresholdNs: DefaultThresholdNs,
			LastUpdated:        time.Now(),
			Stats: ThresholdStats{
				WindowMinutes: 30,
			},
		},
	}
	if !tc.load() {
		// Config file doesn't exist, save the default state
		tc.mu.Lock()
		tc.saveLocked()
		tc.mu.Unlock()
	}
	return tc
}

// CurrentThreshold returns the current threshold in nanoseconds.
// It periodically reloads from the config file to support cross-process communication.
func (tc *ThresholdController) CurrentThreshold() uint64 {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Periodically reload from file to pick up changes from other processes
	if time.Since(tc.lastReload) > tc.reloadInterval {
		tc.reloadLocked()
	}

	return tc.state.CurrentThresholdNs
}

// reloadLocked reloads the config from file. Caller must hold the lock.
func (tc *ThresholdController) reloadLocked() {
	tc.lastReload = time.Now()

	data, err := os.ReadFile(tc.filePath)
	if err != nil {
		return // File doesn't exist or can't be read, keep current state
	}

	var state ThresholdState
	if err := json.Unmarshal(data, &state); err != nil {
		return // Invalid JSON, keep current state
	}

	// Only update if the file has a newer timestamp
	if state.LastUpdated.After(tc.state.LastUpdated) {
		oldThreshold := tc.state.CurrentThresholdNs
		tc.state.CurrentThresholdNs = state.CurrentThresholdNs
		tc.state.LastUpdated = state.LastUpdated
		if oldThreshold != state.CurrentThresholdNs {
			log.Logf(0, "threshold: reloaded from file %d -> %d ns",
				oldThreshold, state.CurrentThresholdNs)
		}
	}
}

// GetStats returns a copy of the current statistics.
func (tc *ThresholdController) GetStats() ThresholdStats {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.state.Stats
}

// UpdateStats updates the statistics and recalculates the threshold.
// Effective adjustment is based on corpus-level totals (totalCorpus, verifiedCorpus);
// recentCollected/recentVerified are stored but not used in the calculation.
func (tc *ThresholdController) UpdateStats(totalCorpus, verifiedCorpus, recentCollected, recentVerified uint64) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.state.Stats.TotalCorpus = totalCorpus
	tc.state.Stats.VerifiedCorpus = verifiedCorpus
	tc.state.Stats.RecentCollected = recentCollected
	tc.state.Stats.RecentVerified = recentVerified

	oldThreshold := tc.state.CurrentThresholdNs
	newThreshold := tc.computeNewThreshold()

	if newThreshold != oldThreshold {
		tc.state.CurrentThresholdNs = newThreshold
		tc.addHistoryLocked(newThreshold, "auto-adjust")
		log.Logf(0, "threshold: adjusted %d -> %d ns (corpus=%d verified=%d)",
			oldThreshold, newThreshold, totalCorpus, verifiedCorpus)
	}

	tc.state.LastUpdated = time.Now()
	tc.saveLocked()
}

// computeNewThreshold calculates the new threshold based only on corpus-level backlog.
// Algorithm:
//   - backlogRatio = (totalCorpus - verifiedCorpus) / totalCorpus (clamped to [0,1])
//   - adjustFactor = 1.0 + (0.5 - backlogRatio)
//   - backlog=0.0  -> factor=1.5 (clamped by maxAdjustUp)
//   - backlog=0.5  -> factor=1.0 (no change)
//   - backlog=1.0  -> factor=0.5 (clamped by maxAdjustDown)
//   - Clamp adjustFactor to [maxAdjustDown, maxAdjustUp]
//   - newThreshold = currentThreshold * adjustFactor
func (tc *ThresholdController) computeNewThreshold() uint64 {
	stats := tc.state.Stats

	// Calculate backlog ratio (corpus-level)
	var backlogRatio float64
	if stats.TotalCorpus > 0 {
		backlog := int64(stats.TotalCorpus) - int64(stats.VerifiedCorpus)
		if backlog < 0 {
			backlog = 0
		}
		backlogRatio = float64(backlog) / float64(stats.TotalCorpus)
		if backlogRatio > 1.0 {
			backlogRatio = 1.0
		}
	}

	// Adjustment factor driven purely by backlog
	adjustFactor := 1.0 + (0.5 - backlogRatio)

	// Clamp adjustment factor
	if adjustFactor > tc.maxAdjustUp {
		adjustFactor = tc.maxAdjustUp
	}
	if adjustFactor < tc.maxAdjustDown {
		adjustFactor = tc.maxAdjustDown
	}

	// Apply adjustment
	newThreshold := uint64(float64(tc.state.CurrentThresholdNs) * adjustFactor)

	// Clamp to valid range
	if newThreshold < MinThresholdNs {
		newThreshold = MinThresholdNs
	}
	if newThreshold > MaxThresholdNs {
		newThreshold = MaxThresholdNs
	}

	return newThreshold
}

// SetThreshold manually sets the threshold (for testing or override).
func (tc *ThresholdController) SetThreshold(thresholdNs uint64) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if thresholdNs < MinThresholdNs {
		thresholdNs = MinThresholdNs
	}
	if thresholdNs > MaxThresholdNs {
		thresholdNs = MaxThresholdNs
	}

	tc.state.CurrentThresholdNs = thresholdNs
	tc.state.LastUpdated = time.Now()
	tc.addHistoryLocked(thresholdNs, "manual-set")
	tc.saveLocked()
}

func (tc *ThresholdController) addHistoryLocked(threshold uint64, reason string) {
	entry := ThresholdHistoryEntry{
		Time:      time.Now(),
		Threshold: threshold,
		Reason:    reason,
	}
	tc.state.History = append(tc.state.History, entry)

	// Trim history if too long
	if len(tc.state.History) > tc.maxHistory {
		tc.state.History = tc.state.History[len(tc.state.History)-tc.maxHistory:]
	}
}

// load reads the config from file. Returns true if successfully loaded, false otherwise.
func (tc *ThresholdController) load() bool {
	data, err := os.ReadFile(tc.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Logf(0, "threshold: failed to read config: %v", err)
		}
		return false
	}

	var state ThresholdState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Logf(0, "threshold: failed to parse config: %v", err)
		return false
	}

	// Validate loaded threshold
	if state.CurrentThresholdNs < MinThresholdNs {
		state.CurrentThresholdNs = MinThresholdNs
	}
	if state.CurrentThresholdNs > MaxThresholdNs {
		state.CurrentThresholdNs = MaxThresholdNs
	}

	tc.state = state
	log.Logf(0, "threshold: loaded config threshold=%d ns", tc.state.CurrentThresholdNs)
	return true
}

func (tc *ThresholdController) saveLocked() {
	data, err := json.MarshalIndent(tc.state, "", "  ")
	if err != nil {
		log.Logf(0, "threshold: failed to marshal config: %v", err)
		return
	}

	if err := os.WriteFile(tc.filePath, data, 0644); err != nil {
		log.Logf(0, "threshold: failed to write config: %v", err)
	}
}

// Save persists the current state to disk.
func (tc *ThresholdController) Save() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.saveLocked()
}
