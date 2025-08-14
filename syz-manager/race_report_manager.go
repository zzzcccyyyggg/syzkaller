// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// ===============DDRD====================
// Race report manager for syzkaller
// Manages race detection reports and analysis
// ===============DDRD====================

package main

import (
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/report"
)

// ReportedRaceEntry represents a single reported race with metadata
type ReportedRaceEntry struct {
	Race      report.ReportedRace
	ReportID  string    // Unique identifier for the crash report
	Timestamp time.Time // When the race was reported
	Count     int       // How many times this race pattern was seen
}

// RaceGroup represents a group of races with the same VarName pair
type RaceGroup struct {
	VarName1   string               // First variable name (alphabetically sorted)
	VarName2   string               // Second variable name (alphabetically sorted)
	VarNameKey string               // Combined key for indexing: "var1::var2"
	Entries    []*ReportedRaceEntry // All race entries in this group
	TotalCount int                  // Total number of occurrences
	FirstSeen  time.Time            // When first race in this group was seen
	LastSeen   time.Time            // When last race in this group was seen
}

// RaceReportManager manages all reported races
type RaceReportManager struct {
	mu             sync.RWMutex
	enabled        bool                            // 是否启用race报告管理
	racesByVarName map[string][]*ReportedRaceEntry // VarName -> list of race entries (for individual lookups)
	raceGroups     map[string]*RaceGroup           // VarNameKey -> race group (for classification)
	allRaces       []*ReportedRaceEntry            // All reported races in chronological order
}

// NewRaceReportManager creates a new race report manager
func NewRaceReportManager() *RaceReportManager {
	return &RaceReportManager{
		enabled:        false, // 默认禁用
		racesByVarName: make(map[string][]*ReportedRaceEntry),
		raceGroups:     make(map[string]*RaceGroup),
		allRaces:       make([]*ReportedRaceEntry, 0),
	}
}

// generateVarNameKey creates a normalized key from two variable names
// Ensures consistent ordering for proper grouping: (a,b) and (b,a) produce same key

// 不需要在allrace 中找吧 只需要遍历group 就行

func generateVarNameKey(varName1, varName2 string) string {
	if varName1 <= varName2 {
		return varName1 + "|" + varName2
	}
	return varName2 + "|" + varName1
}

// AddReport adds a new race report to the manager
func (rrm *RaceReportManager) AddReport(rep *report.Report, reportID string) {
	rrm.mu.Lock()
	defer rrm.mu.Unlock()

	// 如果未启用，直接返回
	if !rrm.enabled {
		return
	}

	if !rep.IsDataRaceReport() {
		return
	}

	timestamp := time.Now()

	for _, race := range rep.GetReportedRaces() {
		entry := &ReportedRaceEntry{
			Race:      race,
			ReportID:  reportID,
			Timestamp: timestamp,
			Count:     1,
		}

		// Check if we've seen this race pattern before
		existing := rrm.findExistingRace(race)
		if existing != nil {
			existing.Count++
			continue
		}

		// Add new race entry
		rrm.allRaces = append(rrm.allRaces, entry)

		// Index by VarNames (traditional single-var classification)
		if race.VarName1 != "" {
			rrm.racesByVarName[race.VarName1] = append(rrm.racesByVarName[race.VarName1], entry)
		}
		if race.VarName2 != "" && race.VarName2 != race.VarName1 {
			rrm.racesByVarName[race.VarName2] = append(rrm.racesByVarName[race.VarName2], entry)
		}

		// Add to new VarName pair-based classification
		if race.VarName1 != "" && race.VarName2 != "" {
			varNameKey := generateVarNameKey(race.VarName1, race.VarName2)

			group, exists := rrm.raceGroups[varNameKey]
			if !exists {
				group = &RaceGroup{
					VarName1:   race.VarName1,
					VarName2:   race.VarName2,
					VarNameKey: varNameKey,
					Entries:    make([]*ReportedRaceEntry, 0),
					FirstSeen:  timestamp,
					LastSeen:   timestamp,
				}
				rrm.raceGroups[varNameKey] = group
			}

			group.Entries = append(group.Entries, entry)
			group.TotalCount = len(group.Entries)
			group.LastSeen = timestamp
		}
	}
}

// findExistingRace checks if a similar race has been reported before
func (rrm *RaceReportManager) findExistingRace(newRace report.ReportedRace) *ReportedRaceEntry {
	for _, entry := range rrm.allRaces {
		if rrm.racesMatch(entry.Race, newRace) {
			return entry
		}
	}
	return nil
}

// racesMatch determines if two races are essentially the same
func (rrm *RaceReportManager) racesMatch(race1, race2 report.ReportedRace) bool {
	// Same VarNames (order doesn't matter)
	return (race1.VarName1 == race2.VarName1 && race1.VarName2 == race2.VarName2) ||
		(race1.VarName1 == race2.VarName2 && race1.VarName2 == race2.VarName1)
}

// GetRacesByVarName returns all races involving a specific VarName
func (rrm *RaceReportManager) GetRacesByVarName(varName string) []*ReportedRaceEntry {
	rrm.mu.RLock()
	defer rrm.mu.RUnlock()

	races := rrm.racesByVarName[varName]
	result := make([]*ReportedRaceEntry, len(races))
	copy(result, races)
	return result
}

// GetAllRacesByVarName returns races grouped by variable names
func (rrm *RaceReportManager) GetAllRacesByVarName() map[string][]*ReportedRaceEntry {
	rrm.mu.RLock()
	defer rrm.mu.RUnlock()

	result := make(map[string][]*ReportedRaceEntry)
	for varName, races := range rrm.racesByVarName {
		result[varName] = races
	}
	return result
}

// GetRaceGroups returns races grouped by VarName pairs
func (rrm *RaceReportManager) GetRaceGroups() map[string]*RaceGroup {
	rrm.mu.RLock()
	defer rrm.mu.RUnlock()

	result := make(map[string]*RaceGroup)
	for key, group := range rrm.raceGroups {
		result[key] = group
	}
	return result
}

// GetAllRaces returns all race reports in chronological order
func (rrm *RaceReportManager) GetAllRaces() []*ReportedRaceEntry {
	rrm.mu.RLock()
	defer rrm.mu.RUnlock()

	result := make([]*ReportedRaceEntry, len(rrm.allRaces))
	copy(result, rrm.allRaces)
	return result
}

// GetRaceStats returns statistics about reported races
func (rrm *RaceReportManager) GetRaceStats() map[string]interface{} {
	rrm.mu.RLock()
	defer rrm.mu.RUnlock()

	totalRaces := len(rrm.allRaces)
	uniqueVarNames := len(rrm.racesByVarName)

	totalOccurrences := 0
	for _, entry := range rrm.allRaces {
		totalOccurrences += entry.Count
	}

	return map[string]interface{}{
		"total_unique_races": totalRaces,
		"unique_var_names":   uniqueVarNames,
		"total_occurrences":  totalOccurrences,
	}
}

// SetEnabled 设置race报告管理器的启用状态
func (rrm *RaceReportManager) SetEnabled(enabled bool) {
	rrm.mu.Lock()
	defer rrm.mu.Unlock()
	rrm.enabled = enabled
}

// IsEnabled 检查race报告管理器是否启用
func (rrm *RaceReportManager) IsEnabled() bool {
	rrm.mu.RLock()
	defer rrm.mu.RUnlock()
	return rrm.enabled
}

// ===============DDRD====================
