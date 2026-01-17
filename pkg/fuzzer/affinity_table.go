// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/prog"
)

// ============================================================================
// Syscall Affinity Table
// ============================================================================
// This module tracks the interaction affinity between syscall pairs.
// It learns which syscall combinations are more likely to produce
// cross-program race conditions, enabling smarter partner selection.
// ============================================================================

// SyscallSignature uniquely identifies a syscall by its name.
// We only use syscall name (not ObjectType/ObjectID) to prevent key explosion.
// With ~500 syscall variants, pair count is manageable: C(500,2) ≈ 125,000 entries.
type SyscallSignature struct {
	Name string // Syscall name (e.g., "ioctl$kccwf")
}

// String returns the syscall name as the signature string.
func (s SyscallSignature) String() string {
	return s.Name
}

// IsEmpty returns true if the signature is empty.
func (s SyscallSignature) IsEmpty() bool {
	return s.Name == ""
}

// AffinityStats records interaction statistics for a syscall pair.
type AffinityStats struct {
	Executions   int       // Number of times this pair was executed
	Interactions int       // Number of times this pair produced cross-program races
	RaceYield    int       // Total number of race pairs discovered
	LastSeen     time.Time // Last update timestamp
}

// InteractionRate returns the rate of successful interactions.
func (as *AffinityStats) InteractionRate() float64 {
	if as.Executions == 0 {
		return 0
	}
	return float64(as.Interactions) / float64(as.Executions)
}

// Confidence returns a confidence score based on sample size.
func (as *AffinityStats) Confidence() float64 {
	// Higher confidence with more executions, capped at 1.0
	if as.Executions >= 100 {
		return 1.0
	}
	return float64(as.Executions) / 100.0
}

// SyscallAffinityTable tracks interaction affinity between syscall pairs.
type SyscallAffinityTable struct {
	mu sync.RWMutex

	// (sig1, sig2) → stats, normalized order: sig1 < sig2
	affinities map[string]*AffinityStats

	// Configuration
	decayHalfLife time.Duration
	minExecutions int // Minimum executions before using affinity
}

// NewSyscallAffinityTable creates a new affinity table.
func NewSyscallAffinityTable() *SyscallAffinityTable {
	return &SyscallAffinityTable{
		affinities:    make(map[string]*AffinityStats),
		decayHalfLife: 24 * time.Hour,
		minExecutions: 5,
	}
}

// pairKey generates a normalized key for a syscall pair.
func pairKey(sig1, sig2 SyscallSignature) string {
	s1, s2 := sig1.String(), sig2.String()
	if s1 > s2 {
		s1, s2 = s2, s1
	}
	return s1 + "|" + s2
}

// RecordExecution records an execution attempt (without interaction).
func (sat *SyscallAffinityTable) RecordExecution(sig1, sig2 SyscallSignature) {
	if sig1.IsEmpty() || sig2.IsEmpty() {
		return
	}

	key := pairKey(sig1, sig2)
	sat.mu.Lock()
	defer sat.mu.Unlock()

	stats := sat.affinities[key]
	if stats == nil {
		stats = &AffinityStats{}
		sat.affinities[key] = stats
	}
	stats.Executions++
	stats.LastSeen = time.Now()
}

// RecordInteraction records a successful interaction (produced cross-program race).
func (sat *SyscallAffinityTable) RecordInteraction(sig1, sig2 SyscallSignature, raceCount int) {
	if sig1.IsEmpty() || sig2.IsEmpty() {
		return
	}

	key := pairKey(sig1, sig2)
	sat.mu.Lock()
	defer sat.mu.Unlock()

	stats := sat.affinities[key]
	if stats == nil {
		stats = &AffinityStats{}
		sat.affinities[key] = stats
	}
	stats.Executions++
	stats.Interactions++
	stats.RaceYield += raceCount
	stats.LastSeen = time.Now()
}

// GetAffinity returns the affinity score for a syscall pair.
// Returns a value between 0 and 1, where higher means more likely to interact.
func (sat *SyscallAffinityTable) GetAffinity(sig1, sig2 SyscallSignature) float64 {
	if sig1.IsEmpty() || sig2.IsEmpty() {
		return 0.5 // Neutral for unknown
	}

	key := pairKey(sig1, sig2)
	sat.mu.RLock()
	defer sat.mu.RUnlock()

	stats := sat.affinities[key]
	if stats == nil || stats.Executions < sat.minExecutions {
		return 0.5 // Neutral for insufficient data
	}

	// Base rate from interaction success
	rate := stats.InteractionRate()

	// Apply time decay
	age := time.Since(stats.LastSeen)
	decay := 1.0 / (1.0 + age.Hours()/sat.decayHalfLife.Hours())

	// Combine with confidence
	confidence := stats.Confidence()

	// Final score: weighted average between observed rate and prior (0.5)
	return (rate*confidence + 0.5*(1-confidence)) * decay
}

// AffinityEntry represents an entry in the affinity table for export.
type AffinityEntry struct {
	Key   string
	Stats *AffinityStats
	Score float64
}

// GetTopAffinities returns the top-N highest affinity syscall pairs.
func (sat *SyscallAffinityTable) GetTopAffinities(n int) []AffinityEntry {
	sat.mu.RLock()
	defer sat.mu.RUnlock()

	var entries []AffinityEntry
	for key, stats := range sat.affinities {
		if stats.Executions >= sat.minExecutions {
			entries = append(entries, AffinityEntry{
				Key:   key,
				Stats: stats,
				Score: stats.InteractionRate(),
			})
		}
	}

	// Sort by score descending
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Score > entries[j].Score
	})

	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// GetStats returns overall table statistics.
func (sat *SyscallAffinityTable) GetStats() (pairCount int, totalExecs int, totalInteractions int) {
	sat.mu.RLock()
	defer sat.mu.RUnlock()

	pairCount = len(sat.affinities)
	for _, stats := range sat.affinities {
		totalExecs += stats.Executions
		totalInteractions += stats.Interactions
	}
	return
}

// ============================================================================
// Helper functions for extracting syscall signatures
// ============================================================================

// ExtractSyscallSignature extracts a signature from a program at a specific call index.
// Only uses syscall name for simplicity and to prevent key explosion.
func ExtractSyscallSignature(p *prog.Prog, callIdx int32) SyscallSignature {
	if p == nil || callIdx < 0 || int(callIdx) >= len(p.Calls) {
		return SyscallSignature{}
	}

	call := p.Calls[callIdx]
	if call == nil || call.Meta == nil {
		return SyscallSignature{}
	}

	return SyscallSignature{
		Name: call.Meta.Name,
	}
}

// findObjectInfo is deprecated - we no longer track object-level information
// to prevent key explosion. Keeping as a no-op for compatibility.
func findObjectInfo(p *prog.Prog, call *prog.Call, callIdx int) (objType, objID string) {
	return "", ""
}

// ExtractSignaturesFromPair extracts syscall signatures from a UAF pair.
func ExtractSignaturesFromPair(prog1, prog2 *prog.Prog, pair *ddrd.MayUAFPair) (sig1, sig2 SyscallSignature) {
	if pair == nil {
		return SyscallSignature{}, SyscallSignature{}
	}

	// Determine which program contains the free and use operations
	var freeProg, useProg *prog.Prog
	if pair.FreeProgIdx == 0 {
		freeProg = prog1
	} else if pair.FreeProgIdx == 1 {
		freeProg = prog2
	}
	if pair.UseProgIdx == 0 {
		useProg = prog1
	} else if pair.UseProgIdx == 1 {
		useProg = prog2
	}

	sig1 = ExtractSyscallSignature(freeProg, pair.FreeCallIdx)
	sig2 = ExtractSyscallSignature(useProg, pair.UseCallIdx)

	return sig1, sig2
}

// GetProgramAffinityScore calculates an affinity score for a program pair
// based on their syscall combinations.
func (sat *SyscallAffinityTable) GetProgramAffinityScore(prog1, prog2 *prog.Prog) float64 {
	if prog1 == nil || prog2 == nil {
		return 0.5
	}

	var totalScore float64
	var count int

	// Sample syscalls from both programs
	for i := 0; i < len(prog1.Calls) && i < 5; i++ {
		sig1 := ExtractSyscallSignature(prog1, int32(i))
		if sig1.IsEmpty() {
			continue
		}

		for j := 0; j < len(prog2.Calls) && j < 5; j++ {
			sig2 := ExtractSyscallSignature(prog2, int32(j))
			if sig2.IsEmpty() {
				continue
			}

			affinity := sat.GetAffinity(sig1, sig2)
			totalScore += affinity
			count++
		}
	}

	if count == 0 {
		return 0.5
	}
	return totalScore / float64(count)
}

// ============================================================================
// Namespace-based affinity helpers
// ============================================================================

// GetNamespaceAffinity returns affinity score based on syscall namespaces.
func GetNamespaceAffinity(prog1, prog2 *prog.Prog) float64 {
	ns1 := ExtractNamespaces(prog1)
	ns2 := ExtractNamespaces(prog2)

	if len(ns1) == 0 || len(ns2) == 0 {
		return 0.0
	}

	// Count shared namespaces
	shared := 0
	ns2Set := make(map[string]bool, len(ns2))
	for _, ns := range ns2 {
		ns2Set[ns] = true
	}
	for _, ns := range ns1 {
		if ns2Set[ns] {
			shared++
		}
	}

	if shared == 0 {
		return 0.0
	}

	// Return ratio of shared namespaces
	return float64(shared) / float64(max(len(ns1), len(ns2)))
}

// extractSyscallBaseName extracts the base name from a syscall name.
func extractSyscallBaseName(name string) string {
	if idx := strings.Index(name, "$"); idx > 0 {
		return name[:idx]
	}
	return name
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
