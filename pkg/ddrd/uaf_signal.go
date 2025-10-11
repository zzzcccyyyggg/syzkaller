// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ddrd

import (
	"fmt"
	"math/bits"
	"sort"
)

// UAFSignal represents a set of UAF signals for coverage-guided fuzzing
// Similar to normal signal but specifically for UAF detection
type UAFSignal map[uint64]struct{}

// UAFSignalElem represents a single UAF signal element
type UAFSignalElem uint64

// Priority levels for UAF signals
const (
	UAFSignalPrioLow  = 0 // Low priority UAF signals
	UAFSignalPrioMed  = 1 // Medium priority UAF signals
	UAFSignalPrioHigh = 2 // High priority UAF signals
	UAFSignalPrioMax  = 3 // Maximum priority UAF signals
)

// FromRawUAF creates a UAF signal from raw signal data with priority
func FromRawUAF(raw []uint64, prio uint8) UAFSignal {
	if len(raw) == 0 {
		return nil
	}
	s := make(UAFSignal, len(raw))
	for _, elem := range raw {
		// Apply priority to the signal element
		prioritizedElem := (uint64(prio) << 62) | (elem & ((1 << 62) - 1))
		s[prioritizedElem] = struct{}{}
	}
	return s
}

// FromUAFPairs creates a UAF signal from UAF pairs
func FromUAFPairs(pairs []*MayUAFPair, prio uint8) UAFSignal {
	if len(pairs) == 0 {
		return nil
	}
	s := make(UAFSignal, len(pairs))
	for _, pair := range pairs {
		// Use the UAF pair ID as signal
		prioritizedElem := (uint64(prio) << 62) | (pair.UAFPairID() & ((1 << 62) - 1))
		s[prioritizedElem] = struct{}{}
	}
	return s
}

// Len returns the number of elements in the signal
func (s UAFSignal) Len() int {
	return len(s)
}

// Empty checks if the signal is empty
func (s UAFSignal) Empty() bool {
	return len(s) == 0
}

// Copy creates a copy of the signal
func (s UAFSignal) Copy() UAFSignal {
	if s == nil {
		return nil
	}
	c := make(UAFSignal, len(s))
	for elem := range s {
		c[elem] = struct{}{}
	}
	return c
}

// Merge adds elements from another signal
func (s *UAFSignal) Merge(other UAFSignal) {
	if *s == nil {
		*s = make(UAFSignal)
	}
	for elem := range other {
		(*s)[elem] = struct{}{}
	}
}

// Diff returns elements that are in 'other' but not in 's'
func (s UAFSignal) Diff(other UAFSignal) UAFSignal {
	if other == nil {
		return nil
	}
	diff := make(UAFSignal)
	for elem := range other {
		if s == nil || !s.Has(elem) {
			diff[elem] = struct{}{}
		}
	}
	if len(diff) == 0 {
		return nil
	}
	return diff
}

// DiffRaw returns elements that are in 'other' but not in 's' as raw slice
func (s UAFSignal) DiffRaw(other UAFSignal, prio uint8) []uint64 {
	diff := s.Diff(other)
	if diff == nil {
		return nil
	}
	return diff.ToRaw()
}

// Intersection returns elements that are in both signals
func (s UAFSignal) Intersection(other UAFSignal) UAFSignal {
	if s == nil || other == nil {
		return nil
	}
	intersection := make(UAFSignal)
	for elem := range s {
		if other.Has(elem) {
			intersection[elem] = struct{}{}
		}
	}
	if len(intersection) == 0 {
		return nil
	}
	return intersection
}

// Has checks if the signal contains a specific element
func (s UAFSignal) Has(elem uint64) bool {
	if s == nil {
		return false
	}
	_, exists := s[elem]
	return exists
}

// ToRaw converts signal to raw uint64 slice
func (s UAFSignal) ToRaw() []uint64 {
	if s == nil {
		return nil
	}
	raw := make([]uint64, 0, len(s))
	for elem := range s {
		raw = append(raw, elem)
	}
	// Sort for consistent output
	sort.Slice(raw, func(i, j int) bool {
		return raw[i] < raw[j]
	})
	return raw
}

// Serialize converts signal to a serializable format
func (s UAFSignal) Serialize() []uint64 {
	return s.ToRaw()
}

// Deserialize creates signal from serialized data
func DeserializeUAFSignal(data []uint64) UAFSignal {
	if len(data) == 0 {
		return nil
	}
	s := make(UAFSignal, len(data))
	for _, elem := range data {
		s[elem] = struct{}{}
	}
	return s
}

// FilterByPriority returns elements with specific priority
func (s UAFSignal) FilterByPriority(prio uint8) UAFSignal {
	if s == nil {
		return nil
	}
	filtered := make(UAFSignal)
	for elem := range s {
		if (elem >> 62) == uint64(prio) {
			filtered[elem] = struct{}{}
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

// GetPriority extracts priority from a signal element
func GetUAFSignalPriority(elem uint64) uint8 {
	return uint8(elem >> 62)
}

// GetSignalValue extracts the actual signal value (without priority)
func GetUAFSignalValue(elem uint64) uint64 {
	return elem & ((1 << 62) - 1)
}

// Split splits signal into priority groups
func (s UAFSignal) Split() map[uint8]UAFSignal {
	if s == nil {
		return nil
	}
	groups := make(map[uint8]UAFSignal)
	for elem := range s {
		prio := GetUAFSignalPriority(elem)
		if groups[prio] == nil {
			groups[prio] = make(UAFSignal)
		}
		groups[prio][elem] = struct{}{}
	}
	return groups
}

// GetHighestPriority returns the highest priority level in the signal
func (s UAFSignal) GetHighestPriority() uint8 {
	if s == nil {
		return 0
	}
	var maxPrio uint8 = 0
	for elem := range s {
		prio := GetUAFSignalPriority(elem)
		if prio > maxPrio {
			maxPrio = prio
		}
	}
	return maxPrio
}

// PopCount returns the number of set bits across all signal elements
// Useful for measuring signal "richness"
func (s UAFSignal) PopCount() int {
	if s == nil {
		return 0
	}
	total := 0
	for elem := range s {
		total += bits.OnesCount64(elem)
	}
	return total
}

// Density returns the signal density (unique elements per total possible)
func (s UAFSignal) Density() float64 {
	if s == nil {
		return 0.0
	}
	// Estimate density based on signal space (this is a heuristic)
	// For UAF signals, we consider the lower 62 bits as the signal space
	maxSignalSpace := uint64(1) << 32 // Reasonable estimate for UAF signal space
	return float64(len(s)) / float64(maxSignalSpace)
}

// String returns a string representation of the signal
func (s UAFSignal) String() string {
	if s == nil {
		return "UAFSignal{empty}"
	}
	return fmt.Sprintf("UAFSignal{len=%d, highest_prio=%d}", len(s), s.GetHighestPriority())
}

// ============================================================================
// UAF Signal Corpus and Management
// ============================================================================

// UAFSignalCorpus manages a collection of UAF signals for corpus-guided fuzzing
type UAFSignalCorpus struct {
	signals     map[string]UAFSignal // Keyed by program hash or ID
	maxSignals  UAFSignal            // Union of all signals
	prioSignals map[uint8]UAFSignal  // Signals grouped by priority
}

// NewUAFSignalCorpus creates a new UAF signal corpus
func NewUAFSignalCorpus() *UAFSignalCorpus {
	return &UAFSignalCorpus{
		signals:     make(map[string]UAFSignal),
		maxSignals:  make(UAFSignal),
		prioSignals: make(map[uint8]UAFSignal),
	}
}

// Add adds a signal to the corpus under a specific key
func (c *UAFSignalCorpus) Add(key string, signal UAFSignal) UAFSignal {
	if signal == nil {
		return nil
	}

	// Calculate new signal (elements not in corpus)
	newSignal := c.maxSignals.Diff(signal)

	// Add to corpus
	c.signals[key] = signal.Copy()
	c.maxSignals.Merge(signal)

	// Update priority groups
	for elem := range signal {
		prio := GetUAFSignalPriority(elem)
		if c.prioSignals[prio] == nil {
			c.prioSignals[prio] = make(UAFSignal)
		}
		c.prioSignals[prio][elem] = struct{}{}
	}

	return newSignal
}

// Get retrieves a signal by key
func (c *UAFSignalCorpus) Get(key string) UAFSignal {
	signal, exists := c.signals[key]
	if !exists {
		return nil
	}
	return signal.Copy()
}

// Has checks if the corpus contains a specific key
func (c *UAFSignalCorpus) Has(key string) bool {
	_, exists := c.signals[key]
	return exists
}

// Remove removes a signal from the corpus
func (c *UAFSignalCorpus) Remove(key string) {
	delete(c.signals, key)
	// Note: This doesn't rebuild maxSignals for performance reasons
	// Call Rebuild() if you need accurate maxSignals after removals
}

// Rebuild reconstructs the maxSignals and prioSignals from current corpus
func (c *UAFSignalCorpus) Rebuild() {
	c.maxSignals = make(UAFSignal)
	c.prioSignals = make(map[uint8]UAFSignal)

	for _, signal := range c.signals {
		c.maxSignals.Merge(signal)
		for elem := range signal {
			prio := GetUAFSignalPriority(elem)
			if c.prioSignals[prio] == nil {
				c.prioSignals[prio] = make(UAFSignal)
			}
			c.prioSignals[prio][elem] = struct{}{}
		}
	}
}

// GetMaxSignal returns the union of all signals in the corpus
func (c *UAFSignalCorpus) GetMaxSignal() UAFSignal {
	return c.maxSignals.Copy()
}

// GetByPriority returns all signals of a specific priority
func (c *UAFSignalCorpus) GetByPriority(prio uint8) UAFSignal {
	signal, exists := c.prioSignals[prio]
	if !exists {
		return nil
	}
	return signal.Copy()
}

// Len returns the number of signals in the corpus
func (c *UAFSignalCorpus) Len() int {
	return len(c.signals)
}

// TotalSignalLen returns the total number of unique signal elements
func (c *UAFSignalCorpus) TotalSignalLen() int {
	return c.maxSignals.Len()
}

// Keys returns all keys in the corpus
func (c *UAFSignalCorpus) Keys() []string {
	keys := make([]string, 0, len(c.signals))
	for key := range c.signals {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Clear removes all signals from the corpus
func (c *UAFSignalCorpus) Clear() {
	c.signals = make(map[string]UAFSignal)
	c.maxSignals = make(UAFSignal)
	c.prioSignals = make(map[uint8]UAFSignal)
}

// GetStats returns statistics about the corpus
func (c *UAFSignalCorpus) GetStats() UAFCorpusStats {
	stats := UAFCorpusStats{
		TotalPrograms:     len(c.signals),
		TotalSignals:      c.maxSignals.Len(),
		PriorityBreakdown: make(map[uint8]int),
	}

	for prio, signal := range c.prioSignals {
		stats.PriorityBreakdown[prio] = signal.Len()
	}

	if len(c.signals) > 0 {
		stats.AvgSignalPerProgram = float64(stats.TotalSignals) / float64(len(c.signals))
	}

	return stats
}

// UAFCorpusStats contains statistics about the UAF signal corpus
type UAFCorpusStats struct {
	TotalPrograms       int
	TotalSignals        int
	AvgSignalPerProgram float64
	PriorityBreakdown   map[uint8]int
}

// String returns a string representation of the corpus stats
func (s UAFCorpusStats) String() string {
	return fmt.Sprintf("UAFCorpus{programs=%d, signals=%d, avg=%.2f}",
		s.TotalPrograms, s.TotalSignals, s.AvgSignalPerProgram)
}
