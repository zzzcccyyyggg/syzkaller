// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ddrd

import "sync"

// PairSource indicates the source of a discovered pair.
type PairSource int

const (
	SourceFuzz   PairSource = iota // From normal fuzzing
	SourceTiming                   // From timing exploration (Phase 2 validated)
)

// Store keeps track of unique DDRD pairs observed during fuzzing runs.
type Store struct {
	mu   sync.RWMutex
	seen map[uint64]struct{}

	// Track source of each pair
	pairsFromFuzz   map[uint64]struct{}
	pairsFromTiming map[uint64]struct{}

	// Track unique varnames by source
	varnamesFromFuzz   map[uint64]struct{}
	varnamesFromTiming map[uint64]struct{}
}

// NewStore returns an initialized Store.
func NewStore() *Store {
	return &Store{
		seen:               make(map[uint64]struct{}),
		pairsFromFuzz:      make(map[uint64]struct{}),
		pairsFromTiming:    make(map[uint64]struct{}),
		varnamesFromFuzz:   make(map[uint64]struct{}),
		varnamesFromTiming: make(map[uint64]struct{}),
	}
}

// Add ingests a report and returns the newly discovered UAF pairs. Pairs that
// were already seen are ignored.
func (s *Store) Add(report *Report) []*MayUAFPair {
	if report == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var newPairs []*MayUAFPair
	add := func(pair *MayUAFPair) {
		if pair == nil {
			return
		}
		id := pair.UAFPairID()
		if id == 0 {
			return
		}
		if _, exists := s.seen[id]; exists {
			return
		}
		s.seen[id] = struct{}{}
		newPairs = append(newPairs, pair)
	}

	for _, pair := range report.UAFPairs {
		add(pair)
	}
	for _, pair := range report.Extended {
		if pair == nil {
			continue
		}
		add(&pair.BasicInfo)
	}

	return newPairs
}

// Count returns the number of unique UAF pairs tracked by the store.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.seen)
}

// IsNewPair checks if a pair has NOT been seen before.
// Returns true if the pair is new (not in the store).
func (s *Store) IsNewPair(pair *MayUAFPair) bool {
	if pair == nil {
		return false
	}
	id := pair.UAFPairID()
	if id == 0 {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.seen[id]
	return !exists
}

// AddPair adds a single pair to the store.
// Returns true if the pair was new and added, false if already existed.
func (s *Store) AddPair(pair *MayUAFPair) bool {
	if pair == nil {
		return false
	}
	id := pair.UAFPairID()
	if id == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.seen[id]; exists {
		return false
	}
	s.seen[id] = struct{}{}
	return true
}

// AddPairWithSource adds a single pair with source tracking.
// Returns true if the pair was new and added.
func (s *Store) AddPairWithSource(pair *MayUAFPair, source PairSource) bool {
	if pair == nil {
		return false
	}
	id := pair.UAFPairID()
	if id == 0 {
		return false
	}
	varnameID := varnameID(pair.FreeAccessName, pair.UseAccessName)

	s.mu.Lock()
	defer s.mu.Unlock()

	isNew := false
	if _, exists := s.seen[id]; !exists {
		s.seen[id] = struct{}{}
		isNew = true
	}

	// Track source: first source wins for both pairs and varnames.
	// A pair is attributed to whichever source discovered it first.
	if isNew {
		switch source {
		case SourceFuzz:
			s.pairsFromFuzz[id] = struct{}{}
		case SourceTiming:
			s.pairsFromTiming[id] = struct{}{}
		}
	}
	// Varname: first source wins — only record if not already tracked by the other source.
	if varnameID != 0 {
		_, inFuzz := s.varnamesFromFuzz[varnameID]
		_, inTiming := s.varnamesFromTiming[varnameID]
		if !inFuzz && !inTiming {
			switch source {
			case SourceFuzz:
				s.varnamesFromFuzz[varnameID] = struct{}{}
			case SourceTiming:
				s.varnamesFromTiming[varnameID] = struct{}{}
			}
		}
	}

	return isNew
}

// AddWithSource ingests a report with source tracking.
func (s *Store) AddWithSource(report *Report, source PairSource) []*MayUAFPair {
	if report == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var newPairs []*MayUAFPair
	add := func(pair *MayUAFPair) {
		if pair == nil {
			return
		}
		id := pair.UAFPairID()
		if id == 0 {
			return
		}
		varnameID := varnameID(pair.FreeAccessName, pair.UseAccessName)

		isNew := false
		if _, exists := s.seen[id]; !exists {
			s.seen[id] = struct{}{}
			isNew = true
			newPairs = append(newPairs, pair)
		}

		// Track source: first source wins for both pairs and varnames.
		if isNew {
			switch source {
			case SourceFuzz:
				s.pairsFromFuzz[id] = struct{}{}
			case SourceTiming:
				s.pairsFromTiming[id] = struct{}{}
			}
		}
		// Varname: first source wins — only record if not already tracked by the other source.
		if varnameID != 0 {
			_, inFuzz := s.varnamesFromFuzz[varnameID]
			_, inTiming := s.varnamesFromTiming[varnameID]
			if !inFuzz && !inTiming {
				switch source {
				case SourceFuzz:
					s.varnamesFromFuzz[varnameID] = struct{}{}
				case SourceTiming:
					s.varnamesFromTiming[varnameID] = struct{}{}
				}
			}
		}
	}

	for _, pair := range report.UAFPairs {
		add(pair)
	}
	for _, pair := range report.Extended {
		if pair == nil {
			continue
		}
		add(&pair.BasicInfo)
	}

	return newPairs
}

// Stats returns counts by source.
// With "first source wins" policy, pairsFromFuzz and pairsFromTiming are disjoint,
// as are varnamesFromFuzz and varnamesFromTiming. So simple addition gives correct totals.
func (s *Store) Stats() (total, fromFuzz, fromTiming, varnamesTotal, varnamesFuzz, varnamesTiming int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.seen), len(s.pairsFromFuzz), len(s.pairsFromTiming),
		len(s.varnamesFromFuzz) + len(s.varnamesFromTiming),
		len(s.varnamesFromFuzz), len(s.varnamesFromTiming)
}

// CountFromFuzz returns count of pairs from normal fuzzing.
func (s *Store) CountFromFuzz() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.pairsFromFuzz)
}

// CountFromTiming returns count of pairs from timing exploration.
func (s *Store) CountFromTiming() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.pairsFromTiming)
}

// CountVarnamesFromFuzz returns count of varnames from normal fuzzing.
func (s *Store) CountVarnamesFromFuzz() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.varnamesFromFuzz)
}

// CountVarnamesFromTiming returns count of varnames from timing exploration.
func (s *Store) CountVarnamesFromTiming() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.varnamesFromTiming)
}

// varnameID delegates to the canonical OrderedVarNamePairID.
// Uses ordered (direction-sensitive) ID because UAF pairs have a clear Free→Use direction.
func varnameID(freeAccessName, useAccessName uint64) uint64 {
	return OrderedVarNamePairID(freeAccessName, useAccessName)
}
