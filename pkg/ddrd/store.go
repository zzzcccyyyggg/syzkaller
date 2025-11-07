// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ddrd

import "sync"

// Store keeps track of unique DDRD pairs observed during fuzzing runs.
type Store struct {
	mu   sync.RWMutex
	seen map[uint64]struct{}
}

// NewStore returns an initialized Store.
func NewStore() *Store {
	return &Store{
		seen: make(map[uint64]struct{}),
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
