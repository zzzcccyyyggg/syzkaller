// ===============DDRD====================
// RacePairWorkQueue methods for race pair mode
// ===============DDRD====================
package main

import (
	"sync"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/prog"
)

// ProgPair represents a pair of programs for race detection testing
type ProgPair struct {
	p1 *prog.Prog // First program
	p2 *prog.Prog // Second program
}

// PairWorkTriage represents a triage work item for race pair execution
type PairWorkTriage struct {
	progPair *ProgPair
	info     *ipc.PairProgInfo
}

// PairWorkValuable represents a valuable work item for race pair execution
type PairWorkValuable struct {
	progPair *ProgPair
	info     *ipc.PairProgInfo
}

// RacePairWorkQueue holds race pair work items for RACE PAIR mode
// This queue is completely separate from normal mode queue
type RacePairWorkQueue struct {
	mu sync.RWMutex

	// Two types of race pair work items
	candidates []*ProgPair       // pairs from corpus combinations
	triage     []*PairWorkTriage // pairs that bring new race coverage
	valuable   []*PairWorkValuable
	procs      int
}

// NewRacePairWorkQueue creates a new race pair work queue
func NewRacePairWorkQueue(procs int) *RacePairWorkQueue {
	return &RacePairWorkQueue{
		procs: procs,
	}
}

// enqueue adds work items to the appropriate queues based on item type
func (rpwq *RacePairWorkQueue) enqueue(item interface{}) {
	rpwq.mu.Lock()
	defer rpwq.mu.Unlock()

	switch item := item.(type) {
	case *ProgPair:
		rpwq.candidates = append(rpwq.candidates, item)
	case *PairWorkTriage:
		rpwq.triage = append(rpwq.triage, item)
	case *PairWorkValuable:
		rpwq.valuable = append(rpwq.valuable, item)
	default:
		panic("unknown work type for RacePairWorkQueue")
	}
}

func (rpwq *RacePairWorkQueue) enqueueCandidate(progPair *ProgPair) {
	rpwq.enqueue(progPair)
}

func (rpwq *RacePairWorkQueue) enqueueTriage(triage *PairWorkTriage) {
	rpwq.enqueue(triage)
}

func (rpwq *RacePairWorkQueue) enqueueValuable(valuable *PairWorkValuable) {
	rpwq.enqueue(valuable)
}

// dequeue returns the next work item (candidates first, then triage)
func (rpwq *RacePairWorkQueue) dequeue() interface{} {
	rpwq.mu.RLock()
	if len(rpwq.candidates) == 0 && len(rpwq.triage) == 0 && len(rpwq.valuable) == 0 {
		rpwq.mu.RUnlock()
		return nil
	}
	rpwq.mu.RUnlock()

	rpwq.mu.Lock()
	defer rpwq.mu.Unlock()

	// Prioritize candidates first
	if len(rpwq.candidates) != 0 {
		last := len(rpwq.candidates) - 1
		item := rpwq.candidates[last]
		rpwq.candidates = rpwq.candidates[:last]
		return item
	}

	// Then triage
	if len(rpwq.triage) != 0 {
		last := len(rpwq.triage) - 1
		item := rpwq.triage[last]
		rpwq.triage = rpwq.triage[:last]
		return item
	}

	// Finally valuable
	if len(rpwq.valuable) != 0 {
		last := len(rpwq.valuable) - 1
		item := rpwq.valuable[last]
		rpwq.valuable = rpwq.valuable[:last]
		return item
	}

	return nil
}

// getQueueStats returns statistics about all queues
func (rpwq *RacePairWorkQueue) getQueueStats() (candidatesCount, triageCount, valuableCount int) {
	rpwq.mu.RLock()
	defer rpwq.mu.RUnlock()
	return len(rpwq.candidates), len(rpwq.triage), len(rpwq.valuable)
}

// hasWork returns true if there are any work items to process
func (rpwq *RacePairWorkQueue) hasWork() bool {
	rpwq.mu.RLock()
	defer rpwq.mu.RUnlock()
	return len(rpwq.candidates) > 0 || len(rpwq.triage) > 0 || len(rpwq.valuable) > 0
}

// enqueueCorpusPair adds a race pair derived from corpus combinations
func (rpwq *RacePairWorkQueue) enqueueCorpusPair(p1, p2 *prog.Prog) {
	pair := &ProgPair{
		p1: p1,
		p2: p2,
	}
	rpwq.enqueue(pair)
}

// enqueueNewCoverPair adds a race pair that potentially brings new race coverage
func (rpwq *RacePairWorkQueue) enqueueNewCoverPair(p1, p2 *prog.Prog, pairID string, races []*ddrd.MayRacePair) {
	pair := &ProgPair{
		p1: p1,
		p2: p2,
	}
	// Create PairProgInfo from the provided data
	info := &ipc.PairProgInfo{
		PairCount:    uint32(len(races)),
		MayRacePairs: make([]ddrd.MayRacePair, len(races)),
	}
	// Copy races to the proper format (dereference pointers)
	for i, race := range races {
		if race != nil {
			info.MayRacePairs[i] = *race
		}
	}
	triage := &PairWorkTriage{
		progPair: pair,
		info:     info,
	}
	rpwq.enqueue(triage)
}

// ===============DDRD====================

// hasActiveWork checks if the race pair work queue has any pending work
func (rpwq *RacePairWorkQueue) hasActiveWork() bool {
	rpwq.mu.RLock()
	defer rpwq.mu.RUnlock()

	return len(rpwq.candidates) > 0 ||
		len(rpwq.triage) > 0 ||
		len(rpwq.valuable) > 0
}
