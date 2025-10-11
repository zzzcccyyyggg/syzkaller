// ===============DDRD====================
// UAFPairWorkQueue methods for UAF pair mode
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
	output   []byte // Execution output for logging
}

// PairWorkValuable represents a valuable work item for race pair execution
type PairWorkValuable struct {
	progPair *ProgPair
	score    int
}

// UAFPairWorkQueue holds UAF pair work items for UAF PAIR mode
// This queue is completely separate from normal mode queue
type UAFPairWorkQueue struct {
	mu sync.RWMutex

	// Two types of UAF pair work items
	candidates []*ProgPair       // pairs from corpus combinations
	triage     []*PairWorkTriage // pairs that bring new UAF coverage
	valuable   []*PairWorkValuable
	procs      int
}

// NewUAFPairWorkQueue creates a new UAF pair work queue
func NewUAFPairWorkQueue(procs int) *UAFPairWorkQueue {
	return &UAFPairWorkQueue{
		procs: procs,
	}
}

// enqueue adds work items to the appropriate queues based on item type
func (upwq *UAFPairWorkQueue) enqueue(item interface{}) {
	upwq.mu.Lock()
	defer upwq.mu.Unlock()

	switch v := item.(type) {
	case *ProgPair:
		upwq.candidates = append(upwq.candidates, v)
	case *PairWorkTriage:
		upwq.triage = append(upwq.triage, v)
	case *PairWorkValuable:
		upwq.valuable = append(upwq.valuable, v)
	default:
		panic("unknown work type for UAFPairWorkQueue")
	}
}

func (upwq *UAFPairWorkQueue) enqueueCandidate(progPair *ProgPair) {
	upwq.enqueue(progPair)
}

func (upwq *UAFPairWorkQueue) enqueueTriage(triage *PairWorkTriage) {
	upwq.enqueue(triage)
}

func (upwq *UAFPairWorkQueue) enqueueValuable(valuable *PairWorkValuable) {
	upwq.enqueue(valuable)
}

// dequeue returns the next work item (candidates first, then triage)
func (upwq *UAFPairWorkQueue) dequeue() interface{} {
	upwq.mu.RLock()
	if len(upwq.candidates) == 0 && len(upwq.triage) == 0 && len(upwq.valuable) == 0 {
		upwq.mu.RUnlock()
		return nil
	}
	upwq.mu.RUnlock()

	upwq.mu.Lock()
	defer upwq.mu.Unlock()

	// Triage first
	if len(upwq.triage) != 0 {
		last := len(upwq.triage) - 1
		item := upwq.triage[last]
		upwq.triage = upwq.triage[:last]
		return item
	}

	// Prioritize candidates second
	if len(upwq.candidates) != 0 {
		last := len(upwq.candidates) - 1
		item := upwq.candidates[last]
		upwq.candidates = upwq.candidates[:last]
		return item
	}

	// Finally valuable
	if len(upwq.valuable) != 0 {
		last := len(upwq.valuable) - 1
		item := upwq.valuable[last]
		upwq.valuable = upwq.valuable[:last]
		return item
	}

	return nil
}

// getQueueStats returns statistics about all queues
func (upwq *UAFPairWorkQueue) getQueueStats() (candidatesCount, triageCount, valuableCount int) {
	upwq.mu.RLock()
	defer upwq.mu.RUnlock()
	return len(upwq.candidates), len(upwq.triage), len(upwq.valuable)
}

// enqueueCorpusPair adds a UAF pair derived from corpus combinations
func (upwq *UAFPairWorkQueue) enqueueCorpusPair(p1, p2 *prog.Prog) {
	pair := &ProgPair{
		p1: p1,
		p2: p2,
	}
	upwq.enqueue(pair)
}

// enqueueNewCoverPair adds a UAF pair that potentially brings new UAF coverage
func (upwq *UAFPairWorkQueue) enqueueNewCoverPair(p1, p2 *prog.Prog, pairID string, uafs []*ddrd.MayUAFPair) {
	pair := &ProgPair{
		p1: p1,
		p2: p2,
	}
	// Create PairProgInfo from the provided data
	info := &ipc.PairProgInfo{
		PairCount:   uint32(len(uafs)),
		MayUAFPairs: make([]ddrd.MayUAFPair, len(uafs)),
	}
	// Copy UAFs to the proper format (dereference pointers)
	for i, uaf := range uafs {
		if uaf != nil {
			info.MayUAFPairs[i] = *uaf
		}
	}

	triage := &PairWorkTriage{
		progPair: pair,
		info:     info,
	}
	upwq.enqueue(triage)
}

// ===============DDRD====================
