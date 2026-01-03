package uafvalidate

import (
	"math"
	"math/bits"
	"sort"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
)

const defaultMaxBarrierDelays = 32

// DelayManager prepares per-proc start delays for validation attempts.
type DelayManager struct {
	maxSlots    int
	retryBudget int
}

func NewDelayManager(maxSlots, retryBudget int) DelayManager {
	if maxSlots <= 0 {
		maxSlots = defaultMaxBarrierDelays
	}
	if retryBudget <= 0 {
		retryBudget = 1
	}
	if maxSlots > defaultMaxBarrierDelays {
		maxSlots = defaultMaxBarrierDelays
	}
	return DelayManager{maxSlots: maxSlots, retryBudget: retryBudget}
}

func (dm DelayManager) MaxSlots() int {
	return dm.maxSlots
}

func (dm DelayManager) RetryBudget() int {
	return dm.retryBudget
}

// BuildDelays returns a sanitized copy of the replay delays for the entry.
func (dm DelayManager) BuildDelays(entry *fuzzer.UAFCorpusEntry) []int64 {
	if entry == nil {
		return nil
	}
	desired := dm.desiredSlots(entry)
	if desired == 0 {
		return nil
	}
	delays := dm.deriveSmartDelays(entry)
	if len(delays) == 0 {
		delays = append([]int64(nil), entry.ReplayPlan.DelaysMicros...)
	}
	if len(delays) == 0 {
		delays = make([]int64, desired)
	}
	if len(delays) > desired {
		delays = delays[:desired]
	}
	if len(delays) < desired {
		last := int64(0)
		if len(delays) > 0 {
			last = delays[len(delays)-1]
		}
		for len(delays) < desired {
			delays = append(delays, last)
		}
	}
	for i, v := range delays {
		delays[i] = clampDelay(v)
	}
	return delays
}

func (dm DelayManager) deriveSmartDelays(entry *fuzzer.UAFCorpusEntry) []int64 {
	if entry == nil || len(entry.Pairs) == 0 {
		return nil
	}
	primary := selectPrimaryPair(entry.Pairs)
	if primary == nil {
		return nil
	}
	participants := dm.desiredSlots(entry)
	if participants < 2 {
		return nil
	}
	diff := int64(primary.TimeDiff)
	if diff <= 0 {
		return nil
	}
	diff = clampDelay(diff)
	delays := make([]int64, participants)
	delays[0] = diff
	return delays
}

func selectPrimaryPair(pairs []*ddrd.MayUAFPair) *ddrd.MayUAFPair {
	if len(pairs) == 0 {
		return nil
	}
	filtered := make([]*ddrd.MayUAFPair, 0, len(pairs))
	for _, pair := range pairs {
		if pair == nil || pair.TimeDiff == 0 {
			continue
		}
		filtered = append(filtered, pair)
	}
	if len(filtered) == 0 {
		return nil
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].TimeDiff == filtered[j].TimeDiff {
			return filtered[i].Signal < filtered[j].Signal
		}
		return filtered[i].TimeDiff > filtered[j].TimeDiff
	})
	return filtered[0]
}

func (dm DelayManager) desiredSlots(entry *fuzzer.UAFCorpusEntry) int {
	participants := bits.OnesCount64(entry.Barrier.Participants)
	if participants == 0 && entry.Barrier.GroupSize > 0 {
		participants = entry.Barrier.GroupSize
	}
	if participants == 0 {
		participants = len(entry.ReplayPlan.DelaysMicros)
	}
	if participants == 0 {
		return 0
	}
	if participants > dm.maxSlots {
		participants = dm.maxSlots
	}
	return participants
}

func clampDelay(value int64) int64 {
	if value == 0 {
		return 0
	}
	const maxDelay = int64(math.MaxInt32)
	if value > maxDelay {
		return maxDelay
	}
	if value < -maxDelay {
		return -maxDelay
	}
	return value
}
