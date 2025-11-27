package uafvalidate

import (
	"math"
	"math/bits"

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
	delays := append([]int64(nil), entry.ReplayPlan.DelaysMicros...)
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
