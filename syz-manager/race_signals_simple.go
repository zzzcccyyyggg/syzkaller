// ===============DDRD====================
// 简化的race信号处理方法，替代复杂的RaceCoverageManager
// ===============DDRD====================

package main

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/signal"
)

// processRaceSignalsForCoverage 简化的race signal处理，替代复杂的RaceCoverageManager
func (mgr *Manager) processRaceSignalsForCoverage(signals signal.Signal, callName string, progHash string) uint64 {
	if len(signals) == 0 {
		return 0
	}

	log.Logf(1, "=== RACE SIGNALS PROCESSING ===")
	log.Logf(1, "Call: %s, Program Hash: %s", callName, progHash[:8])
	log.Logf(1, "Found %d race signals", len(signals))
	log.Logf(1, "=== END RACE SIGNALS ===")

	return uint64(len(signals))
}
