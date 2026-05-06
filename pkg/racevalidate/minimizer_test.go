package uafvalidate

import (
	"context"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/fuzzer"
)

func TestHistoryMinimizerUsesExplicitRunner(t *testing.T) {
	entry := &fuzzer.UAFCorpusEntry{
		ReplayHistory: []*fuzzer.BarrierExecutionRecord{
			{Timestamp: time.Unix(0, 1), GroupID: 1},
			{Timestamp: time.Unix(0, 2), GroupID: 2},
		},
	}

	var seenSizes []int
	runner := func(ctx context.Context, testEntry *fuzzer.UAFCorpusEntry) (*ExecutionResult, error) {
		seenSizes = append(seenSizes, len(testEntry.ReplayHistory))
		if len(testEntry.ReplayHistory) == 1 {
			return &ExecutionResult{TriggeredCount: 1}, nil
		}
		return &ExecutionResult{}, nil
	}

	cfg := Config{
		ExecutionTimeout:        time.Second,
		MinimizationMaxAttempts: 1,
		MinimizationStrategy:    "binary",
	}
	minimizer := NewHistoryMinimizer(runner, cfg, entry)
	result := minimizer.Minimize(context.Background())
	if !result.Success {
		t.Fatalf("expected minimization success, got error: %v", result.Error)
	}
	if result.MinimalCount != 1 {
		t.Fatalf("expected minimal count 1, got %d", result.MinimalCount)
	}
	if len(seenSizes) == 0 || seenSizes[0] != 1 {
		t.Fatalf("expected runner to observe a 1-record subset first, got %v", seenSizes)
	}
}
