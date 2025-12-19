// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ddrd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestThresholdController_Default(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "threshold_config.json")
	tc := NewThresholdController(configPath)

	if tc.CurrentThreshold() != DefaultThresholdNs {
		t.Errorf("expected default threshold %d, got %d", DefaultThresholdNs, tc.CurrentThreshold())
	}
}

func TestThresholdController_HighBacklog_Decrease(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "threshold_config.json")
	tc := NewThresholdController(configPath)

	// Start with a higher threshold so we can observe decrease
	tc.SetThreshold(100_000_000) // 100ms

	// Scenario: corpus backlog 90% (1000 total, 100 verified) -> should decrease
	initialThreshold := tc.CurrentThreshold()
	tc.UpdateStats(1000, 100, 0, 0)

	newThreshold := tc.CurrentThreshold()
	if newThreshold >= initialThreshold {
		t.Errorf("threshold should decrease with high backlog: %d -> %d", initialThreshold, newThreshold)
	}
	t.Logf("High backlog decrease: %d -> %d", initialThreshold, newThreshold)
}

func TestThresholdController_ZeroBacklog_Increase(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "threshold_config.json")
	tc := NewThresholdController(configPath)

	// Start with a lower threshold
	tc.SetThreshold(100_000_000) // 100ms

	// Scenario: zero backlog (collected=verified). Expect increase (clamped by maxAdjustUp).
	initialThreshold := tc.CurrentThreshold()
	tc.UpdateStats(100, 100, 0, 0)

	newThreshold := tc.CurrentThreshold()
	if newThreshold <= initialThreshold {
		t.Errorf("threshold should increase with zero backlog: %d -> %d", initialThreshold, newThreshold)
	}
	t.Logf("Zero backlog increase (clamped): %d -> %d", initialThreshold, newThreshold)
}

func TestThresholdController_BacklogModerate_Decrease(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "threshold_config.json")
	tc := NewThresholdController(configPath)

	// Start with a higher threshold so we can observe decrease
	tc.SetThreshold(100_000_000) // 100ms

	// Scenario: collected 10000, verified 1000 (backlog 90%) -> decrease
	initialThreshold := tc.CurrentThreshold()
	tc.UpdateStats(10000, 1000, 0, 0)

	newThreshold := tc.CurrentThreshold()
	if newThreshold >= initialThreshold {
		t.Errorf("threshold should decrease with high backlog: %d -> %d", initialThreshold, newThreshold)
	}
	t.Logf("High backlog: %d -> %d", initialThreshold, newThreshold)
}

func TestThresholdController_ZeroBacklog_ClampUp(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "threshold_config.json")
	tc := NewThresholdController(configPath)

	// Scenario: zero backlog; adjust factor 1.5 but clamped by maxAdjustUp (1.2)
	initialThreshold := tc.CurrentThreshold()
	tc.UpdateStats(1000, 1000, 0, 0)

	newThreshold := tc.CurrentThreshold()
	if newThreshold <= initialThreshold {
		t.Errorf("threshold should increase (clamped) at zero backlog: %d -> %d", initialThreshold, newThreshold)
	}
	ratio := float64(newThreshold) / float64(initialThreshold)
	if ratio > 1.21 || ratio < 1.19 {
		t.Errorf("expected ~1.2x clamp increase, got ratio=%.2f", ratio)
	}
	t.Logf("Zero backlog clamped increase: %d -> %d (ratio=%.2f)", initialThreshold, newThreshold, ratio)
}

func TestThresholdController_MinMax(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "threshold_config.json")
	tc := NewThresholdController(configPath)

	// Test minimum clamp
	tc.SetThreshold(1) // Way below minimum
	if tc.CurrentThreshold() != MinThresholdNs {
		t.Errorf("expected minimum threshold %d, got %d", MinThresholdNs, tc.CurrentThreshold())
	}

	// Test maximum clamp
	tc.SetThreshold(1_000_000_000_000) // Way above maximum
	if tc.CurrentThreshold() != MaxThresholdNs {
		t.Errorf("expected maximum threshold %d, got %d", MaxThresholdNs, tc.CurrentThreshold())
	}
}

func TestThresholdController_Persistence(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "threshold_config.json")

	// Create and set threshold
	tc1 := NewThresholdController(configPath)
	tc1.SetThreshold(100_000_000)
	tc1.UpdateStats(500, 250, 50, 25)
	tc1.Save()

	// Create new controller and verify it loads the saved state
	tc2 := NewThresholdController(configPath)
	if tc2.CurrentThreshold() != tc1.CurrentThreshold() {
		t.Errorf("expected loaded threshold %d, got %d", tc1.CurrentThreshold(), tc2.CurrentThreshold())
	}

	stats := tc2.GetStats()
	if stats.TotalCorpus != 500 || stats.VerifiedCorpus != 250 {
		t.Errorf("expected loaded stats corpus=500 verified=250, got corpus=%d verified=%d",
			stats.TotalCorpus, stats.VerifiedCorpus)
	}
}

func TestThresholdController_ConfigFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "threshold_config.json")
	tc := NewThresholdController(configPath)
	tc.SetThreshold(50_000_000)

	// Check file was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Errorf("config file was not created at %s", configPath)
	}
}

func TestThresholdController_ProgressiveAdjustment(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "threshold_config.json")
	tc := NewThresholdController(configPath)

	t.Log("Testing progressive threshold adjustment:")

	// Simulate progressive improvement with reducing backlog
	for i := 0; i < 5; i++ {
		threshold := tc.CurrentThreshold()
		// Each iteration: backlog shrinks (verified catches up)
		tc.UpdateStats(uint64(1000+i*200), uint64(900+i*150), 0, 0)
		newThreshold := tc.CurrentThreshold()
		t.Logf("  Iteration %d: %d -> %d ns", i+1, threshold, newThreshold)
	}
}
