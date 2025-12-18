// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package uafvalidate

import (
	"testing"

	"github.com/google/syzkaller/pkg/ddrd"
)

func TestHBConfidence(t *testing.T) {
	tests := []struct {
		name      string
		failures  int
		successes int
		wantMin   float64
		wantMax   float64
	}{
		{"no data", 0, 0, 0.49, 0.51},
		{"1 failure", 1, 0, 0.60, 0.80},
		{"5 failures", 5, 0, 0.85, 0.95},
		{"10 failures", 10, 0, 0.90, 0.98},
		{"5 failures 1 success", 5, 1, 0.55, 0.70},
		{"5 failures 2 successes", 5, 2, 0.40, 0.55},
		{"only successes", 0, 3, -0.01, 0.01},
		{"balanced", 5, 5, 0.30, 0.50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := &VarNameHBStats{
				Failures:      tt.failures,
				Successes:     tt.successes,
				TotalAttempts: tt.failures + tt.successes,
			}
			conf := stats.HBConfidence()
			if conf < tt.wantMin || conf > tt.wantMax {
				t.Errorf("HBConfidence() = %.3f, want in [%.2f, %.2f]", conf, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestSkipProbability(t *testing.T) {
	tests := []struct {
		name      string
		failures  int
		successes int
		total     int
		wantZero  bool
		wantMax   float64
	}{
		{"first attempt", 0, 0, 0, true, 0},
		{"after 1 failure", 1, 0, 1, false, maxSkipProb},
		{"after 5 failures", 5, 0, 5, false, maxSkipProb},
		{"after success", 0, 1, 1, true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := &VarNameHBStats{
				Failures:      tt.failures,
				Successes:     tt.successes,
				TotalAttempts: tt.total,
			}
			prob := stats.SkipProbability()
			if tt.wantZero && prob != 0 {
				t.Errorf("SkipProbability() = %.3f, want 0", prob)
			}
			if !tt.wantZero && prob > tt.wantMax {
				t.Errorf("SkipProbability() = %.3f, want <= %.2f", prob, tt.wantMax)
			}
		})
	}
}

func TestVarNamePairKey(t *testing.T) {
	pair := &ddrd.MayUAFPair{
		FreeAccessName: 0x1234567890abcdef,
		UseAccessName:  0xfedcba0987654321,
		FreeCallStack:  0x1111111111111111,
		UseCallStack:   0x2222222222222222,
	}

	key := VarNamePairKey(pair)
	expected := "1234567890abcdef-fedcba0987654321"

	if key != expected {
		t.Errorf("VarNamePairKey() = %s, want %s", key, expected)
	}

	// Different CallStack should produce the same VarNamePairKey
	pair2 := &ddrd.MayUAFPair{
		FreeAccessName: 0x1234567890abcdef,
		UseAccessName:  0xfedcba0987654321,
		FreeCallStack:  0x3333333333333333, // different
		UseCallStack:   0x4444444444444444, // different
	}

	key2 := VarNamePairKey(pair2)
	if key != key2 {
		t.Errorf("Different CallStack should produce same VarNamePairKey: %s vs %s", key, key2)
	}
}

func TestConfidenceProgression(t *testing.T) {
	stats := &VarNameHBStats{}

	prevConf := 0.0
	for i := 0; i < 10; i++ {
		stats.RecordFailure()
		conf := stats.HBConfidence()

		// Confidence should monotonically increase
		if conf <= prevConf {
			t.Errorf("Confidence should increase: prev=%.3f, now=%.3f after %d failures", prevConf, conf, i+1)
		}

		// Confidence increment should decrease (diminishing returns)
		delta := conf - prevConf
		t.Logf("After %d failures: conf=%.3f, delta=%.3f", i+1, conf, delta)
		prevConf = conf
	}

	// Confidence should have an upper bound
	if prevConf > 0.98 {
		t.Errorf("Confidence should have upper bound, got %.3f", prevConf)
	}
}

func TestSuccessReducesConfidence(t *testing.T) {
	stats := &VarNameHBStats{}

	// Accumulate 5 failures
	for i := 0; i < 5; i++ {
		stats.RecordFailure()
	}
	confAfterFailures := stats.HBConfidence()

	// One success
	stats.RecordSuccess()
	confAfterSuccess := stats.HBConfidence()

	// Confidence should decrease significantly
	reduction := confAfterFailures - confAfterSuccess
	t.Logf("After 5 failures: %.3f, after 1 success: %.3f, reduction: %.3f",
		confAfterFailures, confAfterSuccess, reduction)

	if reduction < 0.1 {
		t.Errorf("One success should significantly reduce confidence, only reduced by %.3f", reduction)
	}
}

func TestExplorationGuarantee(t *testing.T) {
	stats := &VarNameHBStats{
		Failures:      100, // Many failures
		Successes:     0,
		TotalAttempts: 100,
	}

	skipProb := stats.SkipProbability()
	verifyProb := 1.0 - skipProb

	// Should guarantee minimum verification probability
	if verifyProb < explorationRate {
		t.Errorf("Should guarantee at least %.0f%% verification, got %.1f%%",
			explorationRate*100, verifyProb*100)
	}

	t.Logf("With 100 failures: skip_prob=%.3f, verify_prob=%.3f", skipProb, verifyProb)
}

func TestVarNameHBStore(t *testing.T) {
	store := NewVarNameHBStore(nil) // No DB for testing

	pair := &ddrd.MayUAFPair{
		FreeAccessName: 0x1234,
		UseAccessName:  0x5678,
		FreeCallStack:  0xaaaa,
		UseCallStack:   0xbbbb,
	}

	// Initial state: should not skip
	skip, prob, _ := store.ShouldSkip(pair, func() float64 { return 0.5 })
	if skip {
		t.Error("Should not skip on first attempt")
	}
	if prob != 0 {
		t.Errorf("Skip probability should be 0 on first attempt, got %.3f", prob)
	}

	// Record some failures
	for i := 0; i < 5; i++ {
		store.RecordFailure(pair)
	}

	// Now should have skip probability
	_, prob, stats := store.ShouldSkip(pair, func() float64 { return 0.99 }) // High rand, won't skip
	if prob <= 0 {
		t.Errorf("Skip probability should be > 0 after failures, got %.3f", prob)
	}
	if stats.Failures != 5 {
		t.Errorf("Should have 5 failures, got %d", stats.Failures)
	}

	// Record success
	store.RecordSuccess(pair)
	_, _, stats = store.ShouldSkip(pair, func() float64 { return 0.99 })
	if stats.Successes != 1 {
		t.Errorf("Should have 1 success, got %d", stats.Successes)
	}

	// Confidence should be lower after success
	conf := stats.HBConfidence()
	t.Logf("After 5 failures and 1 success: conf=%.3f", conf)
	if conf > 0.75 {
		t.Errorf("Confidence should be reduced after success, got %.3f", conf)
	}
}

func TestShouldSkipProbabilistic(t *testing.T) {
	store := NewVarNameHBStore(nil)

	pair := &ddrd.MayUAFPair{
		FreeAccessName: 0x1111,
		UseAccessName:  0x2222,
	}

	// Record 10 failures to get high skip probability
	for i := 0; i < 10; i++ {
		store.RecordFailure(pair)
	}

	_, prob, _ := store.ShouldSkip(pair, func() float64 { return 0.99 })
	t.Logf("Skip probability after 10 failures: %.3f", prob)

	// Test with low rand value - should skip
	skip, _, _ := store.ShouldSkip(pair, func() float64 { return 0.1 })
	if !skip {
		t.Error("Should skip when rand < skip_prob")
	}

	// Test with high rand value - should not skip
	skip, _, _ = store.ShouldSkip(pair, func() float64 { return 0.99 })
	if skip {
		t.Error("Should not skip when rand > skip_prob")
	}
}

func TestStoreStats(t *testing.T) {
	store := NewVarNameHBStore(nil)

	// Add some pairs with different confidence levels
	lowConfPair := &ddrd.MayUAFPair{FreeAccessName: 1, UseAccessName: 1}
	highConfPair := &ddrd.MayUAFPair{FreeAccessName: 2, UseAccessName: 2}

	// Low confidence: 1 failure
	store.RecordFailure(lowConfPair)

	// High confidence: 10 failures
	for i := 0; i < 10; i++ {
		store.RecordFailure(highConfPair)
	}

	total, highConf := store.Stats()
	if total != 2 {
		t.Errorf("Total should be 2, got %d", total)
	}
	if highConf != 1 {
		t.Errorf("High confidence count should be 1, got %d", highConf)
	}
}
