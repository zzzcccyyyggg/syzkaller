// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package uafvalidate

import (
	"testing"

	"github.com/google/syzkaller/pkg/ddrd"
)

func TestBackoffScore(t *testing.T) {
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
		// Successes are handled by the Verified flag and do not affect BackoffScore.
		// The score depends only on the failure count.
		{"5 failures 1 success", 5, 1, 0.85, 0.95},
		{"5 failures 2 successes", 5, 2, 0.85, 0.95},
		{"only successes", 0, 3, 0.49, 0.51},
		{"balanced", 5, 5, 0.85, 0.95},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := &VarNameBackoffStats{
				Failures:      tt.failures,
				Successes:     tt.successes,
				TotalAttempts: tt.failures + tt.successes,
			}
			conf := stats.BackoffScore()
			if conf < tt.wantMin || conf > tt.wantMax {
				t.Errorf("BackoffScore() = %.3f, want in [%.2f, %.2f]", conf, tt.wantMin, tt.wantMax)
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
		// A lone success with no failures: score=0.5, skipProb=0.5*(1-0.05)≈0.475.
		// Successful pairs are caught by IsVerified before SkipProbability is called.
		{"after success", 0, 1, 1, false, maxSkipProb},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := &VarNameBackoffStats{
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

func TestBackoffScoreProgression(t *testing.T) {
	stats := &VarNameBackoffStats{}

	prevScore := 0.0
	for i := 0; i < 10; i++ {
		stats.RecordFailure()
		score := stats.BackoffScore()

		// The score should monotonically increase.
		if score <= prevScore {
			t.Errorf("Backoff score should increase: prev=%.3f, now=%.3f after %d failures", prevScore, score, i+1)
		}

		// Score increments should decrease (diminishing returns).
		delta := score - prevScore
		t.Logf("After %d failures: score=%.3f, delta=%.3f", i+1, score, delta)
		prevScore = score
	}

	// The score should have an upper bound.
	if prevScore > 0.98 {
		t.Errorf("Backoff score should have upper bound, got %.3f", prevScore)
	}
}

func TestSuccessDoesNotAffectBackoffScore(t *testing.T) {
	stats := &VarNameBackoffStats{}

	// Accumulate 5 failures
	for i := 0; i < 5; i++ {
		stats.RecordFailure()
	}
	scoreAfterFailures := stats.BackoffScore()

	// One success — should not change the score because successes are handled
	// by the Verified flag, not by the formula.
	stats.RecordSuccess()
	scoreAfterSuccess := stats.BackoffScore()

	t.Logf("After 5 failures: %.3f, after 1 success: %.3f",
		scoreAfterFailures, scoreAfterSuccess)

	if scoreAfterSuccess != scoreAfterFailures {
		t.Errorf("BackoffScore should be unchanged after a success: before=%.3f, after=%.3f",
			scoreAfterFailures, scoreAfterSuccess)
	}
}

func TestExplorationGuarantee(t *testing.T) {
	stats := &VarNameBackoffStats{
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

func TestVarNameBackoffStore(t *testing.T) {
	store := NewVarNameBackoffStore(nil) // No DB for testing

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

	if !stats.Verified {
		t.Error("RecordSuccess should mark the VarName pair as verified")
	}

	// The score is failure-only; success is represented by Verified.
	score := stats.BackoffScore()
	t.Logf("After 5 failures and 1 success: score=%.3f", score)
	if score < 0.85 {
		t.Errorf("Backoff score should remain failure-driven after success, got %.3f", score)
	}
	skip, prob, stats = store.ShouldSkip(pair, func() float64 { return 0.99 })
	if !skip || prob != 1.0 || !stats.Verified {
		t.Errorf("Verified pair should be skipped unconditionally: skip=%t prob=%.3f verified=%t",
			skip, prob, stats.Verified)
	}
}

func TestShouldSkipProbabilistic(t *testing.T) {
	store := NewVarNameBackoffStore(nil)

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
	store := NewVarNameBackoffStore(nil)

	// Add some pairs with different backoff levels.
	lowConfPair := &ddrd.MayUAFPair{FreeAccessName: 1, UseAccessName: 1}
	highConfPair := &ddrd.MayUAFPair{FreeAccessName: 2, UseAccessName: 2}

	// Low backoff score: 1 failure
	store.RecordFailure(lowConfPair)

	// High backoff score: 10 failures
	for i := 0; i < 10; i++ {
		store.RecordFailure(highConfPair)
	}

	total, highScore, verified := store.Stats()
	if total != 2 {
		t.Errorf("Total should be 2, got %d", total)
	}
	if highScore != 1 {
		t.Errorf("High score count should be 1, got %d", highScore)
	}
	if verified != 0 {
		t.Errorf("Verified count should be 0, got %d", verified)
	}
}

func TestVarNameVerified(t *testing.T) {
	store := NewVarNameBackoffStore(nil)

	pair := &ddrd.MayUAFPair{
		FreeAccessName: 0xAAAA,
		UseAccessName:  0xBBBB,
	}

	// Initially not verified
	if store.IsVerified(pair) {
		t.Error("Should not be verified initially")
	}

	// Record success with key
	store.RecordSuccessWithKey(pair, "test-entry-key")

	// Now should be verified
	if !store.IsVerified(pair) {
		t.Error("Should be verified after success")
	}

	// ShouldSkip should return true with prob=1.0 for verified pair
	skip, prob, stats := store.ShouldSkip(pair, func() float64 { return 0.0 })
	if !skip {
		t.Error("Should skip verified pair")
	}
	if prob != 1.0 {
		t.Errorf("Skip probability should be 1.0 for verified pair, got %.3f", prob)
	}
	if stats.VerifiedKey != "test-entry-key" {
		t.Errorf("VerifiedKey should be 'test-entry-key', got '%s'", stats.VerifiedKey)
	}

	// Another pair with same VarName but different CallStack should also be skipped
	pair2 := &ddrd.MayUAFPair{
		FreeAccessName: 0xAAAA,
		UseAccessName:  0xBBBB,
		FreeCallStack:  0xDDDD, // Different CallStack
		UseCallStack:   0xEEEE,
	}

	if !store.IsVerified(pair2) {
		t.Error("Pair with same VarName but different CallStack should also be verified")
	}

	skip2, _, _ := store.ShouldSkip(pair2, func() float64 { return 0.0 })
	if !skip2 {
		t.Error("Pair with same VarName but different CallStack should also be skipped")
	}

	// Stats should show 1 verified
	_, _, verified := store.Stats()
	if verified != 1 {
		t.Errorf("Verified count should be 1, got %d", verified)
	}
}
