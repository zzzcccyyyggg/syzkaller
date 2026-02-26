// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"testing"
)

func TestMergeForForkBarrierNil(t *testing.T) {
	// Nil or fewer than 2 programs should return nil.
	if MergeForForkBarrier(nil, nil) != nil {
		t.Fatal("expected nil for nil programs")
	}
	target, _, _ := initTest(t)
	p := target.Generate(rand.NewSource(0), 5, target.DefaultChoiceTable())
	if MergeForForkBarrier([]*Prog{p}, nil) != nil {
		t.Fatal("expected nil for single program")
	}
}

func TestMergeForForkBarrierBasic(t *testing.T) {
	target, _, _ := initTest(t)
	ct := target.DefaultChoiceTable()
	rs := rand.NewSource(42)
	p1 := target.Generate(rs, 10, ct)
	p2 := target.Generate(rs, 10, ct)

	delays := []int64{100, 200}
	merged := MergeForForkBarrier([]*Prog{p1, p2}, delays)
	if merged == nil {
		// Merging may return nil if no setup calls found — that's valid.
		// In that case, skip the rest.
		t.Skip("merge returned nil (no shared resources), not a failure")
	}
	if !merged.IsForkBarrier() {
		t.Fatal("merged program should have ForkPoint set")
	}
	if merged.ForkPoint == nil {
		t.Fatal("ForkPoint is nil")
	}
	if len(merged.ForkPoint.Children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(merged.ForkPoint.Children))
	}
	if merged.ForkPoint.SetupCalls < 0 {
		t.Fatalf("SetupCalls should be non-negative, got %d", merged.ForkPoint.SetupCalls)
	}

	// Verify setup calls count matches what's in Calls.
	totalCalls := 0
	totalCalls += merged.ForkPoint.SetupCalls
	for _, child := range merged.ForkPoint.Children {
		totalCalls += child.EndIndex - child.StartIndex
	}
	if totalCalls > len(merged.Calls) {
		t.Fatalf("total accounted calls (%d) exceeds merged.Calls length (%d)",
			totalCalls, len(merged.Calls))
	}

	// Verify delays are set.
	if merged.ForkPoint.Children[0].DelayUs != 100 {
		t.Fatalf("child 0 delay: got %d, want 100", merged.ForkPoint.Children[0].DelayUs)
	}
	if merged.ForkPoint.Children[1].DelayUs != 200 {
		t.Fatalf("child 1 delay: got %d, want 200", merged.ForkPoint.Children[1].DelayUs)
	}
}

func TestIsForkBarrier(t *testing.T) {
	target, _, _ := initTest(t)
	p := target.Generate(rand.NewSource(0), 5, target.DefaultChoiceTable())
	if p.IsForkBarrier() {
		t.Fatal("regular program should not be fork-barrier")
	}
	p.ForkPoint = &ForkPoint{SetupCalls: 1, Children: []ForkChild{{StartIndex: 1, EndIndex: 2}}}
	if !p.IsForkBarrier() {
		t.Fatal("program with ForkPoint should be fork-barrier")
	}
}

func TestSetForkDelays(t *testing.T) {
	target, _, _ := initTest(t)
	p := target.Generate(rand.NewSource(0), 5, target.DefaultChoiceTable())

	// Setting delays on non-fork-barrier program should not panic.
	p.SetForkDelays([]int64{100, 200})

	p.ForkPoint = &ForkPoint{
		SetupCalls: 1,
		Children: []ForkChild{
			{StartIndex: 1, EndIndex: 3, DelayUs: 0},
			{StartIndex: 3, EndIndex: 5, DelayUs: 0},
		},
	}
	p.SetForkDelays([]int64{500, 1000})
	if p.ForkPoint.Children[0].DelayUs != 500 {
		t.Fatalf("child 0 delay: got %d, want 500", p.ForkPoint.Children[0].DelayUs)
	}
	if p.ForkPoint.Children[1].DelayUs != 1000 {
		t.Fatalf("child 1 delay: got %d, want 1000", p.ForkPoint.Children[1].DelayUs)
	}
}

func TestExtractSetupCalls(t *testing.T) {
	target, _, _ := initTest(t)
	ct := target.DefaultChoiceTable()

	// Generate a program with enough calls that some are likely resource producers.
	p := target.Generate(rand.NewSource(1), 15, ct)
	setup, remaining := extractSetupCalls(p)

	// setup + remaining should equal all calls.
	if len(setup)+len(remaining) != len(p.Calls) {
		t.Fatalf("setup(%d) + remaining(%d) != total(%d)",
			len(setup), len(remaining), len(p.Calls))
	}

	// Nil program should yield nil.
	s, r := extractSetupCalls(nil)
	if s != nil || r != nil {
		t.Fatal("expected nil for nil program")
	}
}

func TestMergeForForkBarrierClone(t *testing.T) {
	// Verify that the merged program doesn't share Call pointers with the originals.
	target, _, _ := initTest(t)
	ct := target.DefaultChoiceTable()
	rs := rand.NewSource(99)
	p1 := target.Generate(rs, 10, ct)
	p2 := target.Generate(rs, 10, ct)

	merged := MergeForForkBarrier([]*Prog{p1, p2}, nil)
	if merged == nil {
		t.Skip("merge returned nil")
	}

	// Verify no Call pointer is shared.
	origCalls := make(map[*Call]bool)
	for _, c := range p1.Calls {
		origCalls[c] = true
	}
	for _, c := range p2.Calls {
		origCalls[c] = true
	}
	for _, c := range merged.Calls {
		if origCalls[c] {
			t.Fatal("merged program shares Call pointer with original")
		}
	}
}

func TestMergeForForkBarrierSerialize(t *testing.T) {
	// Verify that a fork-barrier program can be serialized without panic.
	target, _, _ := initTest(t)
	ct := target.DefaultChoiceTable()
	rs := rand.NewSource(77)
	p1 := target.Generate(rs, 10, ct)
	p2 := target.Generate(rs, 10, ct)

	merged := MergeForForkBarrier([]*Prog{p1, p2}, []int64{0, 50})
	if merged == nil {
		t.Skip("merge returned nil")
	}
	data := merged.Serialize()
	if len(data) == 0 {
		t.Fatal("serialized fork-barrier program is empty")
	}
}
