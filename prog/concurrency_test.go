// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"testing"
	"time"
)

func TestConcurrencyMutator(t *testing.T) {
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	config := DefaultConcurrencyConfig()
	mutator := NewConcurrencyMutator(target, rnd, config)

	// Create a simple program
	p := &Prog{Target: target}

	// Test mutation
	mutator.MutateForConcurrency(p)

	// Should have added some syscalls
	if len(p.Calls) == 0 {
		t.Errorf("mutation should have added syscalls")
	}
}

func TestConcurrencyGenerator(t *testing.T) {
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	config := DefaultConcurrencyConfig()
	generator := NewConcurrencyGenerator(target, rnd, config)

	// Generate a program
	p := generator.Generate()

	if p == nil {
		t.Fatalf("generator should produce a program")
	}

	if len(p.Calls) == 0 {
		t.Errorf("generated program should have syscalls")
	}

	// Check that generated program has race-prone syscalls
	hasRaceProneSyscall := false
	for _, call := range p.Calls {
		name := call.Meta.Name
		if name == "read" || name == "write" || name == "open" || name == "mmap" {
			hasRaceProneSyscall = true
			break
		}
	}

	if !hasRaceProneSyscall {
		t.Logf("generated program: %s", p.Serialize())
		t.Errorf("generated program should contain race-prone syscalls")
	}
}

func TestConcurrencyAnalyzer(t *testing.T) {
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}

	analyzer := NewConcurrencyAnalyzer(target)

	// Create a program with high race potential
	p := &Prog{Target: target}

	// Add race-prone syscalls
	if meta := target.SyscallMap["read"]; meta != nil {
		args := make([]Arg, len(meta.Args))
		for i, argType := range meta.Args {
			args[i] = argType.DefaultArg(DirIn)
		}
		p.Calls = append(p.Calls, MakeCall(meta, args))
	}

	if meta := target.SyscallMap["write"]; meta != nil {
		args := make([]Arg, len(meta.Args))
		for i, argType := range meta.Args {
			args[i] = argType.DefaultArg(DirIn)
		}
		p.Calls = append(p.Calls, MakeCall(meta, args))
	}

	score := analyzer.AnalyzeConcurrencyPotential(p)

	if score <= 0.5 {
		t.Errorf("program with read/write should have high concurrency potential, got %f", score)
	}
}

func TestTestPairGeneration(t *testing.T) {
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	config := DefaultConcurrencyConfig()
	mutator := NewConcurrencyMutator(target, rnd, config)

	// Create a small corpus
	corpus := make([]*Prog, 0, 5)
	for i := 0; i < 5; i++ {
		p := &Prog{Target: target}
		if meta := target.SyscallMap["open"]; meta != nil {
			args := make([]Arg, len(meta.Args))
			for j, argType := range meta.Args {
				args[j] = argType.DefaultArg(DirIn)
			}
			p.Calls = append(p.Calls, MakeCall(meta, args))
		}
		corpus = append(corpus, p)
	}

	// Generate test pair
	pair := mutator.GenerateTestPair(corpus)

	if pair == nil {
		t.Fatalf("should generate a test pair")
	}

	if pair.Prog1 == nil || pair.Prog2 == nil {
		t.Errorf("test pair should have both programs")
	}

	if pair.ID == "" {
		t.Errorf("test pair should have an ID")
	}

	if pair.Hash1 == "" || pair.Hash2 == "" {
		t.Errorf("test pair should have hashes")
	}
}

func TestConcurrencyHints(t *testing.T) {
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatalf("failed to get target: %v", err)
	}

	// Create a corpus with varying concurrency potential
	corpus := make([]*Prog, 0, 10)

	// High potential program (read/write)
	for i := 0; i < 3; i++ {
		p := &Prog{Target: target}
		if meta := target.SyscallMap["read"]; meta != nil {
			args := make([]Arg, len(meta.Args))
			for j, argType := range meta.Args {
				args[j] = argType.DefaultArg(DirIn)
			}
			p.Calls = append(p.Calls, MakeCall(meta, args))
		}
		if meta := target.SyscallMap["write"]; meta != nil {
			args := make([]Arg, len(meta.Args))
			for j, argType := range meta.Args {
				args[j] = argType.DefaultArg(DirIn)
			}
			p.Calls = append(p.Calls, MakeCall(meta, args))
		}
		corpus = append(corpus, p)
	}

	// Low potential program (getpid)
	for i := 0; i < 3; i++ {
		p := &Prog{Target: target}
		if meta := target.SyscallMap["getpid"]; meta != nil {
			args := make([]Arg, len(meta.Args))
			for j, argType := range meta.Args {
				args[j] = argType.DefaultArg(DirIn)
			}
			p.Calls = append(p.Calls, MakeCall(meta, args))
		}
		corpus = append(corpus, p)
	}

	hints := NewConcurrencyHints(target, corpus)
	pairs := hints.GetBestPairs(3)

	if len(pairs) == 0 {
		t.Errorf("should generate hint pairs")
	}

	// First pairs should be from high-potential programs
	if len(pairs) > 0 && pairs[0] != nil {
		pair := pairs[0]
		if len(pair.Prog1.Calls) == 0 || len(pair.Prog2.Calls) == 0 {
			t.Errorf("hint pairs should have non-empty programs")
		}
	}
}

func BenchmarkConcurrencyMutation(b *testing.B) {
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		b.Fatalf("failed to get target: %v", err)
	}

	rnd := rand.New(rand.NewSource(1))
	config := DefaultConcurrencyConfig()
	mutator := NewConcurrencyMutator(target, rnd, config)

	// Create a base program
	p := &Prog{Target: target}
	if meta := target.SyscallMap["open"]; meta != nil {
		args := make([]Arg, len(meta.Args))
		for i, argType := range meta.Args {
			args[i] = argType.DefaultArg(DirIn)
		}
		p.Calls = append(p.Calls, MakeCall(meta, args))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clone := p.Clone()
		mutator.MutateForConcurrency(clone)
	}
}

func BenchmarkConcurrencyGeneration(b *testing.B) {
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		b.Fatalf("failed to get target: %v", err)
	}

	rnd := rand.New(rand.NewSource(1))
	config := DefaultConcurrencyConfig()
	generator := NewConcurrencyGenerator(target, rnd, config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generator.Generate()
	}
}
