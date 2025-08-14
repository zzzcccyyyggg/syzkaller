// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package main provides enhanced concurrency testing support for syz-fuzzer
package main

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

// ConcurrencyFuzzer handles concurrency-specific fuzzing operations
type ConcurrencyFuzzer struct {
	fuzzer    *Fuzzer
	mutator   *prog.ConcurrencyMutator
	generator *prog.ConcurrencyGenerator
	analyzer  *prog.ConcurrencyAnalyzer
	hints     *prog.ConcurrencyHints

	// Configuration
	config *prog.ConcurrencyConfig

	// Runtime state
	isActive      bool
	lastModeCheck time.Time
	testPairQueue []*prog.TestPair
	maxQueueSize  int
}

// NewConcurrencyFuzzer creates a new concurrency fuzzer
func NewConcurrencyFuzzer(fuzzer *Fuzzer) *ConcurrencyFuzzer {
	target := fuzzer.target
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	config := prog.DefaultConcurrencyConfig()

	cf := &ConcurrencyFuzzer{
		fuzzer:        fuzzer,
		mutator:       prog.NewConcurrencyMutator(target, rnd, config),
		generator:     prog.NewConcurrencyGenerator(target, rnd, config),
		analyzer:      prog.NewConcurrencyAnalyzer(target),
		config:        config,
		isActive:      false,
		maxQueueSize:  20,
		testPairQueue: make([]*prog.TestPair, 0, 20),
	}

	return cf
}

// UpdateCorpus updates the concurrency hints with the latest corpus
func (cf *ConcurrencyFuzzer) UpdateCorpus(corpus []*prog.Prog) {
	cf.hints = prog.NewConcurrencyHints(cf.fuzzer.target, corpus)
}

// IsConcurrencyMode checks if the fuzzer should operate in concurrency mode
func (cf *ConcurrencyFuzzer) IsConcurrencyMode() bool {
	// Cache mode check to avoid frequent RPC calls
	if time.Since(cf.lastModeCheck) < 5*time.Second {
		return cf.isActive
	}

	cf.lastModeCheck = time.Now()

	// Check with manager
	args := &rpctype.CheckModeArgs{}
	res := &rpctype.CheckModeRes{}

	if err := cf.fuzzer.manager.Call("Manager.CheckTestPairMode", args, res); err != nil {
		log.Printf("CheckTestPairMode RPC failed: %v, defaulting to normal mode", err)
		cf.isActive = false
		return false
	}

	if res.IsTestPairMode != cf.isActive {
		log.Printf("Concurrency mode changed: %v -> %v", cf.isActive, res.IsTestPairMode)
		cf.isActive = res.IsTestPairMode

		if cf.isActive {
			cf.onEnterConcurrencyMode()
		} else {
			cf.onExitConcurrencyMode()
		}
	}

	return cf.isActive
}

// onEnterConcurrencyMode handles entering concurrency testing mode
func (cf *ConcurrencyFuzzer) onEnterConcurrencyMode() {
	log.Printf("Entering concurrency testing mode")

	// Update corpus for hints
	cf.fuzzer.corpusMu.RLock()
	corpus := make([]*prog.Prog, len(cf.fuzzer.corpus))
	copy(corpus, cf.fuzzer.corpus)
	cf.fuzzer.corpusMu.RUnlock()

	cf.UpdateCorpus(corpus)

	// Pre-generate some test pairs
	cf.generateTestPairs(5)
}

// onExitConcurrencyMode handles exiting concurrency testing mode
func (cf *ConcurrencyFuzzer) onExitConcurrencyMode() {
	log.Printf("Exiting concurrency testing mode")

	// Clear test pair queue
	cf.testPairQueue = cf.testPairQueue[:0]
}

// generateTestPairs generates test pairs using various strategies
func (cf *ConcurrencyFuzzer) generateTestPairs(count int) {
	if cf.hints == nil {
		return
	}

	// Strategy 1: Use hints for best pairs (50%)
	hintPairs := cf.hints.GetBestPairs(count / 2)
	for _, pair := range hintPairs {
		if len(cf.testPairQueue) < cf.maxQueueSize {
			cf.testPairQueue = append(cf.testPairQueue, pair)
		}
	}

	// Strategy 2: Generate random pairs from corpus (30%)
	cf.fuzzer.corpusMu.RLock()
	corpus := cf.fuzzer.corpus
	for i := 0; i < count*3/10 && len(cf.testPairQueue) < cf.maxQueueSize; i++ {
		if pair := cf.mutator.GenerateTestPair(corpus); pair != nil {
			cf.testPairQueue = append(cf.testPairQueue, pair)
		}
	}
	cf.fuzzer.corpusMu.RUnlock()

	// Strategy 3: Generate completely new programs (20%)
	for i := 0; i < count/5 && len(cf.testPairQueue) < cf.maxQueueSize; i++ {
		prog1 := cf.generator.Generate()
		prog2 := cf.generator.Generate()
		if prog1 != nil && prog2 != nil {
			pair := &prog.TestPair{
				ID:    fmt.Sprintf("gen_pair_%d_%d", time.Now().UnixNano(), i),
				Prog1: prog1,
				Prog2: prog2,
			}
			cf.testPairQueue = append(cf.testPairQueue, pair)
		}
	}
}

// GetNextTestPair returns the next test pair to execute
func (cf *ConcurrencyFuzzer) GetNextTestPair() *prog.TestPair {
	if len(cf.testPairQueue) == 0 {
		cf.generateTestPairs(3)
	}

	if len(cf.testPairQueue) == 0 {
		return nil
	}

	// Pop from front
	pair := cf.testPairQueue[0]
	cf.testPairQueue = cf.testPairQueue[1:]

	return pair
}

// ExecuteTestPair executes a test pair with proper concurrency configuration
func (cf *ConcurrencyFuzzer) ExecuteTestPair(pair *prog.TestPair, proc *Proc) (*TestPairExecutionResult, error) {
	if pair == nil || pair.Prog1 == nil || pair.Prog2 == nil {
		return nil, fmt.Errorf("invalid test pair")
	}

	result := &TestPairExecutionResult{
		PairID:    pair.ID,
		StartTime: time.Now(),
	}

	// Configure execution options for concurrency testing
	opts := *proc.execOpts
	opts.Flags |= ipc.FlagCollectSignal | ipc.FlagCollectCover

	// Enable race detection if configured
	if cf.config.EnableRaceDetection {
		opts.Flags |= ipc.FlagCollectRace // Assuming this flag exists
	}

	// Enable test pair synchronization if configured
	if cf.config.EnableTestPairSync {
		opts.Flags |= ipc.FlagTestPairSync // Assuming this flag exists
	}

	// Ensure clean executor state
	proc.env.RestartIfNeeded(pair.Prog1.Target)

	// Execute first program
	output1, info1, hanged1, err1 := proc.env.Exec(&opts, pair.Prog1)
	result.Info1 = info1
	result.Output1 = output1
	result.Hanged1 = hanged1
	result.Error1 = err1

	if err1 != nil && !hanged1 {
		return result, fmt.Errorf("first program execution failed: %v", err1)
	}

	// Small delay between programs
	time.Sleep(10 * time.Millisecond)

	// Execute second program
	output2, info2, hanged2, err2 := proc.env.Exec(&opts, pair.Prog2)
	result.Info2 = info2
	result.Output2 = output2
	result.Hanged2 = hanged2
	result.Error2 = err2
	result.EndTime = time.Now()

	if err2 != nil && !hanged2 {
		return result, fmt.Errorf("second program execution failed: %v", err2)
	}

	// Analyze for races
	result.RaceDetected = cf.analyzeForRaces(result)

	return result, nil
}

// analyzeForRaces analyzes execution results for potential races
func (cf *ConcurrencyFuzzer) analyzeForRaces(result *TestPairExecutionResult) bool {
	// Check for race-related signals or outputs
	// This is a simplified implementation - full version would parse
	// race detector output, analyze timing, etc.

	if result.Info1 != nil && len(result.Info1.Extra.Signal) > 0 {
		// Check if any signals indicate race conditions
		return true
	}

	if result.Info2 != nil && len(result.Info2.Extra.Signal) > 0 {
		// Check if any signals indicate race conditions
		return true
	}

	// Check output for race indicators
	if len(result.Output1) > 0 || len(result.Output2) > 0 {
		// Parse output for race detection messages
		return cf.parseRaceOutput(result.Output1) || cf.parseRaceOutput(result.Output2)
	}

	return false
}

// parseRaceOutput parses executor output for race detection messages
func (cf *ConcurrencyFuzzer) parseRaceOutput(output []byte) bool {
	outputStr := string(output)

	// Look for race detector keywords
	raceKeywords := []string{
		"KCCWF", "race", "data race", "use-after-free",
		"double-free", "race condition",
	}

	for _, keyword := range raceKeywords {
		if len(outputStr) > 0 {
			// Simple substring check - full implementation would use regex
			for i := 0; i < len(outputStr)-len(keyword); i++ {
				if outputStr[i:i+len(keyword)] == keyword {
					return true
				}
			}
		}
	}

	return false
}

// GenerateConcurrencyCandidate generates a candidate program optimized for concurrency testing
func (cf *ConcurrencyFuzzer) GenerateConcurrencyCandidate() *prog.Prog {
	if !cf.isActive {
		return nil
	}

	// 70% chance to mutate existing corpus for concurrency
	if rand.Intn(10) < 7 {
		cf.fuzzer.corpusMu.RLock()
		corpus := cf.fuzzer.corpus
		if len(corpus) > 0 {
			base := corpus[rand.Intn(len(corpus))].Clone()
			cf.fuzzer.corpusMu.RUnlock()

			// Apply concurrency-specific mutations
			cf.mutator.MutateForConcurrency(base)
			return base
		}
		cf.fuzzer.corpusMu.RUnlock()
	}

	// 30% chance to generate fresh program
	return cf.generator.Generate()
}

// MutateForConcurrency applies concurrency-specific mutations to a program
func (cf *ConcurrencyFuzzer) MutateForConcurrency(p *prog.Prog) {
	if cf.mutator != nil {
		cf.mutator.MutateForConcurrency(p)
	}
}

// TestPairExecutionResult holds the result of executing a test pair
type TestPairExecutionResult struct {
	PairID    string
	StartTime time.Time
	EndTime   time.Time

	// Program 1 results
	Info1   *ipc.ProgInfo
	Output1 []byte
	Hanged1 bool
	Error1  error

	// Program 2 results
	Info2   *ipc.ProgInfo
	Output2 []byte
	Hanged2 bool
	Error2  error

	// Analysis results
	RaceDetected bool
	RaceDetails  []RaceDetail
}

// RaceDetail contains information about a detected race
type RaceDetail struct {
	Type       string // "data-race", "use-after-free", etc.
	Address    uint64
	Variable   string
	Threads    []int
	Confidence float64
}

// GetConcurrencyStats returns statistics about concurrency testing
func (cf *ConcurrencyFuzzer) GetConcurrencyStats() map[string]interface{} {
	return map[string]interface{}{
		"active":          cf.isActive,
		"queue_size":      len(cf.testPairQueue),
		"max_queue_size":  cf.maxQueueSize,
		"last_mode_check": cf.lastModeCheck,
		"config":          cf.config,
	}
}
