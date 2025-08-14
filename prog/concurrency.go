// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package prog provides concurrency testing support for syzkaller
package prog

import (
	"fmt"
	"math/rand"
	"time"
)

// ConcurrencyMode represents the concurrency testing mode
type ConcurrencyMode int

const (
	ConcurrencyModeDisabled ConcurrencyMode = iota // No concurrency testing
	ConcurrencyModeAuto                            // Automatic mode switching
	ConcurrencyModeAlways                          // Always use concurrency testing
)

// ConcurrencyConfig holds configuration for concurrency testing
type ConcurrencyConfig struct {
	Mode                ConcurrencyMode
	MaxPairs            int           // Maximum number of concurrent test pairs
	PairTimeout         time.Duration // Timeout for test pair execution
	SyncWindow          time.Duration // Time window for race detection
	EnableRaceDetection bool          // Enable race detection in executor
	EnableTestPairSync  bool          // Enable test pair synchronization
}

// DefaultConcurrencyConfig returns default configuration for concurrency testing
func DefaultConcurrencyConfig() *ConcurrencyConfig {
	return &ConcurrencyConfig{
		Mode:                ConcurrencyModeAuto,
		MaxPairs:            2,
		PairTimeout:         30 * time.Second,
		SyncWindow:          100 * time.Millisecond,
		EnableRaceDetection: true,
		EnableTestPairSync:  true,
	}
}

// TestPair represents a pair of programs to be tested concurrently
type TestPair struct {
	ID    string
	Prog1 *Prog
	Prog2 *Prog
	Hash1 string
	Hash2 string
}

// ConcurrencyMutator handles mutations for concurrency testing
type ConcurrencyMutator struct {
	target *Target
	rnd    *rand.Rand
	config *ConcurrencyConfig
}

// NewConcurrencyMutator creates a new concurrency mutator
func NewConcurrencyMutator(target *Target, rnd *rand.Rand, config *ConcurrencyConfig) *ConcurrencyMutator {
	if config == nil {
		config = DefaultConcurrencyConfig()
	}
	return &ConcurrencyMutator{
		target: target,
		rnd:    rnd,
		config: config,
	}
}

// GenerateTestPair generates a test pair from existing corpus
func (cm *ConcurrencyMutator) GenerateTestPair(corpus []*Prog) *TestPair {
	if len(corpus) < 2 {
		return nil
	}

	// Select two different programs
	idx1 := cm.rnd.Intn(len(corpus))
	idx2 := cm.rnd.Intn(len(corpus))
	for idx2 == idx1 && len(corpus) > 1 {
		idx2 = cm.rnd.Intn(len(corpus))
	}

	prog1 := corpus[idx1].Clone()
	prog2 := corpus[idx2].Clone()

	// Apply concurrency-specific mutations
	cm.mutateForConcurrency(prog1)
	cm.mutateForConcurrency(prog2)

	// Generate hashes for the programs
	buf1 := make([]byte, ExecBufferSize)
	n1, _ := prog1.SerializeForExec(buf1)
	buf2 := make([]byte, ExecBufferSize)
	n2, _ := prog2.SerializeForExec(buf2)

	return &TestPair{
		ID:    fmt.Sprintf("pair_%d_%d_%d", time.Now().UnixNano(), idx1, idx2),
		Prog1: prog1,
		Prog2: prog2,
		Hash1: fmt.Sprintf("%x", buf1[:n1]),
		Hash2: fmt.Sprintf("%x", buf2[:n2]),
	}
}

// MutateForConcurrency applies concurrency-specific mutations to a program (public method)
func (cm *ConcurrencyMutator) MutateForConcurrency(p *Prog) {
	cm.mutateForConcurrency(p)
}

// mutateForConcurrency applies mutations that are more likely to cause races
func (cm *ConcurrencyMutator) mutateForConcurrency(p *Prog) {
	if len(p.Calls) == 0 {
		return
	}

	// Strategies for concurrency mutations:
	// 1. Add syscalls that operate on shared resources
	// 2. Modify timing-sensitive syscalls
	// 3. Add syscalls that create/destroy resources

	switch cm.rnd.Intn(3) {
	case 0:
		cm.addSharedResourceSyscalls(p)
	case 1:
		cm.modifyTimingSensitive(p)
	case 2:
		cm.addResourceLifecycleSyscalls(p)
	}
}

// addSharedResourceSyscalls adds syscalls that operate on shared resources
func (cm *ConcurrencyMutator) addSharedResourceSyscalls(p *Prog) {
	// Focus on syscalls that are likely to race:
	// - File operations (read, write, open, close)
	// - Memory operations (mmap, munmap, mprotect)
	// - Socket operations
	// - Signal operations

	raceProneSyscalls := []string{
		"read", "write", "pread64", "pwrite64",
		"open", "openat", "close",
		"mmap", "munmap", "mprotect",
		"socket", "bind", "connect", "accept",
		"kill", "signal", "sigaction",
	}

	for _, name := range raceProneSyscalls {
		if meta := cm.target.SyscallMap[name]; meta != nil {
			// Try to add this syscall if it's not already present
			if !cm.hasSyscall(p, meta) && cm.rnd.Intn(3) == 0 {
				args := make([]Arg, len(meta.Args))
				for i, argType := range meta.Args {
					args[i] = argType.DefaultArg(DirIn)
				}
				call := MakeCall(meta, args)
				p.Calls = append(p.Calls, call)
				break
			}
		}
	}
}

// modifyTimingSensitive modifies existing syscalls to be more timing-sensitive
func (cm *ConcurrencyMutator) modifyTimingSensitive(p *Prog) {
	if len(p.Calls) == 0 {
		return
	}

	// Pick a random call and potentially modify its arguments
	// to make it more timing-sensitive
	idx := cm.rnd.Intn(len(p.Calls))
	call := p.Calls[idx]

	// For certain syscalls, modify specific arguments that affect timing
	switch call.Meta.Name {
	case "nanosleep", "usleep", "select", "poll", "epoll_wait":
		// Reduce sleep/wait times to create tighter timing windows
		cm.reduceSleepTimes(call)
	case "read", "write", "pread64", "pwrite64":
		// Modify buffer sizes to create potential race windows
		cm.adjustBufferSizes(call)
	}
}

// addResourceLifecycleSyscalls adds syscalls for resource creation/destruction
func (cm *ConcurrencyMutator) addResourceLifecycleSyscalls(p *Prog) {
	lifecycleSyscalls := []string{
		"open", "openat", "close",
		"socket", "shutdown",
		"mmap", "munmap",
		"pipe", "pipe2",
		"eventfd", "eventfd2",
	}

	for _, name := range lifecycleSyscalls {
		if meta := cm.target.SyscallMap[name]; meta != nil {
			if cm.rnd.Intn(4) == 0 { // 25% chance
				args := make([]Arg, len(meta.Args))
				for i, argType := range meta.Args {
					args[i] = argType.DefaultArg(DirIn)
				}
				call := MakeCall(meta, args)
				p.Calls = append(p.Calls, call)
				break
			}
		}
	}
}

// Helper functions

func (cm *ConcurrencyMutator) hasSyscall(p *Prog, meta *Syscall) bool {
	for _, call := range p.Calls {
		if call.Meta == meta {
			return true
		}
	}
	return false
}

func (cm *ConcurrencyMutator) reduceSleepTimes(call *Call) {
	// Implementation would depend on the specific syscall signature
	// This is a placeholder for actual argument modification logic
}

func (cm *ConcurrencyMutator) adjustBufferSizes(call *Call) {
	// Implementation would depend on the specific syscall signature
	// This is a placeholder for actual argument modification logic
}

// ConcurrencyGenerator generates programs specifically for concurrency testing
type ConcurrencyGenerator struct {
	target *Target
	rnd    *rand.Rand
	config *ConcurrencyConfig
}

// NewConcurrencyGenerator creates a new concurrency generator
func NewConcurrencyGenerator(target *Target, rnd *rand.Rand, config *ConcurrencyConfig) *ConcurrencyGenerator {
	if config == nil {
		config = DefaultConcurrencyConfig()
	}
	return &ConcurrencyGenerator{
		target: target,
		rnd:    rnd,
		config: config,
	}
}

// Generate creates a program designed for concurrency testing
func (cg *ConcurrencyGenerator) Generate() *Prog {
	p := &Prog{
		Target: cg.target,
	}

	// Generate a program with syscalls that are likely to race
	length := 3 + cg.rnd.Intn(8) // 3-10 syscalls

	for i := 0; i < length; i++ {
		meta := cg.selectRaceProneSyscall()
		if meta != nil {
			args := make([]Arg, len(meta.Args))
			for j, argType := range meta.Args {
				args[j] = argType.DefaultArg(DirIn)
			}
			call := MakeCall(meta, args)
			p.Calls = append(p.Calls, call)
		}
	}

	return p
}

// selectRaceProneSyscall selects a syscall that's likely to cause races
func (cg *ConcurrencyGenerator) selectRaceProneSyscall() *Syscall {
	raceProneSyscalls := []string{
		"read", "write", "pread64", "pwrite64",
		"open", "openat", "close",
		"mmap", "munmap", "mprotect", "madvise",
		"socket", "bind", "connect", "accept", "shutdown",
		"pipe", "pipe2", "dup", "dup2",
		"kill", "signal", "sigaction",
		"futex", "semget", "semop",
		"shmat", "shmdt", "shmctl",
	}

	name := raceProneSyscalls[cg.rnd.Intn(len(raceProneSyscalls))]
	return cg.target.SyscallMap[name]
}

// ConcurrencyAnalyzer analyzes programs for concurrency potential
type ConcurrencyAnalyzer struct {
	target *Target
}

// NewConcurrencyAnalyzer creates a new concurrency analyzer
func NewConcurrencyAnalyzer(target *Target) *ConcurrencyAnalyzer {
	return &ConcurrencyAnalyzer{
		target: target,
	}
}

// AnalyzeConcurrencyPotential analyzes how likely a program is to have races
func (ca *ConcurrencyAnalyzer) AnalyzeConcurrencyPotential(p *Prog) float64 {
	if len(p.Calls) == 0 {
		return 0.0
	}

	score := 0.0

	// Analyze syscalls for race potential
	for _, call := range p.Calls {
		score += ca.getSyscallRaceScore(call.Meta.Name)
	}

	// Normalize by program length
	return score / float64(len(p.Calls))
}

// getSyscallRaceScore returns a score for how likely a syscall is to race
func (ca *ConcurrencyAnalyzer) getSyscallRaceScore(name string) float64 {
	raceScores := map[string]float64{
		// High race potential
		"read": 0.9, "write": 0.9, "pread64": 0.8, "pwrite64": 0.8,
		"open": 0.7, "openat": 0.7, "close": 0.8,
		"mmap": 0.8, "munmap": 0.9, "mprotect": 0.7,
		"socket": 0.6, "bind": 0.5, "connect": 0.6, "accept": 0.7,

		// Medium race potential
		"dup": 0.5, "dup2": 0.5, "pipe": 0.4, "pipe2": 0.4,
		"kill": 0.6, "signal": 0.7, "sigaction": 0.5,
		"futex": 0.8, "semget": 0.6, "semop": 0.7,

		// Low race potential
		"getpid": 0.1, "getuid": 0.1, "gettimeofday": 0.2,
		"brk": 0.3, "sbrk": 0.3,
	}

	if score, exists := raceScores[name]; exists {
		return score
	}
	return 0.3 // Default medium-low score for unknown syscalls
}

// ConcurrencyHints provides hints for test pair generation
type ConcurrencyHints struct {
	target *Target
	corpus []*Prog
}

// NewConcurrencyHints creates a new concurrency hints generator
func NewConcurrencyHints(target *Target, corpus []*Prog) *ConcurrencyHints {
	return &ConcurrencyHints{
		target: target,
		corpus: corpus,
	}
}

// GetBestPairs returns the most promising program pairs for concurrency testing
func (ch *ConcurrencyHints) GetBestPairs(maxPairs int) []*TestPair {
	analyzer := NewConcurrencyAnalyzer(ch.target)

	// Score all programs by concurrency potential
	type progScore struct {
		prog  *Prog
		index int
		score float64
	}

	var scores []progScore
	for i, p := range ch.corpus {
		score := analyzer.AnalyzeConcurrencyPotential(p)
		scores = append(scores, progScore{
			prog:  p,
			index: i,
			score: score,
		})
	}

	// Sort by score descending
	for i := 0; i < len(scores)-1; i++ {
		for j := i + 1; j < len(scores); j++ {
			if scores[i].score < scores[j].score {
				scores[i], scores[j] = scores[j], scores[i]
			}
		}
	}

	// Generate pairs from high-scoring programs
	var pairs []*TestPair
	for i := 0; i < len(scores)-1 && len(pairs) < maxPairs; i++ {
		for j := i + 1; j < len(scores) && len(pairs) < maxPairs; j++ {
			// Generate hashes for the programs
			buf1 := make([]byte, ExecBufferSize)
			n1, _ := scores[i].prog.SerializeForExec(buf1)
			buf2 := make([]byte, ExecBufferSize)
			n2, _ := scores[j].prog.SerializeForExec(buf2)

			pair := &TestPair{
				ID:    fmt.Sprintf("hint_pair_%d_%d_%d", time.Now().UnixNano(), i, j),
				Prog1: scores[i].prog.Clone(),
				Prog2: scores[j].prog.Clone(),
				Hash1: fmt.Sprintf("%x", buf1[:n1]),
				Hash2: fmt.Sprintf("%x", buf2[:n2]),
			}
			pairs = append(pairs, pair)
		}
	}

	return pairs
}
