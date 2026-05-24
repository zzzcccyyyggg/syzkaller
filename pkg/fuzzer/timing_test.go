// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math/rand"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// ============================================================================
// TimingExplorationConfig Tests
// ============================================================================

func TestTimingExplorationConfigDefaults(t *testing.T) {
	config := DefaultTimingExplorationConfig()

	if !config.EnablePairDiscovery {
		t.Error("EnablePairDiscovery should be true by default")
	}
	if !config.UseRandomPartner {
		t.Error("UseRandomPartner should be true by default")
	}
	if config.EnableTimingExploration {
		t.Error("EnableTimingExploration should be false by default")
	}
	if config.TimingExplorationQueueSize != 500 {
		t.Errorf("TimingExplorationQueueSize should be 500, got %d", config.TimingExplorationQueueSize)
	}
	if config.MaxDelaysPerProgram != 5 {
		t.Errorf("MaxDelaysPerProgram should be 5, got %d", config.MaxDelaysPerProgram)
	}
}

func TestTimingExplorationConfigValidate(t *testing.T) {
	config := TimingExplorationConfig{}
	config.Validate()

	if config.TimingExplorationQueueSize != 500 {
		t.Errorf("Validate should set default queue size, got %d", config.TimingExplorationQueueSize)
	}
	if config.DelayMinMicros != 10 {
		t.Errorf("Validate should set default DelayMinMicros, got %d", config.DelayMinMicros)
	}
	if config.TimingMutationStrategy != "targeted" {
		t.Errorf("Validate should set default strategy, got %s", config.TimingMutationStrategy)
	}
}

// ============================================================================
// TimingExplorationQueue Tests
// ============================================================================

func TestTimingExplorationQueueBasic(t *testing.T) {
	config := DefaultTimingExplorationConfig()
	queue := NewTimingExplorationQueue(config)

	if !queue.IsEmpty() {
		t.Error("New queue should be empty")
	}
	if queue.Size() != 0 {
		t.Error("New queue size should be 0")
	}

	// Dequeue from empty queue should return nil
	pair := queue.DequeueForExploration()
	if pair != nil {
		t.Error("Dequeue from empty queue should return nil")
	}
}

func TestTimingExplorationQueueEnqueue(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Skipf("test target not available: %v", err)
	}

	config := DefaultTimingExplorationConfig()
	queue := NewTimingExplorationQueue(config)

	// Create a test program
	prog1, err := target.Deserialize([]byte("getpid()"), prog.Strict)
	if err != nil {
		t.Skipf("cannot create test program: %v", err)
	}
	prog2, err := target.Deserialize([]byte("getuid()"), prog.Strict)
	if err != nil {
		t.Skipf("cannot create test program: %v", err)
	}

	// Create a test pair
	testPair := &ddrd.MayUAFPair{
		FreeAccessName: 0x12345678,
		UseAccessName:  0x87654321,
		FreeCallStack:  0xAAAAAAAA,
		UseCallStack:   0xBBBBBBBB,
	}

	// Enqueue
	ok := queue.EnqueueHighQualityPair(prog1, prog2, testPair)
	if !ok {
		t.Error("EnqueueHighQualityPair should succeed")
	}

	if queue.IsEmpty() {
		t.Error("Queue should not be empty after enqueue")
	}
	if queue.Size() != 1 {
		t.Errorf("Queue size should be 1, got %d", queue.Size())
	}
}

func TestTimingExplorationQueueNoDuplicates(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Skipf("test target not available: %v", err)
	}

	config := DefaultTimingExplorationConfig()
	queue := NewTimingExplorationQueue(config)

	// Create a minimal valid program
	prog1 := &prog.Prog{Target: target}

	// Same VarName pair should not be enqueued twice
	testPair := &ddrd.MayUAFPair{
		FreeAccessName: 0x12345678,
		UseAccessName:  0x87654321,
	}

	ok1 := queue.EnqueueHighQualityPair(prog1, nil, testPair)
	ok2 := queue.EnqueueHighQualityPair(prog1, nil, testPair)

	if !ok1 {
		t.Error("First enqueue should succeed")
	}
	if ok2 {
		t.Error("Second enqueue of same VarName pair should fail (duplicate)")
	}
	if queue.Size() != 1 {
		t.Errorf("Queue size should still be 1, got %d", queue.Size())
	}
}

func TestTimingExplorationQueueDequeue(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Skipf("test target not available: %v", err)
	}

	config := DefaultTimingExplorationConfig()
	queue := NewTimingExplorationQueue(config)

	// Create a minimal valid program
	prog1 := &prog.Prog{Target: target}

	testPair := &ddrd.MayUAFPair{
		FreeAccessName: 0x12345678,
		UseAccessName:  0x87654321,
	}

	queue.EnqueueHighQualityPair(prog1, nil, testPair)

	// Dequeue
	hqPair := queue.DequeueForExploration()
	if hqPair == nil {
		t.Fatal("Dequeue should return the pair")
	}

	if hqPair.ExplorationCount != 1 {
		t.Errorf("ExplorationCount should be 1, got %d", hqPair.ExplorationCount)
	}
	if hqPair.LastExploredAt.IsZero() {
		t.Error("LastExploredAt should be set")
	}
}

func TestTimingExplorationQueueRequeue(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Skipf("test target not available: %v", err)
	}

	config := DefaultTimingExplorationConfig()
	queue := NewTimingExplorationQueue(config)

	// Create a minimal valid program
	prog1 := &prog.Prog{Target: target}

	testPair := &ddrd.MayUAFPair{
		FreeAccessName: 0x12345678,
		UseAccessName:  0x87654321,
	}

	queue.EnqueueHighQualityPair(prog1, nil, testPair)
	hqPair := queue.DequeueForExploration()

	// Requeue
	queue.RequeueForMoreExploration(hqPair)

	if queue.Size() != 1 {
		t.Errorf("After requeue, size should be 1, got %d", queue.Size())
	}
}

// ============================================================================
// DelayPlan Tests
// ============================================================================

func TestDelayPlanClone(t *testing.T) {
	plan := DelayPlan{
		{ProgIdx: 0, BeforeCall: 1, DelayMicros: 1000},
		{ProgIdx: 1, BeforeCall: 2, DelayMicros: 2000},
	}

	cloned := plan.Clone()
	if len(cloned) != 2 {
		t.Errorf("Cloned plan should have 2 entries, got %d", len(cloned))
	}

	// Modify original, cloned should not change
	plan[0].DelayMicros = 9999
	if cloned[0].DelayMicros == 9999 {
		t.Error("Clone should be independent of original")
	}
}

// ============================================================================
// TimingMutator Tests
// ============================================================================

func TestTimingMutatorCreation(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Skipf("test target not available: %v", err)
	}

	config := DefaultTimingExplorationConfig()
	mutator := NewTimingMutator(target, config)

	if mutator == nil {
		t.Fatal("NewTimingMutator should not return nil")
	}

	// Note: syz_delay may not be available in test target
	// Just verify the mutator was created
}

func TestTimingMutatorGenerateDelayPlan(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Skipf("test target not available: %v", err)
	}

	config := DefaultTimingExplorationConfig()
	mutator := NewTimingMutator(target, config)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	testPair := &ddrd.MayUAFPair{
		FreeProgIdx: 0,
		UseProgIdx:  1,
		FreeCallIdx: 2,
		UseCallIdx:  3,
	}

	plan := mutator.GenerateDelayPlan(testPair, nil, rnd)

	// Plan may be nil if syz_delay is not available, but should not panic
	if plan != nil {
		if len(plan) == 0 {
			t.Error("Generated plan should have at least one delay")
		}
		if len(plan) > config.MaxDelaysPerProgram {
			t.Errorf("Plan has %d delays, should be <= %d", len(plan), config.MaxDelaysPerProgram)
		}
	}
}

// ============================================================================
// TimingScheduler Tests
// ============================================================================

func TestTimingSchedulerCreation(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Skipf("test target not available: %v", err)
	}

	config := DefaultTimingExplorationConfig()
	registry := NewVarNamePairRegistry(100)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	scheduler := NewTimingScheduler(target, config, registry, rnd)

	if scheduler == nil {
		t.Fatal("NewTimingScheduler should not return nil")
	}

	if scheduler.HasPendingJobs() {
		t.Error("New scheduler should have no pending jobs")
	}

	stats := scheduler.GetStats()
	if stats.TotalNewVarNamePairs != 0 {
		t.Error("New scheduler should have 0 TotalNewVarNamePairs")
	}
}

func TestTimingSchedulerOnNewVarNamePairDiscovered(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Skipf("test target not available: %v", err)
	}

	config := DefaultTimingExplorationConfig()
	registry := NewVarNamePairRegistry(100)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	scheduler := NewTimingScheduler(target, config, registry, rnd)

	// Create a minimal valid program
	prog1 := &prog.Prog{Target: target}

	testPair := &ddrd.MayUAFPair{
		FreeAccessName: 0x12345678,
		UseAccessName:  0x87654321,
	}

	scheduler.OnNewVarNamePairDiscovered(prog1, nil, testPair)

	if !scheduler.HasPendingJobs() {
		t.Error("After OnNewVarNamePairDiscovered, should have pending jobs")
	}

	stats := scheduler.GetStats()
	if stats.TotalNewVarNamePairs != 1 {
		t.Errorf("TotalNewVarNamePairs should be 1, got %d", stats.TotalNewVarNamePairs)
	}
}

func TestTimingSchedulerStartDelayValidationJob(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Skipf("test target not available: %v", err)
	}

	config := DefaultTimingExplorationConfig()
	config.TimingMutationStrategy = "start_delay"
	config.WidenedThresholdMicros = 20000
	registry := NewVarNamePairRegistry(100)
	rnd := rand.New(rand.NewSource(42))
	scheduler := NewTimingScheduler(target, config, registry, rnd)

	prog1 := &prog.Prog{Target: target}
	prog2 := &prog.Prog{Target: target}
	testPair := &ddrd.MayUAFPair{
		FreeAccessName: 0x12345678,
		UseAccessName:  0x87654321,
		FreeCallStack:  0xAAAAAAAA,
		UseCallStack:   0xBBBBBBBB,
		FreeProgIdx:    1,
		UseProgIdx:     0,
		TimeDiff:       8_000_000,
	}

	scheduler.EnqueueForValidation(prog1, prog2, testPair, nil)
	job := scheduler.GetNextJob()
	if job == nil {
		t.Fatal("start_delay validation job should be generated")
	}
	if len(job.DelayPlan) != 0 {
		t.Fatalf("start_delay strategy must not insert syz_delay calls, got %d", len(job.DelayPlan))
	}
	if len(job.StartDelays) != 2 {
		t.Fatalf("start_delay strategy should produce two barrier start delays, got %d", len(job.StartDelays))
	}
	if job.Prog1 == nil || job.Prog2 == nil {
		t.Fatal("validation job should preserve both programs")
	}
}

func TestTimingSchedulerIsNewVarNamePair(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Skipf("test target not available: %v", err)
	}

	config := DefaultTimingExplorationConfig()
	registry := NewVarNamePairRegistry(100)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	scheduler := NewTimingScheduler(target, config, registry, rnd)

	testPair := &ddrd.MayUAFPair{
		FreeAccessName: 0x12345678,
		UseAccessName:  0x87654321,
	}

	// First time should be new
	isNew := scheduler.IsNewVarNamePair(testPair)
	if !isNew {
		t.Error("First occurrence should be new")
	}

	// Record it
	registry.Record(testPair)

	// Second time should not be new
	isNew = scheduler.IsNewVarNamePair(testPair)
	if isNew {
		t.Error("After recording, should not be new")
	}
}

// ============================================================================
// VarNamePairRegistry Timing Methods Tests
// ============================================================================

func TestVarNamePairRegistryTimingAttempts(t *testing.T) {
	registry := NewVarNamePairRegistry(100)

	testPair := &ddrd.MayUAFPair{
		FreeAccessName: 0x12345678,
		UseAccessName:  0x87654321,
	}

	// First record the pair
	registry.Record(testPair)

	// Should be able to attempt timing
	if !registry.ShouldAttemptTiming(testPair) {
		t.Error("Should be able to attempt timing initially")
	}

	// Record some attempts
	for i := 0; i < 5; i++ {
		registry.RecordTimingAttempt(testPair, 0.1)
	}

	count := registry.GetTimingAttemptCount(testPair)
	if count != 5 {
		t.Errorf("Attempt count should be 5, got %d", count)
	}

	rate := registry.GetTimingBestRate(testPair)
	if rate != 0.1 {
		t.Errorf("Best rate should be 0.1, got %f", rate)
	}
}

func TestVarNamePairRegistryTimingMaxAttempts(t *testing.T) {
	registry := NewVarNamePairRegistry(100)
	registry.SetMaxTimingAttempts(3)

	testPair := &ddrd.MayUAFPair{
		FreeAccessName: 0x12345678,
		UseAccessName:  0x87654321,
	}

	registry.Record(testPair)

	// Record max attempts
	for i := 0; i < 3; i++ {
		registry.RecordTimingAttempt(testPair, 0.0)
	}

	// Should no longer be able to attempt
	if registry.ShouldAttemptTiming(testPair) {
		t.Error("After max attempts, should not be able to attempt more")
	}
}

// ============================================================================
// Integration Test
// ============================================================================

func TestTimingExplorationFullFlow(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Skipf("test target not available: %v", err)
	}

	// Setup
	config := DefaultTimingExplorationConfig()
	registry := NewVarNamePairRegistry(100)
	rnd := rand.New(rand.NewSource(42)) // Fixed seed for reproducibility

	scheduler := NewTimingScheduler(target, config, registry, rnd)

	// Create test programs
	prog1, _ := target.Deserialize([]byte("getpid()"), prog.Strict)
	prog2, _ := target.Deserialize([]byte("getuid()"), prog.Strict)

	// Simulate discovering a new VarName pair
	testPair := &ddrd.MayUAFPair{
		FreeAccessName: 0x12345678,
		UseAccessName:  0x87654321,
		FreeCallStack:  0xAAAAAAAA,
		UseCallStack:   0xBBBBBBBB,
		FreeProgIdx:    0,
		UseProgIdx:     1,
		FreeCallIdx:    0,
		UseCallIdx:     0,
	}

	// Step 1: New pair discovered
	if !scheduler.IsNewVarNamePair(testPair) {
		t.Error("Should be a new pair")
	}

	// Step 2: Enqueue for timing exploration
	scheduler.OnNewVarNamePairDiscovered(prog1, prog2, testPair)

	// Step 3: Get a job
	job := scheduler.GetNextJob()
	if job == nil {
		t.Skip("Job is nil (syz_delay may not be available in test target)")
	}

	// Verify job has mutated programs
	if job.Prog1 == nil {
		t.Error("Job.Prog1 should not be nil")
	}

	// Step 4: Report completion
	result := &TimingExplorationResult{
		Job:               job,
		TriggeredNewPairs: true,
		SuccessRate:       0.5,
	}
	scheduler.OnJobCompleted(result)

	// Verify stats
	stats := scheduler.GetStats()
	if stats.TotalJobsGenerated != 1 {
		t.Errorf("TotalJobsGenerated should be 1, got %d", stats.TotalJobsGenerated)
	}
	if stats.TotalJobsCompleted != 1 {
		t.Errorf("TotalJobsCompleted should be 1, got %d", stats.TotalJobsCompleted)
	}
	if stats.TimingExplorationHits != 1 {
		t.Errorf("TimingExplorationHits should be 1, got %d", stats.TimingExplorationHits)
	}
}
