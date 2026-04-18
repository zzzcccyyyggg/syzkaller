package ddrd

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestThresholdStateReadWrite(t *testing.T) {
	workdir := t.TempDir()

	// Write validator stats
	vstats := ValidatorStats{
		PendingCount:       10,
		ProcessedCount:     100,
		SuccessCount:       5,
		ProcessingRatePerM: 8.3,
		LastUpdate:         time.Now().Truncate(time.Second),
		Idle:               false,
	}
	if err := WriteValidatorStats(workdir, vstats); err != nil {
		t.Fatalf("WriteValidatorStats failed: %v", err)
	}

	// Read back
	state, err := ReadThresholdState(workdir)
	if err != nil {
		t.Fatalf("ReadThresholdState failed: %v", err)
	}
	if state.Validator.PendingCount != 10 {
		t.Errorf("PendingCount: got %d, want 10", state.Validator.PendingCount)
	}
	if state.Validator.ProcessedCount != 100 {
		t.Errorf("ProcessedCount: got %d, want 100", state.Validator.ProcessedCount)
	}

	// Write fuzzer stats (should preserve validator section)
	fstats := FuzzerStats{
		CurrentThresholdUs:   2500,
		MRPDiscoveryRatePerM: 12.5,
		TotalMRPsDiscovered:  350,
		LastUpdate:           time.Now().Truncate(time.Second),
	}
	if err := WriteFuzzerStats(workdir, fstats); err != nil {
		t.Fatalf("WriteFuzzerStats failed: %v", err)
	}

	// Read back — both sections should be present
	state, err = ReadThresholdState(workdir)
	if err != nil {
		t.Fatalf("ReadThresholdState failed: %v", err)
	}
	if state.Validator.PendingCount != 10 {
		t.Errorf("Validator PendingCount lost: got %d, want 10", state.Validator.PendingCount)
	}
	if state.Fuzzer.CurrentThresholdUs != 2500 {
		t.Errorf("Fuzzer CurrentThresholdUs: got %d, want 2500", state.Fuzzer.CurrentThresholdUs)
	}
	if state.Fuzzer.TotalMRPsDiscovered != 350 {
		t.Errorf("Fuzzer TotalMRPsDiscovered: got %d, want 350", state.Fuzzer.TotalMRPsDiscovered)
	}
}

func TestThresholdStateReadNonexistent(t *testing.T) {
	workdir := t.TempDir()
	state, err := ReadThresholdState(workdir)
	if err != nil {
		t.Fatalf("ReadThresholdState should not error for nonexistent file: %v", err)
	}
	if state == nil {
		t.Fatal("ReadThresholdState should return non-nil zero state")
	}
	if state.Validator.PendingCount != 0 || state.Fuzzer.CurrentThresholdUs != 0 {
		t.Error("zero state should have zero values")
	}
}

func TestThresholdStatePath(t *testing.T) {
	path := ThresholdStatePath("/tmp/workdir")
	expected := filepath.Join("/tmp/workdir", "threshold-state.json")
	if path != expected {
		t.Errorf("ThresholdStatePath: got %s, want %s", path, expected)
	}
}

func TestThresholdStateAtomicWrite(t *testing.T) {
	workdir := t.TempDir()

	// Write initial state
	if err := WriteValidatorStats(workdir, ValidatorStats{PendingCount: 1}); err != nil {
		t.Fatal(err)
	}

	// Verify no temp file left behind
	tmpPath := filepath.Join(workdir, "threshold-state.json.tmp")
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("temp file should not exist after successful write")
	}

	// Verify main file exists
	mainPath := filepath.Join(workdir, "threshold-state.json")
	if _, err := os.Stat(mainPath); err != nil {
		t.Errorf("main state file should exist: %v", err)
	}
}
