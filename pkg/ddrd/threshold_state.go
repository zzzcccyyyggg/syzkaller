package ddrd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ThresholdSharedState is the cross-process communication file between fuzzer and validator.
// Fuzzer writes its section; validator writes its section.
// Both read the other's section to coordinate dynamic threshold adjustment.
type ThresholdSharedState struct {
	Validator ValidatorStats `json:"validator"`
	Fuzzer    FuzzerStats    `json:"fuzzer"`
}

// ValidatorStats is written by the validation process.
type ValidatorStats struct {
	PendingCount       int       `json:"pending_count"`
	ProcessedCount     int       `json:"processed_count"`
	SuccessCount       int       `json:"success_count"`
	ProcessingRatePerM float64   `json:"processing_rate_per_min"`
	LastUpdate         time.Time `json:"last_update"`
	Idle               bool      `json:"idle"`
}

// FuzzerStats is written by the fuzzing process.
type FuzzerStats struct {
	CurrentThresholdUs   int64     `json:"current_threshold_us"`
	MRPDiscoveryRatePerM float64   `json:"mrp_discovery_rate_per_min"`
	TotalMRPsDiscovered  int       `json:"total_mrps_discovered"`
	TotalVarNamesFound   int       `json:"total_varnames_found"`
	LastUpdate           time.Time `json:"last_update"`
}

// ThresholdStatePath returns the canonical path for the threshold state file.
func ThresholdStatePath(workdir string) string {
	return filepath.Join(workdir, "threshold-state.json")
}

// ReadThresholdState reads the shared state file. Returns zero-value state on error.
func ReadThresholdState(workdir string) (*ThresholdSharedState, error) {
	path := ThresholdStatePath(workdir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ThresholdSharedState{}, nil
		}
		return nil, fmt.Errorf("read threshold state: %w", err)
	}
	var state ThresholdSharedState
	if err := json.Unmarshal(data, &state); err != nil {
		return &ThresholdSharedState{}, nil
	}
	return &state, nil
}

// WriteValidatorStats atomically updates the validator section of the shared state.
func WriteValidatorStats(workdir string, stats ValidatorStats) error {
	state, _ := ReadThresholdState(workdir)
	if state == nil {
		state = &ThresholdSharedState{}
	}
	state.Validator = stats
	return writeThresholdState(workdir, state)
}

// WriteFuzzerStats atomically updates the fuzzer section of the shared state.
func WriteFuzzerStats(workdir string, stats FuzzerStats) error {
	state, _ := ReadThresholdState(workdir)
	if state == nil {
		state = &ThresholdSharedState{}
	}
	state.Fuzzer = stats
	return writeThresholdState(workdir, state)
}

func writeThresholdState(workdir string, state *ThresholdSharedState) error {
	path := ThresholdStatePath(workdir)
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal threshold state: %w", err)
	}
	// Atomic write: write to temp file + rename
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write threshold state tmp: %w", err)
	}
	return os.Rename(tmpPath, path)
}
