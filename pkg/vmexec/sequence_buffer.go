// Package vmexec provides VM-level execution sequence buffering for UAF analysis
//
// This package implements a simple circular buffer that maintains the most recent
// program pair executions across all processes in a VM. When a UAF is detected,
// we can capture the execution sequence that led to the UAF for analysis and reproduction.
package vmexec

import (
	"encoding/json"
	"sync"
)

// ExecutionRecord represents a single program pair execution
type ExecutionRecord struct {
	SeqID     uint64 `json:"seq_id"`     // Global sequence number (monotonically increasing)
	Prog1Data []byte `json:"prog1_data"` // Serialized program 1 data
	Prog2Data []byte `json:"prog2_data"` // Serialized program 2 data
}

// VMExecutionSequenceBuffer maintains a circular buffer of recent executions
// This buffer is shared across all processes in a VM instance
type VMExecutionSequenceBuffer struct {
	// Core circular buffer
	executions []ExecutionRecord // Circular buffer of execution records
	head       int               // Current write position
	size       int               // Buffer size (number of records to keep)
	count      int               // Current number of records stored

	// Synchronization
	mu    sync.RWMutex // Protects buffer access across multiple processes
	seqID uint64       // Global sequence number generator
}

// NewVMExecutionSequenceBuffer creates a new execution sequence buffer
func NewVMExecutionSequenceBuffer(size int) *VMExecutionSequenceBuffer {
	return &VMExecutionSequenceBuffer{
		executions: make([]ExecutionRecord, size),
		size:       size,
	}
}

// AddExecution adds a new execution record to the buffer
// This is called by each process after executing a program pair
func (vb *VMExecutionSequenceBuffer) AddExecution(prog1Data, prog2Data []byte) {
	vb.mu.Lock()
	defer vb.mu.Unlock()

	// Generate unique sequence ID
	vb.seqID++

	// Create execution record
	record := ExecutionRecord{
		SeqID:     vb.seqID,
		Prog1Data: append([]byte{}, prog1Data...), // Deep copy to avoid data races
		Prog2Data: append([]byte{}, prog2Data...), // Deep copy to avoid data races
	}

	// Add to circular buffer
	vb.executions[vb.head] = record
	vb.head = (vb.head + 1) % vb.size

	if vb.count < vb.size {
		vb.count++
	}
}

// GetRecentExecutions returns the most recent N execution records
// Returns them in chronological order (oldest first, newest last)
func (vb *VMExecutionSequenceBuffer) GetRecentExecutions(n int) []ExecutionRecord {
	vb.mu.RLock()
	defer vb.mu.RUnlock()

	if n > vb.count {
		n = vb.count
	}

	if n == 0 {
		return nil
	}

	result := make([]ExecutionRecord, n)

	// Calculate starting position (n records back from head)
	start := (vb.head - n + vb.size) % vb.size

	// Copy records in chronological order
	for i := 0; i < n; i++ {
		idx := (start + i) % vb.size
		result[i] = vb.executions[idx]
	}

	return result
}

// GetExecutionCount returns the current number of execution records in buffer
func (vb *VMExecutionSequenceBuffer) GetExecutionCount() int {
	vb.mu.RLock()
	defer vb.mu.RUnlock()
	return vb.count
}

// GetLatestSeqID returns the latest sequence ID
func (vb *VMExecutionSequenceBuffer) GetLatestSeqID() uint64 {
	vb.mu.RLock()
	defer vb.mu.RUnlock()
	return vb.seqID
}

// SerializeExecutions converts execution records to JSON format for storage
func SerializeExecutions(executions []ExecutionRecord) ([]byte, error) {
	return json.MarshalIndent(executions, "", "  ")
}
