// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sync"
	"time"

	"github.com/google/syzkaller/prog"
)

// DefaultHistoryBufferSize is the default capacity for the execution history buffer.
const DefaultHistoryBufferSize = 1000

// DefaultNewVarNamePairHistory is the default number of history records to save for new VarName pairs.
const DefaultNewVarNamePairHistory = 1000

// DefaultNewStackHistory is the default number of history records to save for new stacks.
const DefaultNewStackHistory = 100

// BarrierExecutionRecord records a single barrier execution with its program group.
type BarrierExecutionRecord struct {
	Programs  []*prog.Prog
	Timestamp time.Time
	GroupID   int64
	VMIndex   int // The VM index where this execution happened
}

// Clone creates a deep copy of the record.
func (r *BarrierExecutionRecord) Clone() *BarrierExecutionRecord {
	if r == nil {
		return nil
	}
	clone := &BarrierExecutionRecord{
		Timestamp: r.Timestamp,
		GroupID:   r.GroupID,
		VMIndex:   r.VMIndex,
	}
	if len(r.Programs) > 0 {
		clone.Programs = make([]*prog.Prog, len(r.Programs))
		for i, p := range r.Programs {
			if p != nil {
				clone.Programs[i] = p.Clone()
			}
		}
	}
	return clone
}

// VMHistoryBuffers manages per-VM execution history buffers.
// Each VM has its own independent ring buffer to track execution history.
// When a VM restarts, its history should be cleared.
type VMHistoryBuffers struct {
	mu       sync.RWMutex
	buffers  map[int]*ExecutionHistoryBuffer
	capacity int // capacity for each VM's buffer
}

// NewVMHistoryBuffers creates a new per-VM history buffer manager.
func NewVMHistoryBuffers(capacityPerVM int) *VMHistoryBuffers {
	if capacityPerVM <= 0 {
		capacityPerVM = DefaultHistoryBufferSize
	}
	return &VMHistoryBuffers{
		buffers:  make(map[int]*ExecutionHistoryBuffer),
		capacity: capacityPerVM,
	}
}

// getOrCreate returns the buffer for a specific VM, creating it if necessary.
func (vmb *VMHistoryBuffers) getOrCreate(vmIndex int) *ExecutionHistoryBuffer {
	if vmb == nil {
		return nil
	}
	vmb.mu.Lock()
	defer vmb.mu.Unlock()

	buf, exists := vmb.buffers[vmIndex]
	if !exists {
		buf = NewExecutionHistoryBuffer(vmb.capacity)
		vmb.buffers[vmIndex] = buf
	}
	return buf
}

// AddPrograms adds a program group execution record to a specific VM's history.
func (vmb *VMHistoryBuffers) AddPrograms(vmIndex int, programs []*prog.Prog, groupID int64) {
	if vmb == nil || len(programs) == 0 {
		return
	}
	buf := vmb.getOrCreate(vmIndex)
	if buf == nil {
		return
	}
	record := &BarrierExecutionRecord{
		Programs:  programs,
		Timestamp: time.Now(),
		GroupID:   groupID,
		VMIndex:   vmIndex,
	}
	buf.Add(record)
}

// GetLatest returns up to n most recent records from a specific VM's history.
func (vmb *VMHistoryBuffers) GetLatest(vmIndex int, n int) []*BarrierExecutionRecord {
	if vmb == nil || n <= 0 {
		return nil
	}
	vmb.mu.RLock()
	buf, exists := vmb.buffers[vmIndex]
	vmb.mu.RUnlock()

	if !exists || buf == nil {
		return nil
	}
	return buf.GetLatest(n)
}

// ClearVM clears the history buffer for a specific VM (e.g., on VM restart).
func (vmb *VMHistoryBuffers) ClearVM(vmIndex int) {
	if vmb == nil {
		return
	}
	vmb.mu.Lock()
	defer vmb.mu.Unlock()

	if buf, exists := vmb.buffers[vmIndex]; exists {
		buf.Clear()
	}
}

// ClearAll clears all VM history buffers (e.g., on UAF mode activation).
func (vmb *VMHistoryBuffers) ClearAll() {
	if vmb == nil {
		return
	}
	vmb.mu.Lock()
	defer vmb.mu.Unlock()

	for vmIndex := range vmb.buffers {
		delete(vmb.buffers, vmIndex)
	}
}

// Size returns the current size of a specific VM's history buffer.
func (vmb *VMHistoryBuffers) Size(vmIndex int) int {
	if vmb == nil {
		return 0
	}
	vmb.mu.RLock()
	buf, exists := vmb.buffers[vmIndex]
	vmb.mu.RUnlock()

	if !exists || buf == nil {
		return 0
	}
	return buf.Size()
}

// TotalSize returns the total number of records across all VMs.
func (vmb *VMHistoryBuffers) TotalSize() int {
	if vmb == nil {
		return 0
	}
	vmb.mu.RLock()
	defer vmb.mu.RUnlock()

	total := 0
	for _, buf := range vmb.buffers {
		if buf != nil {
			total += buf.Size()
		}
	}
	return total
}

// ExecutionHistoryBuffer is a thread-safe ring buffer that maintains the last N barrier executions.
type ExecutionHistoryBuffer struct {
	mu       sync.RWMutex
	records  []*BarrierExecutionRecord
	head     int // next write position
	size     int // current number of elements
	capacity int // maximum capacity
}

// NewExecutionHistoryBuffer creates a new history buffer with the specified capacity.
func NewExecutionHistoryBuffer(capacity int) *ExecutionHistoryBuffer {
	if capacity <= 0 {
		capacity = DefaultHistoryBufferSize
	}
	return &ExecutionHistoryBuffer{
		records:  make([]*BarrierExecutionRecord, capacity),
		capacity: capacity,
	}
}

// Add adds a new execution record to the buffer.
// If the buffer is full, the oldest record is overwritten.
func (buf *ExecutionHistoryBuffer) Add(record *BarrierExecutionRecord) {
	if buf == nil || record == nil {
		return
	}
	buf.mu.Lock()
	defer buf.mu.Unlock()

	// Clone the record to ensure we own the data
	buf.records[buf.head] = record.Clone()
	buf.head = (buf.head + 1) % buf.capacity
	if buf.size < buf.capacity {
		buf.size++
	}
}

// AddPrograms is a convenience method to add a program group with current timestamp.
func (buf *ExecutionHistoryBuffer) AddPrograms(programs []*prog.Prog, groupID int64) {
	if buf == nil || len(programs) == 0 {
		return
	}
	record := &BarrierExecutionRecord{
		Programs:  programs,
		Timestamp: time.Now(),
		GroupID:   groupID,
	}
	buf.Add(record)
}

// GetLatest returns up to n most recent records, ordered from oldest to newest.
// The returned records are clones and safe to modify.
func (buf *ExecutionHistoryBuffer) GetLatest(n int) []*BarrierExecutionRecord {
	if buf == nil || n <= 0 {
		return nil
	}
	buf.mu.RLock()
	defer buf.mu.RUnlock()

	if buf.size == 0 {
		return nil
	}

	// Determine how many records to return
	count := n
	if count > buf.size {
		count = buf.size
	}

	result := make([]*BarrierExecutionRecord, count)

	// Calculate the starting position for the oldest record we want
	// head points to next write position, so head-1 is the newest, head-size is the oldest
	startIdx := (buf.head - count + buf.capacity) % buf.capacity

	for i := 0; i < count; i++ {
		idx := (startIdx + i) % buf.capacity
		if buf.records[idx] != nil {
			result[i] = buf.records[idx].Clone()
		}
	}

	return result
}

// GetAll returns all records in the buffer, ordered from oldest to newest.
func (buf *ExecutionHistoryBuffer) GetAll() []*BarrierExecutionRecord {
	if buf == nil {
		return nil
	}
	buf.mu.RLock()
	size := buf.size
	buf.mu.RUnlock()
	return buf.GetLatest(size)
}

// Size returns the current number of records in the buffer.
func (buf *ExecutionHistoryBuffer) Size() int {
	if buf == nil {
		return 0
	}
	buf.mu.RLock()
	defer buf.mu.RUnlock()
	return buf.size
}

// Capacity returns the maximum capacity of the buffer.
func (buf *ExecutionHistoryBuffer) Capacity() int {
	if buf == nil {
		return 0
	}
	return buf.capacity
}

// Clear removes all records from the buffer.
func (buf *ExecutionHistoryBuffer) Clear() {
	if buf == nil {
		return
	}
	buf.mu.Lock()
	defer buf.mu.Unlock()
	for i := range buf.records {
		buf.records[i] = nil
	}
	buf.head = 0
	buf.size = 0
}
