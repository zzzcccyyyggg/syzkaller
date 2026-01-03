# Race-Yield-Guided Program-Group Fuzzing Design

## Overview

This document describes the design and implementation of the Race-Yield-Guided Program-Group Fuzzing framework in DDRD-syzkaller. The framework consists of three main modules (M1', M2, M3) plus a VarName Pair Registry for efficient race detection and fuzzing.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Fuzzer Main Loop                             │
└────────────────┬───────────────────────────────────────┬────────────┘
                 │                                       │
                 ▼                                       ▼
┌────────────────────────────┐        ┌─────────────────────────────┐
│  M1' Hybrid Partner        │        │  M2 Bandit Corpus           │
│  Selector                  │        │  Selector                   │
│  ─────────────────────     │        │  ────────────────────       │
│  • 60% StrongShare         │        │  • Thompson Sampling        │
│  • 30% RacePrior           │        │  • Beta(α,β) per program    │
│  • 10% Explore             │        │  • Feedback: VarName pairs  │
└────────────────┬───────────┘        └──────────────┬──────────────┘
                 │                                   │
                 └──────────────┬────────────────────┘
                                │
                                ▼
                 ┌──────────────────────────────┐
                 │  M3 Window Preserving        │
                 │  Mutation                    │
                 │  ──────────────────────      │
                 │  • Extract race window       │
                 │  • Use FreeCallIdx/UseCallIdx│
                 │  • Protect syscall ordering  │
                 └──────────────┬───────────────┘
                                │
                                ▼
                 ┌──────────────────────────────┐
                 │  VarName Pair Registry       │
                 │  ──────────────────────      │
                 │  • Max 20 stacks per pair    │
                 │  • Deduplication by hash     │
                 └──────────────────────────────┘
```

## Module 1' (M1'): Hybrid Partner Selector

### Purpose
Select a partner program to pair with the current program for concurrent execution to maximize the chance of triggering races.

### Algorithm: Three-Bucket Sampling

```go
type RaceGroupConfig struct {
    StrongShareWeight float64  // 0.6 - High priority
    RacePriorWeight   float64  // 0.3 - Medium priority
    ExploreWeight     float64  // 0.1 - Low priority (random exploration)
}
```

1. **StrongShare Bucket (60%)**: Select programs that share strong key objects with the current program. Strong keys are derived from syscall-accessed objects (e.g., file descriptors, memory regions).

2. **RacePrior Bucket (30%)**: Select programs that have historically produced race conditions when paired with the current program. The `RacePriorIndex` tracks:
   - Program pair → race count mapping
   - Higher counts get higher selection probability

3. **Explore Bucket (10%)**: Random selection for exploration to discover new race pairs.

### Implementation

```go
// RacePriorIndex tracks program pairs that have historically produced races
type RacePriorIndex struct {
    mu    sync.RWMutex
    pairs map[RacePairKey]*RacePairEntry
}

type RacePairKey struct {
    Prog1Hash uint64
    Prog2Hash uint64
}

type RacePairEntry struct {
    Prog1     *prog.Prog
    Prog2     *prog.Prog
    RaceCount int
    LastSeen  time.Time
}
```

## Module 2 (M2): Bandit Corpus Selector

### Purpose
Select which program from the corpus to use as the base for fuzzing, using a Multi-Armed Bandit approach to balance exploitation and exploration.

### Algorithm: Thompson Sampling with Beta Distribution

Each program in the corpus maintains a Beta(α, β) distribution:
- **α (success)**: Incremented when the program produces a new unique VarName pair
- **β (failure)**: Incremented when the program produces no new VarName pairs

```go
type BanditCorpusSelector struct {
    mu           sync.RWMutex
    progStats    map[uint64]*BanditProgStats  // hash → stats
    seenVarPairs map[VarPairKey]struct{}      // for deduplication
}

type BanditProgStats struct {
    prog  *prog.Prog
    alpha float64  // success count (new VarName pairs)
    beta  float64  // failure count (no new pairs)
}
```

### Selection Process

```go
func (b *BanditCorpusSelector) Select() *prog.Prog {
    // Thompson Sampling: sample from Beta(α, β) for each program
    var best *prog.Prog
    var bestSample float64
    
    for _, stats := range b.progStats {
        sample := sampleBeta(stats.alpha, stats.beta)
        if sample > bestSample {
            bestSample = sample
            best = stats.prog
        }
    }
    return best
}
```

### Feedback Update

```go
func (b *BanditCorpusSelector) UpdateWithFeedback(p *prog.Prog, pairs []MayUAFPair) {
    newPairs := 0
    for _, pair := range pairs {
        key := VarPairKey{pair.VarName1, pair.VarName2}
        if _, seen := b.seenVarPairs[key]; !seen {
            b.seenVarPairs[key] = struct{}{}
            newPairs++
        }
    }
    
    hash := p.Hash()
    stats := b.progStats[hash]
    if newPairs > 0 {
        stats.alpha += 1  // reward
    } else {
        stats.beta += 1   // penalty
    }
}
```

## Module 3 (M3): Window Preserving Mutation

### Purpose
When mutating programs that have produced races, preserve the relative ordering of syscalls involved in the race to maintain the race-triggering capability.

### Key Innovation: tid→call_index Mapping

Previous approach used timestamps (FreeSN/UseSN) which were unreliable because they represent sequence numbers in the DDRD trace, not syscall indices.

New approach uses explicit `call_index` tracking:

```c
// In executor: syscall context tracking
typedef struct {
    uint64_t start_ns;     // syscall start timestamp
    uint64_t end_ns;       // syscall end timestamp  
    int      call_index;   // syscall index in program
} SyscallContextHistoryEntry;

typedef struct {
    uint32_t current_call_index;
    uint32_t history_count;
    SyscallContextHistoryEntry history[MAX_SYSCALL_HISTORY];
} SyscallContextEntry;
```

### Race Window Extraction

```go
type RaceWindow struct {
    FreeCallIdx int  // index of Free syscall in program
    UseCallIdx  int  // index of Use syscall in program
    ProgHash    uint64
}

func ExtractRaceWindow(pair *MayUAFPair) *RaceWindow {
    return &RaceWindow{
        FreeCallIdx: pair.FreeCallIdx,
        UseCallIdx:  pair.UseCallIdx,
        ProgHash:    pair.ProgHash,
    }
}
```

### Mutation Constraints

When mutating a program with a known race window:
1. **Preserve Window**: The syscalls at FreeCallIdx and UseCallIdx must not be removed
2. **Maintain Order**: The relative order (Free before Use) must be preserved
3. **Allow Surrounding Changes**: Syscalls outside the window can be freely mutated

```go
func MutateWithWindow(p *prog.Prog, window *RaceWindow) *prog.Prog {
    // Clone the program
    newP := p.Clone()
    
    // Mark protected syscalls
    protected := map[int]bool{
        window.FreeCallIdx: true,
        window.UseCallIdx:  true,
    }
    
    // Mutate only non-protected syscalls
    // ... mutation logic ...
    
    return newP
}
```

## VarName Pair Registry

### Purpose
Limit the number of unique stack traces recorded per VarName pair to prevent explosion of race reports and focus on distinct root causes.

### Configuration

```go
const MaxStacksPerVarNamePair = 20
```

### Implementation

```go
type VarNamePairRegistry struct {
    mu       sync.RWMutex
    registry map[VarPairKey]*VarPairStacks
}

type VarPairKey struct {
    VarName1 string
    VarName2 string
}

type VarPairStacks struct {
    stacks    map[uint64]struct{}  // stack hash → exists
    count     int
    atLimit   bool
}

func (r *VarNamePairRegistry) ShouldRecord(pair *MayUAFPair) bool {
    key := VarPairKey{pair.VarName1, pair.VarName2}
    stackHash := hashStacks(pair.FreeStack, pair.UseStack)
    
    r.mu.Lock()
    defer r.mu.Unlock()
    
    entry, exists := r.registry[key]
    if !exists {
        entry = &VarPairStacks{stacks: make(map[uint64]struct{})}
        r.registry[key] = entry
    }
    
    // Already seen this stack combination
    if _, seen := entry.stacks[stackHash]; seen {
        return false
    }
    
    // At limit
    if entry.count >= MaxStacksPerVarNamePair {
        entry.atLimit = true
        return false
    }
    
    // Record new stack
    entry.stacks[stackHash] = struct{}{}
    entry.count++
    return true
}
```

## Data Flow

### Executor Side (C/C++)

1. **Syscall Context Tracking**:
   ```c
   void execute_syscall(call* c, int call_index) {
       syscall_context_enter(tid, call_index);
       // ... execute syscall ...
       syscall_context_exit(tid);
   }
   ```

2. **Race Event Recording**:
   - DDRD detects potential UAF
   - Looks up syscall context by (tid, timestamp)
   - Records `free_call_idx` and `use_call_idx`

3. **FlatBuffers Serialization**:
   ```c
   DdrdUafPairRaw {
       // ... existing fields ...
       free_tid: int32;
       use_tid: int32;
       free_call_idx: int32;
       use_call_idx: int32;
   }
   ```

### Fuzzer Side (Go)

1. **Receive Race Reports** via FlatBuffers
2. **Convert to MayUAFPair** with call indices
3. **VarName Pair Registry** filters duplicates (max 20)
4. **M2 Bandit Feedback** updates program statistics
5. **M1' Partner Selector** updates race prior index
6. **M3 Window Preserving** extracts race windows for mutation

## File Locations

| Component | File |
|-----------|------|
| Syscall Context Tracking | `executor/ddrd/race_detector.h`, `executor/ddrd/race_detector.c` |
| DDRD Data Structures | `executor/ddrd/ddrd.h` |
| Executor Integration | `executor/executor.cc` |
| FlatBuffers Schema | `pkg/flatrpc/flatrpc.fbs` |
| Go Types | `pkg/ddrd/types.go` |
| Race Report Conversion | `pkg/ddrd/report.go` |
| M1', M2, M3, VarName Registry | `pkg/fuzzer/race_group.go` |

## Configuration Summary

| Parameter | Value | Description |
|-----------|-------|-------------|
| StrongShareWeight | 0.6 | M1' bucket weight for strong key sharing |
| RacePriorWeight | 0.3 | M1' bucket weight for historical race pairs |
| ExploreWeight | 0.1 | M1' bucket weight for random exploration |
| Initial Alpha | 1.0 | M2 Beta distribution initial α |
| Initial Beta | 1.0 | M2 Beta distribution initial β |
| MaxStacksPerVarNamePair | 20 | VarName pair stack limit |
| MAX_SYSCALL_HISTORY | 32 | Max history entries per thread |
| MAX_THREADS | 64 | Max tracked threads |

## Future Improvements

1. **Decay Mechanism**: Add time-based decay for M2 Beta parameters
2. **Adaptive Weights**: Dynamically adjust M1' bucket weights based on effectiveness
3. **Cross-Program Analysis**: Share race information across fuzzing sessions
4. **Priority Queuing**: Prioritize execution of high-value program pairs
