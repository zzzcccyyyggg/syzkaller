# Race-Yield-Guided Program-Group Fuzzing Design

## Overview

This document describes the design and implementation of the Race-Guided Program-Group Fuzzing framework in DDRD-syzkaller. The framework combines M1' partner selection, M2 bandit corpus selection, object linking, pair cooldown, syscall affinity learning, solo filtering, coverage triage, and a VarName Pair Registry.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Fuzzer Main Loop                             │
└────────────────┬───────────────────────────────────────┬────────────┘
                 │                                       │
                 ▼                                       ▼
┌────────────────────────────┐        ┌─────────────────────────────┐
│  M2 Bandit Corpus          │        │  M1' Hybrid Partner         │
│  Selector                  │        │  Selector                   │
│  ────────────────────      │        │  ─────────────────────     │
│  • Thompson Sampling       │        │  • 60% ScoreBased           │
│  • Beta(α,β) per program   │        │  • 30% RacePrior            │
│  • Feedback: VarName pairs │        │  • 10% Explore              │
└──────────────┬─────────────┘        └──────────────┬──────────────┘
               │                                   │
               └──────────────┬────────────────────┘
                              │
                              ▼
                 ┌──────────────────────────────┐
                 │  Object Linking V2           │
                 │  ──────────────────────      │
                 │  • Syscall-type unification  │
                 └──────────────┬───────────────┘
                                │
                                ▼
                 ┌──────────────────────────────┐
                 │  Barrier Execution           │
                 └──────────────┬───────────────┘
                                │
         ┌──────────────────────┼──────────────────────┐
         ▼                      ▼                      ▼
┌────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│ Solo Filter         │  │ Coverage Triage Job  │  │ VarName Pair Registry│
│ (cross-prog only)   │  │ (bandit boost)       │  │ (max 20 stacks/pair) │
└────────────────────┘  └──────────────────────┘  └──────────────────────┘
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

1. **ScoreBased Bucket (60%)**: Select programs by weighted score (Bandit × Length × Affinity × Cooldown).

2. **RacePrior Bucket (30%)**: Select programs that have historically produced race conditions when paired with the current program. The `RacePriorIndex` tracks:
   - Program pair → race count mapping
   - Higher counts get higher selection probability

3. **Explore Bucket (10%)**: Random selection for exploration to discover new race pairs.

### Score Formula

```
PairScore = BanditScore × LengthPenalty × AffinityScore × PairPenalty

BanditScore  = α / (α + β)
LengthPenalty = 1 / (1 + 0.3 * |lenDiff|)
AffinityScore = 0.5 + rawAffinity * AffinityWeight
PairPenalty   = 1.0 (normal) or 0.01 (cooldown)
```

**Constraints**:
- `MaxLengthDiff = 3`
- `MinPairScore = 0.1`

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

The M2 bandit uses a **three-tier reward system** based on discovery type:

| Discovery Type | Alpha Update | Description |
|----------------|--------------|-------------|
| New VarName pair | `α += 10` | Highest value: completely new (FreeAccessName, UseAccessName) |
| New Stack | `α += 2/(1+existingStackCount)` | Medium value: new callstack for existing VarName pair |
| Nothing new | `β += 1` | Failure penalty |

**Harmonic Decay for Stack Discovery**:

The stack reward uses harmonic decay to model diminishing returns:
- 1st stack for a VarName pair: +2.0
- 2nd stack: +1.0
- 10th stack: +0.2
- 100th stack: +0.02

Cumulative reward for discovering 100 stacks ≈ 10 (same as one new VarName pair).

```go
func (b *BanditCorpusSelector) RecordExecution(p *prog.Prog, pairs []*ddrd.MayUAFPair) (newVarNamePairCount, newStackCount int) {
    // ... discovery tracking ...
    
    if newVarNamePairCount > 0 {
        // New VarName pair: high reward
        params.Alpha += float64(newVarNamePairCount) * 10.0
        params.Alpha += stackAlphaBoost  // also add any stack discoveries
    } else if newStackCount > 0 {
        // New stacks only: harmonic decay reward
        // stackAlphaBoost = Σ 2.0/(1+existingStackCount)
        params.Alpha += stackAlphaBoost
    } else {
        // Nothing new: failure
        params.Beta += 1.0
    }
    
    return newVarNamePairCount, newStackCount
}
```

## Object Linking V2

### Purpose
Increase the probability that program pairs access the same kernel objects.

### Strategy
For syscalls of the **same type** between prog1 and prog2, unify resource arguments
in prog2 to match prog1 (e.g., file paths), avoiding brittle path matching.

## Pair Cooldown

### Purpose
Avoid repeatedly executing exhausted (main, partner) pairs.

### Three-Tier Penalty System

Instead of simple consecutive failure counting, the cooldown uses a **three-tier scoring system**:

| Discovery Type | Failure Score Change | Rationale |
|----------------|---------------------|------------|
| New VarName pair | Reset to 0 | Highest value, pair still has potential |
| New Stack only | `+NewStackPenalty` (default: 1) | Some value, gentle penalty |
| Nothing new | `+NoDiscoveryPenalty` (default: 2) | True failure, faster cooldown |

When `FailureScore >= CooldownThreshold` (default: 20), the pair enters cooldown.

### Behavior Examples

With default configuration (threshold=20, stack_penalty=1, no_discovery=2):
- **Only discovers new stacks**: 20 executions to cooldown
- **Discovers nothing**: 10 executions to cooldown
- **Mixed**: 5 stacks + 5 nothing = 5×1 + 5×2 = 15 (not yet cooldown)
- **Occasionally discovers new VarName pair**: Resets, stays active

### Configuration

```go
type PairCooldownConfig struct {
    CooldownThreshold  int // Failure score threshold (default: 20)
    NewStackPenalty    int // Penalty for new stack only (default: 1)
    NoDiscoveryPenalty int // Penalty for no discovery (default: 2)
    CooldownDuration   int // How many selections to skip (default: 200)
}
```

### Policy
- Penalty multiplier during cooldown: `0.01`

## Syscall Affinity Table

### Purpose
Learn which syscall pairs produce more cross-program races and bias selection.

### Affinity
```
Affinity = InteractionRate × Confidence
InteractionRate = Interactions / Executions
Confidence = min(Executions / 100, 1.0)
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

The maximum stacks per VarName pair is configurable (default: 100):

```go
// Default value
const DefaultMaxStacksPerVarPair = 100

// Can be configured via:
// "max_stacks_per_varname_pair": 100
```

### Implementation

```go
type VarNamePairRegistry struct {
    mu            sync.RWMutex
    stacksPerPair map[uint64]map[uint64]bool  // varPairID → stackPairID → exists
    maxStacks     int
}

func (r *VarNamePairRegistry) ShouldRecord(pair *MayUAFPair) bool {
    varPairID := varNamePairID(pair.FreeAccessName, pair.UseAccessName)
    stkPairID := stackPairID(pair.FreeCallStack, pair.UseCallStack)
    
    r.mu.Lock()
    defer r.mu.Unlock()
    
    stacks, exists := r.stacksPerPair[varPairID]
    if !exists {
        // New VarName pair
        r.stacksPerPair[varPairID] = map[uint64]bool{stkPairID: true}
        return true
    }
    
    // Already seen this stack combination
    if stacks[stkPairID] {
        return false
    }
    
    // At limit
    if len(stacks) >= r.maxStacks {
        return false
    }
    
    // Record new stack
    stacks[stkPairID] = true
    return true
}
```

## Coverage Triage Job

### Purpose
When barrier execution discovers new coverage, attribute it to the responsible program(s)
and boost the bandit scores for exploration.

### Flow
1. Solo run prog1 → collect cover1
2. Solo run prog2 → collect cover2
3. If new coverage overlaps cover1/cover2 (≥10% or ≥1 PC), boost bandit
4. Record high-yield interaction in affinity table

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
| M1', M2, VarName Registry, Solo Filter | `pkg/fuzzer/race_group.go` |
| Object Linking V2 | `pkg/fuzzer/object_linking_v2.go` |
| Pair Cooldown | `pkg/fuzzer/pair_cooldown.go` |
| Syscall Affinity Table | `pkg/fuzzer/affinity_table.go` |
| Coverage Triage Job | `pkg/fuzzer/coverage_triage_job.go` |

## Configuration Summary

| Parameter | Value | Description |
|-----------|-------|-------------|
| ScoreBasedWeight | 0.6 | M1' bucket weight for score-based selection |
| RacePriorWeight | 0.3 | M1' bucket weight for historical race pairs |
| ExploreWeight | 0.1 | M1' bucket weight for random exploration |
| MaxLengthDiff | 3 | Max syscall length difference for partners |
| MinPairScore | 0.1 | Minimum score to accept a pair |
| Initial Alpha | 1.0 | M2 Beta distribution initial α |
| Initial Beta | 1.0 | M2 Beta distribution initial β |
| NewVarNamePairReward | 10.0 | M2 Alpha boost for new VarName pair |
| StackRewardBase | 2.0 | M2 Base for harmonic stack reward |
| ExploitRate | 0.8 | M2 exploit probability for high-yield programs |
| HighYieldThreshold | 3 | High-yield threshold for program selection |
| AffinityWeight | 0.2 | Weight for syscall affinity score |
| CooldownThreshold | 20 | Failure score to enter cooldown |
| NewStackPenalty | 1 | Cooldown penalty for new stack only |
| NoDiscoveryPenalty | 2 | Cooldown penalty for no discovery |
| CooldownDuration | 200 | Cooldown length (selection rounds) |
| MaxStacksPerVarNamePair | 100 | VarName pair stack limit |
| MAX_SYSCALL_HISTORY | 32 | Max history entries per thread |
| MAX_THREADS | 64 | Max tracked threads |
| RandomBaselineMode | false | Disable all strategies for A/B testing |

## A/B Testing: Random Baseline Mode

For evaluating the effectiveness of race-guided strategies, a **Random Baseline Mode** is provided.

### Configuration

```json
{
  "experimental": {
    "random_baseline_mode": true
  }
}
```

### Behavior When Enabled

| Component | Normal Mode | Random Baseline Mode |
|-----------|-------------|---------------------|
| M2 Bandit Corpus Selection | Thompson Sampling | Random selection |
| M1' Partner Selection | ScoreBased/RacePrior/Explore | Random selection |
| Pair Cooldown | Three-tier penalty tracking | Disabled |
| Affinity Table | Learning from interactions | Disabled |
| Object Linking | Enabled | Enabled (preserved) |

### Use Case

Run two experiments with identical configurations except for `random_baseline_mode`:

1. **Experiment A (Guided)**: `"random_baseline_mode": false`
2. **Experiment B (Baseline)**: `"random_baseline_mode": true`

Compare:
- VarName pairs discovered over time
- Unique stack combinations found
- Time to first discovery

## Future Improvements

1. **Decay Mechanism**: Add time-based decay for M2 Beta parameters
2. **Adaptive Weights**: Dynamically adjust M1' bucket weights based on effectiveness
3. **Cross-Program Analysis**: Share race information across fuzzing sessions
4. **Priority Queuing**: Prioritize execution of high-value program pairs
