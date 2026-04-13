# Race-Yield-Guided Program-Group Fuzzing Design

> **⚠️ 历史设计文档 (2026-02-14 更新)**
>
> M1'（Hybrid Partner Selection）、M2（Bandit Corpus Selection）、PairCooldown 已被**完全移除**。
> 当前系统使用**纯随机选择 + ObjectLinker V2**。
> 本文档保留历史设计供参考。当前架构见 [genfuzz_redesign.md](genfuzz_redesign.md)。

## Overview

This document describes the **historical** design of the Race-Guided Program-Group Fuzzing framework.
The M1'/M2/PairCooldown components documented here have been removed due to the Thompson Sampling
over-exploitation problem (positive feedback loop causing program starvation).

**Current architecture (post-cleanup)**:
- Corpus selection: `Corpus.ChooseProgram(rnd)` — pure random
- Partner selection: `Corpus.ChooseProgram(rnd)` — pure random + Clone
- Object Linking V2: preserved — syscall variant unification
- Solo Filter: preserved — cross-program pair filtering
- VarName Pair Registry: preserved — max stacks per pair
- Affinity Table: preserved — syscall interaction learning
- Coverage Triage: preserved — coverage attribution (no bandit boost)

## Architecture (Current)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Fuzzer Main Loop                             │
└────────────────┬───────────────────────────────────────┬────────────┘
                 │                                       │
                 ▼                                       ▼
┌────────────────────────────┐        ┌─────────────────────────────┐
│  Corpus Selection          │        │  Partner Selection          │
│  ────────────────────      │        │  ─────────────────────     │
│  • Random (uniform)        │        │  • Random (uniform)         │
│  • No bandit feedback      │        │  • No scoring/prior         │
└──────────────┬─────────────┘        └──────────────┬──────────────┘
               │                                   │
               └──────────────┬────────────────────┘
                              │
                              ▼
                 ┌──────────────────────────────┐
                 │  Object Linking V2           │
                 │  ──────────────────────      │
                 │  • Two-tier object alignment │
                 │    (same-name + cross-family)│
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
│ (cross-prog only)   │  │ (affinity recording) │  │ (max 100 stacks/pair)│
└────────────────────┘  └──────────────────────┘  └──────────────────────┘
```

---

## Historical Design (Removed Components)

> The following sections document M1'/M2/PairCooldown as they existed before removal.
> They are preserved for historical reference only.

## Module 1' (M1'): Hybrid Partner Selector [REMOVED]

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
type RacePriorIndex struct {
    mu    sync.RWMutex
    index map[string][]*RacePriorEntry  // progSig → partner entries
}
```

> **Note**: The `RacePairKey`/`RacePairEntry` types shown in earlier design drafts have been
> replaced by a simpler `progSig → []*RacePriorEntry` map in the current implementation.
> See `pkg/fuzzer/race_group.go` for the actual structure.

## Module 2 (M2): Bandit Corpus Selector [REMOVED]

### Purpose
Select which program from the corpus to use as the base for fuzzing, using a Multi-Armed Bandit approach to balance exploitation and exploration.

### Algorithm: Thompson Sampling with Beta Distribution

Each program in the corpus maintains a Beta(α, β) distribution:
- **α (success)**: Incremented when the program produces a new unique VarName pair
- **β (failure)**: Incremented when the program produces no new VarName pairs

```go
type BanditCorpusSelector struct {
    mu           sync.RWMutex
    betaParams   map[string]*BetaParams   // progSignature → params
    seenVarPairs map[uint64]struct{}       // for deduplication
}

type BetaParams struct {
    Alpha float64  // success count (new VarName pairs)
    Beta  float64  // failure count (no new pairs)
}
```

### Selection Process

```go
func (b *BanditCorpusSelector) SelectProgramWithBandit(corpus []*prog.Prog) *prog.Prog {
    // Thompson Sampling: sample from Beta(α, β) for each program
    var best *prog.Prog
    var bestSample float64
    
    for _, p := range corpus {
        sig := progSignature(p)
        params := b.getOrCreateParams(sig)
        sample := sampleBeta(params.Alpha, params.Beta)
        if sample > bestSample {
            bestSample = sample
            best = p
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

## Pair Cooldown [REMOVED]

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

> **⚠️ NOT IMPLEMENTED — Removed in current version.**
>
> The M3 module was designed but never fully implemented. The current codebase uses
> standard syzkaller mutation instead. The design below is preserved for reference
> in case this feature is revisited in the future.

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
    maxStacks     int                          // default: 100 (configurable)
}

// RegisterPair checks and records a new stack for a VarName pair.
// Returns true if the pair was accepted (under the stack limit).
func (r *VarNamePairRegistry) RegisterPair(pair *MayUAFPair) bool {
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
3. **VarName Pair Registry** filters duplicates (max 100 stacks per VarName pair)
4. **Affinity Table** records syscall interaction data

## File Locations

| Component | File |
|-----------|------|
| Syscall Context Tracking | `executor/ddrd/race_detector.h`, `executor/ddrd/race_detector.c` |
| DDRD Data Structures | `executor/ddrd/ddrd.h` |
| Executor Integration | `executor/executor.cc` |
| FlatBuffers Schema | `pkg/flatrpc/flatrpc.fbs` |
| Go Types | `pkg/ddrd/types.go` |
| Race Report Conversion | `pkg/ddrd/report.go` |
| M1', M2, VarName Registry, Solo Filter | `pkg/fuzzer/race_group.go` (M1'/M2 removed, Registry/SoloFilter remain) |
| Object Linking V2 | `pkg/fuzzer/object_linking_v2.go` |
| Pair Cooldown | ~~`pkg/fuzzer/pair_cooldown.go`~~ (deleted) |
| Syscall Affinity Table | `pkg/fuzzer/affinity_table.go` |
| Coverage Triage Job | `pkg/fuzzer/coverage_triage_job.go` |

## Configuration Summary

> Parameters marked ~~strikethrough~~ belong to removed components M1'/M2/PairCooldown.

| Parameter | Value | Description |
|-----------|-------|-------------|
| ~~ScoreBasedWeight~~ | ~~0.6~~ | ~~M1' bucket weight for score-based selection~~ |
| ~~RacePriorWeight~~ | ~~0.3~~ | ~~M1' bucket weight for historical race pairs~~ |
| ~~ExploreWeight~~ | ~~0.1~~ | ~~M1' bucket weight for random exploration~~ |
| ~~MaxLengthDiff~~ | ~~3~~ | ~~Max syscall length difference for partners~~ |
| ~~MinPairScore~~ | ~~0.1~~ | ~~Minimum score to accept a pair~~ |
| ~~Initial Alpha~~ | ~~1.0~~ | ~~M2 Beta distribution initial α~~ |
| ~~Initial Beta~~ | ~~1.0~~ | ~~M2 Beta distribution initial β~~ |
| ~~NewVarNamePairReward~~ | ~~10.0~~ | ~~M2 Alpha boost for new VarName pair~~ |
| ~~StackRewardBase~~ | ~~2.0~~ | ~~M2 Base for harmonic stack reward~~ |
| ~~ExploitRate~~ | ~~0.0~~ | ~~M2 exploit probability~~ |
| ~~HighYieldThreshold~~ | ~~3~~ | ~~High-yield threshold~~ |
| ~~AffinityWeight~~ | ~~0.2~~ | ~~Weight for syscall affinity score~~ |
| ~~CooldownThreshold~~ | ~~20~~ | ~~Failure score to enter cooldown~~ |
| ~~NewStackPenalty~~ | ~~1~~ | ~~Cooldown penalty for new stack only~~ |
| ~~NoDiscoveryPenalty~~ | ~~2~~ | ~~Cooldown penalty for no discovery~~ |
| ~~CooldownDuration~~ | ~~200~~ | ~~Cooldown length (selection rounds)~~ |
| MaxStacksPerVarNamePair | 100 | VarName pair stack limit |
| MAX_SYSCALL_HISTORY | 128 | Max history entries per thread |
| MAX_THREADS | 64 | Max tracked threads |
| RandomBaselineMode | false | Disable all strategies for A/B testing |

## A/B Testing: Random Baseline Mode

> **Note**: With M1'/M2 removed, `random_baseline_mode` now only affects Affinity Table recording
> and a few minor code paths. The core selection is already random by default.

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
| Corpus Selection | Random | Random (same) |
| Partner Selection | Random | Random (same) |
| Affinity Table | Learning from interactions | Disabled |
| Object Linking | Enabled | Enabled (preserved) |

## Future Improvements

1. ~~**Decay Mechanism**: Add time-based decay for M2 Beta parameters~~ (M2 removed)
2. ~~**Adaptive Weights**: Dynamically adjust M1' bucket weights based on effectiveness~~ (M1' removed)
3. **Cross-Program Analysis**: Share race information across fuzzing sessions
4. **Resource-Aware Partner Selection**: Leverage syzkaller's `ResourceType`/`ResultArg` system for smarter partner matching
5. **Race-Aware Mutation**: Protect high-affinity syscalls from mutation (see [genfuzz_redesign.md](genfuzz_redesign.md) Module B)
6. **Multi-Strategy Delay Injection**: Inject `syz_delay()` in normal barrier execution (see [genfuzz_redesign.md](genfuzz_redesign.md) Module C)
