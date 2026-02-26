# Timing Exploration Configuration Guide

## Overview

This document describes the configuration options for the dual-queue timing exploration system used in race-guided fuzzing. The system uses two queues:

1. **Pair Discovery Queue**: Uses random pairing with normal race detection thresholds to discover new variable name pairs
2. **Timing Exploration Queue**: Uses widened thresholds and `syz_delay()` mutations to explore timing variations for high-value pairs

## Configuration Options

All configuration options are placed in the `experimental` section of your `syz-manager` configuration file (e.g., `config.json`).

### Example Configuration

```json
{
  "target": "linux/amd64",
  "http": "127.0.0.1:56741",
  "workdir": "/path/to/workdir",
  "kernel_obj": "/path/to/kernel",
  "image": "/path/to/image",
  "sshkey": "/path/to/ssh/key",
  "syzkaller": "/path/to/syzkaller",
  "procs": 8,
  "type": "qemu",
  "vm": {
    "count": 4,
    "kernel": "/path/to/bzImage",
    "cpu": 2,
    "mem": 2048
  },
  "experimental": {
    "uaf_mode": true,
    "barrier_mode": true,
    "enable_timing_exploration": true,
    "enable_partner_selection": false,
    "enable_race_yield_feedback": false,
    "timing_exploration_queue_size": 500,
    "timing_exploration_ratio": 0.1,
    "delay_min_micros": 10,
    "delay_max_micros": 200000,
    "max_delays_per_program": 5,
    "timing_mutation_strategy": "targeted"
  }
}
```

### Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_timing_exploration` | bool | `false` | Enable the timing exploration queue and `syz_delay()` mutation system |
| `enable_partner_selection` | bool | `false` | Enable intelligent partner selection for race pairs (disabled by default for Pair Discovery) |
| `enable_race_yield_feedback` | bool | `false` | Enable feedback-based yield adaptation for race detection |
| `timing_exploration_queue_size` | int | `500` | Maximum number of programs in the timing exploration queue |
| `timing_exploration_ratio` | float | `0.1` | Fraction of fuzzing time spent on timing exploration (0.0-1.0) |
| `delay_min_micros` | int | `10` | Minimum delay in microseconds for `syz_delay()` |
| `delay_max_micros` | int | `200000` | Maximum delay in microseconds for `syz_delay()` (200ms) |
| `max_delays_per_program` | int | `5` | Maximum number of `syz_delay()` calls to insert per program |
| `timing_mutation_strategy` | string | `"targeted"` | Mutation strategy: `"timediff"`, `"targeted"`, `"binary_search"`, or `"random"` |
| `widened_threshold_micros` | int64 | `500000` | Widened timing threshold (μs) for Phase 1 pair discovery. Allows detecting pairs with larger time differences. |
| `max_attempts_per_pair` | int | `20` | Max timing exploration attempts per unique pair |
| `max_corpus_count_per_varname` | int | `0` (no limit) | Skip timing exploration for VarName pairs with this many corpus entries |
| `success_threshold` | float | `0.1` | Trigger rate threshold to consider exploration successful (0.0-1.0) |
| `executions_per_attempt` | int | `5` | Executions per delay plan to evaluate trigger rate |

## Detailed Field Descriptions

### `enable_timing_exploration`

When enabled, the fuzzer will:
- Maintain a separate timing exploration queue for high-value race pairs
- Insert `syz_delay()` calls to control timing between syscalls
- Use widened race detection thresholds (8x normal) for timing exploration
- Track timing attempts and success rates per variable pair

### `enable_partner_selection`

Controls intelligent partner selection for race pairs:
- **Disabled (default)**: Random pairing mode for Pair Discovery Queue. Better for discovering new pairs without bias.
- **Enabled**: Intelligent pairing based on historical success rates. Useful when focusing on known high-value pairs.

### `enable_race_yield_feedback`

Controls M2 Bandit corpus selection:
- **Disabled (default)**: Random corpus selection for exploration-first strategy
- **Enabled**: Thompson Sampling with Beta(α, β) distribution per program. Biases corpus selection towards programs that historically produced more VarName pairs and stacks.

### `timing_exploration_ratio`

Controls how much fuzzing time is dedicated to timing exploration:
- `0.0`: No timing exploration (all time in Pair Discovery)
- `0.1`: 10% time on timing exploration, 90% on Pair Discovery (recommended)
- `0.5`: Equal time split
- `1.0`: All time on timing exploration (not recommended)

### `timing_mutation_strategy`

Controls how `syz_delay()` calls are mutated:
- `"targeted"` (default): Insert delays near racing syscalls with random durations
- `"timediff"`: **Uses actual time difference from race pair** to calculate optimal delay. If Free happened X µs before Use, it inserts a delay of ~X µs before Free to make them collide. Includes jitter (50%-150%) for exploration.
- `"binary_search"`: Start with targeted, then iteratively refine delay values (±50%)
- `"random"`: Random insertion of delays at any position

## Usage Examples

### Conservative Setup (Discovery Focus)

```json
{
  "experimental": {
    "uaf_mode": true,
    "barrier_mode": true,
    "enable_timing_exploration": true,
    "enable_partner_selection": false,
    "timing_exploration_ratio": 0.05,
    "timing_exploration_queue_size": 200
  }
}
```

### Aggressive Timing Exploration

```json
{
  "experimental": {
    "uaf_mode": true,
    "barrier_mode": true,
    "enable_timing_exploration": true,
    "enable_partner_selection": false,
    "timing_exploration_ratio": 0.2,
    "timing_exploration_queue_size": 1000,
    "delay_max_micros": 500000,
    "max_delays_per_program": 10
  }
}
```

### Pair Discovery Only (No Timing Exploration)

```json
{
  "experimental": {
    "uaf_mode": true,
    "barrier_mode": true,
    "enable_timing_exploration": false,
    "enable_partner_selection": false
  }
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Fuzzer                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────────────┐     ┌──────────────────────┐         │
│   │  Phase 1             │     │  Phase 2              │        │
│   │  Pair Discovery      │     │  Timing Validation    │        │
│   │  Queue               │     │  Queue                │        │
│   │                      │     │                       │        │
│   │  - Random pairing    │────▶│  - syz_delay() mut   │        │
│   │  - Widened threshold │     │  - Normal threshold  │        │
│   │  - New pair discovery│     │  - Timing optimization│        │
│   └──────────────────────┘     └──────────┬───────────┘        │
│            │                               │                     │
│            ▼                               ▼                     │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │              VarNamePairRegistry                         │   │
│   │  - Records timing attempts per pair                     │   │
│   │  - Tracks best timing configurations                    │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└──────────────────────────────────┬──────────────────────────────┘
                                   │ Phase 2 Success
                                   │ (builds UAFCorpusEntry)
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Manager                                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────────────────────────────────┐                  │
│   │  Phase 3: RaceValidateLoop               │                  │
│   │  (wraps StageManager pipeline)           │                  │
│   │                                           │                  │
│   │  ┌────────────────────────────────┐      │                  │
│   │  │ StageManager (online mode)      │      │                  │
│   │  │ - Collection: find stable pairs │      │                  │
│   │  │ - Verification: delay sweep     │      │                  │
│   │  │ - Fork-barrier execution       │      │                  │
│   │  │ - DDRD protocol (UkcPair)      │      │                  │
│   │  └────────────┬───────────────────┘      │                  │
│   │               │                           │                  │
│   │               ▼                           │                  │
│   │  ┌────────────────────────────────┐      │                  │
│   │  │ ExecutorAdapter (per worker)    │      │                  │
│   │  │ - pool.Run() → VM acquisition  │      │                  │
│   │  │ - runForkBarrier() execution   │      │                  │
│   │  │ - Close() → VM release         │      │                  │
│   │  └────────────────────────────────┘      │                  │
│   └──────────────────┬───────────────────────┘                  │
│                      │                                           │
│                      ▼                                           │
│   ┌─────────────────────────┐    ┌──────────────────────┐       │
│   │  ValidationResult        │    │  CrashReproLoop      │      │
│   │  - StablePairs found    ├───▶│  (syzkaller native)  │      │
│   │  - Crash detected       │    │  - C reproducer      │      │
│   │  - Error/timeout        │    │  - syz-repro         │      │
│   └─────────────────────────┘    └──────────────────────┘      │
│                                                                  │
│   VM Pool: [fuzzing VMs | raceValidate VMs | crashRepro VMs]    │
│            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^      │
│            Managed by dispatcher.Pool with ReserveForRun()      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Phase 3: Race Validation (via StageManager Pipeline)

After Phase 2 validates a timing pair with delays, the validated program is automatically
forwarded to the **RaceValidateLoop** in the Manager. This loop wraps the full
**StageManager** pipeline from `pkg/racevalidate` — the same engine used in standalone
UAF Validate mode. This ensures complete consistency between online validation and
batch validation:

**Execution pipeline** (identical to `uaf_validate` mode):
- **Fork-Barrier execution**: Programs merged via `MergeForForkBarrier()`, executed with fork() for shared fd table
- **DDRD protocol**: Proper `ExecFlagCollectDdrdUaf` + `UkcPair` for targeted detection
- **Two-phase validation**: Collection (find stable pairs) → Verification (per-pair delay sweep)
- **Delay sweep**: Progressive start_delay sweep with exponential curve

**How it works**:

1. Phase 2 success callback builds a `UAFCorpusEntry` from the validated timing pair
   (Programs, MergedProg, Barrier, Pairs, ReplayPlan with delays)
2. Entry is deduplicated and submitted via `StageManager.Enqueue()`
3. StageManager workers acquire VMs from the **dispatcher pool's reserved slots**
   (via `pool.Run()`, same mechanism as crash reproduction)
4. Each worker creates an `ExecutorAdapter` with full barrier/fork-barrier support
5. Collection phase: repeat execution to find stable DDRD pairs
6. Verification phase: per-pair targeted verification with delay sweep
7. Results (crash/stable pair detection/failure) are logged and reported

### VM Acquisition Bridge

The race validation ExecutorFactory bridges two different models:
- **Dispatcher pool model**: `pool.Run(callback)` — acquires a reserved VM, runs callback, releases on return
- **StageManager model**: `factory(ctx) → Executor` — returns an executor the caller uses freely

The bridge (`pooledRaceExecutor`) works by:
1. `pool.Run()` acquires VM in a goroutine, creates ExecutorAdapter, sends to channel
2. Factory function reads from channel, returns executor to StageManager worker
3. When StageManager calls `executor.Close()`, it signals the goroutine → `pool.Run` callback returns → VM released

### Race Validation Configuration

Configure under `experimental.race_repro`:

```json
{
  "experimental": {
    "race_repro": {
      "enabled": true,
      "vms": 2,
      "repeat_budget": 100,
      "delay_sweep": true,
      "delay_sweep_steps": 5,
      "delay_max_us": 1000,
      "stability_threshold": 0.3
    }
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable race validation pipeline |
| `vms` | int | `0` | Number of VMs dedicated to race validation |
| `repeat_budget` | int | `50` | RepeatCount for Collection phase |
| `delay_sweep` | bool | `false` | Enable delay sweep during Verification phase |
| `delay_sweep_steps` | int | `5` | Number of delay steps to sweep |
| `delay_max_us` | int64 | `1000` | Max delay during sweep (μs) |
| `stability_threshold` | float | `0.3` | Detection rate threshold for stable validation |
| `enable_snapshot` | bool | `false` | Use VM snapshots for faster reset |

## Related Documentation

- [DDRD Configuration Reference](ddrd_configuration_reference.md) - Complete configuration reference for all DDRD settings (including Race Reproduction)
- [Race Guided Fuzzing Design](race_guided_fuzzing_design.md)
- [UAF Barrier Fuzzing](uaf_barrier_fuzzing.md)
- [DDRD Integration](ddrd_integration_update.md)
