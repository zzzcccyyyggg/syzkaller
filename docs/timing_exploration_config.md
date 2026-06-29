# Timing Exploration Configuration Guide

## Overview

This is a legacy configuration guide for reproducing the optional dual-queue
timing exploration system. Current MRPFuzz paper experiments keep this path
disabled (`enable_timing_exploration=false`) and use the lightweight May-Race
Pair discovery path instead.

When explicitly re-enabled for historical comparison, the system uses two queues:

1. **Pair Discovery Queue**: Uses random pairing with normal race detection thresholds to discover new variable name pairs
2. **Timing Exploration Queue**: Uses widened thresholds and `syz_delay()` mutations to explore timing variations for high-value pairs

## Configuration Options

All configuration options are placed in the `experimental` section of your `syz-manager` configuration file (e.g., `config.json`).

### Legacy Reproduction Configuration

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
| `widened_threshold_micros` | int64 | `500000` | Widened timing threshold (μs) for Phase 1 pair discovery. In dynamic-threshold mode it acts as the minimum Phase 1 discovery window. |
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

When dynamic threshold is enabled, the widened threshold is not used as a cap. Instead:
- `Phase 1 threshold = max(current normal threshold * 8, widened_threshold_micros)`
- `Phase 2 threshold = current normal threshold`

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
│   │  Pair Discovery      │     │  Timing Exploration   │        │
│   │  Queue               │     │  Queue                │        │
│   │                      │     │                       │        │
│   │  - Random pairing    │────▶│  - syz_delay() mut   │        │
│   │  - Normal threshold  │     │  - Widened threshold │        │
│   │  - New pair discovery│     │  - Timing optimization│        │
│   └──────────────────────┘     └──────────────────────┘        │
│            │                            │                        │
│            ▼                            ▼                        │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │              VarNamePairRegistry                         │   │
│   │                                                          │   │
│   │  - Records timing attempts per pair                     │   │
│   │  - Tracks best timing configurations                    │   │
│   │  - Manages exploration queue additions                  │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Related Documentation

- [DDRD Configuration Reference](ddrd_configuration_reference.md) - Complete configuration reference for all DDRD settings
- [Race Guided Fuzzing Design](race_guided_fuzzing_design.md)
- [UAF Barrier Fuzzing](uaf_barrier_fuzzing.md)
- [DDRD Integration](ddrd_integration_update.md)
