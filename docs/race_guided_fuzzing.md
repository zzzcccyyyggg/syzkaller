# Race-Guided Program-Group Fuzzing

本文档描述 DDRD-syzkaller 中的 **Race-Guided Program-Group Fuzzing** 机制，覆盖选择、链接、过滤、反馈等完整链路。

> **更新 (2026-02-14)**: M1'（Hybrid Partner Selection）、M2（Bandit Corpus Selection）、
> PairCooldown 已被移除。当前选择策略为**纯随机 + ObjectLinker V2**。
> 详见 [genfuzz_redesign.md](genfuzz_redesign.md)。

## 概述

并发 fuzzing 的核心痛点：
1. **组合盲区**：随机组合程序对，忽略共享资源前提
2. **反馈盲区**：覆盖率与 race 产出不一致，无法指导并发探索

本框架通过 **ObjectLinker V2**（资源统一）、**Syscall Affinity 学习**（交互记录）、
**Solo Filter**（跨程序过滤）和 **Coverage Triage**（覆盖率归因）来提高跨程序 race 发现效率。

选择策略采用**广度优先探索**：程序选择和 partner 选择均为随机，
避免 M1'/M2 时期的正反馈陷阱（Thompson Sampling 过度聚焦问题）。

## 模块架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Race-Guided Program-Group Fuzzing                     │
├─────────────────────────────────────────────────────────────────────────┤
│   Corpus Selection: 随机选择（ChooseProgram）                            │
│                             │                                            │
│                             ▼                                            │
│   Partner Selection: 随机选择 + Clone                                    │
│                             │                                            │
│                             ▼                                            │
│   Object Linking V2: syscall 同型资源统一                                 │
│                             │                                            │
│                             ▼                                            │
│   Barrier 执行 (prog1 || prog2)                                           │
│        │                        │                                        │
│        ▼                        ▼                                        │
│   Solo Filter              Coverage Triage                               │
│   └─ 过滤同程序对            └─ 归因覆盖率                                │
│        │                        │                                        │
│        ▼                        ▼                                        │
│   Affinity Table            VarName Pair Registry                        │
│   └─ 记录 syscall 交互       └─ 限制 stack 数量                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## 已移除的组件（M1'/M2）

> 以下组件已于 2026-02-14 移除，仅保留文档记录。详细的历史设计参见
> [race_guided_fuzzing_design.md](race_guided_fuzzing_design.md)。

| 组件 | 说明 | 移除原因 |
|------|------|---------|
| M2 BanditCorpusSelector | Thompson Sampling 选择变异源程序 | α += 10 正反馈陷阱，导致程序饥饿 |
| M1' Hybrid Partner Selection | 三桶采样（ScoreBased/RacePrior/Explore） | 过度利用已有发现，限制探索广度 |
| PairCooldown | (main, partner) 组合冷却机制 | 依赖 M1' 的评分系统，已无意义 |
| RaceYieldTracker | M2 辅助的 race yield 跟踪 | M2 移除后不再需要 |
| RacePriorIndex | 历史 race 组合记录 | M1' 移除后不再需要 |
| ShareScore | Namespace 评分 | 未被实际使用 |

## Object Linking V2

**目标**：提高共享内核对象的概率。

做法：对 prog2 中与 prog1 同类型 syscall 的资源参数进行统一（如路径字符串），避免路径匹配带来的脆弱性。

## Syscall Affinity Table

学习 syscall 组合的交互倾向：
```
Affinity = InteractionRate × Confidence
InteractionRate = Interactions / Executions
Confidence = min(Executions / 100, 1.0)
```
> 注：M1'/M2 移除后，AffinityTable 仍在记录交互数据，用于统计分析和未来可能的变异引导。

## Solo Filter（跨程序过滤）
| 仅新 Stack | `+NewStackPenalty` (默认: 1) | 有一定价值，温和惩罚 |
| 无新发现 | `+NoDiscoveryPenalty` (默认: 2) | 真正失败，更快进入 cooldown |

### 配置参数
- `CooldownThreshold = 20`：触发 cooldown 的失败分数阈值
- `CooldownDuration = 200`：cooldown 持续轮数
- 冷却时 `PairPenalty = 0.01`

### 行为示例
- **只发现新 stack 的 pair**：需要 20 次执行才进入 cooldown
- **什么都发现不了的 pair**：只需 10 次就进入 cooldown
- **偶尔发现新 VarName pair**：分数重置，持续活跃

## Syscall Affinity Table

学习 syscall 组合的交互倾向：
```
Affinity = InteractionRate × Confidence
InteractionRate = Interactions / Executions
Confidence = min(Executions / 100, 1.0)
```
在 M1' 中以 `AffinityWeight` 参与打分。

## Solo Filter（跨程序过滤）

Barrier 执行发现新 pairs 时触发：
1. prog1 solo → pairs1
2. prog2 solo → pairs2
3. cross = combined - pairs1 - pairs2

只保留跨程序 pairs，避免同程序噪声。

## Coverage Triage Job（覆盖率归因）

当 barrier 执行发现新覆盖率：
1. solo 执行 prog1/prog2 收集覆盖率
2. 判断贡献者（新覆盖率匹配阈值 ≥ 10% 或至少 1 个 PC）
3. 记录亲和度交互到 AffinityTable

## VarName Pair Registry

每个 VarName pair 仅保留最多 **100** 组不同的 stack pair（`DefaultMaxStacksPerVarPair = 100`），防止结果爆炸。

> **注意**：`uafCorpus` 中另有一个独立的每 VarName pair 限制（`DefaultMaxStacksPerVarnamePair = 20`），
> 用于控制保存到 UAF corpus 的条目数。两个限制作用于不同层级。

## Timing Exploration（双队列时序探索）

> **详细配置参见** [`timing_exploration_config.md`](timing_exploration_config.md)

在 fuzzing 过程中发现新 VarName pair 后，Timing Exploration 系统通过插入 `syz_delay()` 调用来探索最佳时序窗口。

### 双队列架构

```
Phase 1 (Pair Discovery Queue)     Phase 2 (Timing Exploration Queue)
┌───────────────────────────┐      ┌───────────────────────────┐
│ - 随机配对                 │      │ - 插入 syz_delay() 调用    │
│ - 宽阈值 (8x normal)      │─────▶│ - 正常阈值                │
│ - 发现候选 pair            │      │ - 验证 & 优化时序          │
└───────────────────────────┘      └───────────────────────────┘
```

### 关键配置
- `enable_timing_exploration`: 开启双队列系统
- `timing_exploration_ratio`: 分配给 Phase 2 的时间比例（默认 10%）
- `timing_mutation_strategy`: delay 变异策略（默认 `"targeted"`）

### 代码位置
- `pkg/fuzzer/timing_scheduler.go` — 双队列调度
- `pkg/fuzzer/timing_mutator.go` — `syz_delay()` 插入策略
- `pkg/fuzzer/timing_queue.go` — 高质量程序对队列
- `pkg/fuzzer/timing_config.go` — 配置与默认值

## 文件结构

```
pkg/fuzzer/
├── race_group.go          # RaceGroupManager/Registry/NamespaceIndex/SoloFilter
├── object_linking.go      # ObjectLinker 基础结构
├── object_linking_v2.go   # Object Linking V2 实现
├── pair_evaluator.go      # Pair 评估 (ShouldExplore/ShouldSave)
├── affinity_table.go      # Syscall Affinity Table
├── solo_cache.go          # Solo 执行结果 LRU 缓存
├── history_buffer.go      # Per-VM Barrier 执行历史缓冲
├── coverage_triage_job.go # Coverage Triage Job
├── timing_scheduler.go    # Timing Exploration 双队列调度
├── timing_mutator.go      # syz_delay() 插入策略
├── timing_queue.go        # 高质量程序对队列
└── timing_config.go       # Timing Exploration 配置
```
