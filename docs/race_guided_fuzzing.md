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
│   Object Linking V2: 两层对象对齐（同名匹配 + 同族跨syscall匹配）          │
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

## Object Linking V2（资源感知对象对齐）

**目标**：在并发执行前，提高两个程序共同触达同一内核对象的概率。

### 核心机制

系统从 prog1 中提取决定"操作哪个对象"的关键参数（路径、socket 地址等），
然后在 prog2 中找到语义兼容的位置并对齐，使两个程序指向同一底层对象。

对齐分两层执行（Tier 1 优先）：

| 层级 | 匹配方式 | 示例 |
|-----|---------|------|
| Tier 1 | 同名精确匹配 | `open$kccwf` ↔ `open$kccwf` |
| Tier 2 | 同族跨 syscall 匹配 | `open$kccwf` ↔ `stat$kccwf`（同属 `kccwf_file` 族） |

### 对象族（Object Family）

每个对象族定义了一组共享同类内核对象的 syscall 及其对象标识参数位置：

| 族 | 成员示例 | 对象标识 | 参数位置 |
|---|---------|---------|--------|
| `kccwf_file` | open, stat, chmod, truncate, unlink, rename, link, ... `$kccwf` | 绝对路径 `/mnt/kccwf/testfile#` | arg[0] |
| `kccwf_file_rel` | openat, faccessat, fchmodat, unlinkat, ... `$kccwf` | 相对路径 `testfile#`（依赖 dirfd） | arg[1] |
| `kccwf_dir` | mkdir, rmdir, open$kccwf_dir | 目录路径 | arg[0] |
| `bt_sco/l2cap/rfcomm` | bind/connect `$bt_*` | 蓝牙地址结构体 | arg[1] |
| `unix_sock` | bind/connect `$unix` | UNIX socket 路径 | arg[1] |
| `floppy` | `syz_open_dev$floppy` | 设备路径 `/dev/fd#` | arg[0] |

`kccwf_file` 和 `kccwf_file_rel` 是独立族，不会互相对齐（绝对路径 vs 相对路径语义不同）。

### 安全过滤

以下情况会跳过对齐：

- **dirfd 依赖**：未注册族的 `*at` 类 syscall（openat、mkdirat 等）在 fallback 路径中被 `isUnsafeAlignment` 拦截
- **特殊路径前缀**：`/proc/self/`、`/proc/thread-self/`、`/sys/kernel/debug/`、`/sys/kernel/security/`、`/dev/pts/` 不参与跨程序对齐
- **局部句柄**：fd、socket fd 等运行时派生值不跨程序复制，通过 fd 链自动继承
- **Per-family 限额**：每个对象族最多重写 3 个 call，避免过度抹平对象多样性

### 代码结构

- `object_family.go` — 对象族定义、兼容表、安全过滤规则
- `object_linking.go` — ObjectLinker 结构体、共享工具函数
- `object_linking_v2.go` — 两层对齐主逻辑（extractSyscallResources → buildFamilyIndex → unifyResourcesTwoTier）

## Syscall Affinity Table

学习 syscall 组合的交互倾向：
```
Affinity = InteractionRate × Confidence
InteractionRate = Interactions / Executions
Confidence = min(Executions / 100, 1.0)
```
> 注：M1'/M2 移除后，AffinityTable 仍在记录交互数据，用于统计分析和未来可能的变异引导。

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
├── object_family.go       # 对象族定义、兼容表、安全过滤
├── object_linking.go      # ObjectLinker 基础结构、共享工具函数
├── object_linking_v2.go   # Object Linking V2 两层对齐实现
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
