# DDRD Documentation Index

本文档是 DDRD (Data Race / UAF Detector) 扩展的文档索引，帮助开发者快速定位和理解各个文档的内容与关系。

---

## 📚 文档结构概览

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        DDRD 文档体系                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────┐                                                │
│  │  设计与架构文档      │                                                │
│  ├─────────────────────┤                                                │
│  │ • uaf_barrier_fuzzing.md     ← UAF Barrier Fuzzing 整体设计          │
│  │ • race_guided_fuzzing.md     ← Race-Guided Fuzzing 概览（已更新）     │
│  │ • race_guided_fuzzing_design.md ← 历史设计（M1'/M2 已移除）         │
│  │ • genfuzz_redesign.md        ← ★ GenFuzz 重设计（M1'/M2 移除说明）   │
│  │ • timing_exploration_config.md ← Timing Exploration + Race Repro 架构 │
│  │ • barrier_dispatch_flow.md   ← Barrier 派发与 DDRD 集成流程          │
│  │ • ddrd_executor_flow.md      ← Executor/Runner 中的 DDRD 处理流程    │
│  │ • ddrd_configuration_reference.md ← ★ 完整配置参考手册              │
│  └─────────────────────┘                                                │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────────┐                                                │
│  │  验证模式文档        │                                                │
│  ├─────────────────────┤                                                │
│  │ • uaf_validate_mode.md       ← UAF 验证模式详细说明                  │
│  │ • uaf_barrier_validation.md  ← 验证进度与问题追踪                    │
│  └─────────────────────┘                                                │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────────┐                                                │
│  │  工具使用文档        │                                                │
│  ├─────────────────────┤                                                │
│  │ • ddrd_tools_usage.md        ← 各种工具和运行模式使用指南            │
│  └─────────────────────┘                                                │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────────┐                                                │
│  │  更新日志与状态      │                                                │
│  ├─────────────────────┤                                                │
│  │ • ddrd_integration_update.md ← 集成更新记录                          │
│  │ • ddrd_stack_logging.md      ← Stack Hash 日志更新                   │
│  │ • DDRD_BARRIER_IMPLEMENTATION_STATUS.md (根目录)                     │
│  └─────────────────────┘                                                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 📖 核心文档详解

### 1. 设计与架构

#### [`ddrd_configuration_reference.md`](ddrd_configuration_reference.md)
**定位**: ★ 完整配置参考手册

**内容**:
- 所有 `experimental` 节下的 DDRD 配置项（基础模式、Data Race 去重、历史记录、Race-Guided 策略、Timing Exploration、UAF Validate）
- 每个配置项的类型、默认值、行为说明
- 配置交互关系与依赖关系
- 完整 JSON 配置示例（Fuzzing / Baseline / Validate）
- Executor 编译时常量

**适合**: 配置任何 DDRD 相关功能时的权威参考

---

#### [`uaf_barrier_fuzzing.md`](uaf_barrier_fuzzing.md)
**定位**: 顶层设计文档

**内容**:
- UAF-Barrier Fuzzing 的目标与范围
- 高层架构（syz-manager → syz-fuzzer → executor）
- 数据模型（`UAFCorpusEntry`, `BarrierSnapshot`）
- 控制流程（Selection → Barrier Preparation → Execution → Post-processing）
- Mutation 策略
- 与上游 Syzkaller 的集成计划

**适合**: 了解整体设计思路和系统架构

---

#### [`race_guided_fuzzing.md`](race_guided_fuzzing.md)
**定位**: Race-Guided Fuzzing 概览

**内容**:
- 当前架构：随机选择 + ObjectLinker V2 + Solo Filter + Affinity Table
- 已移除组件（M1'/M2/PairCooldown）说明
- Solo Filter 与 Coverage Triage
- 关键文件结构

**适合**: 快速理解 race-guided 的当前架构

---

#### [`race_guided_fuzzing_design.md`](race_guided_fuzzing_design.md)
**定位**: 历史设计与实现（参考用）

**内容**:
- 当前简化架构图
- 历史 M1'/M2/PairCooldown 详细设计（标记为已移除）
- VarName Registry、Coverage Triage 细节
- A/B Testing 配置

**适合**: 了解历史设计决策和演进过程

---

#### [`genfuzz_redesign.md`](genfuzz_redesign.md)
**定位**: ★ GenFuzz 重设计方案

**内容**:
- M1'/M2 过度聚焦问题分析
- Phase 1：M1'/M2 代码移除（✅已完成）
- Phase 2：多策略延时注入设计（待定）
- Phase 3：竞争知识引导的变异设计（待定）
- 实现计划与风险评估

**适合**: 理解 M1'/M2 为何被移除、未来改进方向

---

#### [`timing_exploration_config.md`](timing_exploration_config.md)
**定位**: Timing Exploration + Race Reproduction 三阶段架构指南

**内容**:
- 三阶段架构：Fuzzer Phase 1（Pair Discovery）→ Phase 2（Timing Exploration）→ Manager Phase 3（Race Reproduction）
- `syz_delay()` 插入策略与配置
- 4 种变异策略（targeted/timediff/binary_search/random）
- Phase 3: RaceReproLoop → VM 级别复现 → CrashReproLoop C reproducer
- 完整配置字段说明与示例（含 `race_repro` 配置）

**适合**: 配置 Timing Exploration 及 Race Reproduction 参数

---

#### [`barrier_dispatch_flow.md`](barrier_dispatch_flow.md)
**定位**: Runner 层实现文档

**内容**:
- `Runner::Loop()` 中的 Barrier 处理阶段
- Barrier 状态管理（`BarrierGroupState`, `pending_barriers_`）
- 派发逻辑（`TryDispatchBarrier()`, `DispatchBarrierGroups()`）
- Proc 槽位预留机制
- **DDRD 集成章节**（第8节）:
  - Pre-Dispatch DDRD Setup
  - Post-Completion Collection
  - Result Injection（仅 master 注入）
  - Cleanup 流程

**适合**: 理解 Barrier 如何在 Runner 中调度和执行

---

#### [`ddrd_executor_flow.md`](ddrd_executor_flow.md)
**定位**: DDRD 数据流文档

**内容**:
- DDRD 在 Executor/Runner 中的完整流程
- `RunnerDdrdController` 类的三个核心方法:
  - `PrepareForGroup()` - 初始化 LOG 模式
  - `CollectResults()` - 收集 UAF pairs
  - `ResetAfterGroup()` - 清理状态
- `ddrd_build_output()` 序列化逻辑
- 失败处理与清理机制
- 关键设计点（单点收集、Master-Only 结果、DISABLE 模式）

**适合**: 理解 DDRD 数据如何产生、收集和传递

---

### 2. 验证模式

#### [`uaf_validate_mode.md`](uaf_validate_mode.md)
**定位**: 验证模式配置与使用文档

**内容**:
- One-Shot Mode 与 Continuous Mode
- `StageManager` 组件说明
- 配置选项详解:
  - `MaxConcurrent`, `RepeatCount`, `TimeoutSeconds`
  - `ContinuousMode`, `IncrementalReloadMinutes`
- Delay 策略（`StartDelayUs`, `AccessDelayUs`）
- 日志与诊断
- 持久化文件说明（`uaf-corpus.db`, `validated_uaf.db`, `invalid_uaf.db`）

**适合**: 配置和运行 UAF 验证模式

---

#### [`uaf_barrier_validation.md`](uaf_barrier_validation.md)
**定位**: 验证进度追踪

**内容**:
- 已完成的工作（debug 标志、barrier trace、多 VM 并发修复等）
- 当前行为描述
- 待处理项目

**适合**: 了解验证功能的开发状态

---

### 3. 工具使用

#### [`ddrd_tools_usage.md`](ddrd_tools_usage.md)
**定位**: 操作手册

**内容**:
- 运行模式概览（Normal Fuzzing / UAF Validate / Debug Validate）
- 正常 Fuzzing 模式配置与使用
- UAF Validate 模式:
  - 基本用法与调试技巧
  - 验证流程（Discovery → Verification）
  - Delay 策略说明
- 调试特定 VarName Pair
- 相关工具:
  - `syz-uaf-corpus` - UAF 语料库查看工具
  - `syz-db` - 通用数据库工具
- 数据库文件说明
- 架构图

**适合**: 日常使用和问题排查

---

### 4. 更新日志

#### [`ddrd_integration_update.md`](ddrd_integration_update.md)
**定位**: 集成更新记录

**内容**:
- `pkg/ddrd` 包重构说明
- FlatBuffer 序列化更新
- 移除的功能（PairSyscallSharedData）
- 构建与测试状态

---

#### [`ddrd_stack_logging.md`](ddrd_stack_logging.md)
**定位**: 小型功能更新

**内容**:
- Stack Hash 日志扩展说明
- 调试可见性改进

---

### 5. 实现状态

#### [`DDRD_BARRIER_IMPLEMENTATION_STATUS.md`](../DDRD_BARRIER_IMPLEMENTATION_STATUS.md) (根目录)
**定位**: 实现进度追踪

**内容**:
- 已完成工作清单
- 当前架构说明（延迟发送 + 统一注入）
- Barrier + DDRD 请求流程图
- 测试建议（编译、运行时验证）
- 下一步工作优先级
- 代码位置索引

**适合**: 开发者快速了解实现状态和代码入口

---

## 🔗 阅读顺序建议

### 新手入门
1. [`uaf_barrier_fuzzing.md`](uaf_barrier_fuzzing.md) - 了解整体设计
2. [`ddrd_configuration_reference.md`](ddrd_configuration_reference.md) - 完整配置参考
3. [`race_guided_fuzzing.md`](race_guided_fuzzing.md) - 快速理解 race-guided 核心机制
4. [`ddrd_tools_usage.md`](ddrd_tools_usage.md) - 学习基本使用
5. [`uaf_validate_mode.md`](uaf_validate_mode.md) - 配置验证模式

### 深入理解实现
1. [`genfuzz_redesign.md`](genfuzz_redesign.md) - M1'/M2 移除说明与未来改进方向
2. [`race_guided_fuzzing_design.md`](race_guided_fuzzing_design.md) - 历史 M1'/M2 设计（参考）
3. [`timing_exploration_config.md`](timing_exploration_config.md) - Timing Exploration + Race Reproduction 三阶段架构
4. [`barrier_dispatch_flow.md`](barrier_dispatch_flow.md) - Barrier 调度机制
5. [`ddrd_executor_flow.md`](ddrd_executor_flow.md) - DDRD 数据流
6. [`DDRD_BARRIER_IMPLEMENTATION_STATUS.md`](../DDRD_BARRIER_IMPLEMENTATION_STATUS.md) - 代码入口点

### 问题排查
1. [`ddrd_tools_usage.md`](ddrd_tools_usage.md) - 调试技巧章节
2. [`uaf_barrier_validation.md`](uaf_barrier_validation.md) - 已知问题

---

## 📁 相关代码位置

| 功能模块 | 代码位置 |
|---------|---------|
| RunnerDdrdController | `executor/executor_runner.h` (~line 767) |
| Barrier 派发 | `executor/executor_runner.h::TryDispatchBarrier()` |
| 完成检测 | `executor/executor_runner.h::CheckBarrierCompletions()` |
| DDRD 序列化 | `executor/executor.cc::ddrd_build_output()` |
| UKC 控制 | `executor/ukc.h` |
| Race Detector | `executor/ddrd/race_detector.{h,c}` |
| Race-Guided Fuzzing | `pkg/fuzzer/race_group.go`, `affinity_table.go` |
| Timing Exploration | `pkg/fuzzer/timing_scheduler.go`, `timing_mutator.go`, `timing_queue.go` |
| Pair Evaluation | `pkg/fuzzer/pair_evaluator.go` |
| UAF Corpus | `pkg/fuzzer/race.go` |
| UAF Store (Go) | `pkg/manager/uaf_store.go` |
| RaceReproLoop | `pkg/manager/race_repro.go` |
| RunRaceRepro (VM) | `syz-manager/race_repro_runner.go` |
| RaceReproConfig | `pkg/mgrconfig/config.go` (`RaceReproConfig` struct) |
| RaceRepro Callback | `syz-manager/manager.go` (`raceReproCallback`) |
| Validate Manager | `pkg/racevalidate/manager.go` (package `uafvalidate`) |
| Executor Adapter | `pkg/racevalidate/executor.go` (package `uafvalidate`) |

---

## 📝 文档维护说明

- 代码变更后请同步更新相关文档
- 新功能需在本索引中添加条目
- 过时内容应标记或删除，避免误导

**最后更新**: 2026-02-25
