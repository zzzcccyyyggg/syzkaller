# Race-Guided Program-Group Fuzzing

本文档描述了为提升 Race Pair 发现效率而实现的核心模块。

## 概述

传统并发 fuzzing 面临两个核心问题：
1. **组合盲区**：随机组合程序对，忽略共享资源前提
2. **反馈盲区**：覆盖率反馈无法指导并发探索

我们提出的 **Race-Guided Program-Group Fuzzing** 框架通过以下模块解决这些问题。

## 模块架构

```
┌─────────────────────────────────────────────────────────────┐
│              Race-Guided Program-Group Fuzzing              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  M1': Score-Based Partner Selection                 │   │
│  │  - ScoreBased (60%): 基于得分的加权选择             │   │
│  │  - RacePrior (30%): 历史产生 race 的程序对          │   │
│  │  - Explore (10%): 随机探索                          │   │
│  │  - 约束: MaxLengthDiff=3, MinPairScore=0.1         │   │
│  └─────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  M2: Race-Yield Weighted Selection (Thompson)       │   │
│  │  - Thompson Sampling 选择高产程序                   │   │
│  │  - Beta(α,β) 分布：α=成功次数, β=失败次数          │   │
│  │  - 基于 VarName Pair 发现作为反馈                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Three-Phase Execution Verification                 │   │
│  │  - Phase 1: prog1 单独执行                          │   │
│  │  - Phase 2: prog2 单独执行                          │   │
│  │  - Phase 3: prog1+prog2 barrier 执行               │   │
│  │  - Filter: 只保留真正的跨程序竞争对                │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## M1': Score-Based Partner Selection

### 动机

当前 buildBarrierPrograms() 完全随机选择 partner，大量执行浪费在低效组合上。

### 核心约束

1. **长度差限制**: 两个程序的 syscall 数量差不能超过 3
2. **最低得分阈值**: 组合得分必须 >= 0.1 才值得运行

### 得分计算

```
PairScore = BanditScore × LengthPenalty

BanditScore = α / (α + β)  // M2 的 Beta 分布均值
LengthPenalty = 1 / (1 + lenDiff × 0.3)  // 长度差越大惩罚越重
```

### 三桶选择策略

- **ScoreBased (60%)**: 基于得分的加权随机选择（类似 ChoiceTable）
- **RacePrior (30%)**: 选择历史产生 race 的 partner  
- **Explore (10%)**: 随机探索

### 配置参数

```go
ScoreBasedWeight: 0.6   // 60% 基于得分选择
RacePriorWeight:  0.3   // 30% 历史 race 对
ExploreWeight:    0.1   // 10% 随机探索
MaxLengthDiff:    3     // 最大长度差
MinPairScore:     0.1   // 最低组合得分
```

### 统计指标

- score-based selections: 基于得分选择的次数
- race prior selections: 从历史 race 对选择的次数
- race random selections: 随机选择的次数

## M2: Race-Yield Weighted Selection (Thompson Sampling)

### 动机

syzkaller 的 corpus 选择基于覆盖率信号，但覆盖率高 ≠ Race 产出高。
我们需要一种机制来识别和优先选择"高产"程序（经常发现新 race 的程序）。

### Thompson Sampling 原理

**多臂老虎机问题**：面对 N 个老虎机，每个回报率未知，如何最大化总回报？

**核心困境**：探索 (exploration) vs 利用 (exploitation)
- 探索：尝试未知老虎机
- 利用：选择已知高回报的老虎机

**Thompson Sampling 解决方案**：

```
1. 每个老虎机维护 Beta(α, β) 分布
   - α = 成功次数 + 1 (发现新 VarName pair)
   - β = 失败次数 + 1 (无新发现)

2. 选择时:
   - 从每个老虎机的 Beta 分布采样一个值
   - 选择采样值最大的老虎机

3. 执行后更新:
   - 成功 (发现新 pair): α += 新pair数
   - 失败 (无新发现): β += 1
```

**为什么有效**：
- 初始 Beta(1,1) = 均匀分布，完全不确定
- 成功多：α 大，分布右移，采样值倾向于高 → 被选中概率增加
- 不确定：方差大，偶尔采样值很高 → 保持探索机会

### 在 M2 中的应用

```
老虎机 = 程序 (prog)
回报 = 发现新的唯一 VarName pair

实现细节:
- betaParams[progSig] = Beta(α, β)
- knownVarPairs = 已发现的唯一 VarName pair 集合
- 只有新发现的 pair 才算成功
```

### 配置

```go
EnableRaceYieldFeedback: true  // 启用 M2
ExploitRate:             0.8   // 80% 利用高产程序，20% 探索
HighYieldThreshold:      3     // 至少 3 个 race pair 才算高产
```

### 与 ChoiceTable 的关系

| 概念 | ChoiceTable | M2 Thompson Sampling |
|------|-------------|----------------------|
| 目标 | 选择下一个 syscall | 选择程序 partner |
| 静态信息 | 资源依赖 | 无 |
| 动态反馈 | corpus 共现 | VarName pair 发现 |
| 选择方式 | 累积分布 + 二分查找 | Beta 采样 + argmax |
| 探索比例 | 5% 完全随机 | 通过方差自动调节 |

## Three-Phase Execution Verification

### 动机

在 barrier 并发执行中，发现的 race pairs 可能包含同程序竞争和跨程序竞争。
我们需要过滤掉同程序竞争，只保留真正的跨程序竞争对。

### 实现

当发现新的 UAF pairs 时，触发 3 阶段执行验证：

Phase 1: prog1 单独执行 → prog1SoloPairs
Phase 2: prog2 单独执行 → prog2SoloPairs
Phase 3: prog1 + prog2 barrier 执行 → combinedPairs
Filter: crossProgramPairs = combinedPairs - prog1SoloPairs - prog2SoloPairs

### 统计指标

- three-phase jobs: 运行的 3 阶段验证任务数
- cross-prog pairs: 过滤后的跨程序竞争对数量

## 文件结构

pkg/fuzzer/
├── race_group.go      # 核心模块实现
│   ├── RaceGroupManager       # 中央协调器
│   ├── NamespaceIndex         # M1' 命名空间索引
│   ├── RacePriorIndex         # M1' 历史 race 对索引
│   ├── BanditCorpusSelector   # M2 Thompson Sampling
│   ├── VarNamePairSet         # 3-Phase VarName 对集合
│   └── FilterCrossProgramPairs()  # 3-Phase 过滤
├── fuzzer.go          # 集成点
│   ├── buildBarrierPrograms() # 使用 M1'
│   └── triggerThreePhaseVerification()  # 触发 3 阶段验证
├── job.go             # 集成点
│   ├── mutateProgRequest()    # 使用 M2
│   └── threePhaseJob          # 3 阶段执行 job
└── race.go            # 集成点
    └── handleNewPairs()       # 反馈 Race 产出
