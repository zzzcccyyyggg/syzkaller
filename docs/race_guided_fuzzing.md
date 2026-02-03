# Race-Guided Program-Group Fuzzing

本文档描述 DDRD-syzkaller 中的 **Race-Guided Program-Group Fuzzing** 机制，覆盖选择、链接、过滤、反馈等完整链路。

## 概述

并发 fuzzing 的两个核心痛点：
1. **组合盲区**：随机组合程序对，忽略共享资源前提
2. **反馈盲区**：覆盖率与 race 产出不一致，无法指导并发探索

本框架通过 M1'/M2、对象链接、冷却与亲和度学习、Solo 过滤与覆盖率归因来提高跨程序 race 发现效率。

## 模块架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Race-Guided Program-Group Fuzzing                     │
├─────────────────────────────────────────────────────────────────────────┤
│   M2: Bandit Corpus Selection (Thompson Sampling)                         │
│   └─ 以 VarName pair 产出为反馈，优先高产程序                              │
│                             │                                            │
│                             ▼                                            │
│   M1': Hybrid Partner Selection                                           │
│   ├─ ScoreBased (60%): Bandit×Len×Affinity×Cooldown                       │
│   ├─ RacePrior  (30%): 历史 race 组合                                      │
│   └─ Explore    (10%): 随机探索                                            │
│                             │                                            │
│                             ▼                                            │
│   Object Linking V2: syscall 同型资源统一                                 │
│                             │                                            │
│                             ▼                                            │
│   Barrier 执行 (prog1 || prog2)                                           │
│        │                        │                                        │
│        ▼                        ▼                                        │
│   Solo Filter              Coverage Triage                               │
│   └─ 过滤同程序对            └─ 归因覆盖 + Bandit Boost                   │
└─────────────────────────────────────────────────────────────────────────┘
```

## M2: Bandit Corpus Selection (Thompson Sampling)

### 核心思想
每个程序维护 Beta(α,β)，以 **新 VarName pair 和新 Stack 的发现** 作为成功信号。

### 三档奖励机制

| 发现类型 | Alpha 更新 | 说明 |
|---------|------------|------|
| 新 VarName pair | `α += 10` | 最高价值：完全新的 (FreeAccessName, UseAccessName) |
| 新 Stack | `α += 2/(1+existingStackCount)` | 中等价值：已知 VarName pair 的新调用栈 |
| 无新发现 | `β += 1` | 失败惩罚 |

### 谐波衰减 (Harmonic Decay)
新 Stack 奖励采用谐波衰减，体现边际价值递减：
- 第1个 stack: +2.0
- 第10个 stack: +0.2
- 第100个 stack: +0.02

**累计效果**：发现 100 个 stack 的总奖励 ≈ 10，等同于发现 1 个新 VarName pair。

### 关键细节
- **唯一性去重**：VarName pair 用顺序无关哈希去重，Stack 用 stackPairID 去重
- **Coverage Boost**：若 barrier 发现新覆盖率，solo triage 后对贡献者执行 $α += 2$

## M1': Hybrid Partner Selection

### 三桶策略
- **ScoreBased (60%)**：按得分加权随机
- **RacePrior (30%)**：历史上产出 race 的组合
- **Explore (10%)**：随机探索

### 组合得分
```
PairScore = BanditScore × LengthPenalty × AffinityScore × PairPenalty

BanditScore  = α / (α + β)
LengthPenalty = 1 / (1 + 0.3 * |lenDiff|)
AffinityScore = 0.5 + rawAffinity * AffinityWeight
PairPenalty   = 1.0 (normal) or 0.01 (cooldown)
```

**约束**：
- `MaxLengthDiff = 3`
- `MinPairScore = 0.1`

## Object Linking V2

**目标**：提高共享内核对象的概率。

做法：对 prog2 中与 prog1 同类型 syscall 的资源参数进行统一（如路径字符串），避免路径匹配带来的脆弱性。

## Pair Cooldown

当某对组合累计失败分数达到阈值时进入冷却，显著降低选择概率。

### 三档惩罚机制

| 发现类型 | 失败分数变化 | 理由 |
|---------|--------------|------|
| 新 VarName pair | 重置为 0 | 最高价值，pair 仍有潜力 |
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
3. 对贡献程序执行 Bandit Boost，并记录亲和度交互

## VarName Pair Registry

每个 VarName pair 仅保留最多 20 组不同的 stack pair，防止结果爆炸。

## 文件结构

```
pkg/fuzzer/
├── race_group.go          # M1'/M2/Registry/SoloFilter
├── object_linking_v2.go   # Object Linking V2
├── pair_cooldown.go       # Pair Cooldown
├── affinity_table.go      # Syscall Affinity Table
├── coverage_triage_job.go # Coverage Triage Job
```
