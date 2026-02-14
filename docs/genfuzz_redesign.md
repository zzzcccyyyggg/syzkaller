# GenFuzz 重设计：去除 M1'/M2，引入轻量级竞争知识引导

> **状态**: Phase 1（去除 M1'/M2）已完成 ✅ — 2026-02-14
> Phase 2/3（延时策略、竞争知识变异）待定

## 1. 问题分析

### 1.1 M2 Thompson Sampling 的过度聚焦问题

M2（BanditCorpusSelector）使用 Thompson Sampling 选择变异源程序：
- 发现新 VarName pair → α += 10
- 发现新 stack → α += 2/(1+n) （谐波衰减）
- 无发现 → β += 1

**正反馈陷阱**：程序 P 发现一个 VarName pair → α 暴增 → 被选中概率大幅提高 → 反复变异 P → 继续发现同一 VarName 的新 stack → α 持续增长 → 其他程序被饥饿。

**实际效果**：从 `xfs.2.14.log` 数据看，M2 已被禁用（`EnableRaceYieldFeedback: false`），`ChooseProgramWithFeedback()` 退化为随机选择。M1' 同样已禁用（`EnablePartnerSelection: false`），partner 选择 100% 随机。

### 1.2 根本矛盾

M1'/M2 的设计思路是 **exploitation**（利用已有发现来指导后续选择），但 DDRD pair 发现的特点是：
- 同一 VarName pair 的不同 stack 价值递减（谐波衰减）
- 真正高价值的是发现**新** VarName pair
- 程序的"产出力"与其被选中次数不成正比——换句话说，选中 100 次的程序不比选中 10 次的程序好 10 倍

因此，正确策略是**广度优先探索**（给所有程序平等机会）+ **轻量级知识利用**（不改变选择概率，而是改善每次执行的质量）。

## 2. 设计目标

1. **去除 M1'/M2**：移除 BanditCorpusSelector、RaceYieldTracker、RacePriorIndex、PairCooldown 的调用路径
2. **保留有效组件**：ObjectLinker V2、VarNamePairRegistry、SoloPairCache、AffinityTable、NamespaceIndex
3. **轻量级竞争知识引导**：利用 AffinityTable 和 NamespaceIndex 的学习成果，在变异和生成中引入引导
4. **多策略延时注入**：在普通 barrier 执行中引入 syz_delay()，而不仅限于 timing exploration queue

## 3. 总体架构

```
genFuzz()
  │
  ├── 95% mutateProgRequest()
  │     │
  │     ├── ChooseProgram(rnd)          ← 随机选择（去除 M2）
  │     │
  │     └── Mutate() with
  │           RaceAwareNoMutateCalls    ← NEW: 保护高亲和力 syscall 不被变异
  │
  └── 5% genProgRequest()
        │
        └── Generate() with
              enrichedChoiceTable       ← NEW: 亲和力加权的 ChoiceTable
  │
  ▼
applyBarrier()
  │
  ├── selectPartner()
  │     │
  │     ├── NamespaceFilter             ← 保留：共享 namespace 过滤
  │     └── random from filtered        ← 简化：去除 M1' 评分系统
  │
  ├── ObjectLinker V2                   ← 保留：syscall variant 统一
  │
  └── DelayAugmenter                    ← NEW: 在普通 barrier 中注入延时
        │
        ├── MicroDelay (40%)            ← 1-100μs
        ├── MilliDelay (30%)            ← 100-5000μs
        ├── HistoryDelay (20%)          ← 基于已知 TimeDiff
        └── YieldPoint (10%)            ← syz_delay(0) 调度让出
```

## 4. 详细设计

### 4.1 Module A：去除 M1'/M2

#### A1. mutateProgRequest() — 去除 M2 ✅

**原代码** ([job.go](../pkg/fuzzer/job.go)):
```go
func mutateProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
    var p *prog.Prog
    if fuzzer.raceGroup != nil {
        corpus := fuzzer.Config.Corpus.Programs()
        p = fuzzer.raceGroup.ChooseProgramWithFeedback(corpus, rnd) // M2
    } else {
        p = fuzzer.Config.Corpus.ChooseProgram(rnd)
    }
    // ...
}
```

**已修改为**:
```go
func mutateProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
    p := fuzzer.Config.Corpus.ChooseProgram(rnd)              // 直接随机
    // ...
}
```

#### A2. buildBarrierPrograms() — 简化 partner 选择 ✅

**原代码** ([fuzzer.go](../pkg/fuzzer/fuzzer.go)):
```go
    if fuzzer.raceGroup != nil {
        programs := fuzzer.raceGroup.BuildBarrierProgramsWithRaceGuidance(...)
        // ...
    }
```

**已修改为**:
```go
func (fuzzer *Fuzzer) buildBarrierPrograms(...) []*prog.Prog {
    programs := make([]*prog.Prog, count)
    programs[0] = req.Prog

    for i := 1; i < count; i++ {
        partner := fuzzer.Config.Corpus.ChooseProgram(rnd)
        if partner != nil {
            partner = partner.Clone()
            // 保留 ObjectLinker V2
            if fuzzer.raceGroup != nil {
                if ol := fuzzer.raceGroup.GetObjectLinker(); ol != nil {
                    partner = ol.LinkProgramsV2(req.Prog, partner)
                }
            }
            programs[i] = partner
        } else {
            programs[i] = req.Prog.Clone()
        }
    }
    return programs
}
```

#### A3. Partner 选择简化说明 ✅

实际实现中，partner 选择直接使用 `Corpus.ChooseProgram(rnd)` 纯随机选取，
不使用 Namespace 过滤（因为大量常用 syscall 如 `read`/`write`/`close` 无 `$` 后缀，Namespace 匹配覆盖率有限）。
保留 Namespace 过滤作为未来优化方向。

**当前实现**: 随机选取 → Clone → ObjectLinker V2 链接

#### A4. 清理保留/废弃组件 ✅

| 组件 | 状态 | 理由 |
|------|------|------|
| BanditCorpusSelector | **已删除** | M2 核心，造成过度聚焦 |
| RaceYieldTracker | **已删除** | M2 辅助，不再需要 |
| RacePriorIndex | **已删除** | M1' 组件，历史 pair 记录 |
| PairCooldown | **已删除**（整文件） | M1' 配套，防止冷却期重选 |
| ShareScore | **已删除** | Namespace 评分，未被使用 |
| ObjectLinker V2 | **保留** | 有效，V2 variant 统一成功率高 |
| VarNamePairRegistry | **保留** | 限制 stack 数量，防止无限增长 |
| SoloPairCache | **保留** | Solo filter 核心，去除非跨程序 pair |
| SyscallAffinityTable | **保留** | 学到的 syscall 亲和力，记录交互数据 |
| NamespaceIndex | **保留**（简化） | 仅保留索引功能，移除 ShareScore |

**删除的文件**: `pair_cooldown.go`（243 行）
**重写的文件**: `race_group.go`（1722 → 723 行，净删除 ~1000 行）

**已标记 Deprecated 的配置字段**（保留 JSON 兼容）:
- `cooldown_threshold`
- `new_stack_penalty`
- `no_discovery_penalty`
- `enable_partner_selection`
- `enable_race_yield_feedback`

---

### 4.2 Module B：竞争知识引导的变异（RaceAwareMutation）

**核心思路**：不改变"选哪个程序来变异"（保持随机），而改善"如何变异"。

#### B1. Namespace 保护变异（主要策略）

利用 `prog.Mutate()` 已有的 `NoMutateCalls` 参数：
- 标记来自高 share score namespace 的 syscall 为不可变异
- 保护产生竞争的调用模式，同时允许其他调用自由变异

```go
func mutateProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
    p := fuzzer.Config.Corpus.ChooseProgram(rnd)
    if p == nil {
        return nil
    }

    newP := p.Clone()

    // 构建 race-aware 的 NoMutateCalls
    noMutateCalls := fuzzer.buildRaceAwareNoMutateCalls(newP, rnd)

    newP.Mutate(rnd,
        prog.RecommendedCalls,
        fuzzer.ChoiceTable(),
        noMutateCalls,
        fuzzer.Config.Corpus.Programs(),
    )
    // ...
}
```

```go
// buildRaceAwareNoMutateCalls 构建保护高亲和力 syscall 的 NoMutateCalls。
// 概率 P_protect (20%) 触发，避免过度约束变异空间。
func (fuzzer *Fuzzer) buildRaceAwareNoMutateCalls(p *prog.Prog, rnd *rand.Rand) map[int]bool {
    // 基础 NoMutateCalls（来自配置）
    base := fuzzer.Config.NoMutateCalls

    // 20% 概率启用保护
    if rnd.Float64() > 0.2 || fuzzer.raceGroup == nil {
        return base
    }

    noMutate := make(map[int]bool)
    for k, v := range base {
        noMutate[k] = v
    }

    // 找出高亲和力 namespace 的 syscall
    affinityTable := fuzzer.raceGroup.GetAffinityTable()
    if affinityTable == nil {
        return base
    }

    for i, call := range p.Calls {
        if call == nil || call.Meta == nil {
            continue
        }
        sig := SyscallSignature{Name: call.Meta.Name}
        // 如果此 syscall 与任何其他 syscall 有高亲和力（interaction rate > 0.1），保护它
        if affinityTable.HasHighAffinity(sig, 0.1) {
            noMutate[i] = true
        }
    }

    // 确保至少 50% 的 call 可变异，否则放弃保护
    protectedCount := 0
    for i := 0; i < len(p.Calls); i++ {
        if noMutate[i] {
            protectedCount++
        }
    }
    if protectedCount > len(p.Calls)/2 {
        return base // 保护太多，退化为正常变异
    }

    return noMutate
}
```

**设计理由**：
- `NoMutateCalls` 是 syzkaller 已有 API，无需侵入 `prog.Mutate()` 内部
- 20% 触发概率：80% 时间正常变异保持多样性，20% 时间保护竞争 syscall
- 50% 上限：如果大部分 syscall 都有高亲和力，说明保护无意义，退化为正常
- 不造成反馈环：AffinityTable 的更新独立于程序选择

#### B2. 亲和力加权的 ChoiceTable（辅助策略）

为 5% 的 `genProgRequest()` 路径提供竞争知识引导：

```go
// raceEnrichedChoiceTable 基于 AffinityTable 数据，对 ChoiceTable 中
// 曾参与竞争的 syscall 给予 1.3x 权重提升。
// 定期（每 5000 次执行）重新计算。
type raceEnrichedChoiceTable struct {
    base        *prog.ChoiceTable
    enriched    *prog.ChoiceTable
    lastRefresh int64  // 上次刷新时的执行计数
    refreshInterval int64
}
```

实现要点：
- `prog.ChoiceTable` 基于 `prog.BuildChoiceTable()` 构建，支持自定义权重
- 从 AffinityTable 中提取 interaction rate > 0 的 syscall
- 对这些 syscall 的选择权重乘以 1.3（温和提升，不会压制其他 syscall）
- 每 5000 次执行刷新一次，避免频繁重建开销

**注意**：此策略优先级较低，可作为 Phase 2 实现。初期可直接用标准 ChoiceTable。

---

### 4.3 Module C：多策略延时注入（DelayAugmenter）

这是本次改动**影响最大**的新功能。当前 syz_delay() 仅在 timing exploration queue 中使用。将延时注入引入普通 barrier 执行：

#### C1. DelayAugmenter 总体设计

```go
// DelayAugmenter 在普通 barrier 执行中注入延时，探索 timing-sensitive 竞争。
type DelayAugmenter struct {
    // 延时注入概率 (0.0-1.0)，默认 0.15（15%）
    injectionRate float64

    // 各策略权重（sum = 1.0）
    strategyWeights []float64

    // timing_mutator 复用
    tm *TimingMutator

    // 统计
    statDelayInjections *stat.Val
    statMicroDelays     *stat.Val
    statMilliDelays     *stat.Val
    statHistoryDelays   *stat.Val
    statYieldPoints     *stat.Val
}

// DelayStrategy 延时策略类型
type DelayStrategy int

const (
    StrategyMicroDelay   DelayStrategy = iota  // 1-100μs：紧密竞争
    StrategyMilliDelay                         // 100-5000μs：中等竞争窗口
    StrategyHistoryDelay                       // 基于已知 TimeDiff
    StrategyYieldPoint                         // syz_delay(0) 调度让出
)
```

#### C2. 四种延时策略

**策略 1：Micro-Delay（微延时）** — 权重 40%
```
目标：捕获紧密竞争（同一 cache line 争用、lock-free 数据结构）
延时范围：1-100μs
分布：对数均匀分布 exp(uniform(0, ln(100)))
位置：随机 syscall 前
数量：1 个延时调用
```

**策略 2：Milli-Delay（毫秒延时）** — 权重 30%
```
目标：捕获中等窗口竞争（IO 依赖、复杂路径竞争）
延时范围：100-5000μs
分布：对数均匀分布 exp(uniform(ln(100), ln(5000)))
位置：随机 syscall 前
数量：1-2 个延时调用
```

**策略 3：History-Delay（历史信息延时）** — 权重 20%
```
目标：利用已知竞争窗口精确探索
延时来源：从 uafCorpus 中匹配 pair 的 TimeDiff
延时计算：TimeDiff × uniform(0.3, 2.0)  — 宽抖动探索
回退：如果没有匹配的历史 pair，退化为 Micro-Delay
位置：在靠近 resource 操作的 syscall 前
数量：1 个
```

**策略 4：Yield-Point（调度让出点）** — 权重 10%
```
目标：触发依赖调度顺序的竞争
延时值：syz_delay(0) — 纯 yield，不等待
特点：零时间开销，强制内核重新调度
位置：在独占资源操作（open, ioctl, write）前
数量：2-3 个 yield 点分散插入
```

#### C3. 延时插入位置策略

除了"随机位置"，增加智能位置选择：

```go
// chooseDelayPosition 选择延时插入位置。
// 50% 随机位置，50% 智能位置（resource 操作前）。
func (da *DelayAugmenter) chooseDelayPosition(prog *prog.Prog, rnd *rand.Rand) int {
    if rnd.Float64() < 0.5 || len(prog.Calls) < 2 {
        // 随机位置
        return rnd.Intn(len(prog.Calls))
    }

    // 智能位置：优先在资源操作 syscall 前
    resourceOps := findResourceOperations(prog)
    if len(resourceOps) > 0 {
        return resourceOps[rnd.Intn(len(resourceOps))]
    }
    return rnd.Intn(len(prog.Calls))
}

// findResourceOperations 找到可能涉及共享资源的 syscall 位置。
// 优先选择 close/free/release/unlink 类操作（UAF 的 free 端）。
func findResourceOperations(p *prog.Prog) []int {
    var positions []int
    for i, call := range p.Calls {
        name := call.Meta.Name
        if isResourceReleaseOp(name) || isFileRelatedSyscall(name) {
            positions = append(positions, i)
        }
    }
    return positions
}
```

#### C4. 集成点：applyBarrier() 中插入

```go
func (fuzzer *Fuzzer) applyBarrier(req *queue.Request) {
    // ... 原有 barrier 设置 ...

    programs := fuzzer.buildBarrierPrograms(req, mask)

    // NEW: 延时增强
    if fuzzer.delayAugmenter != nil && !req.IsTimingExploration {
        programs = fuzzer.delayAugmenter.MaybeInjectDelays(programs, fuzzer.rand())
    }

    req.SetBarrierPrograms(programs)
}
```

```go
// MaybeInjectDelays 以配置的概率在 barrier programs 中注入延时。
// 仅修改其中一个程序（随机选择），保持另一个不变。
func (da *DelayAugmenter) MaybeInjectDelays(
    programs []*prog.Prog, rnd *rand.Rand) []*prog.Prog {

    if rnd.Float64() > da.injectionRate || len(programs) < 2 {
        return programs
    }

    // 随机选一个程序注入延时
    targetIdx := rnd.Intn(len(programs))
    target := programs[targetIdx].Clone()

    // 选择策略
    strategy := da.chooseStrategy(rnd)

    // 根据策略生成延时
    switch strategy {
    case StrategyMicroDelay:
        da.injectMicroDelay(target, rnd)
    case StrategyMilliDelay:
        da.injectMilliDelay(target, rnd)
    case StrategyHistoryDelay:
        da.injectHistoryDelay(target, rnd)
    case StrategyYieldPoint:
        da.injectYieldPoints(target, rnd)
    }

    programs[targetIdx] = target
    return programs
}
```

#### C5. 配置参数

```go
// DelayAugmenter 相关配置（加入 Config struct）
type Config struct {
    // ... 已有字段 ...

    // === 延时增强配置 ===
    // EnableDelayAugmenter 启用普通 barrier 执行中的延时注入
    EnableDelayAugmenter bool
    // DelayInjectionRate 延时注入概率 (0.0-1.0)，默认 0.15
    DelayInjectionRate float64
    // DelayMicroMin/Max 微延时范围，默认 1-100μs
    DelayMicroMinUs int64
    DelayMicroMaxUs int64
    // DelayMilliMin/Max 毫秒延时范围，默认 100-5000μs
    DelayMilliMinUs int64
    DelayMilliMaxUs int64
}
```

**默认值**:
```go
EnableDelayAugmenter: true,
DelayInjectionRate:   0.15,
DelayMicroMinUs:      1,
DelayMicroMaxUs:      100,
DelayMilliMinUs:      100,
DelayMilliMaxUs:      5000,
```

---

### 4.4 Module D：统计与监控

新增统计指标：

```go
// 延时增强
statDelayInjections *stat.Val  // "delay injections" — 延时注入次数
statDelayMicro      *stat.Val  // "delay micro" — 微延时策略使用次数
statDelayMilli      *stat.Val  // "delay milli" — 毫秒延时策略使用次数
statDelayHistory    *stat.Val  // "delay history" — 历史延时策略使用次数
statDelayYield      *stat.Val  // "delay yield" — yield 点策略使用次数

// partner 选择
statNSFilteredPartner *stat.Val  // "ns filtered partner" — namespace 过滤选中次数
statRandomPartner     *stat.Val  // "random partner" — 纯随机选中次数

// 竞争知识变异
statProtectedMutations *stat.Val // "protected mutations" — 保护变异使用次数
```

---

## 5. 实现计划

### Phase 1: 去除 M1'/M2 + 简化 Partner 选择 ✅ 已完成（2026-02-14）

1. ✅ **job.go**: `mutateProgRequest()` 去除 `ChooseProgramWithFeedback()`，使用 `Corpus.ChooseProgram()`
2. ✅ **fuzzer.go**: `buildBarrierPrograms()` 替换为随机选择 + ObjectLinker V2
3. ✅ **race_group.go**: 完全重写（1722 → 723 行），移除 BanditCorpusSelector、RaceYieldTracker、RacePriorIndex、SelectPartner 等 M1'/M2 代码
4. ✅ **pair_cooldown.go**: 整文件删除
5. ✅ **coverage_triage_job.go**: `boostProgramsWithNewCoverage()` 改为 no-op 存根
6. ✅ **syz-manager/manager.go**: 移除对已删 Config 字段的赋值
7. ✅ **pkg/mgrconfig/config.go**: 5 个废弃字段标记 `Deprecated`（保留 JSON 兼容）
8. ✅ **测试**: `go build` / `go vet` / `go test` 全部通过

### Phase 2: 多策略延时注入（待定 — 需进一步考量）

1. 新建 `pkg/fuzzer/delay_augmenter.go`
2. 实现 4 种延时策略
3. 集成到 `applyBarrier()`
4. 添加配置项和统计
5. 添加单元测试

### Phase 3: 竞争知识引导的变异（待定）

1. `buildRaceAwareNoMutateCalls()` 实现
2. `AffinityTable.HasHighAffinity()` 新增 API
3. 集成到 `mutateProgRequest()`
4. 添加单元测试

### Phase 4: 测试与验证（待定）

1. 完整 `go test ./pkg/fuzzer/...` 
2. `go build ./...` 全量编译
3. 配置文件更新 (timing_exploration_config.md, ddrd_configuration_reference.md)
4. 短时间运行验证

---

## 6. 与 Timing Exploration Queue 的关系

**Timing Exploration Queue 保持不变**。两个系统的职责区分：

| 维度 | DelayAugmenter (新) | Timing Exploration Queue (现有) |
|------|---------------------|-------------------------------|
| 目标 | 探索性发现 timing-sensitive 竞争 | 验证已知 pair 的可重现性 |
| 触发 | 每次 barrier 执行的 15% | 由 Phase 1 发现的 candidate pair 触发 |
| 延时策略 | 随机/多策略 | timediff/targeted/binary_search |
| pair 保存 | 正常路径（SourceFuzz） | SourceTiming（需验证） |
| 开销 | 接近零（仅修改少量 syscall） | 专用执行周期 |

二者互补：
- DelayAugmenter 以低成本、大面积扫描 timing 维度
- Timing Exploration Queue 对有希望的 pair 做精确验证

---

## 7. 风险评估

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| 延时注入降低 executions/sec | 中 | 15% 注入率限制总开销；微延时 < 100μs 影响极小 |
| Namespace 过滤过度限制 partner 多样性 | 低 | 30% 纯随机兜底；无匹配时退化为纯随机 |
| 保护变异降低变异探索空间 | 低 | 20% 触发概率 + 50% 上限保证足够空间 |
| 去除 M2 后 pair 发现率下降 | 极低 | M2 已禁用，当前已是随机选择 |

---

## 8. 配置示例

```json
{
    "enable_delay_augmenter": true,
    "delay_injection_rate": 0.15,
    "delay_micro_min_us": 1,
    "delay_micro_max_us": 100,
    "delay_milli_min_us": 100,
    "delay_milli_max_us": 5000,
    "enable_partner_namespace_filter": true,
    "partner_namespace_filter_rate": 0.7,
    "enable_race_aware_mutation": true,
    "race_aware_mutation_rate": 0.2,
    "race_aware_protection_limit": 0.5
}
```

## 9. 总结

本设计的核心策略转变：

**从**：M2 选哪个程序（exploitation → 反馈环 → 局部最优）
**到**：提升每次执行的质量（延时探索 + 亲和力保护 + 对象链接）

三个主要改进方向：
1. **简化选择**：去除 bandit/scoring，用 namespace 过滤 + 随机
2. **知识引导变异**：保护竞争相关 syscall 不被变异破坏
3. **延时增强**：4 策略多层次延时注入，低成本探索 timing 维度
