# Fork-Barrier vs Legacy Barrier: Timing Scheduler 诊断报告

## 1. 实验概要

| 指标 | Legacy Barrier (`xfs.2.14.debug.log`) | Fork-Barrier (`xfs.2.14.debug.fork.log`) |
|------|------|------|
| 运行时长 | ~30 min (16:38 - 17:08) | ~31 min (17:08 - 17:40) |
| exec 总数 | 30,523 | 58,849 |
| 平均 exec/sec | 17 (稳态) | 31 (稳态) |
| UAF corpus | loaded 0 entries (从零开始) | loaded 0 entries (从零开始) |

### 最终产出对比

| 指标 | Legacy | Fork | Fork/Legacy |
|------|--------|------|-------------|
| **ddrd pairs total** | **17,206** | **8,200** | **0.48x** |
| ddrd pairs fuzz | 3,907 | 6,668 | 1.71x |
| ddrd pairs timing | 13,299 | 1,532 | **0.12x (8.7x 差距)** |
| uaf varnames fuzz | 140 | 538 | 3.84x |
| uaf varnames timing | 1,224 | 385 | 0.31x |
| cross-prog pairs | 14,718 | 8,822 | 0.60x |
| Phase1 执行次数 | 1,393 | 99 | **0.07x (14x 差距)** |
| Phase2-SUCCESS | 212 | 23 | 0.11x |
| Phase2 total new_pairs | 19,559 | 2,512 | 0.13x |

## 2. 核心发现：Timing 反馈循环断裂

### 2.1 时间序列证据

**Legacy barrier** — timing 持续运作 30 分钟：
```
16:42: Phase1=33件,  ddrd_timing=519,    uaf_vn_timing=0
16:44: Phase1=50件,  ddrd_timing=5,140,   uaf_vn_timing=613
16:48: Phase1=39件,  ddrd_timing=6,259,   uaf_vn_timing=776
16:54: Phase1=73件,  ddrd_timing=10,154,  uaf_vn_timing=876
17:00: Phase1=66件,  ddrd_timing=12,478,  uaf_vn_timing=1011
17:07: Phase1=51件,  ddrd_timing=13,299,  uaf_vn_timing=1224
```
→ **每分钟持续产生 26-82 个 Phase1 作业，timing varnames 持续增长**

**Fork barrier** — timing 在 3 分钟内死亡：
```
17:11: Phase1=82件,  ddrd_timing=1,196,   uaf_vn_timing=307
17:12: Phase1=12件,  ddrd_timing=1,532,   uaf_vn_timing=385  ← 饱和！
17:13: Phase1=2件,   ddrd_timing=1,532,   uaf_vn_timing=385
17:14~17:37: Phase1=0件 (完全停滞)
17:38: Phase1=3件    ← 零星复苏
```
→ **3分钟后 timing 完全停止，ddrd_timing 和 uaf_vn_timing 永远停在 1,532 和 385**

### 2.2 反馈循环机制

Timing scheduler 的正反馈循环：

```
genFuzz 发现新 VarNamePair 
    → OnNewVarNamePairDiscovered 
    → EnqueueHighQualityPair (入队)
    → Phase1 Discovery (宽阈值执行)
    → 发现 candidate pairs 
    → Phase2 Validation (加 delay 执行)
    → triggerSoloFilter 
    → handleFilteredPairs 
    → 发现新 VarNamePairID ←── 反馈！
    → OnNewVarNamePairDiscovered 
    → 再次入队 → 更多 Phase1 ...
```

**Legacy 模式**：这个循环自我维持。每次 Phase2 执行产生新的 cross-program VarNamePairID → 持续喂养队列。

**Fork 模式**：循环在第一轮后断裂。初始 burst 消耗完毕后，没有足够的新 VarNamePairID 补充队列。

## 3. 根因分析

### 根因 #1：队列单次消耗设计 (One-Shot Queue)

`EnqueueHighQualityPair` 中的 `inQueue` 去重 map **永久保留**：

```go
// timing_queue.go
func (q *TimingExplorationQueue) EnqueueHighQualityPair(...) bool {
    if q.inQueue[varNamePairID] {
        return false  // 永远不再入队
    }
    if len(q.entries) >= q.config.TimingExplorationQueueSize {
        return false  // 队列满 → 丢弃（但 inQueue 未记录！）
    }
    q.entries = append(q.entries, entry)
    q.inQueue[varNamePairID] = true  // 永久标记
    return true
}
```

问题：
- 每个 VarNamePairID 只能入队 **一次**
- `DequeueForExploration` 是破坏性出队（消费后消失），但**不清除 inQueue**
- 新 VarNamePairID 必须来自真正的新发现才能补充队列

### 根因 #2：Solo Filter 异步延迟打破反馈时效性

反馈路径是 **异步的**：
```
Phase2 完成 → triggerSoloFilter → soloFilterJob(需执行2次solo) 
→ handleFilteredPairs → OnNewVarNamePairDiscovered → EnqueueHighQualityPair
```

`soloFilterJob` 需要执行 prog1-solo 和 prog2-solo（2次独立执行），有显著延迟。
在延迟期间，`GetNextJob` 持续消耗队列。

### 根因 #3：Fork-Barrier 模式 timing 执行产生更少的跨程序 VarNamePair

这是最根本的差异：

**Legacy barrier 执行模型**：
- prog1 和 prog2 在**独立进程**中并发执行（barrier 同步）
- 两个进程有独立地址空间和独立的内核交互
- 并发交叉产生丰富的跨程序 DDRD pairs
- Solo 过滤后保留的 cross-program pairs 包含**大量新 VarNamePairID**

**Fork-barrier 执行模型**：
- prog1 和 prog2 合并为**单个程序**，共享 setup 阶段
- fork() 后子进程从共享状态出发
- setup 阶段产生的 pairs 在 solo 执行中也会出现 → 被过滤为 intra-program
- Solo 过滤后，新的 cross-program VarNamePairID **数量不足以维持反馈循环**

数据证据：
- Legacy cross-prog pairs 持续增长：37 → 695 → 1427 → ... → 14,718
- Fork cross-prog pairs 快速饱和：158 → 3650 → 4074 → ... → 8,822（绝大部分来自初始 fuzz burst）

### 根因 #4：Phase1 不记录 Timing Attempt

```go
// processTimingExplorationResult - Phase1 路径:
case queue.PhaseWidenedDiscovery:
    // ✅ 找到 candidates → enqueue Phase2
    // ❌ 不调用 OnJobCompleted()
    // ❌ 不调用 RecordTimingAttempt()

// RecordJobExecution 是 NO-OP:
func (ts *TimingScheduler) RecordJobExecution(job *TimingExplorationJob) {
    // 空函数
}
```

Phase1 结果不参与反馈循环的状态更新。只有 Phase2 结果通过 `triggerSoloFilter → handleFilteredPairs` 产生反馈。系统依赖 Phase2 的输出来维持队列，而 Phase2 的量极为有限。

## 4. 量化影响模型

### 队列消耗速度

| 参数 | Legacy (timing 活跃期) | Fork (timing 活跃期) |
|------|----------------------|---------------------|
| exec/sec | ~100/sec (burst 期间) | ~100/sec (burst 期间) |
| timing 比例 | 10% | 10% |
| 队列消耗速度 | ~10 entries/sec | ~10 entries/sec |
| 初始队列大小 | ~500 | ~500 |
| 理论耗尽时间 | ~50 sec | ~50 sec |

两种模式初始耗尽时间相似 (~50 sec)。差异在于**补充速度**：

| 补充机制 | Legacy | Fork |
|----------|--------|------|
| Phase2-SUCCESS 数量 | 212 | 23 |
| Phase2 → 新 VarNamePairID/次 | 足以维持循环 | 不足以维持 |
| fuzz 持续发现跨程序对 | 是 (140 vn_fuzz) | 是 (538 vn_fuzz，更多) |
| timing 自身发现新跨程序对 | 是 (1,224 vn_timing) | 否 (385 后停止) |

### Per-Phase2 产出对比

| 指标 | Legacy | Fork |
|------|--------|------|
| Phase2-SUCCESS | 212 | 23 |
| Phase2 avg new_pairs | 92.3 | 109.2 |
| Phase2 总 new_pairs | 19,559 | 2,512 |

→ Fork 的单次 Phase2 产出更高 (109 > 92)，但执行次数相差 9.2x。

## 5. 修复建议

### 方案 A：Timing Queue 允许重入队 (最直接)

修改 `DequeueForExploration` 时清除 `inQueue` 标记，允许同一 VarNamePairID 被后续发现重新入队：

```go
func (q *TimingExplorationQueue) DequeueForExploration() *HighQualityProgramPair {
    ...
    entry := q.entries[0]
    q.entries = q.entries[1:]
    delete(q.inQueue, entry.VarNamePairID) // 允许重入队
    ...
}
```

### 方案 B：Phase1 结果也触发 triggerSoloFilter (关键！)

当前 Phase1 只收集 candidates 并入队 Phase2，不调用 solo filter。应添加：

```go
case queue.PhaseWidenedDiscovery:
    if res.Ddrd != nil && len(res.Ddrd.UAFPairs) > 0 {
        // Phase1 也触发 solo filter → 产生新 VarNamePairID → 反馈
        allNewPairs := make([]*ddrd.MayUAFPair, 0)
        for _, p := range res.Ddrd.UAFPairs {
            if fuzzer.ddrd.IsNewPair(p) {
                allNewPairs = append(allNewPairs, p)
            }
        }
        if len(allNewPairs) > 0 {
            fuzzer.triggerSoloFilter(req, res, allNewPairs, SourceTiming)
        }
    }
```

这样每次 Phase1 执行 (99次) 都会有机会给队列补充新条目，而不是只依赖 Phase2 (23次)。

### 方案 C：增大 Timing 比例 or 降低消耗速度

将 timing ratio 从 10% 提升到 20-30%，增加 timing 执行占比，给反馈循环更多时间。

### 方案 D：createDiscoveryJob 失败时不消耗队列条目

当前 `createDiscoveryJob` 先 dequeue 再检查条件，条件不满足则条目被浪费：

```go
func (ts *TimingScheduler) createDiscoveryJob() *TimingExplorationJob {
    hqPair := ts.explorationQueue.DequeueForExploration() // 破坏性出队
    if hqPair == nil { return nil }
    // 后续检查失败 → 条目永远丢失
    if ts.shouldSkipByCorpusCount(targetPair) { return nil } // ← 条目浪费
    if !ts.pairRegistry.ShouldAttemptTiming(targetPair) { return nil } // ← 条目浪费
```

应改为先检查条件再出队，或失败时回退入队。

### 推荐优先级

1. **方案 B (Phase1 触发 soloFilter)** — 最重要，从根本上增加反馈供给
2. **方案 A (允许重入队)** — 消除 inQueue 永久阻塞
3. **方案 D (出队保护)** — 防止条目浪费
4. **方案 C (调整比例)** — 微调级别

## 6. 预期效果

实施方案 B + A 后：
- Fork mode Phase1 应从 99 增长到 ~500-1000+ (与 legacy 1393 接近)
- Phase2-SUCCESS 应从 23 增长到 ~100-200+
- ddrd_timing 应从 1,532 增长到 ~10,000+
- 加上 fork 本身的 fuzz 优势 (6,668 ddrd_fuzz)，总产出应超过 legacy 的 17,206
