# S&P 2027 Rebuttal 意见分类与应对分析

## 1. 总体判断

四位评审中有两位倾向接收（B、D），两位弱拒（A、C），没有直接 Reject。管理员最终归纳出的三个接收 gate 是：

1. 证明相对既有工作的实质性概念推进；
2. 完成动态、固定、随机阈值的 24 小时消融；
3. 完善 artifact 的实现变更与复现说明。

因此，rebuttal 不应把主要篇幅用于逐条反驳 Reviewer C。Reviewer C 确实存在若干误解，但他的阈值消融、novelty、形式化定义、研究问题、威胁模型和实验设置说明等意见成立。最有效的策略是承认论文表达造成了误解，用事实纠正其中两三个关键错误，同时完成管理员指定的三项工作。

本文仅分析评审明确提出的问题。

## 2. 分类标准

- **必须解决**：评审意见成立，且直接影响论文结论或管理员 gate。
- **可通过澄清解决**：实现或实验已经具备，但论文/artifact 没有说清楚。
- **部分误解**：评审结论不准确，但论文表达确实容易导致该误解。
- **明确误解或事实错误**：论文已有直接证据，或评审对系统/实验事实判断错误。
- **建议性扩展**：有价值，但不是当前接收必须条件。

## 3. 跨评审核心问题

| 问题 | 来源 | 分类 | 判断与应对 |
|---|---|---|---|
| 与 Snowboard、SegFuzz、KRACE 等工作的概念差异 | A/B/C/D、管理员 1 | **必须解决** | “首次解耦输入生成与调度”表述过宽。应承认 Snowboard 和 SegFuzz 已采用分阶段处理，再把贡献限定为：以在线收集的 MRP 作为输入生成与目标调度之间的显式接口；两个实例并行生产/消费；通过背压动态控制候选供给；用 site、stack、ASN 和 history 恢复并确认目标访问。需要在引言和 Related Work 中前置对比，而不是等到第 7.6 节。 |
| 动态阈值是否必要 | C、管理员 2 | **必须解决** | 这是当前最明确的实验缺口。正式配置见 [`threshold-ablation-experiment-zh-CN.md`](threshold-ablation-experiment-zh-CN.md)：比较 Dynamic、Fixed-min、Fixed-max、Random，保持初始 corpus、模块、kernel、LLM、CPU、内存和调度策略一致。每阶段使用 6 核运行 8h，对齐原 2 核运行 24h 的 48 core-hours；正文必须如实同时报告墙钟时间和 core-hour，不能直接称为实际 24h run。主指标包括 confirmed races、unique MRPs、候选队列长度/消费率和调度实例利用率。 |
| Artifact 不完整、没有说明修改了什么 | A、管理员 3 | **必须解决** | 增加顶层运行手册、与上游 Syzkaller 的变更清单、内核 instrumentation/runtime、executor、manager、QEMU snapshot 的组件图，以及完整命令、配置、commit 和预期输出。 |
| 数据竞争定义与 conventional HB 定义不同 | C | **部分误解，但有真实表述缺口** | Reviewer C 把“conflicting access pair”的条件当成最终 race 判定。论文第 2.1 节要求端点执行重叠，第 3.1 节明确 MRP 不是 race 证明，第 5.3 节还要求 watchpoint 窗口内出现对端冲突才确认。因此“任何引用计数访问都会被报告为 race”和“187 个结果与定义矛盾”的推论不成立。但论文确实没有充分解释 HB、原子访问、RCU、锁保护访问及 benign race 的处理边界。应明确 operational definition，说明候选、动态确认和 harmfulness 分类是三个不同层次；必要时避免把所有 confirmed conflicting pairs 都笼统称为 conventional data races。 |
| 比较是否使用相同内核版本 | C | **部分误解，可通过证据澄清** | 本地 SegFuzz 比较配置与运行记录指向 Linux 6.17-rc5，而不是原论文使用的 v6.2；因此 Reviewer C 直接认为本次实验用了 v6.2 并不准确。但提交稿第 7.6 节只写了 same setup，没有逐工具列出 kernel commit，造成了合理疑问。应给出每个工具的 kernel commit、config、补丁和二进制哈希，并核对正文“6.17”与实际“6.17-rc5”的精确口径。 |
| 公开 SegFuzz 是否缺少断点与 forced scheduling | C | **可通过 artifact 澄清** | SegFuzz 原设计明确包含基于 VM/VMI 的硬件断点和调度点执行；本地使用的源码也包含 single-thread、threading、scheduling 路径。不能只说 reviewer 看错了，应公布精确上游 commit、移植补丁、对应源码目录及功能 smoke test，证明运行的不是普通旧版 Syzkaller。 |
| LLM 与调度组件缺少独立消融 | A | **主要是读者遗漏，需改善呈现** | 第 7.4 节已经在完整 MRP-Fuzz 中比较 GPT-5.4、DeepSeek-V4-Pro 和纯随机变异；第 7.5 节又分别消融 history、ASN 和 backoff。Reviewer D 也明确注意到了 LLM 消融。Rebuttal 可直接指出 Table 3 与 Tables 4-5，并在修订稿中用显式 RQ 把两组消融串起来。 |
| LLM 货币成本与硬件需求 | A/B | **必须补充但容易解决** | 报告每个模块/24h 的请求数、输入/输出 token、API 价格、总费用、平均/尾延迟、并发数，以及 LLM 是否占用本地 GPU。与 Random 配置同时报告 cost 和 race yield。 |
| 研究问题不清楚 | C | **必须解决的表达问题** | 在 Evaluation 开头显式列 RQ1-RQ4，例如：MRP-Fuzz 的总体有效性；LLM mutation 的贡献；调度组件贡献；动态阈值相对 fixed/random 的贡献。每个小节明确回答一个 RQ。 |
| 威胁模型与目标范围不清楚 | C/D | **必须解决的表达问题** | 明确目标是可由并发 syscall group 触达、表现为共享内存冲突并可通过局部交错放大的内核数据竞争；不声称覆盖死锁、纯顺序错误、仅由弱内存乱序触发的问题或时间距离极长且无法形成 MRP 的并发缺陷。 |

## 4. Reviewer A 逐项判断

1. **Artifact 和实现难以跟踪：成立，必须修。** 这也是管理员明确要求。
2. **LLM 是黑盒：部分成立。** 论文给出了 prompt 结构和语义目标，但缺少模型参数、API 设置、失败重试、token/cost 与完整数据流。
3. **没有 LLM/调度消融：主要是误解。** 第 7.4、7.5 节已有两类消融，但论文没有用 RQ 清楚组织，导致 reviewer 未意识到它们正是在回答该问题。
4. **MRP novelty 过强：成立。** 需要降低 broad claim，强调具体机制组合与 online producer-consumer interface。
5. **“TSan 记录后异步探索交错”：事实不准确。** TSan 是动态 race detector，并不会像 MRP-Fuzz 一样主动执行目标调度搜索。无需在 rebuttal 中强硬纠正，可简短说明“检测与主动调度探索不同”。
6. **KRACE 的 HB DAG 等同于本工作解耦：不等同。** KRACE 的 DAG/HB 建模主要服务于 alias coverage 和精确 race detection，不等于两个并行实例通过候选队列解耦，但这仍说明论文必须更精确地限定贡献。

## 5. Reviewer B 逐项判断

1. **Snowboard/PMC 相似性：成立，而且是最重要的 novelty 问题。** 不能只说 MRP 多了时间阈值。建议增加如下对比：

| 维度 | Snowboard PMC | SegFuzz | MRP-Fuzz |
|---|---|---|---|
| 候选来源 | 从固定初始状态分别顺序执行测试并收集访问，再配对测试 | 单线程 fuzzing 产生输入，基于访问构造 segment，再进入多线程阶段 | 并发执行 syscall group，在线收集 MRP |
| 候选抽象 | 改变值的 write-read PMC | interleaving segment graph | 时间阈值内的 read-write/write-write conflict，加 site/stack 上下文 |
| 输入与调度关系 | PMC 用于构造并调度 concurrent tests | single-thread 与 multi-thread 两阶段，interleaving coverage 驱动 schedule mutation | 独立 producer/consumer 实例并行运行，以持久队列连接并由背压控制供给 |
| 定向执行 | PMC scheduling hint | VM breakpoint 强制 segment schedule | history recovery + site/stack/ASN 定位 + watchpoint confirmation |

2. **“时间接近性是否唯一差异”：是误解。** 上表至少还有候选生成方式、W-W 支持、在线反馈、并行生产消费、动态 admission control 和上下文恢复等差异。但 Snowboard 确实已经做了高层次的分阶段筛选与调度，不能继续声称 broad decoupling 首创。
3. **第 4 节没有讲清检测粒度和 LLM 输入：成立的表达问题。** 应明确内存访问由 LLVM instrumentation 和 kernel runtime 记录，不是 QEMU 全内存 tracing；LLM 输入是 seed syscall group、模块 syscall 白名单、环境/资源约束和跨序列语义目标；有效性检查是 Syzlang parse/type/resource checks 及运行可执行性检查。
4. **阈值不足时的 fallback：建议性问题，且系统已有部分对应机制。** 动态控制在候选不足时增大阈值，候选优先级机制也会 defer 而非永久丢弃。应明确阈值上界之外的候选不保证覆盖，并将其列为 limitation。
5. **LLM 成本：成立，补表即可。**

## 6. Reviewer C（Reviewer 3）专项判断

Reviewer C 不是“整体误解”，其意见应拆开处理。

### 6.1 明确或主要误解

1. **把 conflicting pair 直接等同于最终 race。** MRP 只是 admission candidate；最终结果还需要目标调度与 watchpoint confirmation。因此引用计数例子不能仅凭“不同线程、同地址、至少一个写”推出 MRP-Fuzz 一定报告 race。
2. **由 187 数量较少推出定义未一致应用。** 该推论忽略了 temporal threshold、same-live-object/free-between filtering、共同锁过滤、去重、可复现性和目标确认阶段。
3. **认为本次 SegFuzz 必然运行在原论文的 v6.2。** 本地比较配置明确使用了移植到 Linux 6.17-rc5 的版本。问题在于提交稿没有明确列出这一事实。

### 6.2 部分成立、不能只反驳

1. **HB 与原子/RCU 语义。** 即使最终有动态重叠确认，“overlap”也不自动等价于 LKMM/C++ 意义下缺少 HB 的 data race。论文必须说明原子访问、锁、RCU 和有意 lockless 模式如何过滤或归入 benign，避免术语层面的过度声称。
2. **SegFuzz 公开实现完整性。** 可以用源码和复现记录证明，但 artifact 当前缺文档，所以 reviewer 的可复现性担忧合理。
3. **同版本和等价配置。** 实际可能是同版本，但论文必须给逐工具审计表，而不只是写“same setup”。

### 6.3 完全成立

- Dynamic vs Fixed vs Random threshold 消融缺失。
- Broad decoupling novelty 声明过强。
- `static access site`、`stack context` 和 `real data race` 定义不够明确。
- Evaluation 缺少显式 research questions。
- 缺少 threat model/scope。

### 6.4 建议的回应语气

不要写“Reviewer 3 misunderstood our paper”。更稳妥的表达是：

> We apologize that our terminology and experimental description enabled this interpretation. An MRP is only an admission candidate, not a reported race. A pair is counted in our final results only after targeted replay observes the opposite conflicting access during the armed watchpoint window. We will explicitly distinguish conflicting pairs, MRPs, dynamically confirmed pairs, and harmful bugs, and clarify the treatment of synchronization and atomics.

然后用一两句列出所有 baseline 的确切 kernel commit 和 SegFuzz forced-scheduling 代码位置。

## 7. Reviewer D 逐项判断

1. **目标并发缺陷范围过宽：成立。** 加 scope/limitation，不要声称覆盖所有 concurrency bugs。
2. **“8 个模块中 5 个是文件系统，包括 Floppy”：事实错误。** 实际是 4 个文件系统；Floppy 是块设备驱动。但“非文件系统复杂驱动代表性不足”的总体担忧成立。Rebuttal 可温和纠正数量，并解释 PTMX、OSS DSP、Bluetooth、Floppy 的类别和选择依据；增加 GPU/camera 实验属于建议性扩展。
3. **LLM first claim 过强：成立。** 加入 KnitFuzz，并把声明收窄到 MRP-guided、cross-sequence concurrent syscall-group mutation；若无法完成系统性文献检索，最好删除“first”。
4. **与 SegFuzz 的差异出现太晚：成立。** 将核心差异表移到引言或设计概览。
5. **SegFuzz 缺少就地引用 [27]：成立的排版小问题。** 直接修复。

## 8. 建议优先级

### P0：管理员 gate

1. 写清 Snowboard/SegFuzz/KRACE 与 MRP-Fuzz 的概念边界，降低 broad novelty claim。
2. 立即准备 Dynamic/Fixed/Random 24h 阈值消融。
3. 补 artifact change map 和一键复现文档。

### P1：防止 Reviewer C 阻断

1. 重写 data race/MRP/confirmed pair/harmful bug 四层定义。
2. 增加逐工具 kernel commit、配置、资源和实现完整性表。
3. 增加 RQ 与 threat model。

### P2：低成本高收益修改

1. 报告 LLM token、费用、延迟和本地硬件需求。
2. 修 SegFuzz 引用，加入 KnitFuzz，收窄 LLM first claim。
3. 澄清 4 个文件系统而非 5 个，并补模块选择理由。

## 9. 750 词 rebuttal 的篇幅分配

- 约 280 词：管理员问题 1，给出与 Snowboard/SegFuzz 的具体差异并承诺收窄声明。
- 约 180 词：管理员问题 2，报告阈值消融配置和核心结果。
- 约 120 词：管理员问题 3，说明 artifact 新增文档和复现入口。
- 约 120 词：澄清 Reviewer C 的 race 判定层次、相同 kernel/SegFuzz 完整实现。
- 约 50 词：scope、模块类别、LLM cost/KnitFuzz 等其余修改。

## 10. 核对依据

- 提交论文：`rebuttal/sp2027c1-paper1590.pdf`，特别是 Sections 2.1、3.1、3.3、4、5.3、7.4-7.6。
- SegFuzz 原论文的两阶段设计：single-thread fuzzing 后选择有潜力的 syscall pair，再进入 multi-thread scheduling；本地文本位于 `/home/zzzccc/BASS/segfuzz/segfuzz.md`。
- 本地 SegFuzz 6.17-rc5 配置：`/home/zzzccc/BASS/segfuzz/exp/segfuzz-comparison/*/syzkaller.cfg`。
- Snowboard 官方论文对 PMC 的定义与工作流：<https://research.google/pubs/snowboard-finding-kernel-concurrency-bugs-through-systematic-inter-thread-communication-analysis/>。
- KRACE 原论文对 alias coverage、lockset 和 happens-before 的说明：<https://cs.uwaterloo.ca/~m285xu/assets/publication/krace-paper.pdf>。
