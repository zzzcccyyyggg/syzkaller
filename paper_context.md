# Paper Context for DDRD-syzkaller

这份文件用于汇总当前仓库中和论文写作最相关的文档与代码入口，重点服务于以下目标：

- 快速建立对 DDRD-syzkaller 当前实现的整体认识
- 按技术主题查找一手资料
- 区分“当前有效的实现说明”和“历史设计/演化文档”
- 为后续撰写 Background、Overview、Design、Implementation 提供上下文入口

## 1. 最重要的结论

- 当前 discovery 侧的 program pairing 策略不是复杂的 learned selection，而是纯随机选择 partner，再用 ObjectLinker V2 做资源感知对象对齐。
- race-guided 发现链路的当前有效总览文档是 docs/race_guided_fuzzing.md。
- barrier 执行和 DDRD 数据流的底层实现要看 docs/barrier_dispatch_flow.md 和 docs/ddrd_executor_flow.md。
- validation 侧的当前有效总览文档是 docs/uaf_validate_mode.md 和 docs/uaf_validate_config.md。
- 一些旧文档仍然有参考价值，但不能直接当作“当前实现”，例如 docs/race_guided_fuzzing_design.md 和 docs/uaf_barrier_fuzzing.md。

## 2. 推荐阅读顺序

如果你的目标是尽快形成论文写作上下文，建议按这个顺序阅读：

1. [docs/DDRD_DOCUMENTATION_INDEX.md](docs/DDRD_DOCUMENTATION_INDEX.md)
2. [docs/race_guided_fuzzing.md](docs/race_guided_fuzzing.md)
3. [docs/barrier_dispatch_flow.md](docs/barrier_dispatch_flow.md)
4. [docs/ddrd_executor_flow.md](docs/ddrd_executor_flow.md)
5. [docs/ddrd_configuration_reference.md](docs/ddrd_configuration_reference.md)
6. [docs/uaf_validate_mode.md](docs/uaf_validate_mode.md)
7. [docs/uaf_validate_config.md](docs/uaf_validate_config.md)

如果你优先关心某个机制，可以直接跳到下面对应主题。

## 3. 文档总入口

### [docs/DDRD_DOCUMENTATION_INDEX.md](docs/DDRD_DOCUMENTATION_INDEX.md)

作用：仓库里最好的文档导航页。

推荐原因：

- 给出文档结构概览
- 给出“新手入门 / 深入理解实现 / 问题排查”的阅读顺序
- 给出代码位置索引

重点位置：

- 文档结构概览
- 核心文档详解
- 阅读顺序建议
- 相关代码位置

适合用途：刚开始建立全局上下文，或者写 Overview 前快速定位材料。

## 4. 按技术主题组织的文档

### 4.1 总体架构与当前 race-guided 发现链路

#### [docs/race_guided_fuzzing.md](docs/race_guided_fuzzing.md)

这是当前最重要的 discovery 侧文档。

你可以从这里获得：

- 当前选择策略已经更新为“纯随机 + ObjectLinker V2”
- race-guided program-group fuzzing 的整体模块图
- Object Linking V2 的核心机制
- Object Family 的概念与对象族示例
- 安全过滤规则
- Solo Filter、Coverage Triage、VarName Pair Registry
- Timing Exploration 的双队列总览

最值得读的部分：

- 更新说明：确认 M1'/M2 已移除
- Object Linking V2
- 对象族（Object Family）
- 安全过滤
- Solo Filter
- VarName Pair Registry
- Timing Exploration

适合用途：

- 写第三章 Overview
- 写 discovery stage 的系统描述
- 明确当前实现到底采用了什么策略

注意：这份文档是“当前实现”的一手入口，优先级高于历史设计稿。

#### [docs/uaf_barrier_fuzzing.md](docs/uaf_barrier_fuzzing.md)

这是较早的总览性设计文档，适合建立系统框架感，但不能单独作为当前实现依据。

你可以从这里获得：

- 高层架构图
- UAF/Barrier 模式下的数据模型
- 早期 execution path 描述

最值得读的部分：

- High-Level Architecture
- Data Model
- Current Implementation Snapshot

适合用途：

- 组织自己的脑图
- 理解 corpus entry 和 barrier 相关术语

注意：文中有些段落仍带有 early design 或 future workflow 色彩，写论文时需要和当前代码或其他文档交叉验证。

### 4.2 资源对齐 / Object Linking V2

如果你现在主要想搞清“资源对齐”，优先读下面这组：

#### [docs/race_guided_fuzzing.md](docs/race_guided_fuzzing.md)

重点章节：

- Object Linking V2
- 对象族（Object Family）
- 安全过滤

你能从中理解：

- 为什么需要资源对齐
- 两层对齐的大致语义
- 什么样的 syscall 属于同一对象族
- 哪些路径或句柄不会被跨程序对齐

#### [pkg/fuzzer/object_linking_v2.go](pkg/fuzzer/object_linking_v2.go)

这是资源对齐的核心实现文件。

重点函数：

- LinkProgramsV2
- extractSyscallResources
- buildFamilyIndex
- unifyResourcesTwoTier

建议阅读顺序：

1. 先看 LinkProgramsV2 的主流程
2. 再看 extractSyscallResources 如何抽取对象标识
3. 再看 buildFamilyIndex 如何按对象族分组
4. 最后看 unifyResourcesTwoTier 如何实际重写 partner 程序

#### [pkg/fuzzer/object_family.go](pkg/fuzzer/object_family.go)

这是对象族定义、兼容关系和安全过滤的源头。

适合回答的问题：

- 哪些 syscall 被认为操作同类对象
- 参数位置在哪里
- 绝对路径和相对路径为什么分成不同族
- 哪些模式被判定为不安全对齐

#### [pkg/fuzzer/object_family_test.go](pkg/fuzzer/object_family_test.go)

这是理解对象族设计意图的辅助材料。

适合用途：

- 验证自己对 family index 和兼容匹配的理解
- 看作者预期的边界行为

### 4.3 partner selection 的当前状态与设计演化

#### [docs/genfuzz_redesign.md](docs/genfuzz_redesign.md)

这是解释“为什么当前不是 M1'/M2，而是随机 partner + object linking”的最重要文档。

你可以从这里获得：

- 旧的 M1'/M2 设计为什么被去掉
- 当前 buildBarrierPrograms 如何简化
- 为什么保留 ObjectLinker V2，但移除复杂的 feedback-driven partner selection

最值得读的部分：

- A2. buildBarrierPrograms
- A3. Partner 选择简化说明

适合用途：

- 写 design rationale
- 回答 reviewer 对“为什么不用更复杂调度器”的质疑
- 防止论文误写成 learned partner selection

#### [docs/race_guided_fuzzing_design.md](docs/race_guided_fuzzing_design.md)

这是历史设计稿。

适合用途：

- 看系统设计曾经考虑过哪些机制
- 获取论文 related evolution 的素材

注意：不能把它当成当前实现说明。凡是和 docs/race_guided_fuzzing.md 或当前代码冲突的地方，应以当前实现为准。

### 4.4 barrier 调度与 DDRD 执行流

#### [docs/barrier_dispatch_flow.md](docs/barrier_dispatch_flow.md)

这是 barrier request 在 executor_runner 中如何被调度、保留 proc slot、最终触发 DDRD 集成的说明。

你可以从这里获得：

- barrier state bookkeeping
- ready group dispatch
- barrier group dispatch 成功后的流程
- DDRD 和 barrier execution 的结合点

适合用途：

- 写 runtime execution model
- 理解为什么 barrier 是并发发现的基本执行单元

#### [docs/ddrd_executor_flow.md](docs/ddrd_executor_flow.md)

这是 DDRD 数据在 runner / executor 内部如何初始化、收集、注入结果的说明。

你可以从这里获得：

- 哪些 ExecFlag 驱动 DDRD
- 为什么 barrier requests 才是 DDRD 的核心使用场景
- runner 何时 PrepareForGroup / CollectResults / ResetAfterGroup
- 为什么只有 barrier master 返回 DDRD 结果

适合用途：

- 写 implementation / runtime substrate
- 解释 DDRD 与 executor 的关系

### 4.5 Timing Exploration 与动态阈值

#### [docs/ddrd_configuration_reference.md](docs/ddrd_configuration_reference.md)

这是当前最可靠的配置型参考文档。

最值得读的部分：

- Timing Exploration 双队列配置
- UAF Validate 验证管线配置

你可以从这里获得：

- Phase 1 / Phase 2 的职责区分
- timing_exploration_ratio、widened_threshold、timing_mutation_strategy
- replay、vm snapshot、varname scheduling、backoff、history minimization 的配置项

适合用途：

- 写系统参数与实现细节
- 理解验证与探索的可调机制

注意：如果 timing 相关文档之间有不一致，优先参考这份文档和代码，而不是旧说明。

#### [docs/timing_exploration_config.md](docs/timing_exploration_config.md)

这是 timing exploration 的专题说明。

适合用途：

- 看 Example Configuration
- 看详细字段解释
- 看 timing exploration 的整体架构图

注意：其中仍保留了一些旧配置或已移除字段说明，例如 enable_partner_selection、enable_race_yield_feedback。使用时需要和当前实现交叉验证。

### 4.6 validation / replay / snapshot / backoff

#### [docs/uaf_validate_mode.md](docs/uaf_validate_mode.md)

这是 validation 侧的总览文档。

你可以从这里获得：

- One-Shot 和 Continuous 两种运行模式
- key components
- logging 与 diagnostics
- VM snapshot optimization 的概念与限制

适合用途：

- 写 validation stage 的 overview
- 理解 validate manager 实际会做什么

#### [docs/uaf_validate_config.md](docs/uaf_validate_config.md)

这是 validation 配置项最细的说明文档。

你可以从这里获得：

- scheduling 相关选项
- disable_backoff_skip / continue_after_backoff
- require_origin_match
- verify_repeat_times / async split / verify delay
- replay 配置
- VM snapshot 配置
- debug 模式下 target_varname_pair / target_corpus_key

适合用途：

- 写 validation 机制细节
- 查日志里某个行为是由哪个选项控制的

#### [docs/ddrd_tools_usage.md](docs/ddrd_tools_usage.md)

这是偏使用与运维的文档，但对理解验证流程和数据库文件有帮助。

你可以从这里获得：

- uaf validate 的命令行入口
- 验证结果数据库的含义
- 常见调试/清理方式

适合用途：

- 实验复现
- 查看验证输出物

### 4.7 日志字段、stack hash、集成演化

#### [docs/ddrd_stack_logging.md](docs/ddrd_stack_logging.md)

作用：解释 stack hash logging 更新及其影响。

适合用途：

- 理解日志中的 callstack hash / stack logging 相关字段
- 写日志字段说明时补充上下文

#### [docs/ddrd_integration_update.md](docs/ddrd_integration_update.md)

作用：记录 DDRD 集成过程中的关键更新。

适合用途：

- 写实现演化或 artifact note
- 理解为什么某些文件结构或调用方式发生过变化

## 5. 当前有效文档 vs 历史参考文档

### 当前实现优先参考

- [docs/race_guided_fuzzing.md](docs/race_guided_fuzzing.md)
- [docs/barrier_dispatch_flow.md](docs/barrier_dispatch_flow.md)
- [docs/ddrd_executor_flow.md](docs/ddrd_executor_flow.md)
- [docs/ddrd_configuration_reference.md](docs/ddrd_configuration_reference.md)
- [docs/uaf_validate_mode.md](docs/uaf_validate_mode.md)
- [docs/uaf_validate_config.md](docs/uaf_validate_config.md)

### 历史/演化参考

- [docs/genfuzz_redesign.md](docs/genfuzz_redesign.md)
- [docs/race_guided_fuzzing_design.md](docs/race_guided_fuzzing_design.md)
- [docs/uaf_barrier_fuzzing.md](docs/uaf_barrier_fuzzing.md)
- [docs/ddrd_integration_update.md](docs/ddrd_integration_update.md)

使用原则：

- 如果历史文档和当前实现文档冲突，以当前实现文档和代码为准
- 如果当前实现文档和代码冲突，以代码为准

## 6. 按论文写作任务来找资料

### 如果你要写 Background

建议只用这些材料建立问题背景，不要把设计细节提前写进去：

- [docs/uaf_barrier_fuzzing.md](docs/uaf_barrier_fuzzing.md)
- [docs/ddrd_executor_flow.md](docs/ddrd_executor_flow.md)
- [docs/race_guided_fuzzing.md](docs/race_guided_fuzzing.md)

重点提炼：

- kernel concurrency fuzzing 的困难
- barrier-synchronized execution 的意义
- conflicting-access evidence 和 confirmed race 的差距

### 如果你要写 Overview

优先材料：

- [docs/race_guided_fuzzing.md](docs/race_guided_fuzzing.md)
- [docs/barrier_dispatch_flow.md](docs/barrier_dispatch_flow.md)
- [docs/uaf_validate_mode.md](docs/uaf_validate_mode.md)

重点提炼：

- discovery stage
- barrier execution
- solo filter
- timing exploration
- validation pipeline

### 如果你要写 Design

优先材料：

- [docs/race_guided_fuzzing.md](docs/race_guided_fuzzing.md)
- [docs/ddrd_configuration_reference.md](docs/ddrd_configuration_reference.md)
- [docs/uaf_validate_config.md](docs/uaf_validate_config.md)
- [docs/genfuzz_redesign.md](docs/genfuzz_redesign.md)

### 如果你要写 Implementation

优先材料：

- [docs/ddrd_executor_flow.md](docs/ddrd_executor_flow.md)
- [docs/barrier_dispatch_flow.md](docs/barrier_dispatch_flow.md)
- [pkg/fuzzer/object_linking_v2.go](pkg/fuzzer/object_linking_v2.go)
- [pkg/fuzzer/object_family.go](pkg/fuzzer/object_family.go)

## 7. 资源对齐专题阅读路径

如果你只想集中攻克“资源对齐”这一块，可以直接按这个顺序：

1. [docs/race_guided_fuzzing.md](docs/race_guided_fuzzing.md)
2. [pkg/fuzzer/object_linking_v2.go](pkg/fuzzer/object_linking_v2.go)
3. [pkg/fuzzer/object_family.go](pkg/fuzzer/object_family.go)
4. [pkg/fuzzer/object_family_test.go](pkg/fuzzer/object_family_test.go)

阅读目标：

- 理解为什么需要在随机 partner 之上做对象对齐
- 理解同名匹配和同族跨 syscall 匹配的区别
- 理解对象标识抽取的位置和语义
- 理解哪些对齐会被安全过滤拦截

建议你在读的时候回答这几个问题：

- 系统如何判断两个 syscall 操作的是“同一种对象”？
- partner 程序中哪些参数会被重写？
- 为什么有些路径和句柄禁止跨程序对齐？
- 每个 family 最多重写多少次，为什么要有限额？

## 8. 直接相关的代码入口

### discovery / race-guided

- [pkg/fuzzer/race_group.go](pkg/fuzzer/race_group.go)
- [pkg/fuzzer/race.go](pkg/fuzzer/race.go)
- [pkg/fuzzer/pair_evaluator.go](pkg/fuzzer/pair_evaluator.go)

### resource alignment

- [pkg/fuzzer/object_linking_v2.go](pkg/fuzzer/object_linking_v2.go)
- [pkg/fuzzer/object_family.go](pkg/fuzzer/object_family.go)
- [pkg/fuzzer/object_family_test.go](pkg/fuzzer/object_family_test.go)

### timing exploration

- [pkg/fuzzer/timing_scheduler.go](pkg/fuzzer/timing_scheduler.go)
- [pkg/fuzzer/timing_config.go](pkg/fuzzer/timing_config.go)
- [pkg/fuzzer/timing_mutator.go](pkg/fuzzer/timing_mutator.go)
- [pkg/fuzzer/fuzzer.go](pkg/fuzzer/fuzzer.go)

### validation

- [pkg/racevalidate/manager.go](pkg/racevalidate/manager.go)
- [pkg/racevalidate/config.go](pkg/racevalidate/config.go)
- [pkg/racevalidate/varname_backoff.go](pkg/racevalidate/varname_backoff.go)
- [pkg/racevalidate/minimizer.go](pkg/racevalidate/minimizer.go)

### executor / runner / DDRD substrate

- [executor/executor_runner.h](executor/executor_runner.h)
- [executor/executor.cc](executor/executor.cc)
- [executor/ukc.h](executor/ukc.h)
- [executor/ddrd/race_detector.c](executor/ddrd/race_detector.c)

## 9. 使用建议

- 当你写论文里的系统描述时，优先引用“当前实现优先参考”中的文档。
- 当你想解释为什么系统变成了今天这个样子，再去读历史/演化文档。
- 当文档和日志/代码出现不一致时，不要强行信文档，回到代码确认。
- 如果要写资源对齐、timing exploration、validation 这样的具体机制，最好始终采用“文档 + 代码”配对阅读。

## 10. 一个简短的论文写作用途映射

- Background：从问题、执行模型、runtime evidence 角度抽材料
- Overview：从 race_guided_fuzzing、barrier_dispatch_flow、uaf_validate_mode 抽系统主线
- Design：从 race_guided_fuzzing、ddrd_configuration_reference、uaf_validate_config 抽机制
- Implementation：从 executor flow、object linking 代码、validation manager 代码抽细节
- Evaluation：从配置文档、tools usage、实验日志抽实验设置与行为证据
