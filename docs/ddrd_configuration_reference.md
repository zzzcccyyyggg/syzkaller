# DDRD 配置项完整参考

本文档是 DDRD (Data Race / UAF Detector) 扩展的 **完整配置参考手册**，涵盖所有 `experimental` 节下的配置项及其功能、默认值、交互关系。

> **配置位置**：所有 DDRD 配置项位于 syz-manager 配置文件（JSON）的 `experimental` 节中。  
> **源代码定义**：[pkg/mgrconfig/config.go](../pkg/mgrconfig/config.go)

---

## 目录

- [1. 基础模式配置](#1-基础模式配置)
- [2. Data Race 去重配置](#2-data-race-去重配置)
- [3. 历史记录与限制配置](#3-历史记录与限制配置)
- [4. Race-Guided 选择策略配置](#4-race-guided-选择策略配置)
- [5. Timing Exploration 双队列配置](#5-timing-exploration-双队列配置)
- [6. UAF Validate 验证管线配置](#6-uaf-validate-验证管线配置)
- [7. 配置交互关系](#7-配置交互关系)
- [8. 完整配置示例](#8-完整配置示例)
- [9. Executor 编译时常量](#9-executor-编译时常量)

---

## 1. 基础模式配置

这些配置项控制 DDRD 的核心运行模式。

### `barrier_mode`

| 属性 | 值 |
|------|-----|
| **类型** | `bool` |
| **默认值** | `false` |
| **JSON key** | `"barrier_mode"` |

启用 barrier 同步执行模式。Barrier 模式让多个 executor proc 同步执行程序对，使得两个程序在内核中并发运行，从而增加触发 data race 的概率。

**行为**：
- 启用后，executor 中指定的 proc 通过 barrier 同步机制协调执行
- 必须与 `barrier_procs` 配合使用

### `barrier_procs`

| 属性 | 值 |
|------|-----|
| **类型** | `[]int` |
| **默认值** | 无（必须显式指定） |
| **JSON key** | `"barrier_procs"` |

指定参与 barrier 同步的 executor proc 索引列表。

**约束**：
- 至少包含 **2 个**不同的 proc 索引
- 每个值必须在 `[0, procs)` 范围内
- 不允许重复值
- 系统内部将其转换为位掩码（`BarrierMask`），传递给 executor

**示例**：`"barrier_procs": [0, 1]` → proc 0 和 proc 1 参与 barrier 执行

### `uaf_mode`

| 属性 | 值 |
|------|-----|
| **类型** | `bool` |
| **默认值** | `false` |
| **JSON key** | `"uaf_mode"` |

启用 UAF（Use-After-Free）导向的 fuzzing 模式。

**前置条件**：`barrier_mode` 必须为 `true`

**行为**：
- 激活 UAF corpus 管理（收集、存储 DDRD 发现的 race pair）
- 启用 solo filter（过滤同程序内的 pair，只保留跨程序 pair）
- 禁用 smash/hints/fault injection job，避免干扰 barrier 同步
- 开启 race-guided 选择框架（M1'/M2 等策略受其他开关控制）

### `ddrd_monitor`

| 属性 | 值 |
|------|-----|
| **类型** | `bool` |
| **默认值** | `false` |
| **JSON key** | `"ddrd_monitor"` |

启用 DDRD 后台监控模式。

**行为**：
- Executor 启动时初始化 UKC 为 monitor 模式（只执行一次）
- UKC 在整个 fuzzing 过程中持续运行，被动检测 data race
- **无需 barrier 同步**也能检测 race（但精度较低）
- 每次执行结束后不会调用 `ukc_enter_disable_mode()`，保持监控常驻

**适用场景**：不使用 barrier 模式时的轻量级 race 检测

---

## 2. Data Race 去重配置

这些配置项控制 data race 报告的去重行为，避免已知 race 导致 VM 重启。

### `skip_duplicate_data_races`

| 属性 | 值 |
|------|-----|
| **类型** | `bool` |
| **默认值** | `false` |
| **JSON key** | `"skip_duplicate_data_races"` |

启用 data race 签名去重。启用后，syz-manager 维护一个内存缓存记录已观测到的 data race 签名，指示 VM monitor 忽略缓存中的匹配项，使 fuzzing 无需因已知 race 而重启 VM。

### `max_data_race_combinations`

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `10000` |
| **JSON key** | `"max_data_race_combinations"` |

data race 签名缓存的最大条目数。超出时丢弃旧条目。

---

## 3. 历史记录与限制配置

这些配置项控制 barrier 执行历史记录和 VarName pair 的资源限制。

### `history_buffer_size`

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `1000` |
| **JSON key** | `"history_buffer_size"` |

每个 VM 的 barrier 执行历史滚动缓冲区大小。缓冲区以 ring buffer 方式维护最近 N 次 barrier 程序组的完整记录。

**用途**：当发现新 pair 时，从缓冲区中取出最近的 history 记录附加到 `UAFCorpusEntry` 中，供 validate 阶段 replay 使用。

### `new_varname_pair_history`

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `1000` |
| **JSON key** | `"new_varname_pair_history"` |

发现 **全新 VarName pair**（从未见过的 FreeAccessName + UseAccessName 组合）时，从 history buffer 中保存的记录数量。

**调优建议**：值越大，replay 阶段可恢复越完整的系统状态，但增加存储和 replay 开销。

### `new_stack_history`

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `100` |
| **JSON key** | `"new_stack_history"` |

发现 **新 stack 组合**（已知 VarName pair 的新 FreeCallStack + UseCallStack）时保存的历史记录数。比 `new_varname_pair_history` 少，因为已知 VarName pair 的新 stack 价值较低。

### `max_stacks_per_varname_pair`

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `20` |
| **JSON key** | `"max_stacks_per_varname_pair"` |

每个 VarName pair 最多跟踪的唯一 stack 组合数。达到限制后，该 VarName pair 的新 stack 组合将被忽略。

**双层作用**：
1. **uafCorpus 层**（默认 20）：控制保存到 UAF corpus 的条目数
2. **VarNamePairRegistry 层**（默认 100，内部常量）：控制 race_group 中 timing exploration 和 bandit 的 stack 跟踪数

> 此配置项同时覆盖两个层级的限制值。

### `new_varname_pair_affinity_weight`

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `5` |
| **JSON key** | `"new_varname_pair_affinity_weight"` |

发现全新 VarName pair 时的 affinity 交互权重。当某对 syscall 组合发现了全新的 VarName pair，该交互以此权重记录到 Syscall Affinity Table 中，影响后续 M1' 的 partner 选择。

### `new_stack_affinity_weight`

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `1` |
| **JSON key** | `"new_stack_affinity_weight"` |

发现已知 VarName pair 的新 stack 时的 affinity 交互权重。实际使用时还会经过调和衰减：`weight / (1 + existingStackCount)`。

---

## 4. Race-Guided 选择策略配置

> **⚠️ 已废弃 (2026-02-14)**: M1'/M2/PairCooldown 已被移除。
> 以下配置字段保留在 JSON schema 中以保持向后兼容（现有配置文件不会报错），
> 但**设置这些字段不再有任何效果**。

### `enable_partner_selection` [DEPRECATED]

| 属性 | 值 |
|------|-----|
| **类型** | `bool` |
| **默认值** | `false` |
| **JSON key** | `"enable_partner_selection"` |
| **状态** | **已废弃** — 设置无效 |

~~启用 M1' 智能 partner 选择策略。~~

当前行为：Partner 选择始终为随机（`Corpus.ChooseProgram`），此字段被忽略。

### `enable_race_yield_feedback` [DEPRECATED]

| 属性 | 值 |
|------|-----|
| **类型** | `bool` |
| **默认值** | `false` |
| **JSON key** | `"enable_race_yield_feedback"` |
| **状态** | **已废弃** — 设置无效 |

~~启用 M2 Bandit 反馈选择（Thompson Sampling）。~~

当前行为：Corpus 选择始终为随机（`Corpus.ChooseProgram`），此字段被忽略。

### `cooldown_threshold` [DEPRECATED]

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `20` |
| **JSON key** | `"cooldown_threshold"` |
| **状态** | **已废弃** — 设置无效 |

~~(main, partner) 程序对进入 cooldown 的失败分数阈值。~~

PairCooldown 机制已被移除。此字段被忽略。

### `new_stack_penalty` [DEPRECATED]

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `1` |
| **JSON key** | `"new_stack_penalty"` |
| **状态** | **已废弃** — 设置无效 |

~~仅发现新 stack 时的失败分数惩罚。~~

PairCooldown 机制已被移除。此字段被忽略。

### `no_discovery_penalty` [DEPRECATED]

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `2` |
| **JSON key** | `"no_discovery_penalty"` |
| **状态** | **已废弃** — 设置无效 |

~~什么都没发现时的失败分数惩罚。~~

PairCooldown 机制已被移除。此字段被忽略。

### `random_baseline_mode`

| 属性 | 值 |
|------|-----|
| **类型** | `bool` |
| **默认值** | `false` |
| **JSON key** | `"random_baseline_mode"` |

A/B 测试标记：强制关闭 timing exploration，便于按 baseline 口径运行。

> **注意**：M1'/M2 已被移除，选择策略本身已固定为随机。此模式不再关闭 Affinity Table、Object Linking 或 Solo Filter；这些机制是否启用，取决于它们各自的配置开关。

**相关组件行为**：

| 组件 | 正常模式 | Baseline 模式 |
|------|---------|--------------|
| Corpus 选择 | 随机选择 | 随机选择（相同） |
| Partner 选择 | 随机选择 | 随机选择（相同） |
| ~~M2 Bandit 选择~~ | ~~已移除~~ | ~~已移除~~ |
| ~~M1' Partner 选择~~ | ~~已移除~~ | ~~已移除~~ |
| ~~Pair Cooldown~~ | ~~已移除~~ | ~~已移除~~ |
| Affinity Table | 学习交互信息 | 保持启用，除非单独关闭 |
| Object Linking | 由 `enable_object_linking` 控制 | 保持原配置 |
| Solo Filter | 启用 | **仍然启用** |
| Timing Exploration | 由 `enable_timing_exploration` 控制 | **强制关闭** |

**用途**：运行两组对比实验（Guided vs Random），比较 VarName pair 发现速度。

### `object_link_attempt_ratio`

| 属性 | 值 |
|------|-----|
| **类型** | `float64` |
| **默认值** | `1.0` |
| **JSON key** | `"object_link_attempt_ratio"` |

控制在 `enable_object_linking=true` 时，barrier partner 生成阶段有多大比例会实际尝试 ObjectLinker V2。

- `1.0` 表示每次都尝试。
- `0.1` 表示只有约 10% 的 partner 会做 object-link 扫描，其余直接复用原 partner 程序。
- 取值范围是 `(0, 1]`；超出范围或未设置时按 `1.0` 处理。

这个字段适合用于某些模块上 object-link 命中率很低、但扫描成本持续存在的场景。

---

## 5. Timing Exploration 双队列配置

Timing Exploration 通过插入 `syz_delay()` 系统调用来控制 syscall 之间的时序，增加 race 触发概率。

> 详细架构说明参见 [timing_exploration_config.md](timing_exploration_config.md)

### `enable_timing_exploration`

| 属性 | 值 |
|------|-----|
| **类型** | `bool` |
| **默认值** | `false` |
| **JSON key** | `"enable_timing_exploration"` |

启用双队列 timing exploration 系统。

**双队列架构**：
- **Phase 1（Pair Discovery Queue）**：使用宽阈值（`widened_threshold_micros`），不加 delay，发现候选 pair
- **Phase 2（Timing Exploration Queue）**：对候选 pair 插入 `syz_delay()` 调用，使用正常阈值验证并优化

**调度方式**：通过 `queue.Alternate` 按 `timing_exploration_ratio` 比例穿插到普通执行中。

### `timing_exploration_queue_size`

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `500` |
| **JSON key** | `"timing_exploration_queue_size"` |

Phase 2 timing exploration 队列的最大容量。超出时新任务被丢弃。

### `timing_exploration_ratio`

| 属性 | 值 |
|------|-----|
| **类型** | `float64` |
| **默认值** | `0.1` |
| **JSON key** | `"timing_exploration_ratio"` |

分配给 timing exploration 的执行比例（0.0-1.0）。

**实现机制**：`timingSkip = int(1.0 / ratio)`，即每 `timingSkip` 次普通执行穿插 1 次 timing exploration。
- `0.1` → 每 10 次执行 1 次 timing（推荐）
- `0.05` → 每 20 次执行 1 次
- `0.5` → 每 2 次执行 1 次

### `widened_threshold_micros`

| 属性 | 值 |
|------|-----|
| **类型** | `int64` |
| **默认值** | `500000`（500ms） |
| **JSON key** | `"widened_threshold_micros"` |

Phase 1（Pair Discovery）使用的放宽 timing 阈值（微秒）。允许检测到 time diff 较大的 pair，这些 pair 在正常阈值下会被忽略。随后由 Phase 2 通过插入 delay 来缩小时间差。

当启用动态时间阈值时，`widened_threshold_micros` 作为 Phase 1 的**最小探索窗口**：
- `Phase 1 threshold = max(当前 normal 阈值 × 8, widened_threshold_micros)`
- 这样即使 normal 阈值临时收缩，Phase 1 的候选发现窗口也不会一起塌缩

### `delay_min_micros`

| 属性 | 值 |
|------|-----|
| **类型** | `int64` |
| **默认值** | `10` |
| **JSON key** | `"delay_min_micros"` |

`syz_delay()` 调用的最小延迟值（微秒）。生成的 delay 会被 clamp 到 `[delay_min_micros, delay_max_micros]` 范围内。

### `delay_max_micros`

| 属性 | 值 |
|------|-----|
| **类型** | `int64` |
| **默认值** | `200000`（200ms） |
| **JSON key** | `"delay_max_micros"` |

`syz_delay()` 调用的最大延迟值（微秒）。

### `max_delays_per_program`

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `5` |
| **JSON key** | `"max_delays_per_program"` |

每个程序中允许插入的最大 `syz_delay()` 调用次数。

### `timing_mutation_strategy`

| 属性 | 值 |
|------|-----|
| **类型** | `string` |
| **默认值** | `"targeted"` |
| **JSON key** | `"timing_mutation_strategy"` |

delay 变异策略，控制如何生成 `syz_delay()` 调用。

| 策略 | 行为 |
|------|------|
| `"targeted"` | 在参与 race 的 syscall（Free/Use）前插入 delay，随机时长 |
| `"timediff"` | 根据 pair 的 `TimeDiff`（内核报告的 ns→μs 时间差）计算 delay，在先执行的 access 前插入等长 delay 使两个 access 时间对齐，加 50%-150% jitter |
| `"binary_search"` | 基于上次最佳 delay plan 进行迭代细化（±50%） |
| `"random"` | 在随机位置插入随机时长的 delay |

### `max_attempts_per_pair`

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `20` |
| **JSON key** | `"max_attempts_per_pair"` |

每个唯一 pair 的最大 timing exploration 尝试次数。达到限制后不再对该 pair 进行 timing exploration。

### `max_corpus_count_per_varname`

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `0`（无限制） |
| **JSON key** | `"max_corpus_count_per_varname"` |

当某个 VarName pair 已有此数量的 corpus 条目时，跳过对其的 timing exploration。`0` 表示不限制。

**用途**：避免在已有大量覆盖的 VarName pair 上浪费资源。

### `success_threshold`

| 属性 | 值 |
|------|-----|
| **类型** | `float64` |
| **默认值** | `0.1`（10%） |
| **JSON key** | `"success_threshold"` |

认为 timing exploration 成功的触发率阈值（0.0-1.0）。在 `executions_per_attempt` 次执行中，如果 race 触发率达到此值则认为该 delay plan 有效。

### `executions_per_attempt`

| 属性 | 值 |
|------|-----|
| **类型** | `int` |
| **默认值** | `5` |
| **JSON key** | `"executions_per_attempt"` |

每个 delay plan 的执行次数。用于评估该 plan 的 race 触发率。

---

## 6. UAF Validate 验证管线配置

验证管线在 `experimental.uaf_validate` 节下配置，用于重放和验证 UAF corpus 中的候选 pair。

> 详细说明参见 [uaf_validate_config.md](uaf_validate_config.md) 和 [uaf_validate_mode.md](uaf_validate_mode.md)

### 基础配置

| JSON key | 类型 | 默认值 | 说明 |
|----------|------|--------|------|
| `max_concurrent` | `int` | `1`（自动 clamp 到 VM 数） | 并发验证 worker 数量 |
| `delay_retry_budget` | `int` | `1` | 每次重复执行中因崩溃/错误的最大重试次数 |
| `timeout_seconds` | `int` | `90` | 每次执行超时（秒） |
| `repeat_count` | `int` | `1` | 每个 entry 重复执行次数。stable pair 需出现 ≥ `repeat/2 + 1` 次 |
| `verify_repeat_times` | `int` | `10` | 验证阶段每个 pair 的重复执行次数 |

### 运行模式

| JSON key | 类型 | 默认值 | 说明 |
|----------|------|--------|------|
| `continuous_mode` | `bool` | `false` | `true`: 持续运行，定期检查新 entry；`false`: One-Shot 处理完退出 |
| `incremental_reload_minutes` | `int` | `10` | （仅 continuous_mode）检查新 entry 的间隔（分钟） |
| `idle_reload_seconds` | `int` | `30` | （仅 continuous_mode）无任务时检查新 entry 的间隔（秒） |

### Stable Pairs 收集

| JSON key | 类型 | 默认值 | 说明 |
|----------|------|--------|------|
| `require_origin_match` | `bool` | `false` | `true`: stable pair 必须存在于原始 corpus pairs 中；`false`: 接受任何运行时发现的 pair |

### Delay 控制

| JSON key | 类型 | 默认值 | 说明 |
|----------|------|--------|------|
| `disable_collection_delay` | `bool` | `false` | 禁用收集阶段的 start_delay |
| `disable_verify_delay` | `bool` | `false` | 禁用验证阶段的 start_delay |
| `verify_delay_sweep` | `bool` | `false` | 启用渐进式 delay 扫描 |
| `verify_delay_steps` | `int` | `10` | delay 扫描步数 |
| `verify_delay_max_us` | `int64` | `800` | delay 扫描最大值（μs） |
| `verify_delay_power` | `float64` | `2.0` | 指数曲线陡度。公式：`delay(i) = maxDelay × (i/n)^power` |

### Async Split

| JSON key | 类型 | 默认值 | 说明 |
|----------|------|--------|------|
| `disable_async_split` | `bool` | `false` | `false`: 将 2 个程序扩展为 4 个（加 async 标记版本），增加竞争触发概率；`true`: 保持原样 |

### Replay 配置

| JSON key | 类型 | 默认值 | 说明 |
|----------|------|--------|------|
| `enable_replay` | `bool` | `false` | 验证前回放执行历史，重建系统状态 |
| `replay_collect_pairs` | `bool` | `false` | 回放时是否收集 race pairs（`false` 减少开销） |

### VM 快照优化

| JSON key | 类型 | 默认值 | 说明 |
|----------|------|--------|------|
| `enable_vm_snapshot` | `bool` | `false` | 启用 QEMU VM 快照（重置从 30-60s 降至 3-5s）。仅支持 QEMU + qcow2 镜像 |
| `snapshot_corpus_warmup` | `bool` | `false` | 创建快照前先运行所有 corpus 程序预热内核状态 |

### 调度策略

| JSON key | 类型 | 默认值 | 说明 |
|----------|------|--------|------|
| `enable_varname_scheduling` | `bool` | `false` | 按 VarName pair 分组轮询调度，防止某个 VarName 占用过多资源 |
| `priority_low_history` | `bool` | `false` | 优先验证 replay history 少的 entry（更快完成） |

### Validation Backoff 控制

| JSON key | 类型 | 默认值 | 说明 |
|----------|------|--------|------|
| `disable_backoff_skip` | `bool` | `false` | 禁用基于历史验证结果的概率降权/跳过逻辑。启用时所有 entry 都会被验证，不受历史失败率影响 |
| `continue_after_backoff` | `bool` | `false` | 初始 backoff-guided 验证轮结束后，重新排入先前被降权跳过的 entry，做穷尽测试 |
| `disable_hb_skip` | `bool` | `false` | 兼容旧配置名，等价于 `disable_backoff_skip` |
| `continue_after_hb` | `bool` | `false` | 兼容旧配置名，等价于 `continue_after_backoff` |

> **说明**：这里的 backoff 只是验证阶段的效率启发式，不表示真实的 happens-before 概率。

### 大规模 Corpus 配置

| JSON key | 类型 | 默认值 | 说明 |
|----------|------|--------|------|
| `streaming_load` | `bool` | `false` | 流式加载大型 `uaf-corpus.db`，避免 OOM |
| `streaming_batch_size` | `int` | `500` | 每批加载的 entry 数（8GB RAM: 300-500, 16GB: 500-1000） |
| `skip_validated` | `bool` | `false` | 跳过已验证成功的 entry（存在于 `validated_uaf.db`） |
| `skip_invalid` | `bool` | `false` | 跳过已标记无效的 entry（存在于 `invalid_uaf.db`） |
| `max_entries` | `int` | `0`（无限） | 限制加载的最大 entry 数（调试用） |

### 执行超时

| JSON key | 类型 | 默认值 | 说明 |
|----------|------|--------|------|
| `executor_program_timeout_seconds` | `int` | 使用目标超时 | 覆盖 executor 程序级 watchdog 超时 |
| `executor_syscall_timeout_millis` | `int` | `50` | 覆盖 executor syscall 级 watchdog 超时。DDRD delay 超过 50ms 时需调大 |

### History 最小化

| JSON key | 类型 | 默认值 | 说明 |
|----------|------|--------|------|
| `enable_history_minimization` | `bool` | `false` | 验证成功后最小化 replay history，找到触发 race 所需的最小子集 |
| `minimization_max_attempts` | `int` | `3` | 每步最小化的最大尝试次数 |
| `minimization_strategy` | `string` | `"binary"` | 最小化算法：`"binary"`（快速）/ `"greedy"`（质量好）/ `"hybrid"`（binary+greedy） |

### 调试配置

| JSON key | 类型 | 默认值 | 说明 |
|----------|------|--------|------|
| `target_varname_pair` | `string` | `""` | 指定 VarName pair 调试。格式：`"hex-hex"`。设置后只处理包含该 pair 的 entry，跳过所有过滤 |
| `target_corpus_key` | `string` | `""` | 指定 corpus entry key 调试。格式：`"sig0-sig1-sig2-sig3"`。可与 `target_varname_pair` 组合使用 |

---

## 7. 配置交互关系

### 依赖关系

```
uaf_mode = true  ──requires──▶  barrier_mode = true  ──requires──▶  barrier_procs (≥2)
```

### 覆盖关系

```
random_baseline_mode = true
  ├── 强制禁用 Affinity Table
  ├── 不影响 enable_timing_exploration (独立)
  └── 不影响 Object Linking / Solo Filter (保留)

注：enable_partner_selection / enable_race_yield_feedback 已废弃，
    无论设置什么值都不再有任何效果。
```

### 协作关系

| 配置 A | 配置 B | 协作方式 |
|--------|--------|---------|
| `history_buffer_size` | `new_varname_pair_history` / `new_stack_history` | buffer 是存储池，后者决定取多少 |
| `enable_replay` | `new_varname_pair_history` | replay 依赖 history 记录；history=0 则无法 replay |
| `enable_partner_selection` | `new_varname_pair_affinity_weight` / `new_stack_affinity_weight` | ~~已废弃~~ — partner selection 已固定为随机 |
| `timing_mutation_strategy=timediff` | DDRD 报告的 `TimeDiff` | timediff 策略依赖内核 DDRD 提供的时间差数据 |
| `verify_delay_sweep` | `verify_delay_steps` / `verify_delay_max_us` / `verify_delay_power` | sweep 启用后其他三个参数才生效 |
| `priority_low_history` | `enable_varname_scheduling` | priority_low_history 会自动启用 varname_scheduling |
| `continuous_mode` | `incremental_reload_minutes` / `idle_reload_seconds` | 后两者仅在 continuous_mode 下生效 |
| `streaming_load` | `streaming_batch_size` | batch_size 仅在 streaming_load 启用时生效 |

---

## 8. 完整配置示例

### 最小 UAF Fuzzing 配置

```json
{
  "experimental": {
    "barrier_mode": true,
    "barrier_procs": [0, 1],
    "uaf_mode": true
  }
}
```

### 推荐 Fuzzing 配置（含 Timing Exploration）

```json
{
  "experimental": {
    "barrier_mode": true,
    "barrier_procs": [0, 1],
    "uaf_mode": true,
    "enable_timing_exploration": true,
    "timing_exploration_ratio": 0.1,
    "timing_mutation_strategy": "targeted",
    "skip_duplicate_data_races": true,
    "history_buffer_size": 1000,
    "new_varname_pair_history": 1000,
    "new_stack_history": 100
  }
}
```

### 全功能 Fuzzing（含 Timing Exploration + Affinity）

```json
{
  "experimental": {
    "barrier_mode": true,
    "barrier_procs": [0, 1],
    "uaf_mode": true,
    "enable_timing_exploration": true,
    "timing_exploration_ratio": 0.1,
    "timing_exploration_queue_size": 500,
    "timing_mutation_strategy": "targeted",
    "max_attempts_per_pair": 20,
    "max_stacks_per_varname_pair": 20,
    "new_varname_pair_affinity_weight": 5,
    "new_stack_affinity_weight": 1,
    "skip_duplicate_data_races": true,
    "history_buffer_size": 1000,
    "new_varname_pair_history": 1000,
    "new_stack_history": 100
  }
}
```

> **注意**：`enable_partner_selection`、`enable_race_yield_feedback`、`cooldown_threshold`、
> `new_stack_penalty`、`no_discovery_penalty` 已废弃，不再需要配置。

### A/B 测试 Baseline

```json
{
  "experimental": {
    "barrier_mode": true,
    "barrier_procs": [0, 1],
    "uaf_mode": true,
    "random_baseline_mode": true,
    "enable_timing_exploration": true,
    "timing_exploration_ratio": 0.1,
    "skip_duplicate_data_races": true,
    "history_buffer_size": 1000
  }
}
```

### UAF 验证（One-Shot + Delay Sweep + VM 快照）

```json
{
  "experimental": {
    "barrier_mode": true,
    "barrier_procs": [0, 1],
    "uaf_mode": true,
    "uaf_validate": {
      "max_concurrent": 4,
      "timeout_seconds": 120,
      "repeat_count": 3,
      "verify_repeat_times": 10,
      "enable_vm_snapshot": true,
      "verify_delay_sweep": true,
      "verify_delay_steps": 20,
      "verify_delay_max_us": 1000,
      "enable_replay": true,
      "skip_validated": true,
      "skip_invalid": true
    }
  }
}
```

### UAF 验证（持续模式 + 流式加载）

```json
{
  "experimental": {
    "barrier_mode": true,
    "barrier_procs": [0, 1],
    "uaf_mode": true,
    "uaf_validate": {
      "max_concurrent": 8,
      "continuous_mode": true,
      "incremental_reload_minutes": 5,
      "streaming_load": true,
      "streaming_batch_size": 300,
      "enable_varname_scheduling": true,
      "priority_low_history": true,
      "skip_validated": true,
      "skip_invalid": true
    }
  }
}
```

---

## 9. Executor 编译时常量

以下常量在 executor C/C++ 代码中定义，不可通过 JSON 配置修改。

| 常量 | 值 | 文件 | 说明 |
|------|-----|------|------|
| `kMaxBarrierDelays` | 32 | `executor/barrier_limits.h` | barrier 最大 delay 槽位数 |
| `kDdrdMaxUafPairs` | 512 | `executor/executor_runner.h` | 单次 DDRD 分析最大 UAF pair 数 |
| `DDRD_TRACE_BUFFER_SIZE` | 64 MB | `executor/ddrd/race_detector.c` | DDRD trace buffer 大小 |
| `DDRD_MAX_RECORDS` | 65536 | `executor/ddrd/race_detector.c` | DDRD 最大解析记录数 |
| `DDRD_MAX_UAF_PAIRS` | 512 | `executor/ddrd/race_detector.c` | DDRD 最大 UAF pair 数 |
| `MAX_ACCESS_HISTORY_RECORDS` | 100 | `executor/ddrd/ddrd.h` | 每个 pair 最大 access history 记录数 |
| `KCCWF_MAX_TESTING_TID_NUM` | 2 | `executor/kccwf.h` | UKC 最大 testing TID 数 |
| `MAX_RACE_PAIR_NUM` | 1048576 | `executor/kccwf.h` | UKC 最大 race pair 数 |
| `MAX_TRACKED_THREADS` | 64 | `executor/ddrd/race_detector.h` | DDRD 最大跟踪线程数 |
| `MAX_SYSCALL_HISTORY` | 128 | `executor/ddrd/race_detector.h` | 每次执行最大 syscall 历史数 |

---

## 相关文档

- [Timing Exploration 配置指南](timing_exploration_config.md) — 双队列系统详细架构与配置示例
- [UAF Validate 配置说明](uaf_validate_config.md) — 验证管线所有配置项详细说明
- [UAF Validate 模式概览](uaf_validate_mode.md) — 验证模式工作流程与组件说明
- [Race-Guided Fuzzing 概览](race_guided_fuzzing.md) — 当前架构概览（M1'/M2 已移除）
- [Race-Guided Fuzzing 详细设计](race_guided_fuzzing_design.md) — 历史设计与实现
- [GenFuzz 重设计](genfuzz_redesign.md) — M1'/M2 移除说明与未来改进方向
- [UAF Barrier Fuzzing 框架设计](uaf_barrier_fuzzing.md) — 整体架构设计
- [DDRD 文档索引](DDRD_DOCUMENTATION_INDEX.md) — 完整文档导航
