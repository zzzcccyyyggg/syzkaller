# UAF Validate Mode 配置项说明

本文档详细说明 `uaf_validate` 模式的所有配置项及其用途。

## 配置位置

配置项位于 syz-manager 配置文件的 `experimental.uaf_validate` 节：

```json
{
  "experimental": {
    "uaf_validate": {
      // 配置项放在这里
    }
  }
}
```

---

## 基础配置

### `max_concurrent`
- **类型**: `int`
- **默认值**: 1（自动限制为 VM 数量）
- **说明**: 并发验证的最大 worker 数量。会自动调整为不超过 VM 池大小。

### `timeout_seconds`
- **类型**: `int`
- **默认值**: 90
- **说明**: 每次执行的超时时间（秒）。

### `delay_retry_budget`
- **类型**: `int`
- **默认值**: 1
- **说明**: 每次重复执行中，因崩溃或错误导致重试的最大次数。

### `repeat_count`
- **类型**: `int`
- **默认值**: 1
- **说明**: 每个 entry 的重复执行次数。用于收集稳定的 DDRD pairs。稳定判定需要 pair 出现次数 ≥ `repeat_count/2 + 1`。

---

## 运行模式

### `continuous_mode`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 启用持续模式。
  - `false`: One-Shot 模式，处理完所有现有 entries 后退出。
  - `true`: 持续运行，定期检查并加载新 entries。

### `incremental_reload_minutes`
- **类型**: `int`
- **默认值**: 10
- **说明**: （仅 `continuous_mode`）定期检查新 entries 的间隔（分钟）。

### `idle_reload_seconds`
- **类型**: `int`
- **默认值**: 30
- **说明**: （仅 `continuous_mode`）空闲时（无待处理任务）检查新 entries 的间隔（秒）。

---

## 大规模语料库配置（Streaming Load）

当 `uaf-corpus.db` 文件过大（例如 > 1GB）时，一次性加载可能导致内存溢出（OOM）或加载极慢。以下配置项支持流式加载，分批处理语料库。

### `streaming_load`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 启用内存高效的流式加载。
  - `false`: 传统模式，一次性加载所有 entries 到内存（适用于小型语料库 < 500MB）。
  - `true`: 流式加载，分批读取和处理 entries，避免 OOM。

**推荐场景**:
- 语料库包含 10,000+ entries
- `uaf-corpus.db` 文件大小 > 1GB
- 每个 entry 包含大量 ReplayHistory 记录

### `streaming_batch_size`
- **类型**: `int`
- **默认值**: 500
- **说明**: 流式加载时每批处理的 entry 数量。
  - 较小的值（100-200）: 内存占用更低，但 I/O 开销略高。
  - 较大的值（500-1000）: I/O 效率更高，但内存峰值更高。

**建议**: 根据可用内存调整。8GB RAM 建议 300-500，16GB RAM 可用 500-1000。

### `skip_validated`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 跳过已验证成功的 entries（存在于 `validated_uaf.db` 中）。
  - `false`: 处理所有 entries，包括已验证的。
  - `true`: 跳过已验证的 entries，避免重复工作。

**使用场景**: 验证中断后重新启动时，避免重复处理已成功的 entries。

### `skip_invalid`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 跳过已标记为无效的 entries（存在于 `invalid_uaf.db` 中）。
  - `false`: 处理所有 entries，包括已失败的。
  - `true`: 跳过已知无效的 entries。

**使用场景**: 避免重复尝试已知失败的 entries，节省资源。

### `max_entries`
- **类型**: `int`
- **默认值**: 0（无限制）
- **说明**: 限制加载的最大 entry 数量。
  - `0`: 加载所有 entries。
  - `> 0`: 仅加载前 N 个 entries。

**使用场景**: 测试或调试时使用小规模子集。

**示例配置**:
```json
{
  "experimental": {
    "uaf_validate": {
      "streaming_load": true,
      "streaming_batch_size": 300,
      "skip_validated": true,
      "skip_invalid": true,
      "max_entries": 0
    }
  }
}
```

---

## 调度策略

### `enable_varname_scheduling`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 启用基于 VarName 的轮询调度。
  - `false`: 使用传统的 FIFO 调度，按入队顺序处理。
  - `true`: 将 entries 按 VarName pair 分组，优先处理 entry 数量较少的 VarName，确保资源公平分配。

**使用场景**: 当某个 VarName pair 有大量不同 stack 组合时，传统调度会让该 VarName 占用过多资源。启用此选项可防止"饥饿"现象。

### `priority_low_history`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 优先验证 replay history 数量少的 entries。
  - `false`: 使用默认顺序（FIFO 或 VarName 轮询）。
  - `true`: 在每个调度组内，按 history 数量升序排序，优先处理 history 少的 entries。

**使用场景**: History 数量少的 entry 需要较少的 replay 开销，可以更快完成验证。适合优先处理"轻量级"entries 以快速积累结果。

**注意**: 此选项会自动启用 `enable_varname_scheduling`（如果未启用）。

### `disable_backoff_skip`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 禁用基于历史验证结果的概率降权/跳过逻辑。
  - `false`: 使用 backoff score 对历史失败次数多、验证收益低的 entries 和 pairs 进行概率性降权。
  - `true`: 禁用该降权逻辑，允许所有 entries 被验证。

**注意**: 这里的 backoff score 只是验证阶段的效率启发式，并不声称表示真实的 happens-before 概率。

**兼容性**: 旧配置名 `disable_hb_skip` 仍然可用，语义与本项完全一致。

**使用场景**: 当您在 `target_corpus_key` 模式能成功复现但 `continue` 模式无法复现时，可能是因为 backoff 分数累积导致该 entry 被跳过。启用此选项可以重新尝试被跳过的 entries。

**警告**: 启用此选项会增加无效验证的数量，因为系统不会跳过已知的高失败率 pairs。建议仅在调试时使用。

### `continue_after_backoff`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 在初始 backoff-guided 验证轮完成后，将之前因 backoff 跳过的 entries 重新入队并再次测试。
  - `false`: 结束于 backoff-guided 验证轮。
  - `true`: 再做一轮穷尽测试，避免长期实验中过早空闲。

**兼容性**: 旧配置名 `continue_after_hb` 仍然可用，语义与本项完全一致。

---

## Stable Pairs 收集

### `require_origin_match`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 控制 stable pairs 是否必须在原始 corpus pairs 中存在。
  - `false`: 接受任何运行时发现的 pairs（只要满足稳定性阈值）。
  - `true`: 仅接受同时存在于 `entry.Pairs` 中的运行时 pairs。

**注意**: 设为 `false` 可发现新的 stack 组合，增加覆盖范围。

---

## 验证阶段配置

### `verify_repeat_times`
- **类型**: `int`
- **默认值**: 10
- **说明**: 验证阶段每个 pair 的重复执行次数。更高的值增加置信度但耗时更长。

### `disable_async_split`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 禁用验证阶段的 async call splitting。
  - `false`: 将每对程序（2个）扩展为 4 个程序，增加竞争触发概率。
  - `true`: 保持程序原样执行。

### `disable_collection_delay`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 禁用收集阶段的 start_delay。
  - `false`: 收集阶段使用人工延迟。
  - `true`: 收集阶段使用自然时序，延迟仅在验证阶段应用。

### `disable_verify_delay`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 禁用验证阶段的 start_delay。
  - `false`: 验证阶段使用从收集阶段传递的 start_delay 值。
  - `true`: 验证阶段不使用 start_delay，仅依赖内核侧的 access_delay（ukcDelayMicros）。

**注意**: 此选项与 `disable_collection_delay` 独立。可以组合使用：
- 两者都为 `false`: 收集和验证阶段都使用 start_delay。
- 仅 `disable_collection_delay=true`: 收集使用自然时序，验证使用延迟。
- 仅 `disable_verify_delay=true`: 收集使用延迟，验证仅用内核侧延迟。
- 两者都为 `true`: 完全禁用 start_delay，仅依赖内核侧延迟。

---

## Delay Sweep 配置

用于在验证阶段尝试多个不同的延迟值，增加竞争触发概率。

### `verify_delay_sweep`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 启用渐进式延迟扫描。启用后生成多个具有不同延迟的验证请求。

### `verify_delay_steps`
- **类型**: `int`
- **默认值**: 10
- **说明**: 延迟扫描的步数。每步使用不同的延迟值。

### `verify_delay_max_us`
- **类型**: `int64`
- **默认值**: 800
- **说明**: 延迟扫描的最大延迟值（微秒）。

### `verify_delay_power`
- **类型**: `float64`
- **默认值**: 2.0
- **说明**: 指数曲线的陡峭程度。计算公式：`delay(i) = maxDelay * (i/n)^power`

---

## 执行超时配置

### `executor_program_timeout_seconds`
- **类型**: `int`
- **默认值**: 使用目标超时
- **说明**: executor 的程序级 watchdog 超时（秒）。

### `executor_syscall_timeout_millis`
- **类型**: `int`
- **默认值**: 50
- **说明**: executor 的系统调用级 watchdog 超时（毫秒）。当 DDRD 延迟超过默认 50ms 预算时使用。

---

## Replay 配置

用于在验证前回放执行历史，重建系统状态。

### `enable_replay`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 启用执行历史回放。验证每个 entry 前，回放保存的执行历史以重建发现该 pair 时的系统状态。

### `replay_collect_pairs`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 回放阶段是否收集 race pairs。
  - `false`: 回放时跳过 pair 收集以减少开销。
  - `true`: 回放时也收集 pairs。

---

## VM 快照优化

### `enable_vm_snapshot`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 启用 QEMU VM 快照模式。
  - 初次启动后保存 VM 状态快照
  - 后续任务通过恢复快照而非重启 VM
  - 可将每任务开销从 30-60s 降至 3-5s

**要求**:
- 仅支持 QEMU VM 类型
- 磁盘镜像必须为 qcow2 格式
- 不要使用 `-cpu host,migratable=off`

### `snapshot_corpus_warmup`
- **类型**: `bool`
- **默认值**: `false`
- **说明**: 创建快照前执行所有 corpus 程序进行"预热"，使内核状态（缓存、内部结构）更接近真实运行状态。

---

## 调试配置

### `target_varname_pair`
- **类型**: `string`
- **默认值**: 空
- **格式**: `"freeAccessName-useAccessName"`（16 位十六进制，如 `"610067002c7c8254-235d4d37a0583ad1"`）
- **说明**: 指定要调试的特定 VarName pair。设置后：
  - 仅处理包含该 VarName pair 的 entries
  - 跳过所有过滤逻辑（invalid/validated/backoff skip）
  - 验证结果不写入数据库，仅输出日志

### `target_corpus_key`
- **类型**: `string`
- **默认值**: 空
- **格式**: `"sig0-sig1-sig2-sig3"`（64 位十六进制 key，如 `"d9daa1d91920e5d5-7ae0c8d447027fda-b52a7fe3d5ed9139-027653b5437bc01a"`）
- **说明**: 指定要调试的特定 corpus entry key。设置后：
  - 仅加载并处理匹配该 key 的 entry
  - 跳过所有过滤逻辑（invalid/validated/backoff skip）
  - 可与 `target_varname_pair` 组合使用，进一步过滤该 entry 中的特定 pairs

**组合使用**:
- 仅设置 `target_corpus_key`: 验证该 entry 的所有 pairs
- 仅设置 `target_varname_pair`: 验证所有包含该 VarName 的 entries
- 两者都设置: 验证该 entry 中匹配 VarName 的 pairs

---

## 配置示例

### 基础验证（One-Shot）

```json
{
  "experimental": {
    "uaf_validate": {
      "max_concurrent": 4,
      "timeout_seconds": 120,
      "repeat_count": 3
    }
  }
}
```

### 持续验证（与 Fuzzer 并行）

```json
{
  "experimental": {
    "uaf_validate": {
      "max_concurrent": 8,
      "continuous_mode": true,
      "incremental_reload_minutes": 5,
      "idle_reload_seconds": 15,
      "enable_varname_scheduling": true
    }
  }
}
```

### 高效验证（VM 快照 + Delay Sweep）

```json
{
  "experimental": {
    "uaf_validate": {
      "max_concurrent": 4,
      "enable_vm_snapshot": true,
      "verify_delay_sweep": true,
      "verify_delay_steps": 20,
      "verify_delay_max_us": 1000,
      "require_origin_match": false
    }
  }
}
```

### 调试特定 Pair

```json
{
  "experimental": {
    "uaf_validate": {
      "max_concurrent": 1,
      "target_varname_pair": "610067002c7c8254-235d4d37a0583ad1",
      "repeat_count": 5,
      "verify_repeat_times": 20
    }
  }
}
```

---

## 持久化文件

验证过程会生成以下数据库文件（位于 workdir）：

| 文件 | 说明 |
|------|------|
| `uaf-corpus.db` | 源 corpus entries（来自 fuzzer） |
| `validated_uaf.db` | 验证成功的 pairs 及详细信息 |
| `invalid_uaf.db` | 验证失败的 pairs（用于跳过） |
| `varname_backoff_stats.db` | VarName pair 的 validation backoff 统计信息（兼容旧文件名 `varname_hb_stats.db`） |

---

## 日志前缀

验证过程中的日志使用以下前缀：

- `uafvalidate:` - 一般验证流程
- `uaf validation:` - Manager 层信息
- `varname_backoff:` - VarName backoff 统计
- `[history]` - Replay 相关
- `[batch]` - 批量执行相关
- `[debug mode]` - 调试模式专用
