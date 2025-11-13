# DDRD Barrier Implementation Status

## 已完成的工作

### 1. Runner 侧 DDRD 控制器 ✅
- **RunnerDdrdController** 类实现完整
  - `PrepareForGroup()`: 在派发前初始化 DDRD (LOG 模式、清空 trace、reset detector)
  - `CollectResults()`: 收集所有 barrier 成员完成后的 UAF pairs
  - `ResetAfterGroup()`: 清理状态，恢复 MONITOR 模式
  - 支持扩展历史收集

### 2. Barrier 派发集成 ✅
- `TryDispatchBarrier()` 检查 DDRD 标志并调用 `PrepareForGroup()`
- 在 `BarrierGroupState` 中跟踪 `ddrd_active` 标志
- 在 `ActiveBarrierExecution` 中记录活跃的 barrier 组

### 3. 完成跟踪与结果暂存机制 ✅
- 现在不再使用全局 `g_barrier_completion` 单点通知
- `Proc::HandleCompletion()` 对 barrier 请求不立即发送结果，而是构造 `StagedBarrierResult` 暂存
- Runner 通过 `StageBarrierResult()` 增量记录已完成成员并填充 `ActiveBarrierExecution.pending_results`
- `CheckBarrierCompletions()` 检测整组完成后统一收集 DDRD 并 Flush 全部暂存结果（仅 master 注入 DDRD）

### 4. Executor 侧修改 ✅
- `ddrd_prepare_for_request()` 在 barrier 请求时早退
- `g_ddrd_runner_output` 指针机制用于 runner 注入
- `ddrd_build_output()` 优先使用 runner 注入的输出
- 条件编译防护避免类型重复定义

### 5. 文档更新 ✅
- `docs/ddrd_executor_flow.md`: 完整的 runner 侧流程说明
- `docs/barrier_dispatch_flow.md`: 新增 DDRD 集成章节

## 当前架构说明

### 新的延迟发送架构（已实现）
现在采用 **方案 A 的核心思想（延迟发送 + 统一注入）**：

1. `Proc::HandleCompletion()` 对 barrier 成员只做解析（elapsed/num_calls/output），不调用 `finish_output()`，而是暂存原始参数。
2. Runner 在所有成员完成后：
   - 调用 `RunnerDdrdController::CollectResults()` 聚合并分析 trace。
   - 对 master 成员调用 `ddrd_set_runner_output(&GetOutput())` 注入 DDRD；其它成员调用 `ddrd_clear_runner_output()`。
   - 通过 `Proc::FlushPendingResult()` 重建 FlatBuffer（调用一次真正的 `finish_output()`），并发送。
3. 发送顺序由 Runner 控制（当前实现按索引顺序，master 优先或不优先都可扩展）。
4. 发送后调用 `ddrd_controller_.ResetAfterGroup()` 恢复状态。

### Barrier + DDRD 请求新流程:
```
1. Runner::TryDispatchBarrier()
   ├─ 聚合成员 -> 判断是否需要 DDRD
   ├─ ddrd_controller_.PrepareForGroup()
   └─ 派发成员 (active_barriers_[gid] 建立)

2. Proc::HandleCompletion()（每个成员）
   ├─ 解析 elapsed/num_calls/output
   ├─ 构造 StagedBarrierResult 并调用 stage_barrier_cb_ 暂存
   └─ 标记 has_pending_result_ 阻止再次调度

3. Runner::CheckBarrierCompletions()
   ├─ 检测 active.completed == group_size 且所有 pending_results 就绪
   ├─ DDRD 收集与输出注入（仅 master 注入）
   ├─ 遍历 pending_results 调用 FlushPendingResult() 逐个发送
   └─ 清理 active_barriers_ 与 DDRD 状态
```

### 结果注入行为
- 仅 barrier_index == 0 的成员包含 DDRD 数据（避免重复）。
- 其它成员的 ExecResult 中 DDRD 字段为空（或缺失）。
- 去重策略由上层 manager 根据 barrier 元数据决定。

## 测试建议

### 编译测试
```bash
cd /home/zzzccc/syzkaller
make clean
make TARGETARCH=amd64 HOSTARCH=amd64
```

### 运行时测试

#### 1. 验证 barrier 派发和 DDRD 准备
查看日志中的消息：
```bash
# 应该看到:
runner: barrier group=X ready for dispatch (N members)
ddrd: clearing trace buffer before barrier execution
runner: dispatching barrier group=X members=N
```

#### 2. 验证完成跟踪
```bash
# 应该看到每个成员完成:
proc slot X: barrier completion notify group=Y index=Z
runner: barrier group=Y member index=Z completed (M/N)

# 所有完成后:
runner: barrier group=Y all N members completed
runner: collecting DDRD results for barrier group=Y
runner: DDRD collection complete for group=Y - K UAF pairs found
runner: barrier group=Y cleanup complete
```

#### 3. 验证 DDRD 收集
```bash
# 在 runner 日志中应该看到:
ddrd: collecting results
ddrd: detected N UAF pair(s)
ddrd: pair[0] free_access=0x... use_access=0x...
```

### 当前限制

当前实现已解决“结果无法进入 ExecResult”问题：master 成员的最终 ExecResult 包含 DDRD 数据，非 master 成员不包含，避免重复。若需要所有成员都携带（例如本地调试），可在 Flush 阶段去掉 index 检查。

## 下一步工作

### 优先级 1: 完善分发与回收
- [x] 方案 A 核心（延迟发送与注入）
- [ ] 可选：增加单独 DDRD 消息（用于跨版本兼容或调试）

### 优先级 2: 健壮性改进
- [ ] 处理部分成员失败的情况
- [ ] 添加超时机制避免 barrier 组永久挂起
- [ ] 改进错误处理和日志

### 优先级 3: 性能优化
- [ ] 避免在 CheckBarrierCompletions() 中重复检查
- [ ] 使用更高效的完成通知机制
- [ ] 考虑并发安全性

## 代码位置索引

- **Runner DDRD 控制器与暂存逻辑**: `executor/executor_runner.h` (查找 `RunnerDdrdController`, `StagedBarrierResult`, `FlushPendingResult`)
- **Barrier 派发**: `executor/executor_runner.h::TryDispatchBarrier()` (~line 1200)
- **完成跟踪**: `executor/executor_runner.h::CheckBarrierCompletions()` (~line 1160)
- **Executor 早退**: `executor/executor.cc::ddrd_prepare_for_request()` (~line 410)
- **结果注入机制**: `executor/executor.cc::ddrd_build_output()` (~line 530)
