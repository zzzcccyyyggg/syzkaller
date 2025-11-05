# UAF Validate 模式改动说明（modified.md）

更新时间：2025-11-03

本文档说明本次为新增 “uaf-validate” 模式而做的代码改动：改了哪些文件、如何修改、为什么这样修改，以及如何使用与并行验证行为说明。

## 目标概述

- 在 manager 中新增 uaf-validate 模式：从 `uaf-corpus.db` 读取 UAF pair 并进行“只用于校验”的执行。
- ExecutionContext 仅用于还原状态，不做检测/覆盖收集/上报。
- 对 prog pair 的执行仅用于判定是否出现 UAF，不当作新发现上报、不更新信号/覆盖。
- 每验证完一个 UAF pair 就重启。
- 支持并行验证（多个 fuzzer/VM 同时验证不同 pair，避免重复领取）。

---

## 主要改动一览

### 1) RPC 类型与接口（新增）

文件：`pkg/rpctype/rpctype.go`
- 模式查询结构体（保留兼容旧版 fuzzer，现阶段通过 CLI 参数直接传递模式）：
  - `type CurrentModeArgs struct{ Name string }`
  - `type CurrentModeRes struct{ Mode string }` // "normal" | "concurrency" | "uaf-validate"
- 新增 UAF 验证任务/结果：
  - `type UAFValidateTask struct{ PairID uint64; Prog1, Prog2, ExecutionContext []byte; RebootAfter bool; TimeoutSec int32 }`
  - `type GetUAFValidateTaskArgs struct{ Name string }`
  - `type GetUAFValidateTaskRes struct{ HasTask bool; Task UAFValidateTask }`
  - `type UAFValidateResult struct{ PairID uint64; Succeeded bool; DetectedCount int; UAFs []byte; Error string }`
  - `type ReportUAFValidateResultArgs struct{ Name string; Result UAFValidateResult }`
  - `type ReportUAFValidateResultRes struct{ Ack bool }`

文件：`syz-manager/rpc.go`
- 新增 RPC：
  - `CheckCurrentMode(a *rpctype.CurrentModeArgs, r *rpctype.CurrentModeRes) error`
  - `GetUAFValidateTask(a *rpctype.GetUAFValidateTaskArgs, r *rpctype.GetUAFValidateTaskRes) error`（并发安全分配，传入 fuzzer 名避免重复）
  - `ReportUAFValidateResult(a *rpctype.ReportUAFValidateResultArgs, r *rpctype.ReportUAFValidateResultRes) error`（落库 + 释放 in-flight）
- 保留兼容：原有 `CheckTestPairMode` 仍可用（fuzzer fallback）。

### 2) 模式枚举（新增常量）

文件：`syz-manager/fuzz_scheduler.go`
- 新增 `const FuzzModeUAFValidate FuzzMode = "uaf-validate"`
- 在 `NewFuzzScheduler` 中对该模式禁用 normal/race 两阶段切换（仅作对外模式标识）。

### 3) Manager 侧（验证队列、并行与落库）

文件：`syz-manager/manager.go`
- 新增字段：
  - `uafValidateMode bool`：是否处于验证模式
  - `uafValidatedDB *uafvalidate.ValidatedDB`：验证记录库
  - `uafValidateQueue []uint64, uafValidateIndex int`：待验证队列
  - `uafValidateMu sync.Mutex, uafInFlight map[uint64]string`：并行与去重（pairID -> fuzzer 名）
  - `UAFCorpusItem` 额外包含 `Validated/ValidatedAt/LastValidationErr`，用于记录复现状态与最近一次失败信息
- 初始化：
  - 加载 UAF corpus 后，若配置 `experimental.fuzz_mode == "uaf-validate"`，调用 `initUAFValidateMode()`：
    - 打开/创建 `workdir/race_validated.db`
    - 从 `uaf-corpus.db` 读取未验证的 pairID 列表形成队列（没有 DB 时回退到内存 corpus 键）
    - 初始化 `uafInFlight`
    - 将历史验证记录同步进内存，补上状态与时间戳
- 新增方法：
  - `nextUAFValidateTask(requester string) (rpctype.UAFValidateTask, bool)`：并发安全地派发下一条“未 in-flight”的任务，并标记 in-flight
  - `handleUAFValidateResult(res rpctype.UAFValidateResult) error`：比对复现出的 UAF 信号与 corpus 基线，只有存在交集才落库为 Validated；同步更新 `UAFCorpusItem` 元数据后，写入验证数据库或记录失败原因，并移除 in-flight 标记
- 语义保证：验证模式下不更新全局 UAF corpus/signal/coverage，不触发新的上报。

### 4) Fuzzer 侧（模式选择与验证循环）

文件：`syz-fuzzer/fuzzer.go`
- 新增字段：`currentMode string` // "normal" | "concurrency" | "uaf-validate"
- 启动模式判定：
  - 新增 `-mode` CLI 参数；manager 通过 optional flags 传入，fuzzer 使用 `normalizeModeFlag` 归一化该参数并决定运行路径（不再依赖 RPC 查询）。
- 验证循环：
  - 若 `currentMode == "uaf-validate"`：不启动常规 `proc.loop()` 与 `pollLoop()`，转入 `validateLoop()`
  - `validateLoop()`：
    1) `GetUAFValidateTask` 领取任务
    2) 若带 `ExecutionContext`：反序列化为 `[]vmexec.ExecutionRecord`，逐条回放（仅 `ipc.FlagTestPairSync`），不检测、不收集、不上报
    3) 对 `Prog1/Prog2` 做一次“检测型运行”（`ipc.FlagTestPairSync | ipc.FlagCollectUAF`），并把复现得到的 `MayUAFPair` 明细 JSON 一并上报，供 manager 做交叉校验
       - 不调用 `sendUAFPairsToManager*`，不更新本地/全局信号覆盖，避免污染
    4) `ReportUAFValidateResult` 上报
    5) 若任务 `RebootAfter` 为 true，则 `os.Exit(0)`（交由 manager 重启）

### 5) 仅构建工具的文件（修复编译错误）

文件：`pkg/uafvalidate/validate.go`
- 添加 build tag 使其默认不参与编译：
  - `//go:build uafvalidate_tool`
  - `// +build uafvalidate_tool`
- 原因：该文件是早期未完成的验证器草稿，包含未定义字段/变量，导致默认 `make` 失败；实际运行仅需要同目录下的 `validated_db.go`（Manager 使用它落库）。
- 如需单独编译该工具，可使用 `-tags uafvalidate_tool`。

---

## 为什么这样修改

- 正交性：把“验证流程”与“常规 fuzz/覆盖/上报”彻底分离，严格满足“只校验，不污染”。
- 可扩展：通过 Manager 的 in-flight 去重与多 VM 并行领取，提升吞吐量。
- 兼容性：保留原 RPC 与流程，默认模式不受影响；验证模式只在配置开启时生效。
- 稳定性：每条验证后重启实例，保持环境干净；结果落库支持断点续跑与统计。

---

## 如何使用

1) 在 `manager.cfg` 中设置：
- `experimental.fuzz_mode: "uaf-validate"`

2) 确保 `workdir/uaf-corpus.db` 存在。

3) 构建与运行：
- `make`
- `bin/syz-manager -config /path/to/manager.cfg`

并行度由 VM/fuzzer 数量决定（与常规 fuzz 一样）。

---

## 并行验证行为

- 每个 fuzzer 会调用 `GetUAFValidateTask` 获取下一条任务；Manager 通过 `uafInFlight` 保证不会把同一 pair 同时分配给多个 fuzzer。
- 验证结束后 fuzzer 上报 `ReportUAFValidateResult` 并按任务指令重启；Manager 接续派发下一条，形成稳定流水线。

---

## 后续可选增强

- 最大并发度/任务超时/失败重排队与重试的策略参数化。
- 验证指标导出（成功率、耗时分布、队列长度等）。
- 基于 ExecutionContext 的路径距离/延迟注入，提高复现实验成功率（已有 `vmexec` 基础）。

---

## 受影响的关键文件列表

- `pkg/rpctype/rpctype.go`：新增模式查询与 UAF 验证任务/结果的 RPC 结构体
- `syz-manager/fuzz_scheduler.go`：新增 `FuzzModeUAFValidate`
- `syz-manager/manager.go`：新增验证模式状态与并发调度、任务派发与结果落库
- `syz-manager/rpc.go`：新增 `GetUAFValidateTask`、`ReportUAFValidateResult`（`CheckCurrentMode` 保留兼容但 fuzzer 默认使用 CLI 参数）
- `pkg/instance/instance.go`：optional flag 增加 `mode` 传递；
- `syz-manager/manager.go`：新增 `effectiveFuzzerMode()` 计算实际模式并通过命令行参数传递给 fuzzer
- `syz-fuzzer/fuzzer.go`：新增 `-mode` flag、去除 RPC 模式探测、保持验证循环逻辑
- `syz-fuzzer/fuzzer.go`：新增 `uaf-validate` 启动流与 `validateLoop`（不污染全局）
- `pkg/uafvalidate/validate.go`：加 build tag，默认不参与编译

如需更详细的代码级 diff，请查看上述文件的 git 历史记录。
