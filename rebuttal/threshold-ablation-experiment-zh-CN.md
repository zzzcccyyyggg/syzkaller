# 动态阈值消融正式实验配置

状态：正式配置已修订为 12 小时口径。当前 8 小时轮次保留为 pilot，
不得与后续 12 小时正式结果静默合并。

## 1. 实验问题

在相同初始输入、内核、调度策略、LLM mutator 和资源预算下，比较动态阈值与固定/随机阈值对以下指标的影响：

- confirmed races；
- unique access+stack pairs 与 VarName race families；
- MRP/corpus 产出；
- validation queue 的生产、消费与积压；
- fuzz throughput；
- LLM 请求、token、延迟和成本。

## 2. 模块与实验组

正式实验覆盖三个代表模块：

- `ptmx`：候选较密集；
- `dsp`：候选较稀疏；
- `bt-stack`：候选较稀疏且单次验证开销较高。

每个模块包含四组：

| 组 | 阈值策略 |
| --- | --- |
| Dynamic | `min=100us, initial=1000us, max=2000us` |
| Fixed-min | 恒定 `100us` |
| Fixed-max | 恒定 `2000us` |
| Random | 每 30 秒在闭区间 `[100, 2000]us` 中重新进行一次整数均匀采样 |

Dynamic 使用论文 Algorithm 1 的参数：

```text
Tc = 30s
Wlow = 10
Whigh = 40
rho = 0.8
epsilon = 1
tightening factor = 0.5
relaxation step = 0.05 * (2000 - 100) = 95us
```

Random 和静态输入探索的随机种子均固定为 `1592594996`。

## 3. 资源与时长

论文实验的资源归一化基线是每阶段 `2 cores * 24h = 48 core-hours`。
正式消融恢复论文既有的 12 小时配置，每阶段使用 4 个物理核：

```text
Fuzz:      4 physical cores * 12h = 48 core-hours
Validate:  4 physical cores * 12h = 48 core-hours
```

每组配置：

```text
Fuzz:      4 VMs, 2 vCPUs/VM, procs=2, pinned to 4 physical cores
Validate:  4 VMs, 2 vCPUs/VM, pinned to 4 physical cores
VM memory: 1 GiB/VM
VM lifetime before restart: 1h
LLM producer: one isolated local CPU core; remote request concurrency=2
Duration:   12h wall-clock
```

32 核本机两组并行时的 CPU 划分：

```text
Slot A: fuzz=0-3,  validate=4-7,   LLM=16
Slot B: fuzz=8-11, validate=12-15, LLM=17
Host/watcher/I/O reserve: 18-31
```

每个模块分两轮：

1. Dynamic 与 Fixed-min；
2. Fixed-max 与 Random。

第二轮交换 Slot A/B 的策略位置；不同模块继续轮换位置，降低 CPU slot
偏差。单机两轮完成一个模块需要约 24 小时。远端 56 核主机可以给四组各分配
独立的 4+4 物理核并在 12 小时内并行完成，但每组资源不得改变。

注意：管理员原文接受 24 小时消融。正式结果必须明确写成“12h
wall-clock under a 4-core-per-stage allocation, equivalent to the original
24h/2-core-per-stage compute budget”，不能直接写成实际运行了 24 小时。

Validate VM 数固定为 4，而不是在 4 个物理核上强行运行 8 个双 vCPU VM。
现有 pilot 表明过量 VM 没有带来相称的 processed-pair 提升，反而增加启动、
SSH、内存和重复验证压力。VM 数变化不改变每阶段 4 个物理核的资源口径。

## 4. GPT-5.4 Producer

为避免 DeepSeek-V4-Pro 当前版本与论文实验版本漂移，正式阈值消融统一使用 GPT-5.4。调用方式固定为直接的 Responses-compatible API 请求，不经过 Codex CLI agent：

```text
provider=openai-responses
base_url=https://deepkey.top/v1
auth source=/home/zzzccc/.codex-bass/auth.json
model=gpt-5.4
reasoning effort=medium
store=false
structured output=strict JSON schema
```

2026-08-23 的直接 `/responses` smoke 返回：

```text
model: gpt-5.4
status: completed
usage: input/output/total tokens present
```

Producer 完全恢复论文 12 小时配置，不再做 8 小时容量缩放：

| 参数 | 正式 12h 配置 |
| --- | ---: |
| entries per round | 4 |
| parallel calls | 2 |
| variants per entry | 2 |
| poll interval | 30s |
| max syscalls per generated program | 8 |

每轮最多分两批 `2+2` 请求。并发数是容量上限；实际 model calls、accepted
programs 和 token 使用量仍由各策略产生的 eligible corpus 决定，必须作为结果
完整报告，不能通过重复变异旧 entry 强行补齐。

Producer 的本地 CPU 主要用于 prompt 构造、HTTP I/O、JSON 解析和 checker；模型推理在远端完成。每组将 producer 固定在一个物理核上以隔离 fuzz 核，但该核不纳入 fuzz/validate core-hour 口径。

### API 与模型口径

`~/.codex-bass/config.toml` 配置了 `wire_api=responses` 和 `base_url=https://deepkey.top/v1`，其 `auth.json` 提供 API key。Producer 直接调用该 endpoint 的 `/responses`，不启动 Codex CLI，因此不会注入 Codex agent/system、sandbox 或仓库上下文。

- endpoint 实际返回的模型字段为 `gpt-5.4`；
- API input 只包含实验显式定义的 system/user messages 与 strict JSON schema；
- `deepkey.top` 是 OpenAI-compatible provider endpoint，不是官方 `api.openai.com`；artifact 和 rebuttal 必须披露实际 base URL 和 provider 类型；
- 若后续切换到官方 OpenAI API，必须重新 smoke 并作为不同 provider 记录，不能与当前结果静默混合。

所有四组使用同一 endpoint、模型、reasoning、并发与 prompt 模板。每组根据自身发现的 corpus 独立生成 mutation，不共享 accepted LLM outputs。

Producer 从每个 Responses API 返回值保存 `input_tokens`、cached/cache-write input、`output_tokens`、reasoning tokens 和 `total_tokens`。后续成本按这些 token 分项和所选价格表离线计算。

## 5. 初始状态与功能开关

同一模块的四组必须使用：

- 相同 initial corpus 文件和 SHA256；
- 相同 kernel image、VM image、manager/executor 二进制及其哈希；
- 全新的 workdir、MRP DB、validation DB、backoff DB 和 LLM 输出目录；
- 相同 syscall allowlist 和模块专用 QEMU 设备参数。

功能配置：

```text
full MRPFuzz producer/consumer pipeline = enabled
timing exploration = disabled
solo filter = disabled
coverage triage = disabled
object linking = disabled
history replay = enabled
history size = 100
max stack variants per VarName family = 10
canonical unordered VarName backoff = enabled
max concurrent validation tasks per VarName family = 1
```

canonical backoff 将 `A-B` 与 `B-A` 视为同一 data-race family。同一 family
最多只有一个验证任务在途，其余任务保留在等待队列，不丢弃。该修复避免同一
race 因 stack 变化、反向表示或并发在途任务而被重复确认。

## 6. Collection、Verification 与 Delay

```text
collection repeat count = 2
stable pair minimum occurrences = 1
verification repeat count = 1
max tasks per corpus = 3
max pairs per task = 8
max stable pairs per entry/origin = unlimited
origin match mode = varname
target match mode = sn-fallback
SN fallback range = 2
```

Access delay：

- 按论文 Algorithm 2，strict/range 使用 `lambda * observed_dt`，冻结总倍率 `lambda=2000`；
- stack-only fallback 使用 strict/range 的五分之一，即总倍率 `400`；
- collection 使用每个 queue entry 记录的 admission threshold，而不是统一的固定阈值。

这里必须区分 manager 配置值与内核实际值。当前实验内核对传入的 access delay
应用固定 `x10` 倍数，因此 manager 只负责剩余的 `x200` 和 `x40`：

```text
verify_access_delay_normalize_to_threshold = false
verify_access_delay_multiplier              = 200
verify_stack_access_delay_multiplier        = 40
verify_access_delay_min_us                  = 1000
verify_access_delay_max_us                  = 1000000
kernel multiplier                           = 10
effective strict/range multiplier           = 2000
effective stack-only multiplier             = 400
```

以正式 F2FS 范围 `500-5000us` 为例，strict/range 最长可达到 `10s`，
stack-only 最长可达到 `2s`。对应超时统一冻结为：

```text
executor syscall timeout = 20s
executor program timeout = 180s
validation timeout       = 180s
max batch timeout        = 900s
```

## 7. 截止口径与指标

主结果严格取第 12 小时截止点，不继续排空 validation queue。否则
Fixed-max/Random 会获得额外验证时间，破坏固定资源预算。

每组至少报告：

- calls executed、exec total 和 calls/s；
- MRP、VarName、corpus 及其时间序列；
- queue produced/processed/pending、处理速率与利用率；
- threshold trajectory、处于上下界的时间比例；
- exact validation events、canonical access+stack pairs、unordered VarName families、race-producing corpus；
- time to first race；
- GPT 请求数、eligible/processed backlog、input/cache/output/reasoning/total tokens、延迟和失败率；
- QEMU restart、OOM、SSH failure、磁盘最低余量。

可以复制第 12 小时的冻结队列做诊断性 drain，但其结果不得计入主实验
confirmed-race 数量。

## 8. 启动前 Smoke Contract

正式运行前先进行两组并行的 30 分钟 PTMX smoke，并分别完成 DSP/Bluetooth 的模块设备 smoke。通过条件：

- 两组 smoke 时 16 台 QEMU 全部在线；远端四组并行时应为 32 台；
- calls executed 和 validator processed 持续增长；
- 无 guest OOM、SSH 丢失或 manager 提前退出；
- GPT-5.4 两并发请求成功，模型解析仍为 `gpt-5.4`；
- `eligible - processed` 不持续单调增长；
- initial corpus、kernel、binary 哈希在两组间一致；
- 可用磁盘始终大于 25 GiB。

若 LLM backlog 持续增长，不允许在单组中途修改并发；必须统一修改四组配置并重新开始。

## 9. 运行事故记录

2026-08-24 停止并作废了以下两轮预正式矩阵：

- `20260823-local-ptmx-threshold-formal-gpt54api-wave1-6f12v-1g-8h-v3`；
- `20260823-remote-dsp-threshold-formal-gpt54api-4arm-6f12v-1g-8h-v1`。

这些轮次使用了按 admission threshold 归一化的绝对 delay，而论文 Algorithm 2
规定的是固定 `lambda * observed_dt`。此外，它们没有为秒级内核忙等同步提高
syscall/program timeout，stack-only 也不是独立的五分之一倍率。因此只能作为诊断
材料，不得计入 rebuttal 或论文正式统计。

以下 8 小时、6 fuzz VM/12 validate VM（或 PTMX 6/6 VM）轮次保留为
资源密度与实现诊断 pilot，不作为新的 12 小时正式消融结果：

- `20260824-local-ptmx-threshold-formal-corrected-delay-gpt54api-wave1-6f12v-1g-8h-v1-*`；
- `20260824-local-ptmx-threshold-formal-corrected-delay-gpt54api-wave2-6f12v-1g-8h-v2-*`；
- `20260824-remote-dsp-threshold-formal-improved-queue-gpt54api-wave*-6f12v-1g-8h-v1-*`；
- `20260824-remote-bt-stack-threshold-formal-improved-*-gpt54api-6f12v-1g-8h-v3`；
- `20260824-remote-ptmx-dynamic-gpt54api-6f6v-1g-8h-v3`。

后续正式轮必须使用全新 workdir 和
`bin/syz-manager-canonical-family1`。当前冻结二进制 SHA-256 为：

```text
e7b8bb8ff11f6413b7e4380347295c1facc5367485c28bf79e33405283c3e7fb
```
