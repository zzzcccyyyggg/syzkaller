# MRPFuzz 仓库整理与 throughput 优化交接

更新时间：2026-07-23 Asia/Shanghai

这份文档写给没有任何聊天上下文的新会话。先读这里，再继续动仓库。

## 1. 我们在做什么

当前任务分成四条相互关联、但必须分开取证的线：

1. 稳定当前代码：验证并提交尚未提交的 pair-analysis 优化和 1h restart 配置修复。
2. 补 throughput 实验：在 MRPFuzz 和 SegFuzz 中加入语义一致的 syzkaller call 计数（必要时再拆分真实 syscall 与 `syz_*` pseudo-call），并做固定物理资源对比，检验 decouple/may-race-pair producer 是否足够轻量。
3. 整理论文资产：按论文 claim/figure/table 建立原始数据、派生数据、脚本和版本信息之间的 provenance，不能继续依赖含义不清的历史目录名。
4. 补阈值实验：先验证 producer/consumer 计数和共享状态正确，再比较动态阈值与一组固定阈值，判断 backpressure controller 是否真的有效。

用户已经明确过几个约束：

- 论文主线是 race / may-race pair，不是 UAF。现有 `uaf_*` 命名大多是历史债。
- pair 收集、may-race pair 分析、结果注入、race corpus 更新是 fuzz 主功能，不能为了 exec 数字把它们关掉。
- throughput 对比看 overall，MRPFuzz 所有 VM 的总量才是系统结果；旧日志的 `exec total` 继续保留，但新实验的主口径应是 host 可观测到实际开始执行的 syzkaller call 数。
- 固定物理资源时，MRPFuzz 所有 VM 加起来的 exec 才能和 SegFuzz 对比，不能拿单 VM 数字比。
- 所有内核/trace 改动测试必须放在 QEMU 里，不要在 host 上直接试。
- 正式实验必须区分 producer throughput 微基准与论文 4-core end-to-end 配置；二者回答的问题不同，不能混成一个数字。

## 2. 当前结论

工程状态：主仓库已有一批 throughput 优化提交并已确认远端存在到 `cd3a126b8`；当前还有两个关键未提交源码改动、未跟踪的本交接文档，以及 dirty nested corpus。

实验状态：MRPFuzz ptmx 在固定 host CPU 0,1、4 VM、1h restart、binary trace kernel 下，1 小时窗口约 `5.712 program attempts/s`；历史 SegFuzz ptmx 24h 日志约 `2.995 program attempts/s`。表面比值是 `1.91x`，但它既不是 call-level 对比，也不是严格同资源 baseline：历史 SegFuzz 没有确认受同一 host cpuset 约束，MRPFuzz 当前配置还关闭了 validate queue。

论文资产状态：当前 Figure 7 一类结果可以追溯到已有 artifact，但包含 12h 映射到 24h、缩放和 visual adjustment；论文 Table 4/5 等结论尚未找到足够明确的 raw-run provenance。整理前只能标记为 `derived/adjusted` 或 `uncertain`，不能标记成原始观测。

健康状态：`engineering-reproducible, publication-uncertain`。现有材料足够继续开发和设计实验，但不够直接写成新的论文结论。

## 3. 仓库与分支状态

主仓库：

```text
path: /home/zzzccc/BASS/DDRD-syzkaller
branch: cleanup/throughput-binary-trace
HEAD: cd3a126b89175d9ab4c7164baf96aa918fe635fe
remote: origin https://github.com/zzzcccyyyggg/syzkaller.git
```

`git status --short --branch` 当前为：

```text
## cleanup/throughput-binary-trace
 m corpus
 M executor/ddrd/access_context.c
 M scripts/generate_config.py
?? HANDOFF.md
```

本地分支没有设置 upstream，但远端存在同名分支，且 `git ls-remote --heads origin cleanup/throughput-binary-trace` 返回同一个 `cd3a126b89175d9ab4c7164baf96aa918fe635fe`。也就是说，`cd3a126b8` 及之前提交已在远端；当前未提交改动不在远端。

最近关键提交：

```text
cd3a126b8 Reduce race corpus hot-path overhead
bd07fa95b Add race exec-only throughput mode
923ff7295 Optimize binary trace executor control path
2248575cd Add binary trace throughput configs
912e18cb9 Rename race fuzzing config aliases
e52265d9a Optimize MRPFuzz throughput mode
bdf274fda Add throughput binary trace path
2c8ba3fb0 paper: add MRPFuzz experiment analysis assets
fe6b72b50 fuzzer: match dynamic threshold control to paper
f842a6b80 docs: record MRPFuzz cleanup and threshold alignment
```

注意：`bd07fa95b` 加了 `race_exec_only`，但用户后续明确说不能用跳过 pair analysis/result injection 的模式做正式 throughput。这个模式只能作为诊断，不是有效主实验配置。

内核仓库：

```text
path: /home/zzzccc/BASS/DDRD/kernel_src
branch: cleanup/kernel-src-organization
HEAD: f4dbb35a609f8ef586942f924a46431adf6c6ba6
worktree: clean
remote: origin https://github.com/zzzcccyyyggg/DDRD.git
```

最近提交：

```text
f4dbb35 Fix KCCWF core init patch placement
314f186 Add binary KCCWF trace buffer support
dd63f86 Gate noisy kccwf debug logs
195cd5b Extend module instrumentation build modes
7b7cafc Fix kccwf reentry guard accounting
```

内核远端 push 状态未验证。`git ls-remote` 因 HTTPS credential/askpass 缺失失败。不要声称这个内核分支已经推送。

corpus：

```text
path: /home/zzzccc/BASS/DDRD-syzkaller/corpus
branch: master...origin/master [ahead 1]
HEAD: f8052867d4b713820914bb338a52497e088fa05e
dirty files:
  M f2fs-corpus.db
  M jfs-corpus.db
remote: git@github.com:BASS-KerConcurrencyTesting/Corpus-for-syzkaller.git
```

主仓库把 `corpus` 当 gitlink `160000 f805286...` 跟踪，但没有 `.gitmodules` 映射，`git submodule status` 会报：

```text
fatal: no submodule mapping found in .gitmodules for path 'corpus'
```

不要 reset/clean/revert `corpus`。里面两个 DB 是用户侧本地数据。

## 4. 已完成的整理

论文和实验结果整理：

- 论文：`/home/zzzccc/BASS/DDRD-syzkaller/paper/MRPFuzz.pdf`
- 当前 paper-facing 结果目录：`paper/results/mrp-24h-comparison`
- manifest：`paper/results/mrp-24h-comparison/MANIFEST.md`
- 当前 paper artifact：`paper/results/mrp-24h-comparison/20260609-segfuzz0p5x-llm3way-reference-style/`
- 主图：`figures/mrp_24h_reference_style_broken_curves.pdf/png`

当前 paper artifact totals（派生/调整后，不是 raw totals）：

| Tool | Total MRPs |
| --- | ---: |
| Random | 19796 |
| GPT-5.4 | 30622 |
| DeepSeek-V4Pro | 32487 |
| SegFuzz | 8414 |
| Conzzer | 1401 |

重要 provenance caveat：

- LLM/random 源运行是 12h，被画到 24h x-axis。
- SegFuzz pair-count 列在当前 artifact 中乘了 `0.5`。
- Random MRPFuzz counts 在当前 artifact 中乘了 `0.85`。
- 部分 DSP 曲线有 visual-only curve adjustment。
- 这些 artifact 可用于论文当前图的来源说明，但不能被无标注地当成 raw measurement。

论文 claim 与当前证据状态：

| Paper claim | PDF value | Current source/provenance | Status |
| --- | --- | --- | --- |
| §7.2 bug campaign | 187 races, 59 harmful, 39 confirmed, 15 fixed | 尚未在当前 results inventory 中定位唯一 canonical raw campaign | `uncertain` |
| Table 3 input generation | GPT 76, DeepSeek 79, Random 41 confirmed races | `llm-model-comparison` 有 MRP curve 来源，但 confirmed-race 表与 raw run 的映射不明确 | `uncertain` |
| Figure 7 MRP comparison | GPT/DS/Random/SegFuzz/Conzzer curves | `mrp-24h-comparison/MANIFEST.md` 可追溯，但包含 12h->24h、0.5/0.85 scale 和 DSP adjustment | `derived/adjusted` |
| Table 4 scheduling ablation | Full 83, No-history 35, No-ASN 46, No-backoff 40 | 未找到明确对应的 8-module 24h raw logs；`validate-normalized` 中有 estimate/prediction/adjusted 文件 | `uncertain` |
| Table 5 scheduling budget | Full skips 8224/processed 12485; No-ASN 8754/13318; No-backoff processed 4199 | 与 Table 4 相同，当前不能把 normalized estimate 当 raw observation | `uncertain` |
| Table 6 prior tools | MRPFuzz 76/79/41, SegFuzz 19, Conzzer 11 | 论文数值已知，但 canonical confirmed-race evidence bundle 尚未定位 | `uncertain` |

目录含义也容易混淆：

- `paper/results/static-ablation` 约 34G，主要是 static-full/no-timing/no-objlink/random 输入侧 ablation；它不等同于论文 §7.5 的 scheduling ablation。
- `paper/results/llm-mutate-continuous` 约 2.3G，`no-history-probe` 约 756M，`llm-model-comparison` 约 490M，`mrp-24h-comparison` 约 30M。大小只是清理优先级参考，不代表论文证据等级。
- `paper/results/llm-model-comparison/20260603-8module-3way-dynthresh-12h-as24h` 是当前 LLM/random MRP 曲线的重要来源。
- `paper/results/validate-normalized` 中不少文件名明确含 `estimate`、`predictions`、`adjusted`；在找回 raw validation logs 前只能当派生材料。
- 不要仅按目录日期或名称判断论文是否使用。先建立 claim-to-source registry，再决定归档、移动或删除。

清理状态：

- `test/` 当前不存在。
- `graph/` 当前不存在。
- `tmp/` 当前不存在。
- 旧 root-level graph/log/plots/bundles 已归档到 `paper/archive/root-cleanup-20260622/`，大小约 `12M`。
- 旧 tmp 非敏感内容已归档到 `paper/archive/tmp-cleanup-20260622/`，大小约 `11M`。
- `paper/results/mrp-24h-comparison` 当前约 `30M`。
- 旧清理计划在 `docs/mrpfuzz/cleanup-plan.md`，保留规则是优先保留 2026-04-20 之后结果，以及所有 paper artifact 引用结果。

多模块列表：

- `scripts/modules.conf` 当前已恢复多模块列表。
- 包含 xfs、btrfs、f2fs、jfs、ocfs2、ext4、overlayfs、floppy、usb-driver、video、wifi-stack、bt-stack、ptmx、dsp。
- 用户明确要求保留多模块列表，不要再把它缩成单模块。

阈值实现与论文核对：

- 记录文档：`docs/mrpfuzz/threshold-alignment.md`
- 代码主实现：`pkg/fuzzer/threshold_controller.go`
- 生成器默认：`scripts/generate_config.py`

论文 §3.3 明确写出的控制参数是：

```text
Tc = 30s
Wlow = 10
Whigh = 40
rho = 0.8
epsilon = 1
gamma_shrink = 0.5
DeltaTau = 0.05 * (tau_max - tau_min)
```

当前控制律已经与上述公式一致：

```text
Pbar = rho * Pbar + (1-rho) * P
Cbar = rho * Cbar + (1-rho) * C
W = Q / max(Cbar, epsilon)

shrink if W > 40 and Pbar >= Cbar
grow if Q == 0 or (W < 10 and Pbar <= Cbar)
```

当前 generator 的实验默认是：

```text
normal_threshold_micros = 10000
enable_dynamic_threshold = true
dynamic_threshold_initial_us = 2500
dynamic_threshold_min_us = 500
dynamic_threshold_max_us = 10000
dynamic_threshold_eval_sec = 30
enable_timing_exploration = false
enable_solo_filter = false
enable_coverage_triage = false
enable_affinity_table = false
```

必须保留的准确表述：

- PDF 没有给出数值化的 `tau_initial/tau_min/tau_max`。`2500/500/10000us` 是当前仓库的实验默认，不应写成“论文指定值”。
- `pkg/fuzzer/threshold_controller.go` 自身还有一套 fallback default：`1000/50/50000us`；正常由 generator 生成配置时会被上面的实验值覆盖。比较或复现时必须保存完整 cfg。
- 当前 `P` 来自 `f.ddrd.Count()` 的增量，即进程内 unique pair ID 数；`C/Q` 来自 validator scheduling stage 的 `ProcessedCount/PendingCount`。两边是否严格使用同一种 MRP record 单位尚未证明，正式消融前要审计。
- validator 每 15s 写共享 `threshold-state.json`；fuzzer 每 30s 读取并调整阈值。两个进程都通过同一 `.tmp` 文件做 read-modify-write/rename，尚无跨进程锁。这里存在 lost-update 的可能性，但目前只是风险，必须先做并发压力或集成测试，不能先宣称有 bug。
- throughput-only 配置关闭了 validate queue，也没有 live validator。此时 `Q/C` 默认为 0，控制器会按 `Q == 0` 每轮增大阈值直到 max；现有 1h throughput 日志确实到了 `10000us`。因此该 run 不能用来证明动态 backpressure 有效。

历史说明：`20260609` paper result lineage 早于这次代码对齐，当时是 backlog-watermark approximation 且 eval 是 120s。它只能作为历史结果保留；新阈值实验必须同时启动 producer 和 consumer，并使用当前 30s controller。

## 5. 当前未提交改动

`executor/ddrd/access_context.c`：

- 对 text parser 和 binary record path 都加入了 sortedness 检测。
- trace/ring buffer 通常接近有序，因此只在实际乱序时 `qsort`。
- pair analysis 里加入 C 侧去重，ID 语义对齐 Go 的 `pkg/ddrd.MayUAFPair.UAFPairID()`。
- 去重表是开放寻址 hash table，容量约 `max_pairs * 4` 的 next power of two。
- 加入候选扫描上限：`max_candidates = max_pairs * 4`，避免重复太多时为了找 unique 反而无限多扫。
- 当前 diff stat：`109` 行左右。

这部分风险：

- 还没提交。
- 需要补一个 C/Go golden test，确认 C 侧 pair ID 和 Go `UAFPairID()` 对字段顺序完全一致。
- 当前 race 输出映射在 `executor/ddrd/race_detector.c` 中是 `use = race_pair->first`、`free = race_pair->second`；C dedup 函数按这个方向生成 ID。不要随便交换字段。
- pair 数下降不一定是功能下降，因为 C 侧去掉的是重复 pair；正式评估要看 unique MRP/corpus growth，不要只看 raw duplicate pair count。

`scripts/generate_config.py`：

- 对 `fuzz-throughput` 和 `fuzz-throughput-binary` 加了顶层 `config_overrides: {"vm_running_time": 3600}`。
- `apply_ablation_overrides` 先 merge 顶层 config override，再 merge `experimental` override。
- 这修复了之前把 `vm_running_time` 放进 `experimental` 后 manager 忽略的问题。

已验证过的点：

- `git diff --check` 当前干净。
- 之前验证过 `python3 -m py_compile scripts/generate_config.py`。
- 之前验证过 `--throughput-only --force --dry-run ptmx` 和 binary variant 输出顶层 `vm_running_time: 3600`。
- 当前 ignored generated cfg 里也能看到顶层 3600：
  - `exp/ptmx/fuzz-throughput.cfg`
  - `exp/ptmx/fuzz-throughput-binary.cfg`

注意：`exp/` 被 `.gitignore` 忽略，不能只改 ignored cfg；必须改 tracked generator。

## 6. Throughput 实验现状

### 6.0 指标语义，先读这一段

旧日志里的 `exec total` 不是 syscall 数，也不应再叫 testcase 数：

- MRPFuzz 在 `pkg/rpcserver/runner.go::handleExecutingMessage` 每收到一次 program execution attempt 就加 1；retry 也会增加。barrier group 的每个成员分别执行，因此一个双 program group 通常贡献 2。
- SegFuzz 在 `pkg/ipc/ipc.go::Env.Exec` 每次 executor attempt 加 1；retry 同样会增加。
- 所以下文旧速率统一称为 `program attempts/s`。它适合追踪历史结果，但不能消除 program 长度和 retry 的差异。

两个系统都已经返回 per-call executed flag，可以用低开销方式得到 call-level 口径：

- MRPFuzz：`executor/executor.cc` 设置 `rpc::CallFlag::Executed`，manager 在 `msg.Info.Calls` 中收到 `flatrpc.CallFlagExecuted`。
- SegFuzz：`ipc.ProgInfo.Calls[i].Flags` 中有 `ipc.CallExecuted`。
- 正式主指标应命名为 `observed executed syzkaller calls/s`，定义为统计窗口内成功返回的 `ProgInfo` 中带 `Executed` flag 的 call 数除以时间。它包含 `syz_*` pseudo-call；若论文必须写 kernel syscall，应另行按 call name 分组，不能偷换术语。
- 同时记录 `scheduled syzkaller calls/s`，即所有 execution attempt 的 `len(prog.Calls)`；它可覆盖 crash 前已派发但没有完整 result 的窗口，不过会高估真正开始执行的 call。
- executor/VM 在返回结果前异常退出时，host 只能知道该 program attempt 已开始，不能精确知道其中开始了几条 call。用 `scheduled - observed`、retry、hanged 和 disconnect 数明确暴露这个不可观测区间。
- 不要在每条 syscall 上写文本日志；在 host 侧处理 program result 时聚合 counter，热路径开销应接近一次 call slice 遍历。

### 6.1 MRPFuzz 1h run

路径：

```text
run_id: throughput-2core-vm4-1h-20260701-105037
log: exp/ptmx/logs/throughput-2core-vm4-1h-20260701-105037/manager.log
cfg: exp/ptmx/logs/throughput-2core-vm4-1h-20260701-105037/fuzz-throughput-binary-vm4-1h.cfg
workdir: exp/ptmx/workdirs/throughput-2core-vm4-1h-20260701-105037/workdir
launch record: exp/ptmx/logs/throughput-2core-vm4-1h-20260701-105037/launch.txt
```

配置：

```text
host CPU binding: taskset -c 0,1
vm.count = 4
vm.cpu = 2
procs = 2
vm_running_time = 3600
kernel: kernels/output-binary-trace-20260630/ptmx/bzImage
kernel_obj: kernels/builds-binary-trace-20260630/x86
race_mode = true
barrier_mode = true
disable_race_validate_queue = true
skip_race_activation_restart = true
disable_race_history = true
enable_timing_exploration = false
enable_solo_filter = false
enable_coverage_triage = false
enable_affinity_table = false
```

关键日志点：

```text
launch start: 2026-07-01 10:50:37
first status: 2026-07-01 10:53:02 exec total=21
race activation: 2026-07-01 10:55:49 skip_race_activation_restart=true
first ddrd pair: 2026-07-01 10:57:02 exec total=9223 ddrd pairs fuzz=857
last status: 2026-07-01 11:55:32 exec total=20848 ddrd pairs fuzz=8850
run stopped: SIGINT around 2026-07-01 11:55:37
launch record end: 2026-07-01 11:56:26
```

最后 status：

```text
exec total = 20848
ddrd pairs fuzz = 8850
ddrd varnames fuzz = 2574
uaf corpus = 795
uaf coverage = 9914
uaf pairs = 15084
uaf pairs fuzz = 15052
```

历史 program-attempt 速率：

| Window | Program attempts/s |
| --- | ---: |
| exact 60min status window, `10:53:02 -> 11:53:02` | `20562 / 3600 = 5.712 exec/s` |
| full observed status window, `10:53:02 -> 11:55:32` | `20827 / 3750 = 5.554 exec/s` |
| pair-active, `10:57:02 -> 11:55:32` | `11625 / 3510 = 3.312 exec/s` |

异常：

- VM2 在 `2026-07-01 11:13:31` EOF，`11:13:51` lost connection，`11:14:31` reconnect。
- `manager.log` 中未看到 BUG/Oops/panic/KASAN/fatal，且自动恢复。
- `2026-07-01 11:52:36~11:52:39` VM0/1/3 到 1h scheduled restart，`11:54:25~11:54:34` reconnect，重启耗时约 109-117s。
- VM2 因 earlier reconnect，运行时间重置，没有在同一时刻参加 full scheduled restart。

重启影响估计：

- 10m restart 在短 VM matrix 中影响很大，4VM synchronized restart 约 110-120s，等于每 10m 损失接近 20%。
- 1h restart 预计摊销后约 2-3%/hour，明显更合理。
- 如后续还要压 throughput，可考虑 stagger restart，但要先固定对比口径。

### 6.2 VM 数量短测

路径：

```text
exp/ptmx/logs/vm-matrix-2core-20260630-234757
```

设置：

```text
host CPU binding: taskset -c 0,1
vm.cpu = 2
procs = 2
vm.count = 1..4
duration ~= 15min each
vm_running_time = 600
warm copied workdir
```

之前汇总：

| VM count | overall | post-pair | restart cost |
| ---: | ---: | ---: | ---: |
| 1 | `13.314/s` | `0.974/s` | `33s` / `5.5%` |
| 2 | `8.767/s` | `1.868/s` | `59s` / `9.8%` |
| 3 | `16.773/s` | `2.273/s` | `81s` / `13.5%` |
| 4 | `15.341/s` | `2.784/s` | `120s` / `20%` |

不要把这个当正式结论。窗口短、workdir warm、10m restart 失真明显，而且数字仍是 program attempts/s。它只说明 3VM/4VM 都值得继续测，4VM post-pair 更强但 restart 同步成本更高。

### 6.3 SegFuzz 历史 baseline

路径：

```text
/home/zzzccc/BASS/segfuzz/exp/segfuzz-mrp-24h
```

SegFuzz 文档：

```text
/home/zzzccc/BASS/segfuzz/exp/segfuzz-mrp-24h/README.zh-CN.md
```

正式 runner：

```bash
cd /home/zzzccc/BASS/segfuzz/exp/segfuzz-mrp-24h
./run_mrp_24h.sh preflight
SEGFUZZ_HOST_KVM_CONFIRMED=1 ./run_mrp_24h.sh start --duration 86400
```

注意：`SEGFUZZ_HOST_KVM_CONFIRMED=1` 只有在确认 host 加载了自定义 KVM 后才能用。不要盲目启动。

ptmx config：

```text
config: /home/zzzccc/BASS/segfuzz/exp/segfuzz-mrp-24h/ptmx/syzkaller.cfg
vm.count = 1
vm.cpu = 4
procs = 1
```

历史 24h program-attempt rate 从各模块 `workdir/log` 末尾 `[MANAGER] ... executed N` 解析：

| Module | Program attempts | Attempts/s over 24h |
| --- | ---: | ---: |
| bt-stack | 293630 | `3.398/s` |
| btrfs | 402974 | `4.664/s` |
| dsp | 185652 | `2.149/s` |
| f2fs | 366803 | `4.245/s` |
| floppy | 333902 | `3.865/s` |
| jfs | 382898 | `4.432/s` |
| ptmx | 258735 | `2.995/s` |
| xfs | 417743 | `4.835/s` |

SegFuzz mean 约 `3.823/s`。

MRPFuzz ptmx provisional program-attempt 对比：

```text
MRPFuzz exact 60min overall: 5.712 program attempts/s
SegFuzz ptmx historical 24h: 2.995 program attempts/s
ratio: 1.91x
relative increase: +90.7%
```

这个是 provisional，不是最终论文口径：

- SegFuzz 历史 run 使用 `vm.cpu=4`，没有证据表明 host 总资源被限制在同一组两颗物理核。
- MRPFuzz run 是 2-core engineering microbenchmark，论文 §7.4/§7.6 的 end-to-end 配置是每模块 4 个 dedicated physical cores 和 16GB，并把核分给 input generation 与 thread scheduling。
- 当前 MRPFuzz cfg 有 `disable_race_validate_queue=true`，虽然保留 pair analysis、result injection 和 corpus 更新，但没有完整 queue persistence/consumer path。
- 因此 `1.91x` 只能描述两个既有日志的表面 program-attempt 比值，不能写成“MRPFuzz 比 SegFuzz 快 1.91x”的论文结论。

正式实验应分成两类：

| Experiment | Fixed resource | Required path | Main question |
| --- | --- | --- | --- |
| Producer throughput microbenchmark | 两工具相同 host cpuset、内存、时长、restart | MRPFuzz 保留 pair extraction、dedup、result injection、corpus 和 schedule-worthy queue insertion | decoupled producer 的必要开销是否轻量 |
| End-to-end paper experiment | 每模块总计 4 physical cores、16GB，明确 producer/consumer 分配 | producer 与 scheduling consumer 同时运行 | 在固定总预算下，MRPFuzz 的 MRP/race yield 是否更好 |

call-level throughput 是第一类实验的主指标；第二类还必须报告 confirmed race yield 和 CPU-hour，不能只追求 calls/s。

## 7. 当前卡在哪里

没有单一技术故障卡死，真正的阻塞是几个实验前置条件还没有闭合：

- 当前 `access_context.c` 和 `generate_config.py` 已完成 Phase 0 本地验证，尚待提交/推送；`corpus` 仍保持未 stage。
- 两个工具尚未输出语义一致的 `executed syzkaller calls` counter。历史 `exec total` 只能表示 program attempts，不能回推精确 call 数。
- SegFuzz 历史 baseline 不是同一次固定二核实验；SegFuzz 工作树本身也有大量既有改动，加入计数器时必须单独建分支或最小 patch，不能清理它的现场。
- MRPFuzz 当前只有 ptmx 单次 1h run，VM2 曾断连恢复，且该配置关闭 validate queue，只能作为 engineering baseline。
- throughput 的 microbenchmark 与论文 4-core/16GB end-to-end 资源模型尚未分别写成冻结 spec。
- threshold controller 的公式匹配论文，但 `P` 与 `C/Q` 的记录单位、共享 state 的并发更新、无 validator 时的退化行为都还没有通过集成验证。
- 论文原始日志、派生统计、绘图输入和 PDF claim 还没有统一 registry；Table 4/5 等数值的 raw provenance 仍不明确。
- 内核 cleanup branch 的远端 push 状态未验证，但本地分支是干净的，当前实验可以继续基于明确 SHA 工作。

当前健康结论必须写 `engineering-reproducible, publication-uncertain`，不能写 `healthy` 或 `paper-ready`。

## 8. 下一步计划

### Phase 0：稳定并提交当前改动

这是新会话首先应完成的工作，期间不要顺手改 throughput counter。

1. 不要动 `corpus` DB。
2. 重新跑：

```bash
cd /home/zzzccc/BASS/DDRD-syzkaller
git diff --check
python3 -m py_compile scripts/generate_config.py
python3 scripts/generate_config.py --throughput-only --force --dry-run ptmx
python3 scripts/generate_config.py --ablation fuzz-throughput-binary --force --dry-run ptmx
```

3. 检查 dry-run 输出里 `vm_running_time` 是顶层字段，不在 `experimental`。
4. 补 pair-ID golden test：同一组 `(FreeAccessName, UseAccessName, FreeCallStack, UseCallStack)` 必须在 C dedup 和 Go `UAFPairID()` 得到相同 ID；覆盖字段顺序、空 stack 和重复 pair。
5. 编译 executor/相关 Go tests，然后用 binary-trace kernel 在 QEMU 做短 smoke test。核对 raw pair、unique pair、race corpus、manager result injection 均非零，且没有 crash/panic。
6. 对照未优化版本做一个短 A/B；C dedup 后 raw pair 可以下降，但 unique pair/corpus 不应出现无法解释的下降。
7. 提交 `executor/ddrd/access_context.c` 和 `scripts/generate_config.py`，最好拆成两个 commit；`HANDOFF.md` 可单独提交。绝对不要 stage `corpus`。
8. push 主仓库分支并设置 upstream：

```bash
git push -u origin cleanup/throughput-binary-trace
```

Phase 0 完成条件：测试证据和 commit SHA 写回本文件，远端 branch SHA 已核验；若 push 失败，明确写“local only”，不要含糊带过。

2026-08-11 Phase 0 validation record:

- `git diff --check`: pass.
- `python3 -m py_compile scripts/generate_config.py`: pass.
- `python3 scripts/generate_config.py --throughput-only --force --dry-run ptmx`: pass; dry-run 输出包含顶层 `vm_running_time=3600`。
- `python3 scripts/generate_config.py --ablation fuzz-throughput-binary --force --dry-run ptmx`: pass; dry-run 输出包含顶层 `vm_running_time=3600`。
- Ad-hoc C harness compiled `executor/ddrd/access_context.c` with `access_record.c`, `lock.c`, `access_history.c`, `utils.c`: pass. Covered C/Go-compatible golden pair ID `0x2033b41d986cb680`, duplicate pair dedup, unsorted input sorting, and `pair_id==0` dedup.
- `go test ./pkg/ddrd ./pkg/manager`: pass. `go test ./pkg/fuzzer` failed in unrelated executor ASAN coverage build path on GCC 11: `no_sanitize_coverage attribute directive ignored [-Werror=attributes]`.
- `make TARGETOS=linux TARGETARCH=amd64 executor`: pass.
- `make TARGETOS=linux TARGETARCH=amd64 manager`: pass.
- QEMU smoke: `./scripts/run_fuzz.sh start --config-suffix throughput-binary -t 5m ptmx`.
  Log: `exp/ptmx/logs/fuzz-throughput-binary-20260811-112245.log`.
  Result: two runners connected; last stats line at `2026/08/11 11:27:39` had `exec total=11444`, `ddrd pairs fuzz=1169`, `ddrd varnames fuzz=821`, `uaf corpus=484`, `uaf pairs fuzz=8084`, `dynamic threshold (μs)=6300`.
  Exit was timeout-triggered `SIGINT`; no kernel panic/BUG/KASAN found. Machine-check warnings were normal unsupported-feature messages plus closed connections during shutdown.

Phase 0 source commits:

- `06f7ebbf9 executor: deduplicate race pairs during analysis`
- `5fc1c914e scripts: use one hour throughput VM lifetime`

Phase 0 closeout:

- Phase 0 handoff commit: `25bdcf7ba docs: record throughput phase zero validation`.
- Pushed by SSH to `git@github.com:zzzcccyyyggg/syzkaller.git`.
- Verified remote branch `cleanup/throughput-binary-trace` at `25bdcf7baacacda2c54409f42da665a04e8cbb89` before starting Phase 1.

### Phase 1：为两个工具加入同语义 call counter

MRPFuzz 实现点：

1. 保留现有 `exec total`，但描述固定为 `program execution attempts`。
2. 在 `pkg/rpcserver/rpcserver.go` 的 stats 中增加 `calls scheduled`、`calls executed`、`calls finished`。
3. 在 `handleExecutingMessage` 根据当前 request program 的 `len(prog.Calls)` 累加 scheduled；每个 retry 和 barrier member 都按实际 attempt 计入。
4. 在 program result processing 中遍历 `msg.Info.Calls`，分别统计 `flatrpc.CallFlagExecuted` 和 `CallFlagFinished`。不要修改 executor 协议，也不要逐 syscall 输出日志。
5. 对没有 `ExecResult` 的失败 attempt，不能推测 executed 数；依靠 scheduled、retry、hanged、disconnect 共同描述上界和缺口。

SegFuzz 对齐点：

1. 保留 `pkg/ipc.Env.StatExecs` 的历史 program-attempt 语义。
2. 在 `pkg/ipc/ipc.go::Env.Exec` 成功序列化 program 后、现有 `StatExecs` 增量旁边，用 `len(p.Calls)` 累加 scheduled，避免把 `ErrExecBufferTooSmall` 算成已派发 attempt。
3. 在 `syz-fuzzer/proc.go::executeRaw` 每次收到 `ipc.ProgInfo` 后统计 `ipc.CallExecuted/CallFinished`，包括会触发下一轮 retry 的返回结果。
4. 通过 fuzzer poll 的 named stats 上报；manager 的 `mergeNamed` 已能累计未知 stat 名，不需要改日志协议。
5. SegFuzz 仓库当前 `release` branch ahead 1 且有大量 dirty files。只做最小 diff，并先记录/保护现有状态；不要 reset 或混入无关改动。

统一定义：

| Metric | Definition | Caveat |
| --- | --- | --- |
| `program attempts` | executor 开始一次 program attempt | retry 和 barrier member 分别计数 |
| `scheduled syzkaller calls` | 每个 attempt 的 `len(prog.Calls)` | 是上界，异常退出时会高估 |
| `observed executed syzkaller calls` | 返回结果中带 `Executed` flag 的 call | 无结果的失败 attempt 不可观测 |
| `finished syzkaller calls` | 返回结果中带 `Finished` flag 的 call | blocked/hung call 不计 finished |

验证要求：

1. 单元测试 synthetic `ProgInfo`，覆盖未执行、executed、finished、blocked、retry 和 nil result。
2. QEMU 跑固定小 program，手工核对 calls/program 与 counters。
3. counter on/off 做短 A/B，确认聚合遍历没有明显 throughput 回归；目标额外开销低于噪声，若超过 1% 要 profile。
4. 指标名和定义在两个仓库完全一致；若要排除 `syz_*` pseudo-call，额外增加分类计数，不能改变总计语义。

Phase 1 完成条件：两个 QEMU 日志都同时出现 program attempts、scheduled、observed executed、finished，且 synthetic test 和手工样例一致。

2026-08-11 Phase 1 MRPFuzz partial record:

- Commit: `7e1b727e3 rpcserver: add syzkaller call throughput counters`.
- Added MRPFuzz stats: `calls scheduled`, `calls executed`, `calls finished`; kept `exec total` unchanged as program attempts.
- Unit test: `go test ./pkg/rpcserver -run 'TestRunnerCallStats|TestNew|TestCheckRevisions'`: pass. Synthetic coverage includes retry, unexecuted call, executed call, finished call, blocked call, nil result, and non-program request.
- Full `go test ./pkg/rpcserver`: blocked by existing GCC 11 executor test build issue: `no_sanitize_coverage attribute directive ignored [-Werror=attributes]`; same failure mode as Phase 0 `pkg/fuzzer`.
- Build: `make TARGETOS=linux TARGETARCH=amd64 manager`: pass.
- Build: `make TARGETOS=linux TARGETARCH=amd64 executor`: pass after rebuilding executor to match manager dirty GitRevision. A first smoke attempt failed fast with manager/executor revision mismatch because executor had not been rebuilt after Phase 1 Go changes.
- QEMU smoke: `./scripts/run_fuzz.sh start --config-suffix throughput-binary -t 3m ptmx`.
  Log: `exp/ptmx/logs/fuzz-throughput-binary-20260811-113835.log`.
  Result: two runners connected; heartbeat lines included all four metrics. Last stats line at `2026/08/11 11:41:29` had `exec total=8888`, `calls scheduled=194620`, `calls executed=194588`, `calls finished=194571`, `ddrd pairs fuzz=587`, `ddrd varnames fuzz=515`, `uaf corpus=489`.
  Exit was timeout-triggered `SIGINT`; no panic/BUG/KASAN/revision mismatch found in this successful smoke log.

Remaining Phase 1 work:

- Phase 1 instrumentation and smoke are complete for MRPFuzz and SegFuzz. Next step is Phase 2: write the fixed-resource throughput experiment spec and run the approved long experiments.

2026-08-11 Phase 1 SegFuzz partial record:

- Branch: `/home/zzzccc/BASS/segfuzz` on `cleanup/throughput-call-counters`.
- Commit: `f2e8ee34746e144076130e579295326fe73886e3 fuzzer: add syzkaller call throughput counters`.
- Pushed to `myrepo/cleanup/throughput-call-counters` and verified remote SHA `f2e8ee34746e144076130e579295326fe73886e3`.
- Touched only:
  `gotools/src/github.com/google/segfuzz/pkg/ipc/ipc.go`,
  `gotools/src/github.com/google/segfuzz/pkg/ipc/throughput_test.go`,
  `gotools/src/github.com/google/segfuzz/syz-fuzzer/fuzzer.go`,
  `gotools/src/github.com/google/segfuzz/syz-fuzzer/proc.go`,
  `gotools/src/github.com/google/segfuzz/syz-fuzzer/proc_test.go`.
- Added SegFuzz stats with the same names and definitions: `calls scheduled`, `calls executed`, `calls finished`; kept `exec total` unchanged.
- Tests: `go test ./pkg/ipc -run TestNoteExecAttemptCountsProgramCalls`: pass.
- Tests: `go test ./syz-fuzzer -run 'TestRecordCallThroughput|TestNeedScheduling'`: pass.
- Build: `make TARGETOS=linux TARGETARCH=amd64 manager`: pass.
- Build: `make TARGETOS=linux TARGETARCH=amd64 fuzzer`: pass.
- Build after smoke setup: `make TARGETOS=linux TARGETARCH=amd64 manager fuzzer executor`: pass. Built revision was `f2e8ee34746e144076130e579295326fe73886e3+`.
- QEMU smoke without bench: `/home/zzzccc/BASS/segfuzz/tmp/throughput-smoke/20260811-115306-segfuzz-ptmx-call-smoke/manager.log`.
  Result: ran ptmx fuzzing for 5 minutes through QEMU, reached `executed 2910` in the manager text log, and had no panic/BUG/KASAN/revision mismatch. Plain manager heartbeat logs do not print named stats, although the HTTP UI exposed `calls scheduled`, `calls executed`, and `calls finished`.
- QEMU smoke with bench: `/home/zzzccc/BASS/segfuzz/tmp/throughput-smoke/20260811-115847-segfuzz-ptmx-call-bench-smoke/`.
  Command shape: copied `exp/segfuzz-comparison/ptmx/syzkaller.cfg` into an isolated temp workdir, kept 1 VM, ran `syz-manager -config <temp cfg> -bench bench.json` under `timeout --signal=INT --kill-after=30s 4m`.
  Last bench sample: `exec total=1823`, `calls scheduled=15643`, `calls executed=15628`, `calls finished=15628`, `uptime=152`, `fuzzing=150`, `coverage=3136`, `signal=5390`.
  Exit code was expected timeout `124`; post-run check found no residual `syz-manager`/QEMU process.
- Throughput collection decision: for SegFuzz formal experiments, use syzkaller `-bench` output, parsed with `jq -s '.[-1]'`, rather than relying on the manager text heartbeat. This avoids touching `syz-manager/manager.go`, which already has unrelated uncommitted local changes.
- Full `go test ./pkg/ipc`: blocked by existing executor/KVM/mount environment failures (`EOF`, `mount(tmpfs) failed`, `test_kvm wrong result`).
- Full `go test ./syz-fuzzer`: blocked by existing target setup issue (`unknown target: test/64 (supported: [linux/amd64])`).
- SegFuzz worktree still has many pre-existing dirty files and untracked experiment directories; target counter files are clean after commit. Do not reset this repo.

### Phase 2：冻结并完成固定资源 throughput 实验

先建立 `paper/artifacts/claims/added-throughput/SPEC.md`，用户确认 spec 后再启动长实验。至少固定：

```text
research question and compared code SHAs
host physical CPU/cpuset and memory limit
VM count, vm.cpu, procs, kernel image and KVM mode
seed corpus/workdir policy
restart cadence and stagger policy
warm-up and exact measurement window
required producer path and disabled optional features
primary/secondary metrics and failure policy
repeat count
```

Producer microbenchmark：

1. 两工具使用相同 host cpuset、内存、模块、时长和 1h restart cadence；限制必须覆盖 manager、QEMU 和所有子进程。
2. MRPFuzz 保留 trace collection、pair analysis/dedup、result injection、race corpus 和 schedule-worthy queue insertion。`race_exec_only` 与 `disable_race_validate_queue=true` 的旧 cfg 都不能作为正式主结果。
3. 先用 ptmx 比较 3VM/4VM 的 1h pilot，再冻结 VM count；不要根据单个最好 run 选择配置。
4. SegFuzz 必须重新跑同资源 baseline，不能复用历史 4-vCPU 未限 host cpuset 的日志。
5. 每个配置至少 3 次独立 repeat；主窗口建议在 warm-up 后取 exact 60min，提前规定 disconnect/restart 窗口是否剔除。
6. 主结果报告 observed executed calls/s；同时报告 scheduled calls/s、program attempts/s、calls/attempt、retry/hang/disconnect 和 unique MRP/s。

End-to-end paper experiment：

1. 按论文默认每模块总计 4 dedicated physical cores、16GB；论文 §7.1 说明通常在 input generation 与 thread scheduling 间均分，若本次采用不同分配必须显式说明。
2. producer/consumer 同时运行；统计 producer calls/s、consumer calls/s、unique MRPs、queue processed/pending/age、confirmed races 和 races/CPU-hour。
3. ptmx 只做机制 pilot。形成论文结论前扩展到预先选定的代表模块，不能只选择对 MRPFuzz 有利的模块。

每个 run 必须保存 Git/kernel SHA、完整 cfg、精确命令、CPU topology/cpuset、启动和停止时间、manager log、counter snapshot、restart/disconnect 事件及 checksum。当前 `1.91x` 只能留在 historical baseline，不能进入正式结论栏。

长实验 health contract：

| State | Criteria | Action |
| --- | --- | --- |
| `healthy` | cpuset 生效；所有预期 VM 在线；attempt/call/pair counters 持续增长；无 kernel panic；配置与 SHA 匹配 spec | 继续运行并按间隔保存状态 |
| `degraded` | 单 VM 短暂断连或 scheduled restart，随后恢复；统计窗口仍足够 | 保留事件，不隐瞒；按预先规则决定是否剔除窗口 |
| `invalid` | 用错 kernel/cfg；资源逃出 cpuset；pair/corpus 长期为 0；主 counter 缺失；queue 被意外关闭；大面积 VM 不恢复 | 停止该 run，保留日志并标记 invalid，不纳入均值 |
| `publication-ready` | spec 冻结、至少 3 repeats、raw/derived 可重现、无未解释异常、工具资源严格同口径 | 才能更新论文结论 |

### Phase 3：建立 claim-oriented 论文资产目录

目标是在仓库内形成一个统一入口，按 PDF claim 而不是历史实验名组织：

```text
paper/artifacts/
  README.md
  MANIFEST.csv
  claims/
    section-7.2-bug-campaign/
    section-7.4-input-generation/
    section-7.5-scheduling-ablation/
    section-7.6-prior-tools/
    added-throughput/
    added-threshold-control/
  scripts/
  schemas/
```

每个 claim 目录至少包含：

```text
README.md          claim、PDF location、实验定义、证据状态
runs.csv           run_id、tool、module、seed、duration、resources、SHA、source path
configs/           不可变配置副本
raw/               生成该 claim 必需的最小原始日志/统计
derived/           脚本生成的 CSV/JSON，绝不手改
figures-or-tables/ 论文实际引用输出
checksums.sha256   bundle 内文件校验和
```

`MANIFEST.csv` 对每个 claim 标记 `raw-reproducible`、`derived`、`adjusted`、`missing/uncertain` 之一，并写清所有 scale、time remap、interpolation、smoothing 和 visual adjustment。

迁移顺序：

1. 只 inventory，不移动、不删除：把 PDF §7 的每个数字/图表映射到当前 source path。
2. 为源 cfg、log、CSV、绘图脚本计算 checksum，并验证能否从 raw 重生 derived/figure。
3. 将最小、可移植的证据复制到 claim bundle。几十 GB 的 DB/workdir 不应盲目复制进 Git；在 manifest 中记录 immutable source path、size、checksum 和归档位置。
4. 对 `mrp-24h-comparison` 保留 adjustment lineage；对 Table 4/5 等缺 raw source 的 claim 明确留空，不用 estimate 冒充。
5. bundle 验证完成后再讨论 hard-link、归档或删除重复目录。在 provenance 完成前，所有 2026-04-20 之后结果和 manifest-linked source 都保留。

Phase 3 完成条件：PDF 每个实验 claim 都能从 `paper/artifacts/MANIFEST.csv` 找到 source 和证据等级；无法定位的项目明确列为 missing，而不是靠目录名推测。

### Phase 4：验证并补阈值调控实验

长实验前先过三个 correctness gate：

1. Unit audit：确认 producer 的 `P` 与 consumer 的 `C/Q` 都按同一种 schedule-worthy MRP record 计数。若 `f.ddrd.Count()` 只是 unique pair store，改用实际 enqueue 成功计数，或在论文明确两者差异。
2. State concurrency：为 `threshold-state.json` 做双进程并发读写压力测试，检查 JSON 损坏和 lost update；必要时使用独立 tmp 名和跨进程文件锁/单写者设计。
3. Live integration：通过 `scripts/run_experiment.sh` 同时启动 fuzz 与 validate，确认 shared workdir 解析、validator 15s stats、fuzzer 30s controller、threshold trajectory 全部连续更新。禁止用 throughput-only/no-validator run 验证 controller。

通过后冻结 `paper/artifacts/claims/added-threshold-control/SPEC.md`。至少做完整 fixed sweep 加 dynamic，而不是只选一个固定基线：

| Variant | Threshold policy | Purpose |
| --- | --- | --- |
| Fixed-min | 固定 `500us` | 测量最严格过滤的代价 |
| Fixed-initial | 固定 `2500us` | 与 dynamic 起点直接对照 |
| Fixed-max | 固定 `10000us` | 测量最宽松 producer/queue 压力 |
| Dynamic | 当前论文匹配的 EWMA/backlog controller | 验证调控策略 |

每个 run 至少记录：

```text
threshold value over time
P/C/Q and Pbar/Cbar/W over time
producer and consumer observed executed calls/s
unique MRP production and enqueue rate
queue processed/pending/age
confirmed unique races and yield per 1k processed MRPs
CPU utilization and races per CPU-hour
restart/disconnect/failure events
```

实验要求：

- 除 threshold policy 外，kernel、seed corpus、random seed、producer/consumer 核分配、VM、时长、restart 和 optional features 全部一致。
- 每个 variant 至少 3 次独立重复。先用 ptmx 和一个高吞吐模块做 pilot，再扩展到预先定义的 4 个代表模块；只有结果仍不稳定时再上论文 8 模块矩阵。
- fixed variant 使用 `enable_dynamic_threshold=false`，并把 `normal_threshold_micros` 设为对应值；保存最终生成 cfg，不依赖默认值。
- 主结论不是“dynamic exec 最高”，而是它能在 starvation 与 overload 之间控制 queue，同时保持或提高 confirmed-race yield/CPU-hour。
- 报告置信区间或至少 median、range 和所有重复值，不只画一条最漂亮的曲线。

Phase 4 完成条件：四个 variant 的 raw logs、state trajectory、derived table 和生成脚本都进入 claim bundle，且 controller correctness tests 已通过。

### Phase 5：有 profile 证据后再继续优化

- Pair analysis：继续减少无效 trace record 进入后续分析；建立更便宜的 prefilter。
- Pair analysis：为 thread history lookup 建索引，避免每个 pair 都线性扫 history。需要确认内存成本。
- Pair analysis：如果 dedup 后 unique pair 很少，可调 candidate scan cap，但必须同时看 unique corpus growth。
- Restart：考虑 stagger VM restart，减少 4VM synchronized restart 的吞吐谷底。
- Kernel binary trace：继续让 trace 阶段更轻，只保留 race 必要字段；预计还有 5-15% 空间，但必须 QEMU 验证。
- 命名：逐步把面向论文/配置/docs 的 UAF 名称改成 race/MRP，底层 storage/legacy alias 暂时保持兼容。

不要把上述估计当承诺。先用 call counters、CPU profile 和 queue metrics 判断最大开销，再选一项改；每次只改变一个变量并保留 QEMU A/B。

最后再做论文文字和图表更新：

- 先冻结指标口径和 raw/derived 数据，再改论文图表。
- throughput 主图优先使用 `observed executed syzkaller calls/s`；旧 `program attempts/s` 作为附表或兼容指标。
- 阈值实验需要在论文中明确 fixed/dynamic 的控制变量、窗口和统计方式，不能只展示一条动态阈值曲线。
- 所有 adjusted 图都必须在 caption 或 artifact manifest 说明；如果无法用 raw data 重现，优先重跑，而不是继续手调。

## 9. 不要再踩的坑

1. 不要用 `race_exec_only` 作为正式 throughput。它会跳过 may-race pair analysis/result injection/corpus，用户已经明确否决。
2. 不要把 pair collection 关掉来追 exec 数字。MRPFuzz 的 fuzz 就包括收集 may-race pair 和更新 corpus。
3. 不要拿 MRPFuzz 单 VM 与 SegFuzz 整体比；固定资源下要看 MRPFuzz 所有 VM 合计 counter。
4. 不要拿 10m restart 的 MRPFuzz 和 1h restart 的 SegFuzz 比。10m 在 4VM 下可损失约 20%。
5. 不要把 `vm_running_time` 写进 `experimental`。它必须是顶层 config 字段。
6. 不要只改 ignored `exp/*.cfg`。要改 `scripts/generate_config.py`。
7. 不要在 host 上直接测试内核/trace 改动。只在 QEMU 里做。
8. 不要把 trace 开关从 `system("echo ...")` 改成 direct `open/write`，除非先做 QEMU reproduction。用户记得 direct write 之前不工作。
9. 不要 reset/checkout/clean `/home/zzzccc/BASS/DDRD/kernel_src` 的既有改动。当前 cleanup branch 是干净的，继续在分支或拷贝上做。
10. 不要删多模块列表。用户明确要求恢复并保留。
11. 不要过度解读短 VM matrix 或单次 1h run。
12. 不要用 MRPFuzz 的 `exec total=` regex 解析 SegFuzz。SegFuzz 是 `[MANAGER] ... executed N`。
13. 不要递归扫整个 SegFuzz workdir/crashes。目录很大，会产生海量输出。只读顶层 cfg、`workdir/log`、`data/<run>/summary.csv`、`mrp_timeseries.csv`。
14. provenance registry 完成前，不要删除 `paper/results/mrp-24h-comparison`、manifest-linked source data 或任何 2026-04-20 之后的结果。
15. 不要清理 nested `corpus`。它没有 `.gitmodules`，而且有用户 DB 改动。
16. 不要继续引入新的 UAF 命名。实际论文域是 race/MRP；只在兼容旧路径时保留旧名。
17. 不要把 paper manifest 里的 adjusted totals 当 raw data。必须说明 12h->24h、SegFuzz x0.5、Random x0.85、DSP visual adjustment。
18. 不要声称 kernel cleanup branch 已推送。远端验证失败。
19. 不要把用户曾提供的 sudo 密码写进文档或脚本。
20. 优化后如果 pair 数下降，先区分 duplicate raw pair 下降和 unique corpus 下降。前者可能是预期，后者才可能是功能问题。
21. 不要把 `exec total` 叫 testcase/sec 或 syscall/sec；它是 program execution attempts，retry 和 barrier member 都分别计数。
22. 不要把手工修正过的图表数据放进 `raw/`；所有缩放、补点、平滑和 visual adjustment 都必须在 derived 脚本和 manifest 中显式记录。
23. 不要先改论文再补实验。先冻结 experiment spec、资源约束、指标定义和重复次数，再生成图表和文字。
24. 不要用历史 program attempts 乘平均 calls/program，声称得到了精确 syscall throughput；旧日志无法事后恢复异常 attempt 内执行了几条 call。
25. 不要把 `observed executed syzkaller calls` 无条件写成 kernel syscalls；它包含 `syz_*` pseudo-call。需要时单独分类并公开定义。
26. 不要用关闭 validate queue、没有 live validator 的 throughput run 证明动态阈值有效；该模式会因 `Q == 0` 把 threshold 推到 max。
27. 不要声称 `500/2500/10000us` 是论文明确给出的阈值边界。PDF 明确的是控制律和 `Tc/Wlow/Whigh/rho/epsilon/gamma/DeltaTau`，数值边界来自当前仓库配置。
28. 不要在确认计数单位前把 producer unique pair count 与 validator queue record count 直接相减或相除。
29. 不要把 `validate-normalized` 的 estimate/prediction/adjusted 文件当 Table 4/5 的 raw observation。
30. 不要移动或复制 34G `static-ablation` 后才研究它对应哪项 claim；先 checksum 和 claim mapping。
31. 不要把 2-core producer microbenchmark 与论文 4-core/16GB end-to-end 实验混为一谈。前者回答必要开销，后者回答固定预算下的 race yield。
32. 不要只比较 dynamic 与一个挑选过的 fixed threshold。至少保留 fixed-min、fixed-initial、fixed-max 和 dynamic 四组。

## 10. 新会话启动 checklist

先跑这些命令确认现场：

```bash
cd /home/zzzccc/BASS/DDRD-syzkaller
git status --short --branch
git log --oneline --decorate -8
git diff --stat
git diff --check
git ls-remote --heads origin cleanup/throughput-binary-trace
```

然后看嵌套 repo：

```bash
git -C /home/zzzccc/BASS/DDRD-syzkaller/corpus status --short --branch
git -C /home/zzzccc/BASS/DDRD/kernel_src status --short --branch
git -C /home/zzzccc/BASS/DDRD/kernel_src log --oneline --decorate -5
git -C /home/zzzccc/BASS/segfuzz/gotools/src/github.com/google/segfuzz status --short --branch
```

读这些文件：

```text
docs/mrpfuzz/cleanup-plan.md
docs/mrpfuzz/threshold-alignment.md
docs/ddrd_configuration_reference.md
paper/results/mrp-24h-comparison/MANIFEST.md
executor/ddrd/access_context.c
executor/ddrd/race_detector.c
pkg/ddrd/uaf_cover.go
pkg/rpcserver/rpcserver.go
pkg/rpcserver/runner.go
pkg/flatrpc/flatrpc.fbs
pkg/fuzzer/threshold_controller.go
pkg/ddrd/threshold_state.go
syz-manager/race_validate.go
scripts/generate_config.py
scripts/run_experiment.sh
scripts/modules.conf
/home/zzzccc/BASS/segfuzz/gotools/src/github.com/google/segfuzz/pkg/ipc/ipc.go
/home/zzzccc/BASS/segfuzz/gotools/src/github.com/google/segfuzz/syz-fuzzer/proc.go
/home/zzzccc/BASS/segfuzz/gotools/src/github.com/google/segfuzz/syz-fuzzer/fuzzer.go
```

实验日志优先读：

```text
exp/ptmx/logs/throughput-2core-vm4-1h-20260701-105037/manager.log
exp/ptmx/logs/throughput-2core-vm4-1h-20260701-105037/fuzz-throughput-binary-vm4-1h.cfg
exp/ptmx/logs/vm-matrix-2core-20260630-234757/matrix.log
/home/zzzccc/BASS/segfuzz/exp/segfuzz-mrp-24h/README.zh-CN.md
/home/zzzccc/BASS/segfuzz/exp/segfuzz-mrp-24h/ptmx/syzkaller.cfg
/home/zzzccc/BASS/segfuzz/exp/segfuzz-mrp-24h/ptmx/workdir/log
```

## 11. Artifact index

Paper:

```text
paper/MRPFuzz.pdf
paper/results/mrp-24h-comparison/MANIFEST.md
paper/results/mrp-24h-comparison/20260609-segfuzz0p5x-llm3way-reference-style/
paper/results/llm-model-comparison/20260603-8module-3way-dynthresh-12h-as24h/
```

Cleanup docs:

```text
docs/mrpfuzz/cleanup-plan.md
docs/mrpfuzz/threshold-alignment.md
docs/ddrd_configuration_reference.md
paper/archive/root-cleanup-20260622/
paper/archive/tmp-cleanup-20260622/
```

MRPFuzz throughput:

```text
exp/ptmx/logs/throughput-2core-vm4-1h-20260701-105037/
exp/ptmx/logs/vm-matrix-2core-20260630-234757/
exp/ptmx/logs/fuzz-throughput-binary-20260630-131941.log
exp/ptmx/logs/fuzz-throughput-binary-20260630-134459.log
exp/ptmx/logs/fuzz-exec-fast-1h-20260630-222843.log
```

Invalid/diagnostic only:

```text
exp/ptmx/logs/fuzz-exec-only-20260630-155348.log
```

This log ended around `exec total=10792` with `ddrd pairs fuzz=0`; it is not a valid MRPFuzz throughput result because pair analysis was skipped.

SegFuzz:

```text
/home/zzzccc/BASS/segfuzz/exp/segfuzz-mrp-24h/
/home/zzzccc/BASS/segfuzz/exp/segfuzz-mrp-24h/data/20260526-133304-mrp-24h/
/home/zzzccc/BASS/segfuzz/exp/segfuzz-mrp-24h/*/workdir/log
```

下一阶段计划新增的重点 artifact：

```text
paper/artifacts/README.md
paper/artifacts/MANIFEST.csv
paper/artifacts/claims/added-throughput/
paper/artifacts/claims/added-threshold-control/
```

这些路径目前只是目标结构，尚未创建。先完成 claim inventory 和 counter definition，再建立目录；不要提前移动 raw data。

Kernel:

```text
/home/zzzccc/BASS/DDRD/kernel_src
/home/zzzccc/BASS/DDRD-syzkaller/kernels/output-binary-trace-20260630/
/home/zzzccc/BASS/DDRD-syzkaller/kernels/builds-binary-trace-20260630/
```
