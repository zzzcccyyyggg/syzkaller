# DDRD Experiment Runbook

可复用的实验执行手册。所有操作基于 `scripts/run_experiment.sh` 和 `scripts/generate_config.py`，
修改代码后重新 `make` + 重新生成配置即可快速重跑。

主实验快捷入口：

```bash
./scripts/run_capability_24h.sh check
./scripts/run_capability_24h.sh prepare
./scripts/run_capability_24h.sh start-shared
./scripts/run_capability_24h.sh start-safe4-fuzz
./scripts/run_capability_24h.sh start-safe4-validate
```

---

## 0. 前置准备

```bash
# 1. 编译
make

# 2. 清理上一轮实验残留 (保留 corpus.db)
sudo scripts/run_experiment.sh stop --all || true
sudo scripts/run_experiment.sh clean --all || true
sudo scripts/run_experiment.sh clean-validate --all || true

# 3. 导入统一初始 corpus
CORPUS_SRC=/home/zzzccc/BASS/DDRD-Corpus
CAP_MODS="xfs btrfs f2fs jfs floppy bt-stack ptmx dsp"
git -C "$CORPUS_SRC" remote -v
git -C "$CORPUS_SRC" rev-parse --short HEAD
./scripts/manage_corpus.sh import --src "$CORPUS_SRC" --force $CAP_MODS

# 4. 生成全部 8 模块的 fuzz + validate 配置 (覆盖旧的)
python3 scripts/generate_config.py --all --force

# 5. 生成 ablation 变体 (4 模块代表子集)
ABLATION_MODS="xfs btrfs ptmx dsp"
python3 scripts/generate_config.py --ablation fuzz-no-timing   --force $ABLATION_MODS
python3 scripts/generate_config.py --ablation fuzz-no-objlink  --force $ABLATION_MODS
python3 scripts/generate_config.py --ablation fuzz-random      --force $ABLATION_MODS
python3 scripts/generate_config.py --ablation validate-no-delay   --force $ABLATION_MODS
python3 scripts/generate_config.py --ablation validate-no-replay  --force $ABLATION_MODS
python3 scripts/generate_config.py --ablation validate-no-backoff --force $ABLATION_MODS

# 6. 检查已生成的配置
python3 scripts/generate_config.py --list
scripts/run_experiment.sh list
```

### 0.1 统一 corpus 来源

主实验和 rebuttal 重跑统一使用：

- 远端仓库: `git@github.com:BASS-KerConcurrencyTesting/Corpus-for-syzkaller.git`
- 本地建议路径: `/home/zzzccc/BASS/DDRD-Corpus`

> 建议只导入 `corpus.db` 作为初始 seed，**不要**在主实验开始前导入旧的 `uaf-corpus.db`，
> 否则会把历史 may-race pair 混进新实验，破坏统一起点。

### 0.2 资源语义说明

`scripts/run_experiment.sh` 当前行为是：

- 同一模块先启动 fuzz 再启动 validate 时，validate 会复用该模块已有的 CPU 槽位
- 也就是说，`start --all` 再 `validate --all` 属于“**每模块 2 核共享给 fuzz+validate**”的模式

这和“fuzz 2 核 + validate 2 核，同时严格独占”不是一回事。

- 如果你要 **马上开始**，当前脚本支持前者，32 核机器可以直接跑 8 模块
- 如果你要 **严格满足 2+2 核/模块**，那 8 模块同时跑需要至少 32 个实验核外加系统余量；在当前 32 核机器上建议分两批，优先采用 `6+2`，给系统保留 8 个核心余量

### 0.3 当前 32 核主机的硬分核建议

当前机器是 `unified cgroup v2`，`cset 1.6` 不能直接创建 `cpuset v1 shield`。
仓库里的 `scripts/run_experiment.sh` 已补成自动使用 `cgroup v2 cpuset` 做硬隔离，所以可以继续按“模块独占一组核心”的方式跑：

- `xfs` 绑定 `8-11`
- `btrfs` 绑定 `12-15`
- 其余模块依次顺延

推荐先固定：

```bash
export SYSTEM_RESERVED_CORES=8
export CORES_PER_MODULE=4
```

这样实验核心是 `8-31`，最多同时跑 `6` 个模块，给系统保留 `0-7` 共 `8` 个核心余量。

`run_experiment.sh` 还支持按模块分别调 `fuzz/validate` 的 `vm.count`，而不改 `vm.cpu` / `procs`：

```bash
export EXP_FUZZ_VM_COUNT_XFS=3
export EXP_VALIDATE_VM_COUNT_XFS=1
```

当前仓库默认已经改成 `3+2`：

```bash
export EXP_FUZZ_VM_COUNT=3
export EXP_VALIDATE_VM_COUNT=2
```

在这台机器上，对 `xfs` 的 4 核短测结果如下：

- `fuzz only`: `1/2/3/4 VM` 分别约为 `0.94 / 1.61 / 3.13 / 3.68` 核；其中 `3 VM` 的 fuzz 吞吐最好，`4 VM` 更满但开始掉吞吐
- `validate only`: `1/2/3/4 VM` 分别约为 `0.66 / 1.18 / 1.41 / 1.46` 核；`3 VM` 之后收益很小
- `fuzz+validate` 共用同一组 4 核时：
  - `fuzz=3, validate=1` → 总占用约 `2.90` 核，fuzz `83.64 exec/s`
  - `fuzz=3, validate=2` → 总占用约 `3.01` 核，fuzz `66.98 exec/s`
  - `fuzz=4, validate=1` → 总占用约 `3.16` 核，fuzz `75.56 exec/s`

因此，如果同一模块的 `fuzz+validate` 要共用同一组 4 核，当前建议优先用：

```bash
export EXP_FUZZ_VM_COUNT_XFS=3
export EXP_VALIDATE_VM_COUNT_XFS=1
```

---

## 1. 实验一: 24 小时漏洞发现能力 (Capability)

**目标**: 8 个模块跑 24 小时主实验，统一初始 corpus，记录 may-race pair 与 confirmed race。

**模块**: `xfs btrfs f2fs jfs floppy bt-stack ptmx dsp`

**资源**:

- 共享槽位模式: 每模块 2 核 4GB，fuzz+validate 共用该 2 核
- 严格 2+2 模式: 每模块 fuzz 2 核 4GB + validate 2 核 4GB

如果你的机器只有 32 核，并且要严格按 2+2 模式执行，建议分两批: 先跑 6 个模块，再跑剩余 2 个模块。

### 1.1 方案 A: 立即可跑的共享槽位模式 (全部 8 模块)

fuzz 和 validate 可以同时启动。validate 的 streaming 模式会自动等待 fuzz 产生 corpus 后开始处理，
并持续轮询新增 entry，无需手动分步操作。

```bash
# 启动 fuzz
sudo scripts/run_experiment.sh start --all

# 立即启动 validate (无需等待)
sudo scripts/run_experiment.sh validate --all
```

> validate 启动后会每隔 `idle_reload_seconds`(默认 10s) 检查 corpus 文件是否出现，
> corpus 出现后自动进入持续流式读取模式，每 `incremental_reload_minutes`(默认 10min) 重新扫描新增 entry。
>
> 这一方案适合“现在先把主实验跑起来”，但要在实验记录里注明 fuzz/validate 共用 2 核槽位。

### 1.2 方案 B: 严格 2+2 模式 (32 核机器建议按 6+2 分批)

```bash
# 批次 1
./scripts/run_capability_24h.sh start-batch1

# 24h 后停止批次 1，再跑批次 2
./scripts/run_capability_24h.sh stop
./scripts/run_capability_24h.sh start-batch2
```

> `start-batch1` / `start-batch2` 会自动让 validate 使用独立 CPU 槽位，而不是复用 fuzz 槽位。
>
> 当前仓库默认批次为:
> - `start-batch1`: `xfs btrfs f2fs jfs bt-stack ptmx`
> - `start-batch2`: `floppy dsp`

### 1.2C 方案 C: 4 模块保守模式 (排障优先, 不使用 watcher)

当你优先追求稳态、希望降低 OOM 风险，并且避免 `validate` 被后台循环自动补拉时，推荐先只跑 4 个模块：

- 模块: `xfs btrfs bt-stack ptmx`
- 组合思路: `2 个 fs + 2 个非 fs`，避免把 `4 个文件系统` 的重负载堆在同一轮
- 固定资源:
  - `SYSTEM_RESERVED_CORES=8`
  - `CORES_PER_MODULE=2`
  - `EXP_FUZZ_VM_COUNT=2`
  - `EXP_VALIDATE_VM_COUNT=2`
  - `EXP_FUZZ_VM_COUNT_BTRFS=2`
  - `EXP_VALIDATE_VM_COUNT_BTRFS=1`
- fuzz 侧默认打开动态时间阈值:
  - `normal_threshold_micros=10000`
  - `enable_dynamic_threshold=true`
  - `dynamic_threshold_initial_us=2500`
  - `dynamic_threshold_min_us=500`
  - `dynamic_threshold_max_us=10000`
  - `dynamic_threshold_eval_sec=120`
- timing exploration 阈值策略:
  - 普通 fuzz 请求使用当前动态阈值
  - Timing Phase 1 使用 `max(当前动态阈值 × 8, widened_threshold_micros)`，当前下界为 `20000us`
  - Timing Phase 2 回到当前动态阈值，不再固定写死 `10ms`

对应快捷入口：

```bash
# 第一步: 只启动 fuzz
./scripts/run_capability_24h.sh start-safe4-fuzz

# 建议先等 20-30 分钟, 确认 corpus 持续增长
sleep 1800

# 第二步: 手动启动 validate 独立槽位
./scripts/run_capability_24h.sh start-safe4-validate
```

> `start-safe4-fuzz` / `start-safe4-validate` 在启动前会自动 `--force` 重生成这 4 个模块的配置，
> 确保最新的 timing exploration / dynamic threshold 设置一定生效，而不是继续复用旧 `fuzz.cfg`。

> 这一方案默认**不使用 watcher**。如果 `validate` 退出，先查看日志定位原因，
> 不要再用 `while true; do ... validate ...; sleep 60; done` 之类的后台循环自动补拉，
> 否则会把 CPU/内存波峰和日志分析都搅乱。

如需停止这 4 个模块，可直接使用：

```bash
./scripts/run_capability_24h.sh stop-safe4
```

### 1.3 监控

```bash
# 状态总览
sudo scripts/run_experiment.sh status

# 查看某模块的 fuzz 日志
sudo scripts/run_experiment.sh log xfs fuzz

# 查看某模块的 validate 日志
sudo scripts/run_experiment.sh log xfs validate
```

### 1.4 24h 后停止

```bash
sudo scripts/run_experiment.sh stop --all
```

### 1.5 结果收集

```bash
# 绘图: 4-way 对比
python3 scripts/plot_4way.py --all

# 单模块 pair 发现曲线
python3 scripts/plot_pairs.py -t xfs btrfs f2fs jfs floppy bt-stack ptmx dsp
```

**产出文件**:
- `exp/<module>/logs/exp-fuzz-*.log` — fuzz 日志 (含 may-race pair 计数)
- `exp/<module>/logs/exp-validate-*.log` — validate 日志
- `exp/<module>/workdir/uaf-corpus.db` — may-race pair 数据库
- `exp/<module>/workdir/validate-run/validated_uaf.db` — 确认的真实数据竞争

### 1.6 从 validate 结果中提取 datarace

validate 完成后，可以直接用 `syz-validatedb` 从 `validated_uaf.db` 导出可读日志，便于统计和 case study 分析。

```bash
# 示例: 导出 bt-stack 的 validated race
sudo ./bin/syz-validatedb \
  -db ./exp/bt-stack/workdir/validate-run/validated_uaf.db \
  -format \
  -manager_cfg ./exp/bt-stack/validate.cfg \
  -group_by_var > bt-stack.log
```

如果你想批量导出 8 个模块，可以这样跑：

```bash
for mod in xfs btrfs f2fs jfs floppy bt-stack ptmx dsp; do
  DB="./exp/${mod}/workdir/validate-run/validated_uaf.db"
  CFG="./exp/${mod}/validate.cfg"
  OUT="./exp/${mod}/results/${mod}-validated.log"

  if [[ -f "$DB" ]]; then
    mkdir -p "./exp/${mod}/results"
    sudo ./bin/syz-validatedb \
      -db "$DB" \
      -format \
      -manager_cfg "$CFG" \
      -group_by_var > "$OUT"
    echo "exported: $OUT"
  fi
done
```

常用选项说明：
- `-db`: 指向 validate 生成的 `validated_uaf.db`
- `-format`: 以更可读的格式输出
- `-manager_cfg`: 使用对应模块的 manager 配置辅助解析符号
- `-group_by_var`: 按变量名对 race 分组，适合论文统计

> 建议主实验统一使用 `exp/<module>/validate.cfg` 或 `exp-validate.cfg`，不要再混用旧的 `./test/DDRD-PairCollector/test/*.cfg` 路径。

### 1.7 分批运行 (核心不够时)

```bash
# 批次 1: 推荐 6 模块
sudo scripts/run_experiment.sh start xfs btrfs f2fs jfs bt-stack ptmx
# 1-2h 后启动 validate
sudo scripts/run_experiment.sh --separate-validate-slot validate xfs btrfs f2fs jfs bt-stack ptmx

# 24h 后停止批次 1, 开始批次 2
sudo scripts/run_experiment.sh stop --all
sudo scripts/run_experiment.sh start floppy dsp
sudo scripts/run_experiment.sh --separate-validate-slot validate floppy dsp
```

---

## 2. 实验二: Fuzz 侧敏感度 (Ablation - Fuzz Side)

**目标**: 评估 "资源感知对象链接" 和 "pair-guided 时序探索" 各自的贡献。

**模块**: `xfs btrfs ptmx dsp` (4 模块代表子集)

**变体**:
| 名称 | 配置后缀 | 说明 |
|------|----------|------|
| Full DDRD | (默认) | 所有功能开启 |
| No Timing | `-no-timing` | 关闭 timing exploration |
| No ObjLink | `-no-objlink` | 关闭 ObjectLinker V2 |
| Random | `-random` | 纯随机基线 |

**运行**: 每变体 × 每模块 12h fuzz, 3 次独立重复 (预算紧张时先做 2 次)。

### 2.1 跑一个变体

```bash
# 示例: fuzz-no-timing, 第 1 次
sudo scripts/run_experiment.sh --variant no-timing start xfs btrfs ptmx dsp
```

### 2.2 完整 ablation 流程 (脚本化)

```bash
#!/bin/bash
MODS="xfs btrfs ptmx dsp"
VARIANTS=("" "no-timing" "no-objlink" "random")
FUZZ_HOURS=12
RUNS=3

for run in $(seq 1 $RUNS); do
  for variant in "${VARIANTS[@]}"; do
    VARIANT_FLAG=""
    LABEL="full"
    if [[ -n "$variant" ]]; then
      VARIANT_FLAG="--variant $variant"
      LABEL="$variant"
    fi

    echo "=== Run $run, Variant: $LABEL ==="

    # 清理上一轮数据
    sudo scripts/run_experiment.sh clean --all 2>/dev/null || true

    # 启动 fuzz
    sudo scripts/run_experiment.sh $VARIANT_FLAG start $MODS

    # 等待指定时间
    sleep $((FUZZ_HOURS * 3600))

    # 停止
    sudo scripts/run_experiment.sh stop --all

    # 备份结果
    for mod in $MODS; do
      BACKUP="exp/${mod}/results/ablation-fuzz/${LABEL}/run${run}"
      mkdir -p "$BACKUP"
      cp -r "exp/${mod}/workdir/uaf-corpus.db" "$BACKUP/" 2>/dev/null || true
      cp "exp/${mod}/logs/"exp-fuzz*.log "$BACKUP/" 2>/dev/null || true
    done
  done
done
```

### 2.3 Fuzz 产出的 offline validation

每个 fuzz-ablation run 结束后, 用**相同的完整 validator** 处理 frozen corpus:

```bash
# 假设 ablation fuzz 结果已备份到 exp/<mod>/results/ablation-fuzz/<variant>/run<N>/
# 将 uaf-corpus.db 放回 workdir, 然后跑 validate

for mod in xfs btrfs ptmx dsp; do
  for variant in full no-timing no-objlink random; do
    for run in 1 2 3; do
      SRC="exp/${mod}/results/ablation-fuzz/${variant}/run${run}/uaf-corpus.db"
      if [[ -f "$SRC" ]]; then
        # 准备 workdir
        sudo scripts/run_experiment.sh clean-validate $mod 2>/dev/null || true
        mkdir -p "exp/${mod}/workdir"
        cp "$SRC" "exp/${mod}/workdir/uaf-corpus.db"

        # 跑 validate (完整版)
        sudo scripts/run_experiment.sh validate $mod
        sleep $((6 * 3600))  # 6h validate budget
        sudo scripts/run_experiment.sh stop $mod

        # 备份 validate 结果
        VBACKUP="exp/${mod}/results/ablation-fuzz/${variant}/run${run}/validate"
        mkdir -p "$VBACKUP"
        cp "exp/${mod}/workdir/validate-run/validated_uaf.db" "$VBACKUP/" 2>/dev/null || true
        cp "exp/${mod}/logs/"exp-validate*.log "$VBACKUP/" 2>/dev/null || true
      fi
    done
  done
done
```

### 2.4 指标

**主要**: may-race pair 数 / VarName pair 数 / 发现速率曲线
**关键补充**: 用相同 validator 消化后的确认漏洞数 (confirmed race count)

---

## 3. 实验三: Validate 侧敏感度 (Ablation - Validate Side)

**目标**: 评估 "定向延时调度"、"状态还原(replay)"、"自适应权重调整(backoff)" 各自的贡献。

**模块**: `xfs btrfs ptmx dsp` (4 模块代表子集)

**前提**: 使用 24h 主实验的 frozen corpus 作为统一输入。

**变体**:
| 名称 | 配置后缀 | 说明 |
|------|----------|------|
| Full validator | (默认) | 所有功能开启 |
| No Delay | `-no-delay` | 关闭 directed delay scheduling |
| No Replay | `-no-replay` | 关闭 state replay/restoration |
| No Backoff | `-no-backoff` | 关闭 adaptive backoff |

### 3.1 准备 frozen corpus

```bash
# 从 24h 主实验备份 corpus
for mod in xfs btrfs ptmx dsp; do
  mkdir -p "exp/${mod}/results/frozen-corpus"
  cp "exp/${mod}/workdir/uaf-corpus.db" "exp/${mod}/results/frozen-corpus/"
done
```

### 3.2 跑一个变体

```bash
# 恢复 frozen corpus
cp exp/xfs/results/frozen-corpus/uaf-corpus.db exp/xfs/workdir/uaf-corpus.db
sudo scripts/run_experiment.sh clean-validate xfs

# 用 no-delay 变体跑 validate
sudo scripts/run_experiment.sh --variant no-delay validate xfs
```

### 3.3 完整流程

```bash
#!/bin/bash
MODS="xfs btrfs ptmx dsp"
VARIANTS=("" "no-delay" "no-replay" "no-backoff")
VALIDATE_HOURS=6
RUNS=3

for run in $(seq 1 $RUNS); do
  for variant in "${VARIANTS[@]}"; do
    VARIANT_FLAG=""
    LABEL="full"
    if [[ -n "$variant" ]]; then
      VARIANT_FLAG="--variant $variant"
      LABEL="$variant"
    fi

    for mod in $MODS; do
      echo "=== Validate Run $run, Variant: $LABEL, Module: $mod ==="

      # 恢复 frozen corpus
      cp "exp/${mod}/results/frozen-corpus/uaf-corpus.db" "exp/${mod}/workdir/uaf-corpus.db"
      sudo scripts/run_experiment.sh clean-validate $mod 2>/dev/null || true

      # 启动 validate
      sudo scripts/run_experiment.sh $VARIANT_FLAG validate $mod
    done

    # 等待
    sleep $((VALIDATE_HOURS * 3600))

    # 停止并备份
    sudo scripts/run_experiment.sh stop --all
    for mod in $MODS; do
      VBACKUP="exp/${mod}/results/ablation-validate/${LABEL}/run${run}"
      mkdir -p "$VBACKUP"
      cp "exp/${mod}/workdir/validate-run/validated_uaf.db" "$VBACKUP/" 2>/dev/null || true
      cp "exp/${mod}/workdir/validate-run/varname_backoff_stats.db" "$VBACKUP/" 2>/dev/null || true
      cp "exp/${mod}/logs/"exp-validate*.log "$VBACKUP/" 2>/dev/null || true
    done
  done
done
```

### 3.4 指标

- confirmed real races 数
- time-to-first confirmed race
- confirmed races/hour
- processed pairs/hour
- skipped pairs

---

## 4. 实验四: Δt 分桶验证效率 (Validation Efficiency by Initial Temporal Gap)

**目标**: 证明初始 Δt 越小的 MRP 候选, 越容易被验证确认为真实数据竞争。
即验证预算集中在小 Δt 候选上可获得更高的确认率。

**数据来源**: 24h 主实验的 fuzz + validate 产出 (使用实验一的数据, 无需额外运行)。

**核心思路**:
1. 每个 MRP 候选 pair 在发现时记录了初始 Δt (executor 层 `TimeDiff`, 纳秒)
2. 验证系统对每个 pair 执行相同的验证预算 (相同超时、相同重放次数)
3. 按 Δt 对数分桶, 统计各桶的确认率、中位尝试次数

**分桶方案** (对数刻度):

| 桶 | 范围 |
|----|------|
| Bin 0 | [0, 10μs) |
| Bin 1 | [10μs, 100μs) |
| Bin 2 | [100μs, 1ms) |
| Bin 3 | [1ms, 10ms) |
| Bin 4 | [10ms, 100ms) |
| Bin 5 | [100ms, 500ms] |

**指标**:
1. **HitRate(bin)** = 确认数 / (确认数 + 失败数), 按桶统计
2. **MedianAttemptsToConfirm(bin)** = 确认 pair 的中位验证尝试次数
3. **CPUTimePerConfirmation(bin)** ≈ 平均尝试次数 × 单次超时, 按桶估算

### 4.1 前置: 确保主实验已完成

本实验使用实验一的产出。需确认以下文件存在:

```bash
for mod in xfs btrfs f2fs jfs floppy bt-stack ptmx dsp; do
  echo "=== $mod ==="
  ls -lh "exp/${mod}/workdir/uaf-corpus.db" 2>/dev/null || echo "  MISSING: uaf-corpus.db"
  ls -lh "exp/${mod}/workdir/validate-run/validated_uaf.db" 2>/dev/null || echo "  MISSING: validated_uaf.db"
  ls -lh "exp/${mod}/workdir/validate-run/invalid_uaf.db" 2>/dev/null || echo "  MISSING: invalid_uaf.db"
  ls -lh "exp/${mod}/workdir/validate-run/varname_backoff_stats.db" 2>/dev/null || echo "  MISSING: varname_backoff_stats.db"
done
```

### 4.2 编译分析工具

```bash
go build -o bin/syz-deltat-analysis ./tools/syz-deltat-analysis/
```

### 4.3 单模块分析

```bash
# 以 xfs 为例
./bin/syz-deltat-analysis \
  -corpus  exp/xfs/workdir/uaf-corpus.db \
  -valid   exp/xfs/workdir/validate-run/validated_uaf.db \
  -invalid exp/xfs/workdir/validate-run/invalid_uaf.db \
  -backoff exp/xfs/workdir/validate-run/varname_backoff_stats.db \
  -csv     exp/xfs/results/deltat_buckets.csv \
  -pair-csv exp/xfs/results/deltat_pairs.csv \
  -json    exp/xfs/results/deltat_report.json
```

终端输出示例:
```
Corpus: 1234 entries, 5678 total pairs, 3456 unique pairs
Loaded 2345 records from validated_uaf.db
Loaded 1111 records from invalid_uaf.db
Loaded 890 VarName backoff stats from varname_backoff_stats.db

========== Δt-Bucketed Validation Analysis ==========
Total unique pairs: 3456  (validated=567  invalid=2345  pending=544)

Bucket               Total  Valid  Inval   Pend  HitRate HitR(R)  MedAttempt  MedΔt(μs)
------------------------------------------------------------------------------------------------
[0, 10μs)              420    123    210     87    29.3%   36.9%        2.0      3.5μs
[10μs, 100μs)          680     98    456    126    14.4%   17.7%        3.0     45.2μs
...
```

### 4.4 批量分析全部模块

```bash
for mod in xfs btrfs f2fs jfs floppy bt-stack ptmx dsp; do
  echo "=== Analyzing $mod ==="
  mkdir -p "exp/${mod}/results"
  ./bin/syz-deltat-analysis \
    -corpus  "exp/${mod}/workdir/uaf-corpus.db" \
    -valid   "exp/${mod}/workdir/validate-run/validated_uaf.db" \
    -invalid "exp/${mod}/workdir/validate-run/invalid_uaf.db" \
    -backoff "exp/${mod}/workdir/validate-run/varname_backoff_stats.db" \
    -csv     "exp/${mod}/results/deltat_buckets.csv" \
    -pair-csv "exp/${mod}/results/deltat_pairs.csv" \
    -json    "exp/${mod}/results/deltat_report.json"
done
```

### 4.5 生成图表

```bash
pip install pandas matplotlib  # 如果尚未安装

for mod in xfs btrfs f2fs jfs floppy bt-stack ptmx dsp; do
  python3 tools/plot_deltat_analysis.py \
    --csv  "exp/${mod}/results/deltat_buckets.csv" \
    --pair-csv "exp/${mod}/results/deltat_pairs.csv" \
    -o "exp/${mod}/results/plots/"
done
```

产出图表:
- `deltat_hit_rate.pdf` — 各桶确认率柱状图 (论文主图)
- `deltat_hit_rate_resolved.pdf` — 仅统计已决议 pair 的确认率
- `deltat_median_attempts.pdf` — 各桶中位验证尝试次数
- `deltat_distribution.pdf` — 各桶 pair 分布 (堆叠柱状图)
- `deltat_scatter.pdf` — 逐 pair 散点图 (log₁₀Δt vs 验证结果)

### 4.6 跨模块汇总

如需汇总 8 个模块的 CSV 做整体分析:

```bash
# 合并所有模块的 per-pair CSV
head -1 exp/xfs/results/deltat_pairs.csv > exp/results/deltat_pairs_all.csv
for mod in xfs btrfs f2fs jfs floppy bt-stack ptmx dsp; do
  tail -n +2 "exp/${mod}/results/deltat_pairs.csv" >> exp/results/deltat_pairs_all.csv
done

# 用合并数据重新出图
python3 tools/plot_deltat_analysis.py \
  --csv  <(python3 -c "
import pandas as pd, sys
dfs = []
for m in 'xfs btrfs f2fs jfs floppy bt-stack ptmx dsp'.split():
    try:
        df = pd.read_csv(f'exp/{m}/results/deltat_buckets.csv')
        dfs.append(df)
    except: pass
agg = pd.concat(dfs).groupby('bucket', sort=False).sum().reset_index()
agg['hit_rate'] = agg['validated'] / (agg['validated'] + agg['invalid']).replace(0, 1)
agg['hit_rate_resolved'] = agg['hit_rate']
agg.to_csv(sys.stdout, index=False)
") \
  --pair-csv exp/results/deltat_pairs_all.csv \
  -o exp/results/plots/
```

### 4.7 预期结果

- 小 Δt 桶 (`[0, 10μs)`) 的确认率应显著高于大 Δt 桶 (`[10ms, 100ms)`)
- 确认率随 Δt 增大单调递减 (或近似单调递减)
- 中位验证尝试次数随 Δt 增大而增加
- 这支持论文论点: 初始时序间隔小的 pair 更可能是真实竞争, 应优先验证

### 4.8 Ablation 实验复用

该分析也可以应用于实验二/三的各 ablation 变体产出,
对比不同配置下各 Δt 桶的确认率差异:

```bash
# 示例: 分析 no-delay 变体的 Δt 分布
./bin/syz-deltat-analysis \
  -corpus  exp/xfs/results/frozen-corpus/uaf-corpus.db \
  -valid   exp/xfs/results/ablation-validate/no-delay/run1/validated_uaf.db \
  -invalid exp/xfs/results/ablation-validate/no-delay/run1/invalid_uaf.db \
  -csv     exp/xfs/results/ablation-validate/no-delay/run1/deltat_buckets.csv
```

---

## 5. 产出目录结构

> 注: 实验四的产出集成在各模块 `results/` 下, 无需单独目录。

```
exp/<module>/
  results/
    frozen-corpus/             # 24h 主实验的 frozen uaf-corpus.db
      uaf-corpus.db
    deltat_buckets.csv         # Δt 分桶统计 (实验四)
    deltat_pairs.csv           # 逐 pair 数据 (实验四)
    deltat_report.json         # 完整 JSON 报告 (实验四)
    plots/                     # 图表 (实验四)
      deltat_hit_rate.pdf
      deltat_median_attempts.pdf
      deltat_distribution.pdf
      deltat_scatter.pdf
    ablation-fuzz/
      full/run1/               # fuzz ablation 结果
        uaf-corpus.db
        exp-fuzz-*.log
        validate/              # offline validate 结果
          validated_uaf.db
      no-timing/run1/
      no-objlink/run1/
      random/run1/
    ablation-validate/
      full/run1/
        validated_uaf.db
        varname_backoff_stats.db
        exp-validate-*.log
      no-delay/run1/
      no-replay/run1/
      no-backoff/run1/
```

---

## 6. Ablation 变体配置生成参考

说明: 本手册的当前主线实验不使用 vanilla baseline。当前需要的对照主要是 DDRD-random 和各类 ablation 变体。
如确实要额外做“去掉 experimental 字段的纯净配置”对照，才临时执行相应的 vanilla 配置生成命令。

```bash
# 列出所有可用变体
python3 scripts/generate_config.py --list-ablations

# 生成 fuzz-side 变体
python3 scripts/generate_config.py --ablation fuzz-no-timing   --force xfs btrfs ptmx dsp
python3 scripts/generate_config.py --ablation fuzz-no-objlink  --force xfs btrfs ptmx dsp
python3 scripts/generate_config.py --ablation fuzz-random      --force xfs btrfs ptmx dsp

# 生成 validate-side 变体
python3 scripts/generate_config.py --ablation validate-no-delay   --force xfs btrfs ptmx dsp
python3 scripts/generate_config.py --ablation validate-no-replay  --force xfs btrfs ptmx dsp
python3 scripts/generate_config.py --ablation validate-no-backoff --force xfs btrfs ptmx dsp
```

---

## 7. 代码改动后快速重跑

```bash
# 1. 改代码
# 2. 重新编译
make

# 3. 重新生成配置 (如果改了 experimental 默认值)
python3 scripts/generate_config.py --all --force
python3 scripts/generate_config.py --ablation <variant> --force $ABLATION_MODS

# 4. 清理旧数据 (保留 frozen corpus 不要清)
sudo scripts/run_experiment.sh clean --all
sudo scripts/run_experiment.sh clean-validate --all

# 5. 重新启动
sudo scripts/run_experiment.sh start --all
```

---

## 8. 有用的 JSON 配置开关速查

### Fuzz 侧
| 开关 | 位置 | 默认 | 作用 |
|------|------|------|------|
| `uaf_mode` | experimental | true | 启用 DDRD race 检测 |
| `barrier_mode` | experimental | true | 启用 barrier 同步执行 |
| `enable_timing_exploration` | experimental | true | pair-guided 时序探索 |
| `enable_object_linking` | experimental | true (null=true) | 资源感知对象链接 |
| `random_baseline_mode` | experimental | false | 纯随机基线 |

### Validate 侧
| 开关 | 位置 | 默认 | 作用 |
|------|------|------|------|
| `disable_verify_delay` | uaf_validate | false | 关闭定向延时调度 |
| `enable_replay` | uaf_validate | true | 状态还原/重放 |
| `enable_varname_scheduling` | uaf_validate | true | 自适应权重调度 |
| `continue_after_backoff` | uaf_validate | true | backoff 后继续 |
| `streaming_load` | uaf_validate | true | 流式加载 corpus |

---

## 9. 敏感度实验是否需要跑全部 8 模块?

**不需要**。实验计划中明确使用 4 模块代表子集: `xfs btrfs ptmx dsp`。

理由:
- 覆盖文件系统 (xfs, btrfs) + 非文件系统 (ptmx, dsp) 两类子系统
- 与已有 threshold sensitivity 数据一致
- 3 变体 × 4 模块 × 3 重复 × 12h = 已经需要 432h fuzz 算力
- 全部 8 模块会使敏感度实验算力翻倍, 但不增加统计说服力
