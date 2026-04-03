# pair-collector — 并发对数对比实验完整指南

## 一、实验概述

本文档详细说明如何对 **DDRD**、**Conzzer**、**SegFuzz** 三个并发模糊测试工具进行 Pair Count 对比实验，从环境准备到最终出图的完整步骤。

### 关键结论：Conzzer 和 SegFuzz 无需额外注入收集工具

| 工具 | 数据来源 | 是否需要额外部署收集器 | 说明 |
|------|---------|:---:|------|
| **DDRD** | `race_timeseries.csv` (由 `run-with-collector.sh` 生成) | 需要 | 需要将 `syz-race-collector` 部署到 VM 内 |
| **Conzzer** | `plot-curve` (Fuzzer 原生输出) | **不需要** | Fuzzer 每轮变异自动写入，不需要任何额外处理 |
| **SegFuzz** | `workdir/log` (syz-manager 原生输出) | **不需要** | syz-manager 每 10 秒自动写入，不需要任何额外处理 |

Conzzer 的 AFLCplusplus Fuzzer 在运行时会自动将 `total_travel.size()` 等统计写入 `plot-curve` 文件。
SegFuzz 的 syz-manager 在运行时会自动将 `maxInterleaving` / `maxCommunication` 写入 log 文件。
**因此启动实验时无需做任何特殊配置或注入。**

### 指标映射

| DDRD 指标 | Conzzer 等效 | SegFuzz 等效 | 含义 |
|-----------|-------------|-------------|------|
| **Pair Count** | `total_travel` (plot-curve 列5) | `max_interleaving` (log) | 发现的唯一并发交互对数 |
| **VarName Pair** | `total_another_travel` (列6) | `max_communication` (log) | 发现的唯一变量/指令维度对数 |

---

## 二、前置环境确认

### 2.1 目录结构

```
/home/zzzccc/BASS/
├── DDRD-syzkaller/                # DDRD 项目
│   ├── images/                    # bookworm.img + bookworm.id_rsa (三者共用)
│   ├── exp/                       # DDRD 各模块实验配置 (fuzz.cfg 等)
│   ├── test/DDRD/                 # DDRD 工作目录 (含 corpus.db)
│   └── tools/
│       ├── syz-race-collector/    # DDRD 专用收集器 (部署到 VM 内)
│       └── pair-collector/        # ★ 本工具 (跨工具对比)
├── Conzzer/                       # Conzzer 项目
│   ├── exp/                       # 各模块实验目录 (含 fuzz/output/plot-curve)
│   ├── scripts/                   # run_experiment.sh 等
│   └── kernel/                    # 各模块插桩内核
└── segfuzz/                       # SegFuzz 项目
    ├── exp/segfuzz-comparison/    # SegFuzz 对比实验 (含 run_comparison.sh)
    ├── tools/segfuzz/             # SegFuzz syzkaller 分支 (含 bin/syz-manager)
    ├── tools/qemu/                # SegFuzz 自定义 QEMU (含 QCSCHED)
    └── kernels/                   # SegFuzz 插桩内核
```

### 2.2 确认编译产物

```bash
# === Conzzer ===
# Fuzzer (宿主机运行)
ls /home/zzzccc/BASS/Conzzer/conzzer-kernel-fuzzer-concurrency-fuzz/fuzzer/AFLCplusplus
# Tester (部署到 VM 内)
ls /home/zzzccc/BASS/Conzzer/conzzer-kernel-fuzzer-concurrency-fuzz/fuzzer/NetTester
# 插桩内核 (每个模块一份)
ls /home/zzzccc/BASS/Conzzer/kernel/*/arch/x86/boot/bzImage

# === SegFuzz ===
# syz-manager
ls /home/zzzccc/BASS/segfuzz/gotools/src/github.com/google/segfuzz/bin/syz-manager
# 自定义 QEMU (含 QCSCHED hypercall 支持)
ls /home/zzzccc/BASS/segfuzz/tools/qemu/install/bin/qemu-system-x86_64

# === DDRD ===
# syz-manager
ls /home/zzzccc/BASS/DDRD-syzkaller/bin/linux_amd64/syz-manager
# race-collector (DDRD 专用, Conzzer/SegFuzz 不需要)
ls /home/zzzccc/BASS/DDRD-syzkaller/tools/syz-race-collector/syz-race-collector

# === Python 依赖 (画图用) ===
pip install matplotlib
```

### 2.3 确认 SegFuzz 配置已生成

```bash
cd /home/zzzccc/BASS/segfuzz/exp/segfuzz-comparison

# 如果尚未生成配置（首次需要执行）:
python3 generate_configs.py

# 验证各模块配置是否存在
for mod in xfs btrfs f2fs jfs floppy usb-driver video wifi bt-stack ptmx dsp; do
    echo "$mod: $(ls $mod/syzkaller.cfg 2>/dev/null && echo OK || echo MISSING)"
done
```

---

## 三、完整实验步骤（以 `dsp` 模块为例）

> 其他模块只需将下文中的 `dsp` 替换为对应模块名。

### 第一步：启动三个工具

打开 3 个终端，分别启动：

**终端 1 — 启动 DDRD：**

```bash
cd /home/zzzccc/BASS/DDRD-syzkaller

# 推荐方式: run-with-collector.sh 同时启动 syz-manager + 自动部署 collector + 自动收集
cd tools/syz-race-collector
sudo ./run-with-collector.sh \
    --config ../../exp/dsp/fuzz.cfg \
    --output-dir ../../exp/dsp/collector-output \
    --duration 86400 \
    --interval 60

# 或者简化方式 (仅启动 syz-manager, 不自动收集 pair):
# cd /home/zzzccc/BASS/DDRD-syzkaller
# sudo ./scripts/run_experiment.sh start dsp
```

**终端 2 — 启动 Conzzer：**

```bash
cd /home/zzzccc/BASS/Conzzer

# 一条命令即可，无需额外操作
# 它会: 1) 启动 QEMU VM  2) 启动 AFLCplusplus Fuzzer  3) 部署 NetTester 到 VM
sudo ./scripts/run_experiment.sh start dsp

# ★ Fuzzer 会自动将并发对统计写入:
#   exp/dsp/fuzz/output/plot-curve
# 默认运行 24 小时 (FUZZ_DURATION=86400)，到时自动停止
```

**终端 3 — 启动 SegFuzz：**

```bash
cd /home/zzzccc/BASS/segfuzz/exp/segfuzz-comparison

# 一条命令即可，无需额外操作
# 它会: 1) 自动导入 DDRD corpus  2) 后台启动 syz-manager
./run_comparison.sh start dsp

# ★ syz-manager 会自动将统计写入:
#   dsp/workdir/log   (每 10 秒一行)
# 无内建时限，需手动停止
```

### 第二步（可选）：实时监控 Pair Count 增长

在实验运行期间，可在额外终端实时观察各工具的 Pair Count 变化：

```bash
cd /home/zzzccc/BASS/DDRD-syzkaller/tools/pair-collector

# 监控 Conzzer (新终端)
python3 collect_conzzer_pairs.py \
    /home/zzzccc/BASS/Conzzer/exp/dsp/fuzz/output/plot-curve \
    -o results/dsp/conzzer_dsp_live.csv --live --poll 10

# 监控 SegFuzz (新终端)
python3 collect_segfuzz_pairs.py log \
    /home/zzzccc/BASS/segfuzz/exp/segfuzz-comparison/dsp/workdir/log \
    -o results/dsp/segfuzz_dsp_live.csv --live --poll 10
```

输出示例：
```
[live] +3 records | elapsed=1.50h | pair_count=12345 | varname_pair_count=678 | total_records=150
```

### 第三步：检查实验运行状态

```bash
# Conzzer 状态
cd /home/zzzccc/BASS/Conzzer && sudo ./scripts/run_experiment.sh status

# SegFuzz 状态
cd /home/zzzccc/BASS/segfuzz/exp/segfuzz-comparison && ./run_comparison.sh status

# DDRD 状态
cd /home/zzzccc/BASS/DDRD-syzkaller && sudo ./scripts/run_experiment.sh status
```

### 第四步：等待实验完成并停止

推荐运行 **24 小时**：
- Conzzer 默认 24h 后自动停止
- SegFuzz 和 DDRD 需手动停止

```bash
# 24 小时后:

# 停止 SegFuzz
cd /home/zzzccc/BASS/segfuzz/exp/segfuzz-comparison
./run_comparison.sh stop dsp

# 停止 DDRD (如果用 run_experiment.sh 启动的)
cd /home/zzzccc/BASS/DDRD-syzkaller
sudo ./scripts/run_experiment.sh stop dsp

# Conzzer 通常已自动停止，确认:
cd /home/zzzccc/BASS/Conzzer
sudo ./scripts/run_experiment.sh status
# 如果还在运行:
sudo ./scripts/run_experiment.sh stop dsp
```

### 第五步：提取 Pair Count 时间序列数据

```bash
cd /home/zzzccc/BASS/DDRD-syzkaller/tools/pair-collector

# === 提取 Conzzer 数据 ===
python3 collect_conzzer_pairs.py \
    /home/zzzccc/BASS/Conzzer/exp/dsp/fuzz/output/plot-curve \
    -o results/dsp/conzzer_dsp.csv -v

# === 提取 SegFuzz 数据 ===
python3 collect_segfuzz_pairs.py log \
    /home/zzzccc/BASS/segfuzz/exp/segfuzz-comparison/dsp/workdir/log \
    -o results/dsp/segfuzz_dsp.csv -v

# === DDRD 数据 ===
# 如果用 run-with-collector.sh, 已自动生成:
cp /home/zzzccc/BASS/DDRD-syzkaller/exp/dsp/collector-output/race_timeseries.csv \
   results/dsp/ddrd_dsp.csv
```

输出示例：
```
Parsed 1200 records from .../plot-curve
Wrote 1200 records to results/dsp/conzzer_dsp.csv

============================================================
Conzzer Pair Collection Summary
============================================================
  Records:              1200
  Duration:             24.00 hours
  Final pair_count:     65918
  Final varname_pair:   15264
============================================================
```

### 第六步：生成对比图

```bash
cd /home/zzzccc/BASS/DDRD-syzkaller/tools/pair-collector

# 三者对比 (双子图: VarName Pair + Pair Count)
python3 plot_comparison.py \
    --ddrd    results/dsp/ddrd_dsp.csv \
    --conzzer results/dsp/conzzer_dsp.csv \
    --segfuzz results/dsp/segfuzz_dsp.csv \
    -o results/dsp/comparison_dsp.png \
    --target dsp --max-hours 24

# 论文投稿 PDF 格式
python3 plot_comparison.py \
    --ddrd    results/dsp/ddrd_dsp.csv \
    --conzzer results/dsp/conzzer_dsp.csv \
    --segfuzz results/dsp/segfuzz_dsp.csv \
    -o results/dsp/comparison_dsp.pdf \
    --target dsp --max-hours 24
```

---

## 四、批量运行所有模块

### 4.1 一键启动全部

```bash
# Conzzer: 启动全部 11 个模块 (每模块需 ~4GB RAM + 4 vCPU)
cd /home/zzzccc/BASS/Conzzer
sudo ./scripts/run_experiment.sh start-all

# SegFuzz: 启动全部模块 (每模块需 ~8GB RAM + 4 vCPU + KVM)
cd /home/zzzccc/BASS/segfuzz/exp/segfuzz-comparison
./run_comparison.sh start

# DDRD: 启动全部模块
cd /home/zzzccc/BASS/DDRD-syzkaller
sudo ./scripts/run_experiment.sh start --all
```

> **注意资源需求**: 同时运行 3×11=33 个 VM，需要至少 ~180GB RAM。
> 如果资源不足，按模块分批运行（见下文）。

### 4.2 资源有限时的分批策略

```bash
for mod in dsp btrfs xfs f2fs jfs floppy usb-driver video wifi-stack bt-stack ptmx; do
    echo "========== Starting $mod =========="

    # 1. 启动三个工具
    cd /home/zzzccc/BASS/Conzzer && sudo ./scripts/run_experiment.sh start $mod
    cd /home/zzzccc/BASS/segfuzz/exp/segfuzz-comparison && ./run_comparison.sh start $mod
    cd /home/zzzccc/BASS/DDRD-syzkaller && sudo ./scripts/run_experiment.sh start $mod

    # 2. 等待 24 小时
    sleep 86400

    # 3. 停止
    cd /home/zzzccc/BASS/Conzzer && sudo ./scripts/run_experiment.sh stop $mod
    cd /home/zzzccc/BASS/segfuzz/exp/segfuzz-comparison && ./run_comparison.sh stop $mod
    cd /home/zzzccc/BASS/DDRD-syzkaller && sudo ./scripts/run_experiment.sh stop $mod

    # 4. 提取数据 + 生成图
    cd /home/zzzccc/BASS/DDRD-syzkaller/tools/pair-collector
    ./collect_pairs.sh collect-all $mod
    ./collect_pairs.sh plot $mod

    echo "========== $mod done =========="
done
```

### 4.3 批量提取与出图

```bash
cd /home/zzzccc/BASS/DDRD-syzkaller/tools/pair-collector

# 批量提取所有已有数据的模块
./collect_pairs.sh collect-batch all

# 查看数据可用性
./collect_pairs.sh status

# 批量出图
./collect_pairs.sh plot-batch
```

---

## 五、实验公平性保证

| 维度 | DDRD | Conzzer | SegFuzz |
|------|------|---------|---------|
| **内核版本** | 6.17-rc5 | 6.17-rc5 | 6.17-rc5 |
| **rootfs** | bookworm.img | bookworm.img (共用) | bookworm.img (共用) |
| **初始 Corpus** | 自有 corpus.db | 从 DDRD 导入 | 从 DDRD 导入 |
| **VM 资源** | 4 vCPU + 4GB | 4 vCPU + 4GB | 4 vCPU + 4-8GB |
| **运行时长** | 24h | 24h (自动停) | 24h (手动停) |
| **系统调用范围** | 模块特定 | 模块特定 test.sh | 从 DDRD 翻译 |

---

## 六、高级用法

### 6.1 只画单个指标

```bash
# 只画 Pair Count
python3 plot_comparison.py --ddrd d.csv --conzzer c.csv --segfuzz s.csv \
    -o pair_count.png --metric pair_count --target dsp

# 只画 VarName Pair Count
python3 plot_comparison.py --ddrd d.csv --conzzer c.csv --segfuzz s.csv \
    -o varname.png --metric varname --target dsp
```

### 6.2 包含 Random baseline 的四路对比

```bash
python3 plot_comparison.py \
    --ddrd    results/dsp/ddrd_dsp.csv \
    --random  results/dsp/random_dsp.csv \
    --conzzer results/dsp/conzzer_dsp.csv \
    --segfuzz results/dsp/segfuzz_dsp.csv \
    -o results/dsp/full_comparison_dsp.png \
    --target dsp --max-hours 24
```

### 6.3 通用模式（任意 CSV 对比）

```bash
python3 plot_comparison.py \
    -i exp1.csv exp2.csv exp3.csv \
    --labels "DDRD" "Conzzer" "SegFuzz" \
    -o comparison.png --target btrfs
```

---

## 七、数据格式参考

所有收集脚本输出统一 CSV 格式：

```csv
timestamp,elapsed_sec,elapsed_min,elapsed_hour,pair_count,varname_pair_count
2026-03-13T15:17:21,0.00,0.00,0.0000,0,0
2026-03-13T15:17:31,10.00,0.17,0.0028,513730,292
```

| 列名 | 类型 | 说明 |
|------|------|------|
| `timestamp` | string | ISO 8601 时间戳 |
| `elapsed_sec` | float | 距实验开始的秒数 |
| `elapsed_min` | float | 距实验开始的分钟数 |
| `elapsed_hour` | float | 距实验开始的小时数 (画图 x 轴) |
| `pair_count` | int | 并发对数 |
| `varname_pair_count` | int | 变量名对数 |

---

## 八、数据源技术细节

### Conzzer: `plot-curve` 文件

Conzzer 的 Fuzzer (`AFLCplusplus`) 在每轮变异后调用 `print_result()` 向
`exp/<mod>/fuzz/output/plot-curve` 追加一行：

```
1773305013213096   9040(0.862122%)   0/0   0   2156 1823 0 0 0 0 0 2 ConcurrencyFuzzing
```

- **列1** = 微秒时间戳 (`gettimeofday`)
- **列5** = `total_travel.size()` → 上下文不敏感并发对数 → **pair_count**
- **列6** = `total_another_travel.size()` → 上下文敏感并发对数 → **varname_pair_count**

`total_travel` 是 `set<u64>`，存储 `hashes2hash(hash_A, hash_B)` 的去重集合。
内核模块 `lib_exfunc` 在函数入口/出口时遍历所有线程的调用栈，形成并发对。

### SegFuzz: `log` 文件

SegFuzz 的 syz-manager 每 10 秒输出一行到 `workdir/log`：

```
VMs 1, executed 26, cover 1032, signal 1306/1265, interleaving 509671/513730, comm 292, ...
```

- **interleaving A/B** = corpusInterleaving/maxInterleaving → B = **pair_count**
- **comm** = maxCommunication → **varname_pair_count**

`maxInterleaving` 是 Knot 的 FNV-64a 哈希集合（每个 Knot = 4 条内存访问的交叉）。
`maxCommunication` 是 Communication 的哈希集合（每个 = 2 条不同线程的内存访问配对）。

---

## 九、工具架构图

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     pair-collector 工具链                                │
├────────────────────┬──────────────────────┬──────────────────────────────┤
│   DDRD 数据        │   Conzzer 数据       │   SegFuzz 数据              │
│                    │                      │                              │
│ run-with-collector │ Fuzzer 原生输出      │ syz-manager 原生输出         │
│ → race_timeseries  │ → plot-curve         │ → workdir/log               │
│   .csv             │                      │                              │
│  (已有)            │ collect_conzzer_     │ collect_segfuzz_             │
│                    │   pairs.py 解析      │   pairs.py 解析              │
├────────────────────┴──────────────────────┴──────────────────────────────┤
│                   统一 CSV:                                              │
│  timestamp, elapsed_sec, elapsed_min, elapsed_hour,                      │
│  pair_count, varname_pair_count                                          │
├──────────────────────────────────────────────────────────────────────────┤
│                   plot_comparison.py                                      │
│            → 论文级双子图 (PNG/PDF/SVG)                                   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 十、常见问题

### Q1: 启动 Conzzer/SegFuzz 时需要做什么特殊配置吗?

**不需要。** 直接启动即可。`plot-curve` 和 `log` 是各工具原生自动输出的。

### Q2: Conzzer 的 `plot-curve` 文件找不到?

文件在 `exp/<mod>/fuzz/output/plot-curve`。如果不存在，说明 Fuzzer 尚未运行或启动失败：
```bash
cd /home/zzzccc/BASS/Conzzer && sudo ./scripts/run_experiment.sh status
find /home/zzzccc/BASS/Conzzer/exp -name 'plot-curve'
```

### Q3: 三个工具的 "Pair Count" 含义一样吗?

不完全一样，但都衡量"发现了多少种不同的并发交互"：
- **DDRD**: 基于内存地址级别的 race pair（同一地址、不同线程、至少一方写入）
- **Conzzer**: 基于函数调用栈级别的并发对（两线程同时处于的调用栈哈希配对）
- **SegFuzz**: 基于内存指令级别的 interleaving（两条指令的交叉执行 Knot）

建议论文中注明差异，重点对比增长趋势和收敛速度。

### Q4: 数据量级差异很大怎么办?

由于粒度不同，SegFuzz 的 `max_interleaving` 可达千万级，而 Conzzer 的 `total_travel` 通常在十万级。建议：
- 在论文中注明各工具的定义差异
- 也可修改 `plot_comparison.py` 使用 log scale y 轴

### Q5: 实验中某个工具崩溃了?

```bash
# Conzzer 重启 (plot-curve 会重新开始，备份旧数据)
cd /home/zzzccc/BASS/Conzzer
cp exp/dsp/fuzz/output/plot-curve exp/dsp/fuzz/output/plot-curve.bak
sudo ./scripts/run_experiment.sh stop dsp
sudo ./scripts/run_experiment.sh start dsp

# SegFuzz 重启 (corpus 从 workdir 自动恢复，log 会重开)
cd /home/zzzccc/BASS/segfuzz/exp/segfuzz-comparison
cp dsp/workdir/log dsp/workdir/log.bak
./run_comparison.sh stop dsp && ./run_comparison.sh start dsp
```

---

## 十一、文件清单

| 文件 | 说明 |
|------|------|
| `collect_conzzer_pairs.py` | Conzzer plot-curve 解析器 (post-hoc + live 模式) |
| `collect_segfuzz_pairs.py` | SegFuzz log/bench 解析器 (post-hoc + live 模式) |
| `plot_comparison.py` | 对比图绘制器 (论文级双子图) |
| `collect_pairs.sh` | 统一入口 wrapper (自动发现数据源、批量操作) |
| `README.md` | 本文档 |

---

## 十二、单模块实验 Checklist

针对单个模块的完整操作清单：

- [ ] 确认三个工具的内核、rootfs、corpus 已准备好
- [ ] 确认 SegFuzz 配置已生成 (`generate_configs.py`)
- [ ] **启动 DDRD**: `run-with-collector.sh` 或 `run_experiment.sh start <mod>`
- [ ] **启动 Conzzer**: `run_experiment.sh start <mod>` （无额外操作）
- [ ] **启动 SegFuzz**: `run_comparison.sh start <mod>` （无额外操作）
- [ ] [可选] 开启实时监控终端
- [ ] 等待 24 小时
- [ ] 停止所有工具
- [ ] 提取 Conzzer 数据: `collect_conzzer_pairs.py`
- [ ] 提取 SegFuzz 数据: `collect_segfuzz_pairs.py`
- [ ] 准备 DDRD 数据: 复制 `race_timeseries.csv`
- [ ] 生成对比图: `plot_comparison.py`
- [ ] 检查图表并归档
