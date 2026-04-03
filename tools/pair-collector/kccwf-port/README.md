# KCCWF Pair Collection for Conzzer & SegFuzz

## 概述

本工具集用于在 Conzzer 和 SegFuzz 的内核中部署 KCCWF（Kernel Concurrent Code Watch Framework），
以便使用与 DDRD **完全相同的度量标准**（Race Pair Count）进行公平对比。

### 核心思想

三个工具各自有不同的竞态检测/覆盖机制：
- **DDRD**: KCCWF 框架 → 记录内存访问 → 检测 race pairs
- **Conzzer**: travel_matrix/control_matrix → 覆盖函数调用对
- **SegFuzz**: MemcovPass/KSSB → Store Buffer 模拟控制交错

为了公平对比，我们将 KCCWF 作为**统一的被动度量层**注入到所有工具的内核中，
使得 "Pair Count" 指标在三个工具间完全可比。

## 架构

```
┌──────────────────────────────────────────────────────────────┐
│                    DDRD / Conzzer / SegFuzz                   │
│                    (各自运行自己的 fuzzing)                    │
├──────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────┐         │
│  │            KCCWF (被动监控层)                     │         │
│  │  ┌──────────┐  ┌───────────┐  ┌──────────────┐ │         │
│  │  │ core.c   │  │ tracker.c │  │ race_pairs.c │ │         │
│  │  └──────────┘  └───────────┘  └──────────────┘ │         │
│  │                                                 │         │
│  │  kccwf_rec_mem_access() ──→ ftrace (trace_printk)│        │
│  └─────────────────────────────────────────────────┘         │
│                         ↓ ioctl + read                       │
│  ┌──────────────────────────────────────────────┐            │
│  │          syz-race-collector (VM 内)             │          │
│  │  /dev/kccwf_ctl_dev → LOG_MODE                │           │
│  │  read /sys/kernel/debug/tracing/trace         │           │
│  │  → signals.csv                                │           │
│  └──────────────────────────────────────────────┘            │
└──────────────────────────────────────────────────────────────┘
                         ↓ SCP
┌──────────────────────────────────────────────────────────────┐
│                      Host (收集端)                            │
│  dedup_races.py → race_timeseries.csv → plot                 │
└──────────────────────────────────────────────────────────────┘
```

## 两步流程

### Step 1: KCCWF 内核移植

将 KCCWF 框架源码 + LLVM 插桩注入目标工具的内核。

**涉及组件：**
| 组件 | 路径 | 作用 |
|------|------|------|
| 核心框架 | `kernel/kccwf/` (9 个 .c 文件) | race pair 检测、日志记录 |
| 控制设备 | `drivers/char/kccwf/ctl_dev.c` | `/dev/kccwf_ctl_dev` ioctl 控制 |
| 头文件 | `include/linux/kccwf.h` | 模式定义、API 声明 |
| task_struct 补丁 | `include/linux/sched.h` | 4 个字段 |
| LLVM 插桩器 | `instrumenter` 可执行文件 | 在 LLVM IR 级别插入 `kccwf_rec_mem_access()` 调用 |

**LLVM 插桩编译流水线：**

```
原始:  .c ──→ clang ──→ .o

DDRD:  .c ──→ .ll ──→ instrumenter ──→ .instrumented.ll ──→ .o
                        (adds kccwf_rec_mem_access calls)

Conzzer+KCCWF:
       .c ──→ .ll ──→ SDILP ──→ AFLCplusplusCompiler ──→ .ll
                                                          ↓
                                    instrumenter ──→ .instrumented.ll ──→ .o

SegFuzz+KCCWF:
       .c ──→ .ll ──→ instrumenter ──→ .instrumented.ll
                                        ↓
                           clang (-fpass-plugin=MemcovPass.so) ──→ .o
```

### Step 2: 外部采集控制

在内核具备 KCCWF 后，使用 `syz-race-collector` 工具：
1. 部署到 VM (SCP)
2. 通过 `/dev/kccwf_ctl_dev` ioctl 切换到 LOG_MODE
3. 读取 `/sys/kernel/debug/tracing/trace`
4. 解析 ftrace 记录为 AccessRecord
5. 检测 race pairs（时间阈值 + 地址重叠 + 锁分析）
6. 输出到 signals.csv

宿主机定期 SCP 回 signals.csv，运行 `dedup_races.py` 去重，
生成 `race_timeseries.csv` (timestamp, pair_count)。

## 工具清单

### 脚本说明

| 脚本 | 用途 |
|------|------|
| `port_kccwf.sh` | 将 KCCWF 源码移植到目标内核 |
| `kccwf_cc_wrapper.sh` | 通用 CC 包装器，添加 KCCWF 插桩 |
| `build_conzzer_kccwf_kernel.sh` | 构建 Conzzer + KCCWF 内核 |
| `build_segfuzz_kccwf_kernel.sh` | 构建 SegFuzz + KCCWF 内核 |
| `deploy_collector.sh` | 部署 syz-race-collector 到外部工具 VM |
| `run_pair_comparison.sh` | 完整对比实验自动化 |

### 路径依赖

```
前置条件:
  DDRD Kernel:         /home/zzzccc/Linux-Kernel/DDRD-Kernel
  DDRD instrumenter:   /home/zzzccc/BASS/DDRD/build/bin/instrumenter
  syz-race-collector:  /home/zzzccc/BASS/DDRD-syzkaller/tools/syz-race-collector/syz-race-collector
  
Conzzer:
  Kernel:              /home/zzzccc/Linux-Kernel/Conzzer-Kernel
  Compiler:            /home/zzzccc/BASS/Conzzer/conzzer-kernel-fuzzer-concurrency-fuzz/compiler/
  
SegFuzz:
  Kernel:              /home/zzzccc/BASS/segfuzz/kernels/linux-6.17-rc5
  MemcovPass:          /home/zzzccc/BASS/segfuzz/tools/MemcovPass/build/pass/libMemcovPass.so
```

## 快速开始

### 1. 确保前置工具已编译

```bash
# DDRD instrumenter
cd /home/zzzccc/BASS/DDRD
mkdir -p build && cd build
cmake .. && make -j$(nproc)
# 检查: ls build/bin/instrumenter

# syz-race-collector
cd /home/zzzccc/BASS/DDRD-syzkaller/tools/syz-race-collector
make
# 检查: ls syz-race-collector
```

### 2. 移植 KCCWF 到目标内核

```bash
cd /home/zzzccc/BASS/DDRD-syzkaller/tools/pair-collector/kccwf-port

# Conzzer 内核（可能已有 KCCWF，验证一下）
./port_kccwf.sh \
    --source /home/zzzccc/Linux-Kernel/DDRD-Kernel \
    --target /home/zzzccc/Linux-Kernel/Conzzer-Kernel \
    --verify-only

# SegFuzz 内核（需要完整移植）
./port_kccwf.sh \
    --source /home/zzzccc/Linux-Kernel/DDRD-Kernel \
    --target /home/zzzccc/BASS/segfuzz/kernels/linux-6.17-rc5
```

### 3. 构建带 KCCWF 的内核

```bash
# Conzzer
./build_conzzer_kccwf_kernel.sh --modules btrfs

# SegFuzz
./build_segfuzz_kccwf_kernel.sh --modules btrfs
```

### 4. 部署内核到 VM 并启动 fuzzing

```bash
# 将 bzImage 替换到各工具的 VM 配置中
# 启动 Conzzer / SegFuzz 的 fuzzing

# Conzzer: 修改 exp/btrfs/fuzz/config 中的 kernel 路径
# SegFuzz: 修改对应配置中的 kernel 路径
```

### 5. 收集 pair 数据

```bash
# 单独收集 Conzzer
./deploy_collector.sh \
    --tool conzzer \
    --vm-port 10022 \
    --ssh-key /path/to/key \
    --duration 3600

# 或者运行完整对比实验
./run_pair_comparison.sh \
    --ddrd-config /path/to/ddrd.cfg \
    --conzzer-port 10022 --conzzer-key /path/to/key \
    --segfuzz-port 10023 --segfuzz-key /path/to/key \
    --module btrfs \
    --duration 7200
```

### 6. 查看结果

```
experiments/pair-cmp-btrfs-20250101-120000/
├── ddrd/
│   └── race_timeseries.csv
├── conzzer/
│   └── race_timeseries.csv
├── segfuzz/
│   └── race_timeseries.csv
├── pair_comparison.png       # 对比图
├── pair_comparison.pdf
└── experiment_summary.txt    # 摘要
```

## 注意事项

1. **KCCWF 插桩会影响性能**：KCCWF 的 `kccwf_rec_mem_access()` 在每次内存访问时被调用，
   在 LOG_MODE 下会写 ftrace。这对所有工具的性能影响是**均匀的**，所以对比仍然公平。

2. **双重插桩兼容性**：
   - Conzzer + KCCWF: KCCWF instrumenter 在 Conzzer 的 SDILP + AFLCplusplusCompiler 之后运行，
     两者互不干扰
   - SegFuzz + KCCWF: KCCWF instrumenter 在 MemcovPass 之前运行（在 LLVM IR 级别），
     MemcovPass 随后替换 load/store。KCCWF 的函数调用不受 MemcovPass 影响

3. **KCCWF 排除自身**：`kernel/kccwf/` 和 `drivers/char/kccwf/` 不会被 KCCWF instrumenter 
   或工具自身的 pass 插桩，避免递归

4. **ftrace buffer 大小**：默认 16384 KB/CPU。如果 pair 数据丢失，可以增大：
   ```bash
   echo 65536 > /sys/kernel/debug/tracing/buffer_size_kb
   ```

5. **journal-head.h 依赖**：`kccwf.h` include 了 `linux/journal-head.h`。
   如果目标内核未启用 JBD2（如某些最小化配置），可能需要条件化此 include
