# syz-kcsan-repro

全自动 KCSAN 数据竞争复现工具。

## 概述

将 DDRD 的 `validated_uaf.db` 自动转换为标准 KCSAN 数据竞争报告。

完整流程：
1. **解析 DB** → 提取 crash report、触发程序对、barrier 信息
2. **定位源码** → 通过 Analyzer (VarName hash) 或 addr2line 解析源代码行号
3. **生成 C 复现器** → 将 syz 程序对转换为 barrier 同步的 C 代码
4. **构建 KCSAN 内核** → 下载 vanilla 内核，启用 KCSAN（禁用 KASAN）
5. **运行检测** → QEMU 中启动 KCSAN 内核，执行 reproducer，扫描 dmesg
6. **收集报告** → 提取 KCSAN 报告和源码位置

## 快速开始

### 一键运行全流程

```bash
# 自动处理 btrfs 的 validated_uaf.db
./kcsan_reproduce.sh exp/btrfs/workdir/validate-run/validated_uaf.db

# 指定已有的 KCSAN 内核（跳过构建）
./kcsan_reproduce.sh exp/btrfs/workdir/validate-run/validated_uaf.db \
    --kcsan-kernel /path/to/kcsan/bzImage \
    --skip-build

# 只生成 reproducer，不运行检测
./kcsan_reproduce.sh exp/btrfs/workdir/validate-run/validated_uaf.db \
    --skip-build --skip-detect

# 启用 delay sweep 模式（尝试多个延迟值）
./kcsan_reproduce.sh exp/btrfs/workdir/validate-run/validated_uaf.db \
    --kcsan-kernel /path/to/kcsan/bzImage \
    --delay-sweep
```

### 分步执行

```bash
# Step 1: 解析数据库
python3 parse_validated_db.py <db_path> <output_dir>

# Step 2: 定位源码
python3 locate_source.py <record_dir> --vmlinux <vmlinux_path>

# Step 3: 生成复现器
python3 gen_reproducer.py <record_dir> --compile

# Step 4: 构建 KCSAN 内核
./build_kcsan_kernel.sh --kernel-version v6.17-rc5

# Step 5-6: 运行检测
./run_kcsan_detect.sh --kernel <bzImage> --record-dir <record_dir> --delay-sweep
```

## 文件结构

```
syz-kcsan-repro/
├── kcsan_reproduce.sh              # 主入口 - 全自动流程
├── parse_validated_db.py           # 解析 validated_uaf.db
├── locate_source.py                # 源码定位（Analyzer/addr2line）
├── gen_reproducer.py               # 生成独立 C 复现器 + barrier runner
├── build_kcsan_kernel.sh           # 构建 KCSAN 内核
├── run_kcsan_detect.sh             # QEMU 运行 + 检测
├── template/
│   ├── barrier_repro_template.c    # C 模板参考
│   └── barrier_runner.c            # Fork+exec barrier 同步器
└── README.md                       # 本文件
```

## 输出结构

```
kcsan_output/<target>/
├── parsed/
│   ├── summary.json                # 所有记录摘要
│   ├── record_0000_<key>/
│   │   ├── crash_report.txt        # DDRD crash report
│   │   ├── prog0.syz               # 触发程序 0
│   │   ├── prog1.syz               # 触发程序 1
│   │   ├── barrier_info.json       # Barrier 信息
│   │   ├── metadata.json           # VarName、调用栈等
│   │   ├── source_locations.json   # 源码位置
│   │   ├── prog0.c / prog1.c       # 独立 C 程序（syz-prog2c 生成）
│   │   ├── prog0_bin / prog1_bin   # 编译后的独立二进制
│   │   ├── barrier_runner           # Barrier 同步器二进制
│   │   ├── reproducer              # 运行入口脚本
│   │   ├── run_barrier.sh          # Shell 备用运行器
│   │   └── kcsan_results/          # KCSAN 检测结果
│   │       ├── dmesg_*.log
│   │       ├── kcsan_reports_*.txt
│   │       └── summary.json
│   └── ...
└── kernel/                          # KCSAN 内核输出
    ├── bzImage
    └── vmlinux
```

## 关键技术

### KCSAN 与 KASAN 互斥
KCSAN 内核配置中 `# CONFIG_KASAN is not set`，因为它们使用互斥的编译器插桩。
需要单独构建 KCSAN 内核。

### Barrier 复现器（独立二进制方案）
- syz-prog2c 生成复杂的自包含 C 程序（含 sandbox、信号处理、NONFAILING 宏等）
- 合并方案不可靠，因此采用独立二进制方案：
  1. 各程序独立编译为 `prog0_bin`、`prog1_bin`
  2. `barrier_runner` 使用 `fork()` + 共享内存 futex 同步两个子进程
  3. 子进程通过 `exec()` 执行各自的独立二进制
- 可通过 `delay_us` 参数微调时序偏移

### KCSAN 运行时调参
- `skip_watch=0`: 关闭采样跳过，每次访问都设置 watchpoint
- `udelay_task=200`: 增大检测窗口到 200μs
- 这些参数在 VM 内通过 sysfs 动态调整

### 源码定位双路径
1. **Analyzer 路径**: VarName hash → .instrumented.ll 搜索 → DILocation → file:line
2. **addr2line 路径**: function+offset → nm 查基址 → addr2line → file:line

## 依赖

- Python 3.6+
- QEMU (qemu-system-x86_64)
- GCC (用于编译 reproducer)
- Clang/LLVM (用于构建 KCSAN 内核)
- syz-db, syz-prog2c (在 bin/ 下)
- SSH (用于 QEMU 通信)
