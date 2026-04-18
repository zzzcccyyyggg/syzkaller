# DDRD Tools 使用指南

本文档介绍 DDRD-syzkaller 扩展中实现的各种工具和模式的使用方法。

## 目录

1. [运行模式概览](#运行模式概览)
2. [正常 Fuzzing 模式](#正常-fuzzing-模式)
3. [UAF Validate 模式](#uaf-validate-模式)
4. [配置选项详解](#配置选项详解)
5. [调试技巧](#调试技巧)
6. [相关工具](#相关工具)

---

## 运行模式概览

DDRD-syzkaller 支持多种运行模式：

| 模式 | 命令 | 用途 |
|------|------|------|
| 正常 Fuzzing | `syz-manager --config=xxx.cfg` | 发现 UAF/Race 候选 |
| UAF Validate | `syz-manager --config=xxx.cfg --mode uaf-validate` | 验证 UAF 候选 |
| Debug Validate | 同上 + `target_varname_pair` 配置 | 调试特定 pair |

---

## 正常 Fuzzing 模式

### 基本用法

```bash
sudo ./bin/syz-manager --config=./test/DDRD/your-config.cfg
```

### 关键配置

```json
{
    "experimental": {
        "barrier_mode": true,
        "barrier_procs": [0, 1],
        "uaf_mode": true,
        "uaf_validate": {
            "max_concurrent": 4,
            "delay_retry_budget": 2,
            "timeout_seconds": 120,
            "repeat_count": 3
        }
    }
}
```

### 配置说明

| 字段 | 说明 |
|------|------|
| `barrier_mode` | 启用 barrier 同步执行模式 |
| `barrier_procs` | 参与 barrier 的 proc 列表 |
| `uaf_mode` | 启用 UAF 检测 |
| `uaf_validate` | 验证阶段配置 |

### 输出文件

在 `workdir` 目录下会生成：
- `uaf-corpus.db`: UAF 候选语料库
- `validated_uaf.db`: Layer 1 - 验证成功的 pair (含报告)
- `invalid_uaf.db`: Layer 1 - 验证失败的 pair
- `varname_backoff_stats.db`: Layer 2 - VarName validation backoff 统计（兼容旧文件名 `varname_hb_stats.db`）

---

## UAF Validate 模式

### 基本用法

```bash
sudo ./bin/syz-manager --config=./test/DDRD/your-config.cfg --mode uaf-validate
```

### 添加 `--debug` 获取详细日志

```bash
sudo ./bin/syz-manager --config=./test/DDRD/your-config.cfg --mode uaf-validate --debug
```

### 重定向日志到文件

```bash
sudo ./bin/syz-manager --config=./test/DDRD/your-config.cfg --mode uaf-validate --debug > validate.log 2>&1
```

### 验证流程

1. **Discovery 阶段**: 
   - 从 `uaf-corpus.db` 加载条目
   - 执行多次找出 stable pairs
   - 使用原始程序（不拆分）

2. **Verification 阶段**:
   - 对每个 stable pair 进行验证
   - 程序拆分：2 个程序 → 4 个程序（每个程序复制一份并标记 async）
   - 使用计算的 delay（StartDelay/AccessDelay）

### 验证结果

- **Stable**: 触发次数 ≥ 2
- **Not Stable**: 触发次数 = 1
- **Not Triggerable**: 触发次数 = 0

---

## 配置选项详解

### uaf_validate 完整配置

```json
{
    "uaf_validate": {
        "max_concurrent": 4,
        "delay_retry_budget": 2,
        "timeout_seconds": 120,
        "repeat_count": 3,
        "target_varname_pair": ""
    }
}
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `max_concurrent` | int | 1 | 最大并发验证数（自动限制为 VM 数量） |
| `delay_retry_budget` | int | 1 | 每次重复的最大重试次数 |
| `timeout_seconds` | int | 90 | 执行超时（秒） |
| `repeat_count` | int | 1 | 每个条目的重复次数 |
| `target_varname_pair` | string | "" | 调试模式：只验证特定 VarName pair |

### Delay 策略

验证阶段使用两种 delay：

1. **StartDelayUs**: `min(original_timediff, runtime_timediff)`
   - 用于 barrier 启动延迟（executor 中的 nanosleep）

2. **AccessDelayUs**: `max(original_timediff, runtime_timediff)`
   - 用于内核 UAF 访问延迟（KCCWF 的 udelay）

---

## 调试技巧

### 1. 调试特定 VarName Pair

在配置中添加 `target_varname_pair`：

```json
{
    "uaf_validate": {
        "target_varname_pair": "90e7773e58a631dc-8872744104a515c2"
    }
}
```

效果：
- 只验证包含该 VarName pair 的条目
- 跳过所有 skip 逻辑（invalid/validated/HB）
- 不更新数据库（只打印日志）

### 2. 查看 Pair 信息

VarName pair 格式：`freeAccessName-useAccessName`（16位 hex）

在日志中搜索：
```bash
grep "vnkey=" validate.log
```

### 3. 查看拆分结果

```bash
grep "duplicated with async\|split result" validate.log
```

### 4. 查看验证结果

```bash
grep "verification run finished\|triggered=" validate.log
```

### 5. 常见日志模式

```
# Discovery 阶段
uafvalidate: task start key=xxx attempt=1 repeat=1/3

# Verification 阶段开始
uafvalidate: starting verification phase (with delays)

# 程序拆分
uafvalidate: prog[0] duplicated with async: 15 calls
uafvalidate: verification split result: 2 original -> 4 total

# 验证结果
uafvalidate: verification run finished duration=2m triggered=0/10 status=Not Triggerable
uafvalidate: pair validated after 3 attempt(s)
```

---

## 相关工具

### syz-uaf-corpus

UAF 语料库数据库查看和导出工具。

#### 编译

```bash
make
# 或单独编译
go build -o bin/syz-uaf-corpus ./tools/syz-uaf-corpus
```

#### 基本用法

```bash
# 使用配置文件（推荐）
./bin/syz-uaf-corpus -config=./test/DDRD/your-config.cfg

# 使用 workdir
./bin/syz-uaf-corpus -workdir=/path/to/workdir

# 直接指定数据库文件
./bin/syz-uaf-corpus -db=/path/to/uaf-corpus.db
```

#### 常用选项

```bash
# 只显示统计摘要
./bin/syz-uaf-corpus -config=xxx.cfg -summary

# 查看特定 key 的条目
./bin/syz-uaf-corpus -config=xxx.cfg -key=abc123

# 限制显示条目数
./bin/syz-uaf-corpus -config=xxx.cfg -limit=10

# 按时间排序（最新的在前）
./bin/syz-uaf-corpus -config=xxx.cfg -sort-time

# 导出为 JSON
./bin/syz-uaf-corpus -config=xxx.cfg -json > corpus.json

# 不显示程序内容
./bin/syz-uaf-corpus -config=xxx.cfg -programs=false

# 不显示 pair 详情
./bin/syz-uaf-corpus -config=xxx.cfg -pairs=false
```

#### 命令行参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `-config` | string | "" | syzkaller 配置文件路径 |
| `-workdir` | string | "" | workdir 路径 |
| `-db` | string | "" | 直接指定数据库文件路径 |
| `-key` | string | "" | 只显示包含此 key 的条目 |
| `-summary` | bool | false | 只显示统计摘要 |
| `-programs` | bool | true | 显示程序源码 |
| `-pairs` | bool | true | 显示 UAF pair 详情 |
| `-json` | bool | false | 以 JSON 格式输出 |
| `-limit` | int | 0 | 限制显示条目数（0=全部） |
| `-sort-time` | bool | false | 按时间排序 |

#### 输出示例

**摘要模式 (`-summary`)**:
```
UAF Corpus Database: /path/to/uaf-corpus.db
================================================================================

Total entries: 42

Time range:
  Earliest: 2025-12-20T10:30:00Z
  Latest:   2025-12-21T15:45:00Z
  Duration: 29h15m0s

Statistics:
  Total UAF pairs: 128
  Total programs:  84
  With barrier:    42 (100.0%)
  With replay:     38 (90.5%)

Barrier group sizes:
  Size 2: 42 entries

Use access types:
  read: 35
  write: 93
```

**详细模式**:
```
Entry 1/42
--------------------------------------------------------------------------------
Key:       263c648a4352d468-d663a55c2a3be644-94984b800211fb24-4f7d79bf84da2859
Seq:       1
Timestamp: 2025-12-20T10:30:00Z
CallIdx:   5

Barrier:
  Participants: 0x3
  GroupID:      1
  GroupSize:    2
  ProcList:     [0 1]

Replay Plan:
  Delays (us): [0 1500]

Main UAF Pair:
  FreeAccessName: 0x263c648a4352d468
  UseAccessName:  0xd663a55c2a3be644
  FreeCallStack:  0x94984b800211fb24
  UseCallStack:   0x4f7d79bf84da2859
  Signal:         0x0000000000000000
  TimeDiff:       1500000 ns (1.500 ms)
  FreeSN:         1
  UseSN:          2
  UseAccessType:  write (1)
  LockType:       none (0)

Main Program:
  r0 = openat$ptmx(...)
  ioctl$TCGETS(r0, ...)
  write(r0, ...)
  close(r0)
```

---

### 数据库文件说明

| 文件 | 用途 | 工具 |
|------|------|------|
| `uaf-corpus.db` | UAF 候选语料库 | `syz-uaf-corpus` |
| `validated_uaf.db` | Layer 1 - 验证成功的精确 pair (含报告) | `syz-validatedb` |
| `invalid_uaf.db` | Layer 1 - 验证失败的精确 pair | `syz-db` |
| `varname_backoff_stats.db` | Layer 2 - VarName 级别的 validation backoff 统计 (含 Verified 标记，兼容旧文件名 `varname_hb_stats.db`) | `syz-db` |

### 清理数据库重新验证

```bash
# 清理验证状态，重新验证所有条目
rm workdir/invalid_uaf.db workdir/varname_backoff_stats.db workdir/varname_hb_stats.db

# 然后重新运行 validate
sudo ./bin/syz-manager --config=xxx.cfg --mode uaf-validate
```

### 查看通用数据库

使用 `syz-db` 工具：

```bash
# 查看数据库内容
./bin/syz-db dump /path/to/database.db

# 查看数据库统计
./bin/syz-db stats /path/to/database.db
```

---

## 架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                         syz-manager                              │
│                                                                  │
│  ┌──────────────┐    ┌──────────────────────────────────────┐   │
│  │ UAF Corpus   │───▶│         StageManager                  │   │
│  │   Store      │    │                                       │   │
│  └──────────────┘    │  ┌─────────────┐  ┌──────────────┐   │   │
│                      │  │  Discovery  │  │ Verification │   │   │
│                      │  │   Phase     │──▶│    Phase     │   │   │
│                      │  └─────────────┘  └──────────────┘   │   │
│                      └──────────────────────────────────────┘   │
│                                 │                                │
│                                 ▼                                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    ExecutorAdapter                        │   │
│  │                                                           │   │
│  │  ┌────────────┐    ┌─────────────────────────────────┐   │   │
│  │  │ runSingle  │    │          runBarrier             │   │   │
│  │  └────────────┘    │                                  │   │   │
│  │                    │  Discovery: barrierPrograms()    │   │   │
│  │                    │  Verify: barrierProgramsForVerify()│  │   │
│  │                    │          (2 prog → 4 prog)       │   │   │
│  │                    └─────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                 │                                │
│                                 ▼                                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                      VM Pool                              │   │
│  │    ┌────┐  ┌────┐  ┌────┐  ┌────┐                        │   │
│  │    │VM 0│  │VM 1│  │VM 2│  │VM 3│                        │   │
│  │    └────┘  └────┘  └────┘  └────┘                        │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 相关文档

- [uaf_validate_mode.md](uaf_validate_mode.md) - UAF 验证模式详细设计
- [uaf_barrier_fuzzing.md](uaf_barrier_fuzzing.md) - Barrier Fuzzing 设计
- [uaf_barrier_validation.md](uaf_barrier_validation.md) - Barrier 验证设计
- [barrier_dispatch_flow.md](barrier_dispatch_flow.md) - Barrier 调度流程
- [ddrd_executor_flow.md](ddrd_executor_flow.md) - DDRD Executor 流程
