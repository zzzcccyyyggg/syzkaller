# syz-race-collector

独立的 Race Pair 收集工具，用于在运行任意程序时被动收集 race pair 信息，便于对比不同 fuzzer 或 benchmark 的数据竞争检测效果。

## 概述

`syz-race-collector` 是一个独立的守护进程，周期性地从内核 KCCWF 模块的 trace buffer 中采集数据并分析 race pair。它可以监控任意程序（如 iozone、原版 syzkaller、DDRD-syzkaller 等）运行时产生的数据竞争情况。

**核心特性：**
- 与原始 `executor/ddrd/` 分析逻辑完全一致
- 支持可配置的检测阈值
- 支持 CSV/JSON 格式输出
- 零侵入性，可监控任意程序

## 编译

```bash
cd tools/syz-race-collector
make
```

或者安装到 `bin/` 目录：

```bash
make install
```

## 使用方法

### 基本用法

```bash
# 启动收集器（后台运行）
sudo ./bin/syz-race-collector -o races.csv &

# 运行你要测试的程序
iozone -a -i 0 -i 1

# 停止收集器
kill %1
```

### 命令行选项

```
采样选项:
  -i, --interval <ms>       采样间隔（毫秒），默认 1000
  -d, --duration <sec>      运行时长（秒），0 表示一直运行直到 Ctrl+C，默认 0

检测阈值:
  --race-threshold <ns>     Race pair 时间阈值（纳秒），默认 4270000 (~4.27ms)
                            与原始 ddrd 的 TIME_THRESHOLD 一致

缓冲区设置:
  --trace-buffer <kb>       每个 CPU 的 trace buffer 大小（KB），默认 16384
  --max-records <n>         每次采样最大访问记录数，默认 65536
  --max-pairs <n>           每次采样最大 race pair 数，默认 8192

输出选项:
  -o, --output <file>       输出文件路径
  -f, --format <fmt>        输出格式: csv 或 json，默认 csv
  -v, --verbose             详细输出
  -q, --quiet               静默模式（只显示最终统计）
  --no-realtime             禁用实时输出

分析选项:
  --no-dedup                禁用 race signal 去重
  --include-locked          包含有公共锁保护的 pair（默认排除，与原始 ddrd 一致）

其他:
  -h, --help                显示帮助信息
```

## Race Pair 检测逻辑

本工具的 race pair 检测逻辑与原始 `executor/ddrd/access_context.c` 中的 `access_context_analyze_race_pairs()` 完全一致：

| 条件 | 说明 |
|------|------|
| 1. 不同线程 | `a->tid != b->tid` |
| 2. 至少一个写操作 | `a->access_type == 'W' \|\| b->access_type == 'W'` |
| 3. 地址重叠 | `access_record_addresses_overlap(a, b)` |
| 4. 时间阈值 | `time_diff <= 4270000ns` (默认，可配置) |
| 5. 有效性检查 | 两个访问之间无 Free 操作 |
| 6. 锁检查 | 跳过有公共锁保护的 pair（默认，可通过 `--include-locked` 包含） |

## 示例

### 1. 对比测试 DDRD-syzkaller 和原版 syzkaller

```bash
# 测试 DDRD-syzkaller (1小时)
sudo ./bin/syz-race-collector --duration=3600 -o ddrd_races.csv &
sudo ./bin/syz-manager --config=ddrd.cfg
wait

# 测试原版 syzkaller (1小时)
sudo ./bin/syz-race-collector --duration=3600 -o vanilla_races.csv &
sudo ./bin/syz-manager --config=vanilla.cfg
wait

# 对比结果
echo "DDRD 总唯一 race pairs:"
tail -1 ddrd_races.csv | cut -d',' -f8
echo "原版 总唯一 race pairs:"
tail -1 vanilla_races.csv | cut -d',' -f8
```

### 2. 监控 iozone 基准测试

```bash
sudo ./bin/syz-race-collector -v -o iozone_races.csv &
iozone -a -i 0 -i 1 -s 1G
kill %1
```

### 3. 自定义检测阈值

```bash
# 使用更严格的阈值（1ms）检测更紧密的竞争
sudo ./bin/syz-race-collector --race-threshold=1000000 -o strict_races.csv

# 使用更宽松的阈值（10ms）检测更多潜在竞争
sudo ./bin/syz-race-collector --race-threshold=10000000 -o relaxed_races.csv
```

### 4. 高频采样

```bash
# 每 100ms 采样一次，详细输出
sudo ./bin/syz-race-collector --interval=100 -v -o races.csv
```

### 5. JSON 格式输出

```bash
sudo ./bin/syz-race-collector -f json -o races.json --duration=60
```

## 输出格式

### CSV 格式

```csv
timestamp,elapsed_sec,iteration,access_count,free_count,race_pairs,unique_races_interval,total_unique_races
2025-12-21T21:30:00,0,1,1234,56,12,5,5
2025-12-21T21:30:01,1,2,2345,78,23,8,13
...
```

字段说明：
- `timestamp`: 采样时间戳
- `elapsed_sec`: 运行时间（秒）
- `iteration`: 采样迭代次数
- `access_count`: 本次采样的访问记录数
- `free_count`: 本次采样的 Free 操作数
- `race_pairs`: 本次采样检测到的 race pair 数
- `unique_races_interval`: 本次采样新发现的唯一 race 数
- `total_unique_races`: 累计唯一 race 总数

### JSON 格式

```json
{
  "config": {
    "interval_ms": 1000,
    "race_time_threshold_ns": 4270000,
    "skip_locked_pairs": true
  },
  "summary": {
    "duration_seconds": 3600,
    "sample_count": 3600,
    "total_accesses": 4567890,
    "total_race_pairs": 45678,
    "total_unique_races": 1234,
    "avg_races_per_second": 12.69
  },
  "samples": [...]
}
```

## 依赖

- **KCCWF 内核模块**：必须已加载（`/dev/kccwf_ctl_dev` 可用）
- **debugfs**：必须已挂载（`/sys/kernel/debug/tracing/trace` 可用）
- **root 权限**：访问 trace buffer 和 KCCWF 设备需要 root 权限

## 代码复用

本工具最大程度复用了 `executor/ddrd/` 目录下的代码：

| 文件 | 复用方式 | 说明 |
|------|----------|------|
| `types.h` | 直接包含 | 数据结构定义 |
| `access_record.c` | `#include` 内联 | AccessRecord 解析 |
| `lock.c` | `#include` 内联 | 锁状态判断 |
| `utils.c` | `#include` 内联 | 哈希等工具函数 |

核心的 race pair 分析逻辑完全复用 `access_context.c` 中的判断条件，仅增加了阈值可配置的特性。

## 注意事项

1. **采样间隔选择**：间隔过短（<100ms）可能导致 CPU 占用过高；间隔过长（>5s）可能导致 trace buffer 溢出
2. **trace buffer 大小**：根据系统负载调整，高负载时建议增大到 32768KB 或更多
3. **UAF 检测**：当前版本暂时禁用 UAF 检测，仅收集 race pair
