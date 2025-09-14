# Syzkaller 增强功能使用指南

本指南介绍了两个新增的实验性功能，用于提高syzkaller的测试效率。

## 功能概述

### 1. 跳过重复数据竞争 (Skip Duplicate Data Races)

**问题**：相同的数据竞争VarName组合会重复报告，导致VM频繁重启，降低测试效率。

**解决方案**：自动跟踪已报告的VarName组合，跳过重复的数据竞争报告。

### 2. 忽略SYZFATAL崩溃 (Ignore SYZFATAL Crashes)

**问题**：SYZFATAL错误会导致VM重启，但这些错误通常是无害的。

**解决方案**：配置VM忽略SYZFATAL错误，继续执行而不重启。

## 配置选项

### 数据竞争相关配置

在配置文件的 `experimental` 部分添加：

```json
{
  "experimental": {
    "skip_duplicate_data_races": true,
    "max_data_race_combinations": 10000
  }
}
```

**配置说明**：
- `skip_duplicate_data_races` (bool): 是否跳过重复的数据竞争报告
  - `true`: 启用功能
  - `false` (默认): 禁用功能

- `max_data_race_combinations` (int): VarName组合缓存的最大数量
  - 默认值: 10000
  - 当达到此限制时，会清理一半的缓存以防止内存无限增长

### SYZFATAL相关配置

```json
{
  "experimental": {
    "ignore_syz_fatal": true
  }
}
```

**配置说明**：
- `ignore_syz_fatal` (bool): 是否忽略SYZFATAL错误
  - `true`: 忽略SYZFATAL错误，VM继续执行
  - `false` (默认): 正常处理SYZFATAL错误

## 使用步骤

### 1. 编译syzkaller

```bash
cd /path/to/syzkaller
make all
```

### 2. 修改配置文件

根据需要添加相应的experimental配置选项到您的配置文件中。

### 3. 启动syzkaller

```bash
./bin/syz-manager -config=/path/to/your/config.json
```

### 4. 监控效果

查看日志输出中的统计信息：

```
VMs 2, executed 12003 (normal 12003, race 0), cover 20345, signal 29070/31007, raceSignal 0/0, crashes 1, repro 0, triageQLen 0, skippedDataRaces 5
```

- `skippedDataRaces`: 显示跳过的重复数据竞争数量

## 日志输出说明

### 数据竞争跳过日志

当跳过重复数据竞争时，会看到如下日志：

```
2025/09/14 03:23:10 skipping duplicate data race: VarName1=1320040775806694287, VarName2=2870364362311847012, total_skipped=1
```

### SYZFATAL忽略

启用ignore_syz_fatal后，SYZFATAL错误将不会在日志中显示为crash，VM也不会重启。

## 性能影响

### 数据竞争跳过功能

**优势**：
- 减少VM重启次数
- 提高测试覆盖率
- 节省测试时间

**开销**：
- 内存使用增加（存储VarName组合）
- 少量CPU开销（组合查找和比较）

### SYZFATAL忽略功能

**优势**：
- 消除因SYZFATAL导致的VM重启
- 提高测试连续性

**风险**：
- 可能忽略某些重要的错误（需要根据测试目标评估）

## 故障排除

### 功能未生效

1. 检查配置文件中experimental部分是否正确
2. 检查syzkaller是否使用了正确的配置文件
3. 查看启动日志确认配置被正确加载

### 内存使用过高

如果数据竞争组合缓存占用过多内存：
1. 降低 `max_data_race_combinations` 值
2. 监控日志中的缓存清理消息

### 调试模式

可以通过增加日志级别来查看更详细的调试信息：

```bash
./bin/syz-manager -config=/path/to/config.json -debug
```

## 注意事项

1. 这些功能是实验性的，可能在未来版本中发生变化
2. 建议在生产环境使用前进行充分测试
3. 数据竞争跳过功能只影响相同VarName组合的重复报告，新的VarName组合仍会被报告
4. SYZFATAL忽略功能会完全跳过这类错误，请确保这符合您的测试需求

## 示例配置文件

参考提供的示例配置文件：
- `example_config_skip_datarace.json`: 仅启用数据竞争跳过
- `example_config_ignore_syzfatal.json`: 仅启用SYZFATAL忽略  
- `example_config_combined.json`: 同时启用两个功能