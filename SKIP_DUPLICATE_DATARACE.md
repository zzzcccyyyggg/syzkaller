# Skip Duplicate Data Race Feature

## 概述

这个功能允许syzkaller跳过具有相同VarName组合的重复数据竞争报告，从而提高测试效率并减少不必要的测试中断。

## 背景

在内核fuzzing过程中，某些数据竞争可能是无害的但会重复出现，导致：
- 测试进程频繁暂停
- 大量重复的crash报告
- 降低整体测试效率

## 功能特性

### 1. VarName组合去重
- 跟踪已报告的VarName1和VarName2组合
- 对于相同组合的数据竞争，只报告第一次出现
- 后续相同组合的数据竞争会被静默跳过

### 2. 内存管理
- 自动限制缓存大小，防止内存无限增长
- 周期性清理旧的VarName组合
- 可配置的最大组合数量限制

### 3. 统计和监控
- 跟踪跳过的重复数据竞争数量
- 在日志中显示统计信息
- 详细的调试日志记录

## 配置选项

在manager配置文件的`experimental`部分添加以下选项：

```json
{
    "experimental": {
        "skip_duplicate_data_races": true,
        "max_data_race_combinations": 10000
    }
}
```

### 配置参数说明

- `skip_duplicate_data_races` (bool): 是否启用重复数据竞争跳过功能
  - `true`: 启用功能
  - `false` (默认): 禁用功能

- `max_data_race_combinations` (int): 最大缓存的VarName组合数量
  - 默认值: 10000
  - 当达到此限制时，会自动清理一半的旧组合

## 工作原理

### 1. 数据竞争检测
当检测到数据竞争时，系统会：
1. 提取VarName1和VarName2
2. 创建标准化的组合键 (确保顺序一致)
3. 检查该组合是否已存在于缓存中

### 2. 重复处理
- **首次出现**: 正常处理并保存报告
- **重复出现**: 跳过报告，更新统计计数

### 3. 内存管理
- 实时检查: 在每次检查时验证缓存大小
- 周期性清理: 每30分钟检查一次，清理75%满时的缓存
- 清理策略: 保留一半的组合，清除另一半

## 日志示例

### 启用功能时的日志输出
```
2024/09/14 10:30:15 VMs 4, executed 50000 (normal 30000, race 20000), cover 12500, signal 8500/15000, raceSignal 150/300, crashes 25, repro 2, triageQLen 10, skippedDataRaces 15
```

### 跳过重复数据竞争时的日志
```
2024/09/14 10:30:20 skipping duplicate data race: VarName1=11092649739372329985, VarName2=16137568736083084809, total_skipped=16
```

### 内存清理时的日志
```
2024/09/14 11:00:00 Periodic cleanup: reduced data race combinations from 7500 to 3750
```

## 性能影响

### 内存使用
- 每个VarName组合大约占用 50-100 字节
- 默认10000个组合约占用 0.5-1 MB内存
- 通过周期性清理防止无限增长

### CPU开销
- VarName提取和比较: 微秒级别
- HashMap查找: O(1)时间复杂度
- 整体性能影响可忽略不计

## 适用场景

### 推荐使用
- 长期运行的fuzzing任务
- 已知存在重复无害数据竞争的系统
- 需要最大化测试覆盖率的场景

### 不推荐使用
- 短期测试任务
- 需要收集所有数据竞争实例的调试场景
- 首次运行未知系统的测试

## 实现细节

### 文件修改
1. `pkg/mgrconfig/config.go`: 添加配置选项
2. `syz-manager/manager.go`: 主要逻辑实现
3. `syz-manager/stats.go`: 统计信息跟踪

### 关键函数
- `normalizeVarNameKey()`: VarName组合标准化
- `isNewDataRaceCombination()`: 重复检查逻辑
- `cleanupDataRaceCombinations()`: 内存管理

## 测试建议

1. **启用功能前**: 记录基线数据竞争频率
2. **启用功能后**: 观察skippedDataRaces统计
3. **调整参数**: 根据实际情况调整max_data_race_combinations
4. **监控内存**: 确认内存使用在合理范围内

## 故障排除

### 常见问题
1. **功能未生效**: 检查配置文件experimental部分
2. **内存增长**: 降低max_data_race_combinations值
3. **过度跳过**: 可能需要定期重启manager清空缓存

### 调试方法
- 查看日志中的skippedDataRaces计数
- 监控VarName组合的规律化程度
- 使用详细日志级别观察跳过行为