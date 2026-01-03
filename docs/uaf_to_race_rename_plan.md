# UAF → Race 重命名计划

本文档记录将代码中的 "UAF" (Use-After-Free) 命名改为 "Race" 的完整计划。

## 背景

虽然代码中使用 "UAF" 命名，但实际检测的是 **数据竞争 (Data Race)**，而不仅仅是 Use-After-Free。为了更准确地反映功能，需要进行重命名。

## 重命名映射表

### 1. 目录重命名

| 原名 | 新名 |
|------|------|
| `pkg/uafvalidate` | `pkg/racevalidate` |
| `tools/syz-uaf-corpus` | `tools/syz-race-corpus` |

### 2. Go 源文件重命名

| 原文件 | 新文件 |
|--------|--------|
| `syz-manager/uaf_validate.go` | `syz-manager/race_validate.go` |
| `pkg/manager/uaf_store.go` | `pkg/manager/race_store.go` |
| `pkg/manager/uaf_store_test.go` | `pkg/manager/race_store_test.go` |
| `pkg/ddrd/uaf_signal.go` | `pkg/ddrd/race_signal.go` |
| `pkg/ddrd/uaf_cover.go` | `pkg/ddrd/race_cover.go` |
| `pkg/fuzzer/uaf.go` | `pkg/fuzzer/race.go` |

### 3. 配置字段重命名

| 原字段 | 新字段 | 文件 |
|--------|--------|------|
| `uaf_mode` | `race_mode` | `pkg/mgrconfig/config.go` |
| `uaf_validate` | `race_validate` | `pkg/mgrconfig/config.go` |
| `ModeUAF` | `ModeRace` | `pkg/mgrconfig/config.go` |
| `UAFValidate` | `RaceValidate` | `pkg/mgrconfig/config.go` |
| `UAFValidateConfig` | `RaceValidateConfig` | `pkg/mgrconfig/config.go` |

### 4. 数据库文件名

| 原名 | 新名 |
|------|------|
| `uaf-corpus.db` | `race-corpus.db` |
| `uaf-validated.db` | `race-validated.db` |
| `invalid_uaf.db` | `invalid_race.db` |
| `validated_uaf.db` | `validated_race.db` |

### 5. 类型/结构体重命名

| 原名 | 新名 | 文件 |
|------|------|------|
| `uafMode` | `raceMode` | `pkg/fuzzer/uaf.go` |
| `uafCorpus` | `raceCorpus` | `pkg/fuzzer/uaf.go` |
| `UAFCorpusEntry` | `RaceCorpusEntry` | `pkg/fuzzer/uaf.go` |
| `UAFCorpusStore` | `RaceCorpusStore` | `pkg/manager/uaf_store.go` |
| `UAFCorpusReplayPlan` | `RaceCorpusReplayPlan` | `pkg/fuzzer/uaf.go` |
| `UAFPairProfile` | `RacePairProfile` | `pkg/fuzzer/uaf.go` |
| `UAFSignal` | `RaceSignal` | `pkg/ddrd/uaf_signal.go` |
| `MayUAFPair` | `MayRacePair` | `pkg/ddrd/*.go` |

### 6. 函数重命名

| 原名 | 新名 |
|------|------|
| `newUAFMode` | `newRaceMode` |
| `newUAFCorpus` | `newRaceCorpus` |
| `newUAFPairProfile` | `newRacePairProfile` |
| `ActivateUAFMode` | `ActivateRaceMode` |
| `validatorExecutorFactory` | 保持不变 |
| `validatorExecutorFactoryWithSnapshot` | 保持不变 |

### 7. 变量/字段重命名

| 原名 | 新名 |
|------|------|
| `uaf` | `race` |
| `uafReady` | `raceReady` |
| `uafSeedKey` | `raceSeedKey` |
| `seedKindUAF` | `seedKindRace` |

### 8. 日志前缀

| 原前缀 | 新前缀 |
|--------|--------|
| `uaf:` | `race:` |
| `uafvalidate:` | `racevalidate:` |
| `uaf validation:` | `race validation:` |

### 9. 统计指标名

| 原名 | 新名 |
|------|------|
| `uaf corpus` | `race corpus` |
| `uaf coverage` | `race coverage` |
| `uaf pairs` | `race pairs` |

### 10. 命令行模式

| 原名 | 新名 |
|------|------|
| `uaf-validate` | `race-validate` |

### 11. 文档文件

| 原文件 | 新文件 |
|--------|--------|
| `docs/uaf_validate_mode.md` | `docs/race_validate_mode.md` |
| `docs/uaf_barrier_fuzzing.md` | `docs/race_barrier_fuzzing.md` |
| `docs/uaf_barrier_validation.md` | `docs/race_barrier_validation.md` |

## 保持不变的命名

以下命名与底层 DDRD 检测器相关，建议保持不变：

- `DdrdUafPairRaw` - FlatBuffers 生成的类型，修改需要重新生成
- `ddrd_uaf` - executor 中的标志位
- `ExecFlagDdrdUAF` - FlatBuffers 中定义的标志

## 执行顺序

1. **备份代码**: `git stash` 或创建分支
2. **重命名目录**: 先处理 `pkg/uafvalidate` 和 `tools/syz-uaf-corpus`
3. **重命名文件**: 使用 `git mv` 保留历史
4. **批量替换**: 使用 `sed` 或 IDE 的全局替换
5. **更新 import**: 修改所有 import 路径
6. **编译测试**: `make manager` 验证
7. **运行测试**: `make test` 确保无回归

## 影响范围估算

```bash
# 统计 "uaf" 出现次数
grep -ri "uaf" --include="*.go" | wc -l
# 约 800+ 行需要修改

# 统计 "UAF" 出现次数  
grep -r "UAF" --include="*.go" | wc -l
# 约 400+ 行需要修改
```

## 配置文件兼容性

为了向后兼容，可以在配置加载时支持新旧两种字段名：

```go
// 兼容性处理示例
if cfg.RaceMode == nil && cfg.UAFMode != nil {
    cfg.RaceMode = cfg.UAFMode // 使用旧字段
}
```

## 注意事项

1. **FlatBuffers 类型**: `DdrdUafPairRaw` 等类型定义在 `.fbs` 文件中，修改需要重新运行 `flatc` 生成代码
2. **数据库兼容性**: 旧的 `.db` 文件可能需要迁移或同时支持新旧文件名
3. **二进制工具**: `syz-uaf-corpus` 重命名后，用户脚本可能需要更新
4. **文档更新**: 所有相关文档需要同步更新

## 时间估算

- 自动化脚本批量替换: 1-2 小时
- 手动检查和修复: 2-3 小时
- 测试验证: 1-2 小时
- 总计: 约半天工作量
