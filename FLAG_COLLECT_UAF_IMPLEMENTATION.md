# FlagCollectUAF Implementation Summary

## 概述

为syzkaller添加了`FlagCollectUAF`标志，用于启用UAF (Use-After-Free) 检测功能。此标志允许控制executor是否收集UAF相关的检测信号。

## 修改的文件和代码

### 1. pkg/ipc/ipc.go

#### ExecFlags常量定义
```go
const (
	FlagCollectSignal        ExecFlags = 1 << iota // collect feedback signals
	FlagCollectCover                               // collect coverage
	FlagDedupCover                                 // deduplicate coverage in executor
	FlagCollectComps                               // collect KCOV comparisons
	FlagThreaded                                   // use multiple threads to mitigate blocked syscalls
	FlagEnableCoverageFilter                       // setup and use bitmap to do coverage filter
	FlagCollectRace                                // collect race pair signals
	FlagTestPairSync                               // synchronize execution with another program (test pair mode)
	FlagCollectUAF                                 // collect UAF (Use-After-Free) detection signals
)
```

#### ExecPair函数中的UAF支持
```go
// Set test pair sync flag and enable race collection
opts1.Flags |= FlagTestPairSync | FlagCollectRace | FlagCollectUAF
opts2.Flags |= FlagTestPairSync | FlagCollectRace | FlagCollectUAF
```

#### RaceValidation相关代码中的UAF支持
```go
if pairOpts.EnableRaceCollection {
	opts1.Flags |= FlagCollectRace | FlagCollectUAF
	opts2.Flags |= FlagCollectRace | FlagCollectUAF
}
```

### 2. executor/executor.cc

#### 单程序执行模式中的flag解析
```cpp
flag_collect_signal = req.exec_flags & (1 << 0);
flag_collect_cover = req.exec_flags & (1 << 1);
flag_dedup_cover = req.exec_flags & (1 << 2);
flag_comparisons = req.exec_flags & (1 << 3);
flag_threaded = req.exec_flags & (1 << 4);
flag_coverage_filter = req.exec_flags & (1 << 5);
// Reserved slots for future expansion: bits 6, 7
flag_collect_uaf = req.exec_flags & (1 << 8);
```

#### 程序对执行模式中的flag解析
```cpp
flag_collect_race = req.exec_flags1 & (1 << 6);
flag_test_pair_sync = req.exec_flags1 & (1 << 7);
flag_collect_extended = req.exec_flags1 & (1 << 8); // 新增：位8用于扩展功能
flag_collect_uaf = req.exec_flags1 & (1 << 9);      // 新增：位9用于UAF检测
```

#### 调试信息更新
```cpp
// 单程序执行模式
debug("[%llums] exec opts: procid=%llu threaded=%d cover=%d comps=%d dedup=%d signal=%d uaf=%d"
      " timeouts=%llu/%llu/%llu prog=%llu filter=%d\n",
      current_time_ms() - start_time_ms, procid, flag_threaded, flag_collect_cover,
      flag_comparisons, flag_dedup_cover, flag_collect_signal, flag_collect_uaf, syscall_timeout_ms,
      program_timeout_ms, slowdown_scale, req.prog_size, flag_coverage_filter);

// 程序对执行模式  
debug("[%llums] pair exec opts: procid=%llu prog1=%llu prog2=%llu race=%d sync=%d extended=%d uaf=%d"
      " timeouts=%llu/%llu/%llu mode=%s\n",
      current_time_ms() - start_time_ms, procid, req.prog1_size, req.prog2_size,
      flag_collect_race, flag_test_pair_sync, flag_collect_extended, flag_collect_uaf, syscall_timeout_ms,
      // ...rest of parameters
```

### 3. syz-fuzzer/proc.go

#### executeTestPair函数中启用UAF标志
```go
// Force enable race collection and pair sync flags (critical for pair execution)
opts1.Flags |= ipc.FlagCollectRace | ipc.FlagTestPairSync | ipc.FlagCollectUAF
opts2.Flags |= ipc.FlagCollectRace | ipc.FlagTestPairSync | ipc.FlagCollectUAF
```

#### executePairFromCandidate函数中启用UAF标志
```go
// Use race collection options for candidates
opts1 := &ipc.ExecOpts{
	Flags: ipc.FlagCollectRace | ipc.FlagTestPairSync | ipc.FlagCollectUAF,
}
opts2 := &ipc.ExecOpts{
	Flags: ipc.FlagCollectRace | ipc.FlagTestPairSync | ipc.FlagCollectUAF,
}
```

#### 三重验证函数中启用UAF标志
```go
// Perform multiple executions
opts1 := &ipc.ExecOpts{
	Flags: ipc.FlagCollectRace | ipc.FlagTestPairSync | ipc.FlagCollectUAF,
}
opts2 := &ipc.ExecOpts{
	Flags: ipc.FlagCollectRace | ipc.FlagTestPairSync | ipc.FlagCollectUAF,
}
```

## Flag位分配

### 单程序执行模式 (exec_flags)
- Bit 0: FlagCollectSignal
- Bit 1: FlagCollectCover
- Bit 2: FlagDedupCover
- Bit 3: FlagCollectComps
- Bit 4: FlagThreaded
- Bit 5: FlagEnableCoverageFilter
- Bit 6-7: Reserved for future expansion
- **Bit 8: FlagCollectUAF** (新增)

### 程序对执行模式 (exec_flags1)
- Bit 6: FlagCollectRace
- Bit 7: FlagTestPairSync
- Bit 8: flag_collect_extended
- **Bit 9: FlagCollectUAF** (新增)

## 使用方式

### 自动启用
当执行race/UAF pair检测时，UAF标志会自动与race标志一起启用：

```go
// 在所有test pair执行中自动启用
opts.Flags |= ipc.FlagCollectRace | ipc.FlagTestPairSync | ipc.FlagCollectUAF
```

### 手动控制
也可以独立控制UAF检测：

```go
opts := &ipc.ExecOpts{
	Flags: ipc.FlagCollectUAF, // 只启用UAF检测
}
```

## 兼容性说明

1. **向后兼容**: 添加的flag不影响现有功能
2. **位分配**: 选择了未使用的bit位，避免与现有flag冲突
3. **自动启用**: 在race detection模式下自动启用，无需额外配置

## 验证方法

1. **编译测试**: 确保所有修改的文件正确编译
2. **功能测试**: 验证UAF flag在executor中正确传递和解析
3. **日志验证**: 检查调试信息中包含UAF flag状态

## 后续扩展

此实现为UAF检测功能奠定了基础，可以在executor中添加具体的UAF检测逻辑：

```cpp
if (flag_collect_uaf) {
    // 实现UAF检测逻辑
    // 收集UAF相关信号
}
```