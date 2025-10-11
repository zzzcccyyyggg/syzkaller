# UAF 测试数据生成功能

## 概述

为了便于测试UAF验证流程的正确性，在executor中添加了测试数据生成功能。当真实的UAF检测没有发现任何UAF pairs时，系统会以30%的概率生成随机的测试UAF数据，用于验证整个UAF处理管道的正确性。

## 功能特性

### 1. 自动触发条件
- **触发时机**: 仅当真实UAF检测结果为0时才会尝试生成测试数据
- **生成概率**: 30%的概率生成测试数据，70%的概率不生成
- **生成数量**: 每次生成1-3个测试UAF pairs

### 2. 测试数据特性

#### 基本UAF信息
- **内存地址**: 随机生成现实的内存地址范围 (0x1000-0x2fff)
- **调用栈哈希**: 随机生成现实的调用栈哈希值 (0x400000-0x5fffff)
- **信号值**: 基于0x12345678的测试信号
- **时间差**: 1-100ms的随机时间差
- **系统调用**: 模拟常见的系统调用(mmap, brk等)
- **序列号**: 连续的序列号确保逻辑一致性
- **线程信息**: 1-4线程的随机分配
- **锁类型**: 无锁/互斥锁/读写锁的随机选择
- **访问类型**: 读/写的随机选择

#### 扩展UAF信息（当flag_collect_extended=true时）
- **历史记录数量**: 每个线程1-5条历史记录
- **目标时间**: 基于当前时间的纳秒级时间戳
- **路径距离**: 0.0-10.0的随机浮点距离值
- **访问历史**: 包含变量名、调用栈、时间戳、序列号和访问类型的完整记录

### 3. 实现函数

```cpp
static int generate_test_uaf_data(may_uaf_pair_t* uaf_pairs_out, 
                                  extended_uaf_pair_t* ext_uaf_pairs_out, 
                                  int max_pairs, bool generate_extended)
```

**参数说明:**
- `uaf_pairs_out`: 输出基本UAF pairs的缓冲区
- `ext_uaf_pairs_out`: 输出扩展UAF pairs的缓冲区
- `max_pairs`: 最大生成数量
- `generate_extended`: 是否生成扩展信息

**返回值:** 实际生成的UAF pairs数量

### 4. 集成方式

测试数据生成已无缝集成到`collect_and_output_uaf_data()`函数中：

```cpp
// 在真实UAF检测之后
if (uaf_count == 0) {
    // 尝试生成测试数据
    uaf_count = generate_test_uaf_data(...);
}
```

### 5. 调试信息

系统提供详细的调试日志来区分真实数据和测试数据：

- **真实模式**: `REAL MODE: Using X real UAF pairs from race detector`
- **测试模式**: `TEST MODE: Using X generated test UAF pairs`
- **详细日志**: 每个生成的UAF pair的详细信息

### 6. 数据格式兼容性

生成的测试数据完全兼容真实UAF数据的格式：
- 与`pkg/ddrd/types.go:MayUAFPair`结构体完全匹配
- 支持基本和扩展两种数据格式
- 输出格式与真实数据相同

## 使用场景

### 1. 管道测试
- 验证UAF数据从executor到fuzzer的传输正确性
- 测试UAF数据的序列化和反序列化
- 验证UAF validation系统的处理逻辑

### 2. 集成测试
- 在没有真实UAF的环境中测试整个工作流
- 验证阶梯式UAF验证系统的各个阶段
- 测试UAF统计信息的收集和报告

### 3. 调试支持
- 提供可预测的测试数据用于调试
- 帮助定位UAF处理管道中的问题
- 验证新功能的正确性

## 配置和控制

### 概率调整
可以通过修改代码中的概率值来调整测试数据生成的频率：
```cpp
// 30% probability to generate test data
if ((simple_rand() % 100) >= 30) {
    return 0;  // 修改30为其他值调整概率
}
```

### 数量控制
可以调整每次生成的UAF pairs数量：
```cpp
// Generate 1-3 test UAF pairs
int test_count = (simple_rand() % 3) + 1;  // 修改3和1来调整范围
```

### 数据特性
可以根据需要调整生成数据的特性，如：
- 内存地址范围
- 时间差范围
- 系统调用类型
- 线程数量等

## 性能影响

- **最小开销**: 仅在uaf_count=0时触发，对正常流程无影响
- **快速生成**: 使用简单的随机函数，生成速度很快
- **内存友好**: 复用现有的静态缓冲区，无额外内存分配

## 日志示例

```
[1234ms] No real UAF pairs detected, attempting to generate test data...
[1234ms] TEST: Generating 2 test UAF pairs for pipeline testing
[1234ms] TEST: Generated UAF pair 0: free_sn=10->use_sn=13, signal=0x12345a7b, time_diff=45230
[1234ms] TEST: Generated UAF pair 1: free_sn=15->use_sn=17, signal=0x12346c89, time_diff=78920
[1234ms] TEST: Successfully generated 2 test UAF pairs
[1234ms] TEST MODE: Using 2 generated test UAF pairs
```

这个测试功能为UAF验证系统提供了强大的测试能力，确保即使在没有真实UAF的情况下也能验证整个处理流程的正确性。