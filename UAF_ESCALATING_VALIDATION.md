# 阶梯式UAF验证系统实现文档

## 概述

本文档描述了在syzkaller中实现的阶梯式UAF (Use-After-Free) 验证系统。该系统采用"阶梯式上涨"的策略，通过多个递增的验证阶段来提高UAF检测的成功率和效率。

## 系统架构

### 核心组件

1. **UAFValidationConfig** - 验证配置结构
2. **UAFValidationStage** - 单个验证阶段定义
3. **DelayStrategy** - 延迟注入策略
4. **UAFValidationResult** - 验证结果记录
5. **DelayInjectionResult** - 延迟注入结果

### 关键文件

- `pkg/racevalidate/racevalidate.go` - 核心验证逻辑
- `tools/syz-race-validate/race_validate.go` - 命令行工具
- `pkg/ddrd/types.go` - UAF数据结构定义

## 阶梯式验证策略

### 三阶段递增方法

#### 阶段 1：基础验证
- **测试程序对数量**: 100
- **最大尝试次数**: 50
- **延迟策略**: 程序级延迟
- **最大延迟**: 10ms
- **目标**: 快速检测明显的UAF

#### 阶段 2：中等强度验证
- **测试程序对数量**: 1000
- **最大尝试次数**: 200
- **延迟策略**: 程序级 + 访问级延迟
- **最大延迟**: 50ms (程序级) + 1ms (访问级)
- **目标**: 检测需要更多测试的UAF

#### 阶段 3：高强度验证
- **测试程序对数量**: 10000
- **最大尝试次数**: 1000
- **延迟策略**: 增强的程序级 + 访问级延迟
- **最大延迟**: 100ms (程序级) + 5ms (访问级)
- **目标**: 检测难以复现的UAF

### 延迟注入策略

#### 程序级延迟 (Program-level)
- **作用范围**: 整个程序执行时序
- **计算方式**: 基于UAF的TimeDiff字段
- **应用概率**: 100% (每次都应用)
- **目标**: 调整程序间的执行时机差

#### 访问级延迟 (Access-level)
- **作用范围**: 特定内存访问点
- **计算方式**: 基于访问距离的反比函数 `1/(d+1)`
- **应用概率**: 可配置 (0.1-0.3)
- **目标**: 在关键访问点注入精确延迟

## 数据结构详解

### UAFValidationConfig
```go
type UAFValidationConfig struct {
    Stages           []UAFValidationStage // 验证阶段列表
    MaxTotalAttempts int                  // 总最大尝试次数
    GiveUpThreshold  int                  // 放弃阈值
    EnablePathAware  bool                 // 启用路径感知调度
    CollectHistory   bool                 // 收集历史数据
}
```

### UAFValidationStage
```go
type UAFValidationStage struct {
    TestPairCount   int             // 测试程序对数量
    MaxAttempts     int             // 该阶段最大尝试次数
    DelayStrategies []DelayStrategy // 延迟策略列表
}
```

### DelayStrategy
```go
type DelayStrategy struct {
    Type             string  // 延迟类型: "program_level" 或 "access_level"
    BaseProbability  float64 // 基础应用概率
    DistanceFunction string  // 距离计算函数
    MaxDelayMicros   int     // 最大延迟微秒数
    TargetAttempts   int     // 目标尝试次数
}
```

## 使用方法

### 1. 集成到现有验证流程

UAF验证已集成到`validateRace`函数中：

```go
// 在race validation之后自动执行UAF validation
if len(uafPairs) > 0 {
    uafResult := ctx.validateUAFWithEscalation(raceItem, uafPairs)
    result.UAFValidation = uafResult
}
```

### 2. 通过命令行工具使用

```bash
# 运行race validation，包含UAF validation
./syz-race-validate -corpus race_corpus.db -workdir ./workdir -v=2

# 查看验证统计信息（包含UAF统计）
./syz-race-validate -corpus race_corpus.db -workdir ./workdir -stats-only
```

### 3. 结果输出

验证结果包含详细的UAF统计信息：

```json
{
  "summary": {
    "uaf_validations": {
      "total_validated": 15,
      "confirmed": 8,
      "uaf_success_rate": 53.33,
      "avg_stages": 2.1,
      "avg_attempts": 250.5
    }
  }
}
```

## 算法特性

### 1. 渐进式强度增加
- 从轻量级验证开始，逐步增加测试强度
- 避免在简单案例上浪费计算资源
- 对复杂UAF提供充分的验证机会

### 2. 智能延迟注入
- **程序级**: 基于实际时间差调整程序启动时机
- **访问级**: 使用距离反比函数精确定位关键访问点
- **自适应**: 根据UAF特征动态调整延迟参数

### 3. 状态跟踪
- 记录每个阶段达到的系统状态
- 追踪延迟注入的效果
- 提供详细的调试信息

### 4. 路径感知调度
- 集成现有的路径距离感知调度算法
- 优化程序执行顺序以提高复现概率
- 基于历史数据进行智能调度

## 性能优化

### 1. 早期终止
- 一旦UAF被确认，立即停止后续验证
- 避免不必要的计算开销

### 2. 自适应阈值
- 根据UAF特征调整验证参数
- 动态优化延迟注入策略

### 3. 并行验证
- 支持多个验证实例并行运行
- 充分利用多核资源

## 扩展接口

### 1. 自定义延迟策略
```go
// 实现自定义延迟计算逻辑
func customDelayCalculation(uaf ddrd.MayUAFPair) int {
    // 自定义延迟计算
    return delayMicros
}
```

### 2. 插件化验证逻辑
```go
// 扩展验证判断逻辑
func customUAFDetection(injection DelayInjectionResult) bool {
    // 自定义UAF检测逻辑
    return isUAFDetected
}
```

## 监控和调试

### 1. 详细日志
- 支持多级别日志输出 (0-3)
- 记录每个验证阶段的详细信息
- 追踪延迟注入的具体效果

### 2. 统计信息
- 提供完整的验证统计数据
- 支持成功率分析
- 包含性能指标监控

### 3. 结果分析
- 生成详细的验证报告
- 支持JSON格式输出
- 便于后续分析和处理

## 最佳实践

### 1. 配置调优
- 根据系统资源调整最大尝试次数
- 基于UAF类型优化延迟策略
- 合理设置放弃阈值

### 2. 资源管理
- 监控内存和CPU使用情况
- 合理分配VM实例
- 避免过度并发导致的资源竞争

### 3. 结果解读
- 关注确认率和平均阶段数
- 分析延迟注入的有效性
- 识别需要进一步优化的场景

## 故障排除

### 1. 常见问题
- **UAF解析失败**: 检查UAF数据格式
- **延迟注入无效**: 验证延迟计算逻辑
- **验证超时**: 调整超时参数和重试策略

### 2. 调试技巧
- 使用高级别日志 (-v=3) 查看详细信息
- 检查UAF pair的字段完整性
- 验证程序解析是否正确

### 3. 性能问题
- 减少测试程序对数量
- 优化延迟策略参数
- 使用更高效的VM配置

这个阶梯式UAF验证系统为syzkaller提供了强大而灵活的UAF检测能力，通过智能的递增策略和精确的延迟注入，显著提高了UAF复现和验证的成功率。