# syz-uaf-validate - UAF Corpus Inspector and Validator

## 功能说明

`syz-uaf-validate` 工具提供两个主要功能：

### 1. 查看UAF Corpus详情 (新功能)

使用 `-show-details` 标志可以读取并显示 UAF corpus 数据库中所有 UAF pair 的详细信息，**不进行任何验证操作**。

#### 用法

```bash
# 基本用法 - 显示摘要信息
./bin/syz-uaf-validate -config=manager.cfg -show-details

# 详细输出 - 包含程序大小、信号等额外信息
./bin/syz-uaf-validate -config=manager.cfg -show-details -verbose
```

#### 输出信息

**摘要信息（默认）：**
- 总UAF pair数量
- 每个pair的：
  - Pair ID
  - 来源（Source fuzzer）
  - 首次发现时间
  - 最后更新时间
  - 发现次数
  - **UAF详情**（如果有UAFs数据）：
    - Free/Use VarName（变量名哈希值）
    - Free/Use CallStack（调用栈哈希值）
    - Signal（UAF信号）
    - TimeDiff（时间差，纳秒）
    - Free/Use Syscall信息（索引、编号、序列号）
    - Lock Type和Access Type

**详细信息（-verbose）：**
- 程序1和程序2的大小（字节）
- UAF signal大小
- UAFs数据大小
- 日志路径（如果有）
- 执行输出预览（前200字符）

#### 示例输出

```
========== UAF Corpus Summary ==========
Total UAF pairs: 15

========== UAF Pair #1 ==========
Pair ID: uaf_123abc456def
Source: fuzzer-01
First seen: 2025-10-11T10:30:45Z
Last updated: 2025-10-12T08:15:22Z
Discovery count: 3
UAF Details (2 pairs):
  [1] Free VarName: 0x00007f8a9c4d5000, Use VarName: 0x00007f8a9c4d5000
      Free CallStack: 0xa3b4c5d6e7f81234, Use CallStack: 0xb4c5d6e7f8123456
      Signal: 0x1234567890abcdef, TimeDiff: 125000 ns
      Free Syscall: idx=3 num=56 sn=10
      Use Syscall: idx=5 num=78 sn=15
      Lock Type: 0, Use Access Type: 1
  [2] Free VarName: 0x00007f8a9c4d6000, Use VarName: 0x00007f8a9c4d6000
      Free CallStack: 0xc5d6e7f812345678, Use CallStack: 0xd6e7f81234567890
      Signal: 0x234567890abcdef1, TimeDiff: 98000 ns
      Free Syscall: idx=7 num=90 sn=20
      Use Syscall: idx=9 num=112 sn=25
      Lock Type: 1, Use Access Type: 2

========== UAF Pair #2 ==========
...

========== Summary ==========
Displayed 15 UAF pairs
```

### 2. UAF验证 (开发中)

原有的UAF验证功能当前处于开发状态。

```bash
# 将来的用法
./bin/syz-uaf-validate -config=manager.cfg -attempts=3
```

## 命令行选项

### 通用选项
- `-config string` : 必需。manager配置文件路径（manager.cfg）
- `-help` : 显示帮助信息
- `-verbose` : 打印详细输出

### 查看模式选项
- `-show-details` : 只显示UAF pair详情，不进行验证

### 验证模式选项（开发中）
- `-count int` : VM数量（覆盖配置文件中的count参数）
- `-attempts int` : 每个UAF的验证尝试次数（默认：3）
- `-output string` : 验证结果输出文件（默认："uaf-validation-results.json"）
- `-path-aware` : 启用路径距离感知调度
- `-collect-history` : 收集并使用访问历史进行延迟注入

## 数据库格式

工具读取的是 LevelDB 格式的 UAF corpus数据库，默认位置在 `<workdir>/uaf-corpus.db`。

每条记录包含：
- Program 1 和 Program 2 的字节码
- UAF信号数据
- 执行输出
- 元数据（时间戳、来源、计数等）

## 实现细节

- 使用 `pkg/db` 包读取 LevelDB 数据库
- 使用 JSON 反序列化 UAF corpus 条目
- 零验证操作，只读模式
- 不需要VM或执行环境

## 典型工作流

1. **检查corpus内容**：
   ```bash
   ./bin/syz-uaf-validate -config=manager.cfg -show-details
   ```

2. **获取详细信息**：
   ```bash
   ./bin/syz-uaf-validate -config=manager.cfg -show-details -verbose
   ```

3. **验证UAF（开发中）**：
   ```bash
   # 未来功能
   ./bin/syz-uaf-validate -config=manager.cfg -attempts=5
   ```

## 错误处理

- 如果corpus数据库不存在，工具会报错并退出
- 如果某个条目无法解析，会记录警告并继续处理其他条目
- 使用 `-verbose` 标志可以看到所有警告信息
