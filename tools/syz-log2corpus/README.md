# syz-log2corpus - Crash Log to Corpus Converter

## 功能说明

`syz-log2corpus` 工具用于从 syzkaller crash log 文件中提取程序,并将其转换为 manager 可识别的 corpus 格式。

## 主要特性

- 自动识别并提取 log 中的所有程序
- 按执行顺序保持程序顺序
- 解析并验证程序语法
- 转换为标准的 corpus 数据库格式
- 自动去重(相同程序只保存一次)
- 同时生成文本格式的程序文件供查看

## 使用方法

### 基本用法

```bash
./syz-log2corpus -log <log_file> -output <output_dir>
```

### 完整参数

```bash
./syz-log2corpus \
    -log test/workdir-xfs-new/crashes/XXX/log0 \
    -output extracted-corpus \
    -target linux/amd64 \
    -v
```

### 参数说明

- `-log <file>`: 输入的 crash log 文件路径 **(必需)**
- `-output <dir>`: 输出的 corpus 目录路径 **(必需)**
- `-target <OS/arch>`: 目标系统和架构,默认为 `linux/amd64`
- `-v`: 显示详细输出

## 输出格式

工具会在输出目录中生成:

1. **corpus.db/**: LevelDB 格式的 corpus 数据库,可直接被 syz-manager 使用
2. **prog-NNN.txt**: 每个程序的文本文件(按序号命名),便于人工查看

## 工作流程

1. **提取程序**: 扫描 log 文件,识别 `executing program N:` 标记
2. **解析验证**: 使用 syzkaller 的 parser 解析每个程序
3. **去重检查**: 计算程序哈希,跳过重复的程序
4. **保存 corpus**: 将程序以标准格式存储到数据库
5. **生成文本**: 同时保存为文本文件供查看

## Log 文件格式要求

工具期望 log 文件包含以下格式的程序:

```
02:01:22 executing program 4:
fdatasync$kccwf(0xffffffffffffffff)
r0 = dup2$kccwf(0xffffffffffffffff, 0xffffffffffffffff)
pread64$kccwf(r0, &(0x7f0000000000)=""/228, 0xe4, 0x400)
...

02:01:22 executing program 5:
r0 = dup$kccwf(0xffffffffffffffff)
fdatasync$kccwf(r0)
...
```

## 使用示例

### 示例 1: 从单个 crash log 提取程序

```bash
# 提取程序
./syz-log2corpus \
    -log test/workdir-xfs-new/crashes/806e50c5e83e756764ae3fa8641e645b434f7776/log0 \
    -output extracted-corpus

# 输出:
# extracted 50 programs from log
# program 1: saved to corpus (sig=a1b2c3d4e5f6789, 30 calls)
# program 2: saved to corpus (sig=b2c3d4e5f67890a, 25 calls)
# ...
# successfully converted 48/50 programs to corpus
```

### 示例 2: 使用提取的 corpus

将提取的 corpus 合并到现有的 workdir:

```bash
# 复制 corpus.db 到 workdir
cp -r extracted-corpus/corpus.db workdir/corpus.db

# 或者使用 syz-db 工具合并
./bin/syz-db merge workdir/corpus.db extracted-corpus/corpus.db
```

### 示例 3: 查看提取的程序

```bash
# 查看所有提取的程序
ls -l extracted-corpus/prog-*.txt

# 查看特定程序
cat extracted-corpus/prog-001.txt
cat extracted-corpus/prog-010.txt
```

## 错误处理

- **解析失败**: 如果某个程序无法解析,工具会显示警告并继续处理其他程序
- **重复程序**: 相同的程序(相同哈希)只会保存一次
- **空程序**: 没有 syscall 的程序会被跳过

## 技术细节

### 程序识别

工具使用以下正则表达式识别程序:

- 程序头: `^(\d{2}:\d{2}:\d{2}\s+)?executing program (\d+):$`
- Syscall 行: `^(r\d+\s*=\s*)?[a-z_][a-z0-9_$]*\(`

### 数据格式

- **内部存储**: LevelDB key-value 数据库
- **Key**: 程序的 SHA1 哈希(十六进制字符串)
- **Value**: 程序的序列化字节数组

### 兼容性

生成的 corpus 格式与 syzkaller 标准 corpus 完全兼容,可以:
- 直接用于 syz-manager
- 与 syz-db 工具配合使用
- 被其他 syzkaller 工具读取

## 故障排除

### 问题: 没有提取到程序

**可能原因**:
- Log 文件格式不正确
- 程序被其他日志信息分隔

**解决方法**:
- 使用 `-v` 查看详细日志
- 检查 log 文件是否包含 "executing program" 行
- 确认 syscall 行格式正确

### 问题: 程序解析失败

**可能原因**:
- Syscall 定义不存在
- 语法错误

**解决方法**:
- 检查 `-target` 参数是否正确
- 查看 prog-NNN.txt 文件查看原始文本
- 使用 syz-prog2c 工具手动验证程序

## 相关工具

- `syz-db`: corpus 数据库管理工具
- `syz-prog2c`: 将程序转换为 C 代码
- `syz-mutate`: 程序变异工具
- `syz-upgrade`: corpus 格式升级工具
