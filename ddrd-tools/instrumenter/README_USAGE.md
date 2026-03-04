# Instrumenter 使用文档

## 概述
本工具提供了对LLVM IR文件进行多种插桩的功能，包括函数进入退出、共享变量访问、基本块和锁操作等。

## 编译
```bash
mkdir build && cd build
cmake ..
make
```

## 使用方法

### 基本语法
```bash
./instrumenter <input_file> [options]
```

### 命令行选项

- `-f, --functions`     启用函数进入退出插桩
- `-v, --variables`     启用共享变量访问插桩
- `-b, --basic-blocks`  启用基本块插桩
- `-l, --locks <file>`  启用锁插桩并指定锁配置文件
- `-t, --trylock <file>` 指定trylock配置文件
- `-a, --all`           启用所有插桩（需要锁文件）
- `-h, --help`          显示帮助信息

### 使用示例

1. 只启用函数和变量插桩：
```bash
./instrumenter input.ll -f -v
```

2. 启用锁插桩：
```bash
./instrumenter input.ll -l locks.txt -t trylocks.txt
```

3. 启用所有插桩：
```bash
./instrumenter input.ll -a -l locks.txt
```

4. 只启用基本块插桩：
```bash
./instrumenter input.ll -b
```

### 锁配置文件格式
锁配置文件应该包含锁函数对，每行格式为：
```
<require_function> <release_function> <lock_attribute>
```

例如：
```
pthread_mutex_lock pthread_mutex_unlock 0
pthread_rwlock_rdlock pthread_rwlock_unlock 1
pthread_rwlock_wrlock pthread_rwlock_unlock 2
```

其中lock_attribute的含义：
- 0: 普通锁
- 1: 读锁
- 2: 写锁

### 输出
插桩后的文件将保存为 `<input_filename>.instrumented.ll`

## 注意事项
- 输入文件必须是有效的LLVM IR文件(.ll格式)
- 如果启用锁插桩，必须提供有效的锁配置文件
- 插桩后的代码会经过验证，如果验证失败将报错并退出
