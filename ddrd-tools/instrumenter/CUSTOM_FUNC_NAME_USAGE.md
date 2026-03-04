# 自定义插桩函数名使用说明

本功能允许您自定义所有插桩过程中使用的函数名，而不是使用默认名称。

## 支持的插桩函数类型

1. **内存访问记录函数** (默认: `kccwf_rec_mem_access`)
2. **函数进入记录函数** (默认: `kccwf_rec_func_enter`)  
3. **函数退出记录函数** (默认: `kccwf_rec_func_exit`)
4. **基本块记录函数** (默认: `kccwf_rec_bbs`)
5. **锁操作记录函数** (默认: `rec_lock`)

## 使用方法

### 1. 命令行方式

```bash
# 使用默认函数名
./instrumenter input.ll -v -f -b

# 自定义内存访问函数名
./instrumenter input.ll -v --func-name __ddrace_rec_mem_access

# 自定义函数进入/退出函数名
./instrumenter input.ll -f --enter-name my_func_enter --exit-name my_func_exit

# 自定义基本块函数名
./instrumenter input.ll -b --bb-name my_bb_recorder

# 自定义锁函数名
./instrumenter input.ll -l locks.txt --lock-name my_lock_recorder

# 同时自定义多个函数名
./instrumenter input.ll -v -f -b \
    --func-name __ddrace_rec_mem_access \
    --enter-name __ddrace_func_enter \
    --exit-name __ddrace_func_exit \
    --bb-name __ddrace_rec_bbs
```

### 2. 编程方式

```cpp
#include "record_shared_variable.hpp"

// 在调用相应插桩函数之前设置函数名
SetInstrumentationFuncName("__ddrace_rec_mem_access");
SetFuncEnterName("__ddrace_func_enter");
SetFuncExitName("__ddrace_func_exit");
SetBasicBlockName("__ddrace_rec_bbs");
SetLockFuncName("__ddrace_rec_lock");

// 然后进行插桩
RecordSharedVariableAccess(mod);
RecordFunctionEnterExit(mod);
RecordBBs(mod);
RecordLockPrimitive(mod, lockfile);
```

### 3. 编译时定义

在编译时通过宏定义设置默认函数名：

```bash
g++ -DINSTRUMENTATION_FUNC_NAME=\"__ddrace_rec_mem_access\" \
    -DFUNC_ENTER_NAME=\"__ddrace_func_enter\" \
    -DFUNC_EXIT_NAME=\"__ddrace_func_exit\" \
    -DBASIC_BLOCK_NAME=\"__ddrace_rec_bbs\" \
    -DLOCK_FUNC_NAME=\"__ddrace_rec_lock\" \
    ...
```

## 配置优先级

1. 命令行参数有最高优先级
2. 编程方式调用 `SetXxxName()` 函数
3. 编译时宏定义
4. 默认值

## 函数签名

无论使用什么函数名，您的记录函数都必须具有正确的签名：

### 1. 内存访问记录函数
```c
void your_mem_access_func(
    const volatile void *addr,     // 内存地址
    unsigned long var_name,        // 变量名哈希
    int is_write,                  // 是否为写操作 (0=读, 1=写)
    int file_line,                 // 文件行号信息
    int size                       // 访问大小（字节）
);
```

### 2. 函数进入记录函数
```c
void your_func_enter(
    unsigned long func_name,       // 函数名哈希
    int func_line                  // 函数行号
);
```

### 3. 函数退出记录函数
```c
void your_func_exit(
    unsigned long func_name,       // 函数名哈希
    int func_line                  // 函数行号
);
```

### 4. 基本块记录函数
```c
void your_bb_func(
    unsigned long block_hash       // 基本块哈希
);
```

### 5. 锁操作记录函数
```c
void your_lock_func(
    char* lock_name,               // 锁名称
    int lock_type,                 // 锁类型
    int operation,                 // 操作类型 (加锁/解锁)
    void* lock_addr                // 锁地址
);
```

## 完整示例

假设您想使用 DDRace 风格的函数名：

### 1. 实现运行时库函数

```c
// memory_access.c
void __ddrace_rec_mem_access(
    const volatile void *addr,
    unsigned long var_name,
    int is_write,
    int file_line,
    int size) 
{
    printf("Memory %s: addr=%p, hash=%lu, line=%d, size=%d\n",
           is_write ? "WRITE" : "READ", addr, var_name, file_line, size);
}

void __ddrace_func_enter(unsigned long func_name, int func_line) {
    printf("Function ENTER: hash=%lu, line=%d\n", func_name, func_line);
}

void __ddrace_func_exit(unsigned long func_name, int func_line) {
    printf("Function EXIT: hash=%lu, line=%d\n", func_name, func_line);
}

void __ddrace_rec_bbs(unsigned long block_hash) {
    printf("Basic Block: hash=%lu\n", block_hash);
}

void __ddrace_rec_lock(char* lock_name, int lock_type, int operation, void* lock_addr) {
    printf("Lock %s: name=%s, type=%d, addr=%p\n",
           operation ? "ACQUIRE" : "RELEASE", lock_name, lock_type, lock_addr);
}
```

### 2. 进行插桩

```bash
./instrumenter input.ll -v -f -b -l locks.txt \
    --func-name __ddrace_rec_mem_access \
    --enter-name __ddrace_func_enter \
    --exit-name __ddrace_func_exit \
    --bb-name __ddrace_rec_bbs \
    --lock-name __ddrace_rec_lock
```

### 3. 编译和链接

```bash
# 编译插桩后的代码
clang input.instrumented.ll -c -o input.o

# 编译运行时库
gcc -c memory_access.c -o memory_access.o

# 链接
gcc input.o memory_access.o -o final_program
```

## 注意事项

- 函数名必须是有效的C/C++标识符
- 确保运行时提供了相应名称的函数实现
- 函数签名必须严格匹配
- 设置的函数名会在插桩过程中输出确认信息
- 不同插桩类型可以独立设置函数名
- 如果只启用某些插桩类型，只需要提供对应的函数实现

## 故障排除

1. **链接错误**: 确保所有自定义函数都有实现
2. **符号未找到**: 检查函数名拼写是否正确
3. **段错误**: 检查函数签名是否匹配
4. **插桩不生效**: 确保在调用插桩函数之前设置了函数名
