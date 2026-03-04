# DDRACE 运行时库链接指南

## 概述
`-fsanitize=ddrace` 不是标准的 GCC/Clang 选项，因此不会自动链接任何库。
如果您想实现自定义的数据竞争检测，需要：

1. 编译时：使用 LLVM pass 插入检测代码
2. 链接时：手动链接包含检测函数的运行时库

## 实现方式

### 方法1：使用编译器包装器
创建一个编译器包装器脚本：

```bash
#!/bin/bash
# ddrace-clang

DDRACE_LIB_PATH="/path/to/ddrace/lib"
DDRACE_RUNTIME_LIB="libddrace_runtime.a"

# 检查是否有 -fsanitize=ddrace 选项
if [[ "$*" == *"-fsanitize=ddrace"* ]]; then
    # 移除 -fsanitize=ddrace 选项（因为编译器不认识）
    args="${@//-fsanitize=ddrace/}"
    
    # 添加运行时库
    args="$args -L$DDRACE_LIB_PATH -lddrace_runtime"
    
    # 如果是链接阶段，添加更多库
    if [[ "$*" != *"-c"* ]]; then
        args="$args -lpthread -ldl"
    fi
    
    exec clang $args
else
    exec clang "$@"
fi
```

### 方法2：CMake 集成
在您的 CMakeLists.txt 中：

```cmake
# 检查是否启用 DDRACE
option(ENABLE_DDRACE "Enable data race detection" OFF)

if(ENABLE_DDRACE)
    # 设置编译选项（不使用 -fsanitize=ddrace）
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O1")
    
    # 链接运行时库
    target_link_libraries(your_target 
        PRIVATE 
        ddrace_runtime
        pthread
        dl
    )
    
    # 添加运行时库路径
    target_link_directories(your_target 
        PRIVATE 
        /path/to/ddrace/lib
    )
endif()
```

### 方法3：Makefile 集成
```makefile
# Makefile
DDRACE ?= 0

ifeq ($(DDRACE), 1)
    CXXFLAGS += -g -O1
    LDFLAGS += -L/path/to/ddrace/lib -lddrace_runtime -lpthread -ldl
endif

# 使用方式：
# make DDRACE=1
```

## 运行时库实现

您需要实现包含以下函数的运行时库：

```c
// ddrace_runtime.c
void kccwf_rec_mem_access(const volatile void *addr, 
                         unsigned long var_name, 
                         int is_write, 
                         int file_line, 
                         int size);

void rec_lock(char* func_name, int flag, int attribute, void* lock_addr);

void rec_func_enter_exit(char* func_name, int is_enter);

// ... 其他检测函数
```

编译运行时库：
```bash
gcc -c ddrace_runtime.c -o ddrace_runtime.o
ar rcs libddrace_runtime.a ddrace_runtime.o
```

## 完整工作流程

1. **插桩阶段**：
```bash
# 使用您的 instrumenter 对 LLVM IR 进行插桩
./instrumenter input.ll -a -l locks.txt
```

2. **编译阶段**：
```bash
# 编译插桩后的代码并链接运行时库
clang input.instrumented.ll -L/path/to/lib -lddrace_runtime -lpthread -o output
```

3. **运行阶段**：
```bash
# 运行时会调用您的检测函数
./output
```

## 注意事项

- 运行时库需要是线程安全的
- 检测函数应该尽量高效，避免过大的性能开销
- 考虑使用环境变量来控制检测行为
- 可以实现信号处理来输出检测报告
