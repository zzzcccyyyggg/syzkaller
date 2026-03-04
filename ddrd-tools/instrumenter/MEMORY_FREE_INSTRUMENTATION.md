# 内存释放函数插桩使用说明

## 概述

新增了对 Linux 内核中常用内存释放函数的插桩支持，包括：
- `kfree`
- `kvfree` 
- `kmem_cache_free`

## 使用方法

### 1. 启用内存释放函数插桩

使用 `--free` 选项来启用内存释放函数的插桩：

```bash
./instrumenter input.ll --free
```

### 2. 与其他插桩选项组合使用

```bash
# 同时启用函数插桩和内存释放函数插桩
./instrumenter input.ll -f --free

# 启用所有插桩（包括内存释放函数）
./instrumenter input.ll -a -l locks.txt
```

### 3. 自定义插桩函数名

```bash
./instrumenter input.ll --free --free-name my_custom_free_func
```

## 插桩功能

### 插桩的函数调用
- `kfree(ptr)` - 释放由 `kmalloc` 等分配的内存
- `kvfree(ptr)` - 释放由 `kvmalloc` 等分配的内存 
- `kmem_cache_free(cache, ptr)` - 释放缓存对象

### 插桩代码
对于每个内存释放函数调用，会在调用前插入：
```c
void kccwf_rec_memory_free(uint64_t identifier);
```

其中 `identifier` 是基于以下信息生成的唯一标识符：
- 所在函数名
- 被调用的释放函数名
- 源代码行号（如果有调试信息）

## 实现文件

- **头文件**: `include/memory_free_instrument.hpp`
- **源文件**: `src/memory_free_instrument.cpp`
- **配置**: 在 `include/config.hpp` 中定义插桩函数名

## 示例

输入的 LLVM IR：
```llvm
define void @test_func() {
  %ptr = call i8* @kmalloc(i64 100, i32 208)
  call void @kfree(i8* %ptr)
  ret void
}
```

插桩后的 LLVM IR：
```llvm
define void @test_func() {
  %ptr = call i8* @kmalloc(i64 100, i32 208)
  call void @kccwf_rec_memory_free(i64 <unique_identifier>)
  call void @kfree(i8* %ptr)
  ret void
}
```

## 注意事项

1. 插桩函数 `kccwf_rec_memory_free` 需要在运行时环境中实现
2. 标识符的生成基于函数名和位置信息，确保在不同位置的相同释放函数调用有不同的标识符
3. 如果没有调试信息，行号将为0，但仍能生成唯一标识符
