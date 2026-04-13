# DDRD Tools — 插桩工具链

DDRD (Data-race Detection & Reproduction for Drivers) 的编译时插桩工具链。
负责在内核编译过程中自动对目标模块进行 LLVM IR 级别的插桩，支持函数、变量访问、锁操作和内存释放的记录。

## 目录结构

```
ddrd-tools/
├── compiler/                        # 编译器包装器
│   ├── clang-wrapper.sh             # ★ 顶层入口: 替代 clang 的内核编译包装器
│   ├── kernel-compiler.cpp          # kernel_compiler 源码
│   ├── kernel_compiler              # [编译产物] 内核插桩编译器
│   ├── instrumentation_targets.conf # 插桩目标配置 (由 build_kernel.sh 动态写入)
│   ├── userspace-compiler.cpp       # ddrace-cc/cxx 用户态编译器源码
│   ├── ddrace-cc                    # [编译产物] 用户态 C 编译器
│   ├── ddrace-cxx                   # [编译产物] 用户态 C++ 编译器
│   ├── user-clang-wrapper.sh        # 用户态 wrapper (ddrace-cc.sh → 此脚本)
│   └── Makefile                     # 原始 Makefile (仅用于 ddrace-cc/cxx)
├── instrumenter/                    # LLVM IR 插桩 pass
│   ├── CMakeLists.txt               # CMake 构建配置 (需要 LLVM 18)
│   ├── src/                         # 插桩器源码
│   ├── include/                     # 头文件
│   ├── LockFunc.txt                 # 锁函数列表
│   └── examples/                    # 使用示例
├── Script/                          # 辅助脚本 (旧版, 参考用)
│   ├── module_instrument_build.sh   # 模块化构建 (功能已并入 build_kernel.sh)
│   ├── create-image.sh              # 创建磁盘镜像
│   └── ...
├── build/                           # [.gitignore] cmake 构建输出
│   └── bin/instrumenter             # [编译产物] LLVM IR 插桩器
├── report-analyzer/                 # VarName/hash → IR/源码位置 反查工具
│   ├── CMakeLists.txt               # CMake 构建配置
│   └── main.cpp                     # 分析器实现
└── .gitignore
```

## 快速开始

### 编译工具链

```bash
# 编译全部 (kernel_compiler + ddrace-cc/cxx + instrumenter)
./scripts/build_ddrd_tools.sh

# 或使用 Makefile
make build-tools

# 仅编译内核相关
./scripts/build_ddrd_tools.sh compiler

# 仅编译 instrumenter (需要 LLVM 18)
./scripts/build_ddrd_tools.sh instrumenter

# 仅编译 report-analyzer
./scripts/build_ddrd_tools.sh analyzer

# 检查工具链状态
./scripts/build_ddrd_tools.sh check

# 清理
./scripts/build_ddrd_tools.sh clean
```

### 依赖

| 依赖 | 用途 | 版本要求 |
|------|------|----------|
| g++ | 编译 kernel_compiler, ddrace-cc | C++14 |
| LLVM | instrumenter / report-analyzer 的链接库 | 18.x |
| CMake | 构建 instrumenter / report-analyzer | ≥ 3.5 |
| clang-18 | 内核编译 (被 wrapper 调用) | 18.x |

## 工作原理

### 内核编译插桩流程

```
make CC=clang-wrapper.sh ...
         │
         ▼
  clang-wrapper.sh
  ├── 检查 instrumentation_targets.conf
  ├── 源文件路径 匹配目标? ──否──→ clang-18 原样编译
  │                 │
  │                 是
  │                 ▼
  └──→ kernel_compiler
       ├── .c  → clang -S -emit-llvm → .ll (LLVM IR)
       ├── .ll → instrumenter 插桩     → .instrumented.ll
       └── .instrumented.ll → clang   → .o (目标文件)
```

### 组件详解

#### 1. `clang-wrapper.sh`

替代 `clang` 的顶层包装器。根据源文件路径决定是否需要插桩：

- 读取 `instrumentation_targets.conf` 中的路径模式
- 匹配的文件交给 `kernel_compiler` 走插桩流程
- 不匹配的文件直接调用 `clang-18` 编译
- 排除 `drivers/firmware/efi/libstub/` 和 `kernel/kccwf/` 等路径

**环境变量:**
- `CLANG` — 底层 clang 路径 (默认: `clang-18`)
- `CLANG_WRAPPER` — kernel_compiler 路径 (默认: 同目录下)
- `DDRD_INSTRUMENT_LIST` — 插桩目标配置文件路径

#### 2. `kernel_compiler` (kernel-compiler.cpp)

内核编译时的实际插桩处理器：

1. 将 `.c` 编译为 LLVM IR (`.ll`)，使用 `-Og` 优化级别
2. 调用 `instrumenter` 对 IR 进行插桩
3. 将插桩后的 IR 编译为目标文件 (`.o`)

**环境变量:**
- `DDRD_INSTRUMENTER` — instrumenter 二进制路径
- `DDRD_TOOLCHAIN` — 工具链根目录 (用于推断其他路径)

#### 3. `instrumenter` (LLVM Pass)

基于 LLVM 的 IR 级别插桩工具，对内核代码注入运行时跟踪点：

```bash
instrumenter input.ll [选项]

选项:
  -f, --functions      函数进入/退出插桩
  -v, --variables      共享变量访问插桩
  -b, --basic-blocks   基本块插桩
  -l, --locks <file>   锁操作插桩 (需要锁函数配置文件)
  -t, --trylock <file> trylock 配置文件
  --free               内存释放函数插桩
  -a, --all            启用全部插桩 (需要 -l 指定锁文件)

自定义回调函数名:
  --enter-name <name>  函数进入回调 (默认: kccwf_rec_func_enter)
  --exit-name <name>   函数退出回调 (默认: kccwf_rec_func_exit)
  --bb-name <name>     基本块回调   (默认: kccwf_rec_bbs)
  --lock-name <name>   锁操作回调   (默认: rec_lock)
  --free-name <name>   释放操作回调 (默认: kccwf_rec_free)
```

**内核编译时默认启用:** `-f -v --free -l LockFunc.txt`

#### 4. `report-analyzer`

用于把 validated report 中的 VarName/hash 反查回插桩 IR 中的真实访问点，并输出对应的源码调试信息链。

示例：

```bash
# 在整个 bluetooth IR 目录中搜索一个或多个 VarName/hash
ddrd-tools/build/report-analyzer/bin/report-analyzer \
  kernels/builds/x86/net/bluetooth \
  7350912627818033108 7350948080608836155

# 直接分析单个 instrumented.ll 文件
ddrd-tools/build/report-analyzer/bin/report-analyzer \
  kernels/builds/x86/net/bluetooth/sco.instrumented.ll \
  7350912627818033108
```

输出包含：
- 命中的 `.instrumented.ll` 文件
- 所在 LLVM 函数
- 命中的插桩调用 (`kccwf_rec_mem_access` / `kccwf_rec_free`)
- 访问类型（read/write/free）
- DebugLoc 对应的源码文件、行号和内联链

#### 5. `instrumentation_targets.conf`

控制哪些内核源文件需要插桩。每行一个路径模式：

```conf
# 以 / 结尾表示目录前缀匹配
fs/xfs/
fs/btrfs/

# 精确匹配单个文件
drivers/block/floppy.c
```

此文件由 `build_kernel.sh` 在编译不同模块时动态写入，无需手动编辑。

#### 6. `ddrace-cc` / `ddrace-cxx` (用户态)

用于用户态程序的数据竞争检测编译器：

```bash
# 编译 C 程序 (启用函数+变量插桩)
ddrace-cc --ddrace-functions --ddrace-variables -o prog prog.c

# 编译 C++ 程序
ddrace-cxx --ddrace-all -o prog prog.cpp

# 不插桩 (直接透传给 clang)
ddrace-cc -o prog prog.c
```

## 配置

### 环境变量一览

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DDRD_TOOLCHAIN` | `<项目>/ddrd-tools` | 工具链根目录 |
| `DDRD_LLVM` | `/home/zzzccc/llvm-15/llvm-project/build` | LLVM 安装路径 |
| `DDRD_CC` | `$DDRD_TOOLCHAIN/compiler/clang-wrapper.sh` | 内核编译器 |
| `DDRD_INSTRUMENT_CONF` | `$DDRD_TOOLCHAIN/compiler/instrumentation_targets.conf` | 插桩目标配置 |
| `DDRD_INSTRUMENTER` | `$DDRD_TOOLCHAIN/build/bin/instrumenter` | instrumenter 路径 |

所有变量在 `source scripts/envsetup.sh` 时自动设置。

### 使用外部 DDRD 工具链

如果希望使用原始 `/home/zzzccc/BASS/DDRD` 而非项目内副本：

```bash
export DDRD_TOOLCHAIN=/home/zzzccc/BASS/DDRD
source scripts/envsetup.sh
```

## 与 build_kernel.sh 的集成

`build_kernel.sh` 自动使用本工具链：

```bash
# 编译时自动:
# 1. 写入 instrumentation_targets.conf (目标模块路径)
# 2. 调用 make CC=$DDRD_CC (即 clang-wrapper.sh)
# 3. clang-wrapper.sh → kernel_compiler → instrumenter 完成插桩

./scripts/build_kernel.sh xfs btrfs            # shared 模式
./scripts/build_kernel.sh --mode=isolated xfs   # isolated 模式
```

## 数据文件

### `LockFunc.txt`

锁函数列表，instrumenter 使用 `-l` 选项读取：

```
mutex_lock
mutex_unlock
spin_lock
spin_unlock
...
```

### `lockset.txt`

锁集分析配置 (参考用)。

## 故障排查

### instrumenter 编译失败

```bash
# 检查 LLVM 版本
llvm-config --version    # 需要 18.x

# 检查 cmake 配置路径
ls /usr/lib/llvm-18/lib/cmake/llvm/  # 或自定义路径

# 指定 LLVM 路径重新编译
DDRD_LLVM=/path/to/llvm ./scripts/build_ddrd_tools.sh instrumenter
```

### 内核编译时插桩不生效

```bash
# 检查 clang-wrapper.sh 是否被使用
echo $DDRD_CC   # 应指向 clang-wrapper.sh

# 检查 instrumentation_targets.conf 内容
cat $DDRD_INSTRUMENT_CONF

# 检查 kernel_compiler 是否存在
ls -la $DDRD_TOOLCHAIN/compiler/kernel_compiler

# 检查 instrumenter 是否存在
ls -la $DDRD_TOOLCHAIN/build/bin/instrumenter

# 快速状态检查
./scripts/build_ddrd_tools.sh check
```

### kernel_compiler 路径错误

`kernel_compiler` 通过环境变量 `DDRD_TOOLCHAIN` 定位 instrumenter。确保：

```bash
source scripts/envsetup.sh   # 设置所有环境变量
echo $DDRD_TOOLCHAIN         # 应指向 ddrd-tools/
```
