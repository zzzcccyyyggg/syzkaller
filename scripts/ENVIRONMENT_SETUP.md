# DDRD-syzkaller 环境搭建指南

从零开始搭建 DDRD 实验环境的完整流程。

---

## 目录

- [0. 硬件要求](#0-硬件要求)
- [1. 安装系统依赖](#1-安装系统依赖)
- [2. 配置环境变量](#2-配置环境变量)
- [3. 编译 syzkaller](#3-编译-syzkaller)
- [4. 编译 DDRD 工具链](#4-编译-ddrd-工具链)
- [5. 准备 DDRD 内核](#5-准备-ddrd-内核)
- [6. 编译内核](#6-编译内核)
- [7. 创建 VM 镜像](#7-创建-vm-镜像)
- [8. 生成实验配置](#8-生成实验配置)
- [9. 验证环境](#9-验证环境)
- [10. 快速参考](#10-快速参考)

---

## 0. 硬件要求

| 资源 | 最低要求 | 推荐配置 |
|------|----------|----------|
| CPU | 8 核 (分批跑 4 模块) | 32+ 核 (8 模块 fuzz+validate 并行) |
| 内存 | 32 GB | 64-128 GB |
| 磁盘 | 200 GB | 500+ GB (SSD 推荐) |
| 系统 | Ubuntu 22.04+ (x86_64) | Ubuntu 24.04 LTS |

**磁盘用量估算**:
- 内核源码 + 构建: ~30 GB
- VM root 镜像: 20 GB
- 文件系统测试镜像: 6 × 2 GB = 12 GB
- 24h 实验 corpus + 日志: ~50-100 GB

---

## 1. 安装系统依赖

### 1.1 一键安装 (推荐)

```bash
./scripts/install_toolchain_ubuntu.sh
```

该脚本自动安装:
- **Go** ≥ 1.24.0 (从 go.dev 下载)
- **编译工具**: build-essential, make, git, bc, bison, flex
- **内核编译**: libssl-dev, libelf-dev, libncurses-dev, dwarves, cpio
- **LLVM/Clang**: clang-18, llvm-18 (回退到默认版本)
- **QEMU**: qemu-system-x86, qemu-utils, debootstrap
- **文件系统工具**: xfsprogs, btrfs-progs, f2fs-tools, jfsutils, e2fsprogs
- **DDRD 工具**: cmake, g++
- **Python**: python3, pip, matplotlib, numpy

可选参数:

```bash
./scripts/install_toolchain_ubuntu.sh --minimal     # 跳过文件系统工具
./scripts/install_toolchain_ubuntu.sh --go-only      # 仅安装/升级 Go
./scripts/install_toolchain_ubuntu.sh --dry-run      # 仅打印命令不执行
```

### 1.2 手动安装 (非 Ubuntu)

```bash
# Go >= 1.24
wget https://go.dev/dl/go1.24.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.4.linux-amd64.tar.gz
export PATH=/usr/local/go/bin:$PATH

# LLVM >= 15 (推荐 18)
# 按系统 distro 安装 clang, llvm, llvm-dev, lld

# QEMU
# 按系统 distro 安装 qemu-system-x86

# Python
pip3 install matplotlib numpy
```

---

## 2. 配置环境变量

```bash
source scripts/envsetup.sh
```

会设置以下关键变量:

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PROJECT_HOME` | 自动检测 | 项目根目录 |
| `DDRD_KERNEL_SRC` | `/home/zzzccc/Linux-Kernel/DDRD-Kernel` | 内核源码路径 |
| `DDRD_TOOLCHAIN` | `$PROJECT_HOME/ddrd-tools` | DDRD 工具链路径 |
| `DDRD_LLVM` | `/home/zzzccc/llvm-15/llvm-project/build` | LLVM 构建路径 |
| `SYZ_MANAGER` | `$PROJECT_HOME/bin/syz-manager` | syz-manager 路径 |

> **注意**: 如果你的内核或 LLVM 路径不同, 在 `source` 之前先 export 覆盖:
> ```bash
> export DDRD_KERNEL_SRC=/path/to/your/kernel
> export DDRD_LLVM=/path/to/your/llvm/build
> source scripts/envsetup.sh
> ```

---

## 3. 编译 syzkaller

```bash
make -j$(nproc)
```

**产出** (`bin/` 目录):
- `syz-manager` — 实验管理器 (fuzz / validate 主进程)
- `syz-validatedb` — 验证结果提取工具
- `syz-prog2c` — 将 syz 程序转为 C 代码 (复现用)
- `linux_amd64/syz-executor` — 在 VM 内运行的执行器

**验证**:

```bash
./bin/syz-manager -h 2>&1 | head -1
# 应输出: Usage of ./bin/syz-manager: ...
```

---

## 4. 编译 DDRD 工具链

```bash
./scripts/build_ddrd_tools.sh
```

分别构建三个组件:

| 组件 | 路径 | 功能 |
|------|------|------|
| compiler | `ddrd-tools/compiler/kernel_compiler` | 内核编译器 wrapper, 在编译期插桩 |
| instrumenter | `ddrd-tools/build/instrumenter/` | LLVM IR pass, 插入运行时 hook |
| report-analyzer | `ddrd-tools/build/report-analyzer/` | 将 hash → 源码位置 |

也可分别构建:

```bash
./scripts/build_ddrd_tools.sh compiler
./scripts/build_ddrd_tools.sh instrumenter
./scripts/build_ddrd_tools.sh analyzer
```

> **依赖**: LLVM ≥ 15 (instrumenter 需要 `llvm-config`, `clang`)。
> 如果 LLVM 未在标准路径, 设 `DDRD_LLVM=/path/to/llvm/build`。

---

## 5. 准备 DDRD 内核

DDRD 需要一个带有运行时插桩支持的定制内核。

### 5.1 获取 DDRD-Kernel

```bash
# 克隆 DDRD-Kernel (与 DDRD-syzkaller 同级目录)
cd /home/zzzccc/Linux-Kernel
git clone <DDRD-Kernel-repo-url> DDRD-Kernel
```

该内核在标准 Linux 内核基础上包含:
- 函数入口/出口 hook
- 内存访问记录
- Barrier 同步原语
- UAF 运行时检测

### 5.2 内核配置

基础配置存放在 `kernels/configs/`:

```
kernels/configs/
├── x86-64.config          # 标准配置 (用于 fuzz + validate)
└── x86-64-kcsan.config    # 带 KCSAN 的配置 (可选, 用对比实验)
```

如果没有配置文件, `build_kernel.sh` 会自动用 `defconfig` + `kvm_guest.config` 生成。

---

## 6. 编译内核

### 6.1 查看可用模块

```bash
./scripts/build_kernel.sh --list
```

模块定义在 `scripts/modules.conf`, 当前支持:

| 类别 | 模块 | 插桩路径 |
|------|------|----------|
| 文件系统 | xfs, btrfs, f2fs, jfs, ext4, ocfs2, overlayfs | `fs/<name>/` |
| 驱动 | floppy, usb-driver, video | `drivers/...` |
| 网络/蓝牙 | wifi-stack, bt-stack | `net/...` |
| TTY/声卡 | ptmx, dsp | `drivers/tty/`, `sound/...` |

### 6.2 构建指定模块

```bash
# 构建实验所需的 8 个模块
./scripts/build_kernel.sh xfs btrfs f2fs jfs floppy bt-stack ptmx dsp

# 或构建全部
./scripts/build_kernel.sh --all
```

每个模块会:
1. 配置内核 (使用 `kernels/configs/x86-64.config`)
2. 使用 DDRD compiler wrapper 编译, 对指定路径进行插桩
3. 输出到 `kernels/output/<module>/`

### 6.3 构建产出

```
kernels/output/
├── plain/                # 无插桩的基准内核
│   ├── vmlinux
│   └── bzImage
├── xfs/                  # 对 fs/xfs/ 插桩的内核
│   ├── vmlinux
│   └── bzImage
├── btrfs/
└── ...
```

### 6.4 构建模式

```bash
# 共享构建 (默认 — 同一个 build dir, 切换插桩目标后增量编译)
./scripts/build_kernel.sh xfs btrfs

# 隔离构建 (每模块独立 build dir, 一慢但在测试时更安全)
./scripts/build_kernel.sh --isolated xfs btrfs

# 同时构建 KCSAN 版本
./scripts/build_kernel.sh --with-kcsan xfs
```

---

## 7. 创建 VM 镜像

### 7.1 基础 rootfs 镜像

```bash
# 创建 Debian Bookworm 基础镜像 (20G)
./scripts/create_image.sh --create-rootfs
```

或指定国内源加速:

```bash
# 可选 mirror: tsinghua / ustc / aliyun / official
./scripts/create_image.sh --create-rootfs --mirror tsinghua
```

**产出**: `images/bookworm.img` (含 SSH key: `images/ssh_key`, `images/ssh_key.pub`)

### 7.2 文件系统测试镜像

文件系统模块 (xfs, btrfs, f2fs, jfs) 需要额外的测试分区镜像:

```bash
# 创建所有文件系统镜像 (各 2G)
./scripts/create_image.sh --create-all

# 或单独创建
./scripts/create_image.sh --create-fs xfs 2G
./scripts/create_image.sh --create-fs btrfs 2G
./scripts/create_image.sh --create-fs f2fs 2G
./scripts/create_image.sh --create-fs jfs 2G
```

**产出**:

```
images/
├── bookworm.img           # 基础 rootfs
├── ssh_key / ssh_key.pub  # VM SSH 密钥
├── xfs-2G.qcow2
├── btrfs-2G.qcow2
├── f2fs-2G.qcow2
├── jfs-2G.qcow2
├── ext4-2G.qcow2
└── ocfs2-2G.qcow2
```

### 7.3 导入已有镜像

如果已有团队共享的镜像文件:

```bash
# 从 test/fs/ 目录导入
./scripts/create_image.sh --import
```

### 7.4 验证镜像

```bash
./scripts/create_image.sh --verify
```

---

## 8. 生成实验配置

### 8.1 生成所有模块的 fuzz + validate 配置

```bash
python3 scripts/generate_config.py --all
```

为每个模块生成:

```
exp/<module>/
├── fuzz.cfg           # fuzz 模式配置
├── validate.cfg       # validate 模式配置
└── syscalls.txt       # 允许的系统调用列表
```

### 8.2 查看已生成的配置

```bash
python3 scripts/generate_config.py --list
```

### 8.3 配置结构说明

每个 `.cfg` 文件是一个 JSON, 核心字段:

```json
{
  "target": "linux/amd64",
  "http": "0.0.0.0:62001",
  "workdir": "/home/.../exp/xfs/workdir",
  "kernel_obj": "/home/.../kernels/output/xfs/vmlinux",
  "image": "/home/.../images/bookworm.img",
  "sshkey": "/home/.../images/ssh_key",
  "syzkaller": "/home/.../DDRD-syzkaller",
  "procs": 2,
  "type": "qemu",
  "vm": {
    "count": 2,
    "cpu": 2,
    "mem": 4096,
    "kernel": "/home/.../kernels/output/xfs/bzImage",
    "qemu_args": "-hdb /home/.../images/xfs-2G.qcow2"
  },
  "experimental": {
    "barrier_mode": true,
    "race_mode": true,
    "enable_timing_exploration": false,
    "enable_solo_filter": false,
    "enable_coverage_triage": false,
    "enable_affinity_table": false,
    "enable_object_linking": null
  }
}
```

validate 配置额外包含 `uaf_validate` 字段，控制验证行为。

### 8.4 端口分配

每个模块使用固定端口 (避免冲突), validate 端口 = fuzz 端口 + 100:

| 模块 | fuzz 端口 | validate 端口 |
|------|-----------|---------------|
| xfs | 62001 | 62101 |
| btrfs | 62002 | 62102 |
| f2fs | 62003 | 62103 |
| jfs | 62004 | 62104 |
| floppy | 62005 | 62105 |
| bt-stack | 62006 | 62106 |
| ptmx | 62007 | 62107 |
| dsp | 62008 | 62108 |

### 8.5 生成 ablation 变体 (敏感度实验用)

```bash
MODS="xfs btrfs ptmx dsp"
python3 scripts/generate_config.py --ablation fuzz-no-timing   --force $MODS
python3 scripts/generate_config.py --ablation fuzz-no-objlink  --force $MODS
python3 scripts/generate_config.py --ablation fuzz-random      --force $MODS
python3 scripts/generate_config.py --throughput-only           --force $MODS
python3 scripts/generate_config.py --ablation validate-no-delay   --force $MODS
python3 scripts/generate_config.py --ablation validate-no-replay  --force $MODS
python3 scripts/generate_config.py --ablation validate-no-backoff --force $MODS

# 列出所有可用变体
python3 scripts/generate_config.py --list-ablations
```

### 8.6 导入统一初始 corpus

主实验和 rebuttal 重跑建议统一使用同一个 corpus 仓库：

- 远端仓库: `git@github.com:BASS-KerConcurrencyTesting/Corpus-for-syzkaller.git`
- 本地建议路径: `/home/zzzccc/BASS/DDRD-Corpus`

```bash
CORPUS_SRC=/home/zzzccc/BASS/DDRD-Corpus
CAP_MODS="xfs btrfs f2fs jfs floppy bt-stack ptmx dsp"

# 检查 corpus 来源
git -C "$CORPUS_SRC" remote -v
git -C "$CORPUS_SRC" rev-parse --short HEAD

# 清理上一轮 may-race / validate 结果
sudo scripts/run_experiment.sh stop --all || true
sudo scripts/run_experiment.sh clean --all || true
sudo scripts/run_experiment.sh clean-validate --all || true

# 只导入统一的初始 corpus.db
./scripts/manage_corpus.sh import --src "$CORPUS_SRC" --force $CAP_MODS
./scripts/manage_corpus.sh stat $CAP_MODS
```

> 建议不要在主实验开始前导入历史 `uaf-corpus.db`。  
> `corpus.db` 是统一 seed，`uaf-corpus.db` 应该由这次新实验自己产生。

---

## 9. 验证环境

完成上述步骤后, 做一次完整验证:

```bash
# 1. syzkaller 编译正常
./bin/syz-manager -h 2>&1 | head -1

# 2. 内核产物存在
ls kernels/output/xfs/vmlinux kernels/output/xfs/bzImage

# 3. 镜像存在
ls images/bookworm.img images/ssh_key

# 4. 配置生成正常
python3 scripts/generate_config.py --list

# 4.1 统一 corpus 已导入
./scripts/manage_corpus.sh stat xfs btrfs f2fs jfs floppy bt-stack ptmx dsp

# 5. QEMU 可用
qemu-system-x86_64 --version

# 6. 快速冒烟测试 (启动一个模块跑 5 分钟)
sudo scripts/run_experiment.sh start xfs
sleep 300
sudo scripts/run_experiment.sh status
sudo scripts/run_experiment.sh stop xfs
```

如果冒烟测试显示 xfs 正常运行且有日志输出, 说明环境搭建成功。

---

## 10. 快速参考

### 完整搭建流程 (一行一步)

```bash
# 依赖
./scripts/install_toolchain_ubuntu.sh

# 环境变量
source scripts/envsetup.sh

# 编译 syzkaller
make -j$(nproc)

# 编译 DDRD 工具链
./scripts/build_ddrd_tools.sh

# 编译内核 (8 个实验模块)
./scripts/build_kernel.sh xfs btrfs f2fs jfs floppy bt-stack ptmx dsp

# 创建 VM 镜像
./scripts/create_image.sh --create-rootfs --mirror tsinghua
./scripts/create_image.sh --create-all

# 生成配置
python3 scripts/generate_config.py --all --force

# 导入统一 corpus
./scripts/manage_corpus.sh import --src /home/zzzccc/BASS/DDRD-Corpus --force \
  xfs btrfs f2fs jfs floppy bt-stack ptmx dsp

# 启动实验
sudo scripts/run_experiment.sh start --all
sudo scripts/run_experiment.sh validate --all
```

### 8 模块主实验快捷入口

```bash
./scripts/run_capability_24h.sh check
./scripts/run_capability_24h.sh prepare
./scripts/run_capability_24h.sh start-shared
```

### 目录结构总览

```
DDRD-syzkaller/
├── bin/                    # 编译产物
├── kernels/
│   ├── configs/            # 内核 .config
│   ├── builds/             # out-of-tree 构建目录
│   └── output/<module>/    # vmlinux + bzImage
├── images/                 # VM 镜像 + SSH key
├── exp/<module>/           # 实验配置 + workdir
├── ddrd-tools/             # DDRD 工具链源码 + 构建
├── scripts/                # 所有操作脚本
│   ├── envsetup.sh
│   ├── install_toolchain_ubuntu.sh
│   ├── build_kernel.sh
│   ├── build_ddrd_tools.sh
│   ├── create_image.sh
│   ├── generate_config.py
│   ├── run_experiment.sh
│   └── modules.conf
└── docs/                   # 文档
```

### 常见问题

**Q: Go 版本不对?**
```bash
./scripts/install_toolchain_ubuntu.sh --go-only
```

**Q: LLVM 未找到?**
```bash
export DDRD_LLVM=/path/to/llvm/build
source scripts/envsetup.sh
./scripts/build_ddrd_tools.sh instrumenter
```

**Q: QEMU 启动失败 "Could not access KVM kernel module"?**
```bash
# 确认 KVM 可用
ls /dev/kvm
# 如果不存在, 确认 CPU 虚拟化已启用 (BIOS/宿主机), 然后:
sudo modprobe kvm_intel   # Intel CPU
sudo modprobe kvm_amd     # AMD CPU
```

**Q: 编译内核时 "clang-wrapper.sh: not found"?**
```bash
source scripts/envsetup.sh   # 需要加载环境变量
./scripts/build_ddrd_tools.sh compiler  # 先编译 compiler
```

**Q: 磁盘空间不足?**
- 使用 `--isolated` 模式仅编译需要的模块
- 实验间 `sudo scripts/run_experiment.sh clean --all` 清理旧数据
- 将 `kernels/builds/` 放在外部大磁盘并 symlink

**Q: fuzz 和 validate 可以同时启动吗?**
可以，但要先分清资源语义。

- 当前 `scripts/run_experiment.sh` 会让同一模块的 validate 复用 fuzz 的 CPU 槽位
- 所以 `start --all` + `validate --all` 是“每模块 2 核共享给 fuzz+validate”的模式
- 如果你要严格满足“fuzz 2 核 + validate 2 核，同时独占”，32 核机器建议按 4 模块一批跑

**Q: 我现在能直接开跑吗?**
可以，前提是你已经：

- 编译好 `bin/syz-manager`
- 准备好 8 个模块的 kernel/image/config
- 从 `git@github.com:BASS-KerConcurrencyTesting/Corpus-for-syzkaller.git` 对应的本地副本导入统一 `corpus.db`

如果最后一项还没做，先执行上面的 `8.6 导入统一初始 corpus`。
