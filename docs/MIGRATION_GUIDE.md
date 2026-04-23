# DDRD-syzkaller 迁移指南

> 本文主线覆盖 DDRD-syzkaller 主环境迁移。若你还要继续做 `DDRD vs Conzzer vs SegFuzz` 对比实验，请同时迁移 `Conzzer` 和 `segfuzz`，并在运行 `exp/pair-count-comparison` 脚本前设置 `CONZZER_HOME`、`SEGFUZZ_HOME`。

## 一、项目资源结构总览

```
DDRD-syzkaller/                    ← 项目根目录
├── bin/                           ← syzkaller 编译产物 (syz-manager 等)
├── images/                        ← 磁盘镜像 + SSH 密钥 (需重新创建)
│   ├── bookworm.img               ← Debian 12 rootfs (20GB, 所有模块共用)
│   ├── bookworm.id_rsa            ← SSH 私钥 (VM 访问用)
│   ├── bookworm.id_rsa.pub        ← SSH 公钥
│   ├── xfs-2G.qcow2              ← XFS 文件系统镜像 (挂载为 /dev/sdb)
│   ├── btrfs-2G.qcow2            ← Btrfs (btrfs 模块用 btrfs.qcow2)
│   ├── f2fs-2G.qcow2             ← F2FS (f2fs 模块用 f2fs-2G.raw)
│   ├── jfs-2G.qcow2              ← JFS
│   ├── ext4-2G.qcow2             ← EXT4
│   ├── ocfs2-2G.qcow2            ← OCFS2
│   └── floppy.qcow2              ← 软盘镜像 (floppy 模块专用)
├── kernels/
│   ├── configs/                   ← 内核 .config 文件
│   │   ├── x86-64.config          ← 基础配置 (Linux 6.2.0)
│   │   └── x86-64-kcsan.config    ← KCSAN 变体
│   ├── builds/x86/                ← 共享增量编译目录 (自动生成)
│   └── output/                    ← 每个模块的 vmlinux + bzImage
│       ├── plain/
│       ├── xfs/
│       ├── btrfs/
│       └── ...
├── exp/                           ← 实验目录 (每模块一个子目录)
│   ├── xfs/
│   │   ├── fuzz.cfg               ← syz-manager fuzzing 配置 (自动生成)
│   │   ├── validate.cfg           ← syz-manager validate 配置 (自动生成)
│   │   ├── syscalls.txt           ← 模块相关 syscall 列表
│   │   ├── overrides.json         ← 模块特定参数覆盖
│   │   └── workdir/               ← 运行时工作目录 (自动创建)
│   └── ...
├── ddrd-tools/                    ← DDRD 插桩工具链 (需编译)
│   ├── compiler/                  ← kernel_compiler, clang-wrapper.sh
│   ├── instrumenter/              ← LLVM IR 插桩 pass
│   └── build/                     ← 编译输出
├── scripts/                       ← 所有管理脚本
└── test/fs/                       ← 旧版镜像位置 (兼容用, 可忽略)

外部依赖:
├── DDRD-Kernel/                   ← 插桩内核源码 (需单独 clone)
└── LLVM 18                        ← instrumenter 编译依赖

对比实验额外依赖:
├── Conzzer/                       ← Conzzer 仓库 (三工具对比时需要)
└── segfuzz/                       ← SegFuzz 仓库 (三工具对比时需要)
```

---

## 二、镜像系统详细分析

### 2.1 镜像分类

DDRD-syzkaller 使用 **两类** 磁盘镜像:

| 类型 | 文件 | 格式 | 大小 | 作用 |
|------|------|------|------|------|
| **Rootfs** | `bookworm.img` | raw ext4 | 20GB | 所有 VM 的 `-hda` 主系统盘 |
| **FS 镜像** | `{xfs,btrfs,...}-2G.qcow2` | qcow2/raw | 2GB | 作为 `-hdb` 挂载到 `/mnt/kccwf` |

### 2.2 Rootfs 镜像 (`bookworm.img`)

**所有模块共用同一个 rootfs**, 内部关键配置:

1. **Debian bookworm (12)** — `debootstrap --arch=amd64`
2. **root 无密码** — syzkaller 要求
3. **串口控制台** — `getty -L ttyS0 115200`
4. **网络配置** — 同时兼容 `eth0` (net.ifnames=0) 和 `enp0s4`/`enp0s5`
5. **SSH authorized_keys** — 注入生成的公钥
6. **fstab** — 挂载 debugfs, securityfs, configfs, binfmt_misc
7. **kccwf.service** — systemd 服务, 开机自动将 `/dev/sdb` 挂载到 `/mnt/kccwf`
8. **udev 规则** — vim2m 设备符号链接 (video 模块需要)

### 2.3 kccwf.service (统一版本)

**所有模块使用同一个 kccwf.service**, 它能自动检测文件系统类型:

```ini
[Unit]
Description=Mount /dev/sdb to /mnt/kccwf
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c "FS=$(blkid -o value -s TYPE /dev/sdb 2>/dev/null); \
  case $FS in ocfs2) mount -t ocfs2 -o heartbeat=none /dev/sdb /mnt/kccwf ;; \
  *) mount /dev/sdb /mnt/kccwf ;; esac"
ExecStop=/usr/bin/umount /mnt/kccwf
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

**关键点**: 不需要为不同文件系统创建不同的 rootfs. 差异通过 QEMU 参数 `-hdb` 传入不同的文件系统镜像实现.

### 2.4 各模块使用的镜像差异

| 模块 | rootfs | 第二块磁盘 (-hdb / 其他) | 特殊 QEMU 参数 |
|------|--------|--------------------------|----------------|
| xfs | bookworm.img | xfs-2G.qcow2 | — |
| btrfs | bookworm.img | btrfs.qcow2 | — |
| f2fs | bookworm.img | f2fs-2G.raw | — |
| jfs | bookworm.img | jfs-2G.qcow2 | — |
| ext4 | bookworm.img | ext4-2G.qcow2 | — |
| ocfs2 | bookworm.img | ocfs2-2G.qcow2 | — |
| overlayfs | bookworm.img | 无 | (特殊, 用 root backend) |
| floppy | bookworm.img | floppy.qcow2 (软盘接口) | `-drive file=...,if=floppy` |
| dsp | bookworm.img | btrfs-2G.qcow2 (占位) | `-audiodev none,id=pa1 -device AC97,audiodev=pa1` |
| video | bookworm.img | btrfs-2G.qcow2 (占位) | — |
| wifi | bookworm.img | btrfs-2G.qcow2 (占位) | — |
| ptmx | bookworm.img | 无 | 仅 `-enable-kvm` |
| bt-stack | bookworm.img | 无 | `-append rcupdate.rcu_cpu_stall_timeout=120` |
| usb-driver | bookworm.img | usb.qcow2 (USB 设备) | `-device qemu-xhci -device usb-storage,...` |

**说明**: 非文件系统模块 (floppy, dsp, video, wifi, ptmx, bt-stack, usb-driver) 不需要 `/mnt/kccwf`, 但 kccwf.service 不会报错 (无 /dev/sdb 时挂载失败后 restart, 最终放弃).

### 2.5 特殊镜像

- **`bookworm-ocfs2.img`**: 旧版 OCFS2 专用 rootfs (当前版本可统一用 bookworm.img)
- **`bookworm-overlayfs.img`**: OverlayFS 专用 rootfs, 内含 `kccwf-overlayfs-root.service` (创建 overlay 目录结构并挂载)
- **`bookworm-usb.img`**: USB 专用 rootfs
- **`bookworm-validate-N.qcow2`**: Validate 阶段用的 VM snapshot 基盘 (由 syz-manager 自动创建)

---

## 三、迁移前准备

### 3.1 硬件要求

- **CPU**: 支持 KVM 虚拟化 (Intel VT-x / AMD-V)
- **内存**: >= 32GB (每个 VM 4GB, 同时运行多模块需更多)
- **磁盘**: >= 200GB (rootfs 20GB + 内核编译 + 工作目录)
- **核心**: >= 16 (实验用 CPU 核隔离)

### 3.2 需要传输的文件

**必须传输:**

```bash
# 1. DDRD-syzkaller 项目代码
rsync -avz --exclude='kernels/builds/' \
           --exclude='kernels/output/' \
           --exclude='images/' \
           --exclude='exp/*/workdir*' \
           --exclude='exp/*/logs/' \
           --exclude='bin/' \
           --exclude='ddrd-tools/build/' \
           DDRD-syzkaller/ new-machine:~/BASS/DDRD-syzkaller/

# 2. DDRD-Kernel 源码
rsync -avz DDRD-Kernel/ new-machine:~/Linux-Kernel/DDRD-Kernel/

# 3. (可选) 如果自编译了 LLVM, 也需传输
rsync -avz llvm-15/ new-machine:~/llvm-15/
```

**如果还要继续做 DDRD vs Conzzer vs SegFuzz 对比, 额外传输:**

```bash
# 4. Conzzer 项目代码
rsync -avz --exclude='exp/*/workdir*' \
           --exclude='kernel/output/' \
           Conzzer/ new-machine:~/BASS/Conzzer/

# 5. SegFuzz 项目代码
rsync -avz --exclude='exp/*/workdir*' \
           segfuzz/ new-machine:~/BASS/segfuzz/

# 6. (可选) 对比实验已有数据
rsync -avz DDRD-syzkaller/exp/pair-count-comparison/ \
           new-machine:~/BASS/DDRD-syzkaller/exp/pair-count-comparison/
```

**可选传输 (节省重新编译时间):**

```bash
# 已编译的内核输出 (每个 ~600MB-1GB)
rsync -avz DDRD-syzkaller/kernels/output/ new-machine:~/BASS/DDRD-syzkaller/kernels/output/

# 已有实验数据 (corpus, crashes)
rsync -avz DDRD-syzkaller/exp/*/workdir/ new-machine:~/BASS/DDRD-syzkaller/exp/*/workdir/
```

**不要传输 (在新机器重建):**

- `images/` — 包含 20GB+ 的 rootfs, 重新创建更快
- `kernels/builds/` — 编译中间文件, 数十 GB
- `bin/` — Go 编译产物, 需在新机器重编
- `ddrd-tools/build/` — LLVM pass 编译产物, 需重编

### 3.3 三工具对比场景的最低要求

如果你的目标是继续跑 `DDRD vs Conzzer vs SegFuzz`，新机器上至少要满足下面三件事:

1. `DDRD-syzkaller` 主环境可正常创建镜像、生成配置并启动 VM。
2. `Conzzer` 和 `segfuzz` 仓库都已迁移到新机器，并能独立启动各自实验。
3. 对比脚本使用的路径变量与新机器目录一致。

`exp/pair-count-comparison/common.sh` 默认读取:

```bash
DDRD_HOME="${DDRD_HOME:-/home/zzzccc/BASS/DDRD-syzkaller}"
SEGFUZZ_HOME="${SEGFUZZ_HOME:-/home/zzzccc/BASS/segfuzz}"
CONZZER_HOME="${CONZZER_HOME:-/home/zzzccc/BASS/Conzzer}"
```

如果新机器路径不是这三个默认值，运行对比脚本前必须显式导出环境变量。

---

## 四、迁移后完整步骤

### Step 0: 验证基础环境

```bash
# 登录新机器后
ssh new-machine

# 检查 KVM 支持
ls -la /dev/kvm
# 如果不存在, 需要:
# sudo modprobe kvm_intel  (Intel) 或 sudo modprobe kvm_amd (AMD)

# 确认项目位置
cd ~/BASS/DDRD-syzkaller
ls scripts/
```

### Step 1: 安装系统依赖

```bash
# 一键安装所有依赖 (Go, GCC, LLVM 18, QEMU, debootstrap, mkfs 工具等)
sudo bash scripts/install_toolchain_ubuntu.sh

# 或最小安装
sudo bash scripts/install_toolchain_ubuntu.sh --minimal

# 验证安装
go version          # >= 1.24
clang-18 --version  # LLVM 18
qemu-system-x86_64 --version
debootstrap --version
```

### Step 2: 配置环境变量

```bash
# 编辑 envsetup.sh 中的路径 (如果用户名/目录不同)
vim scripts/envsetup.sh

# 需要修改的关键变量:
#   DDRD_KERNEL_SRC — 指向 DDRD-Kernel 源码
#   DDRD_LLVM       — 指向 LLVM 安装路径

# 加载环境
source scripts/envsetup.sh
```

**如果新机器的用户名或目录结构不同**, 需要修改 `envsetup.sh` 中的默认路径:

```bash
# 例如用户名从 zzzccc 变为 newuser:
export DDRD_KERNEL_SRC="${DDRD_KERNEL_SRC:-/home/newuser/Linux-Kernel/DDRD-Kernel}"
export DDRD_LLVM="${DDRD_LLVM:-/usr/lib/llvm-18}"  # 如果用 apt 装的 LLVM 18
```

### Step 2.5: 对比实验路径变量

如果还要继续跑 `DDRD vs Conzzer vs SegFuzz`，建议在 shell 初始化文件或当前终端中补充:

```bash
export DDRD_HOME="$HOME/BASS/DDRD-syzkaller"
export CONZZER_HOME="$HOME/BASS/Conzzer"
export SEGFUZZ_HOME="$HOME/BASS/segfuzz"
```

先做一次快速检查:

```bash
test -d "$DDRD_HOME/exp/pair-count-comparison"
test -d "$CONZZER_HOME"
test -d "$SEGFUZZ_HOME"
bash "$DDRD_HOME/exp/pair-count-comparison/run_comparison.sh" status
```

### Step 2.6: 为三工具准备独立资产目录

如果你不希望 `Conzzer` 和 `SegFuzz` 继续直接引用 `DDRD-syzkaller/images/`，可以在 DDRD 主环境准备好后执行:

```bash
cd "$DDRD_HOME/exp/pair-count-comparison"

# 查看当前是否已经隔离
bash prepare_isolated_assets.sh --status

# 复制独立资产
bash prepare_isolated_assets.sh all
```

执行后默认会准备:

- `Conzzer/images/bookworm.img` 与 `bookworm.id_rsa`
- `Conzzer/images/` 下的常用测试盘镜像
- `segfuzz/kernels/guest/disks/x86_64/` 下的独立测试盘镜像

这样后续三工具对比时，`Conzzer` 不再直接用 `DDRD-syzkaller` 的 rootfs / SSH key，`SegFuzz` 也不再直接把 DDRD 的 FS 镜像作为运行时磁盘路径。

### Step 3: 创建磁盘镜像

```bash
# 一键创建所有镜像: rootfs + 6 种文件系统
sudo bash scripts/create_image.sh --create-all

# 或分步:
sudo bash scripts/create_image.sh --create-rootfs --mirror aliyun  # rootfs
bash scripts/create_image.sh --create-all --skip-rootfs             # 仅 FS 镜像

# 如果用代理:
sudo bash scripts/create_image.sh --create-all --proxy http://127.0.0.1:7890

# 修复/验证
sudo bash scripts/create_image.sh --fix-kccwf
sudo bash scripts/create_image.sh --verify
```

**创建完成后 `images/` 内容:**

```
bookworm.img          ← 20GB rootfs (所有模块共用)
bookworm.id_rsa       ← SSH 私钥
bookworm.id_rsa.pub   ← SSH 公钥
xfs-2G.qcow2         ← XFS 文件系统
btrfs-2G.qcow2       ← Btrfs 文件系统
f2fs-2G.qcow2        ← F2FS 文件系统
jfs-2G.qcow2         ← JFS 文件系统
ext4-2G.qcow2        ← EXT4 文件系统
ocfs2-2G.qcow2       ← OCFS2 文件系统
```

**补充: floppy 和 usb 的特殊镜像**

```bash
# floppy 软盘镜像 (需手动创建)
qemu-img create -f qcow2 images/floppy.qcow2 1440K

# USB 镜像 (如果测试 usb-driver)
qemu-img create -f qcow2 images/usb.qcow2 512M
# 或复用 btrfs 镜像:
# 在 exp/usb-driver/overrides.json 中修改 qemu_args 路径
```

### Step 4: 编译 DDRD 工具链

```bash
source scripts/envsetup.sh

# 编译全部组件 (kernel_compiler + instrumenter + ddrace-cc/cxx + report-analyzer)
bash scripts/build_ddrd_tools.sh

# 验证
bash scripts/build_ddrd_tools.sh check
```

**常见问题:**
- `找不到 LLVM cmake 配置` → 检查 `DDRD_LLVM` 路径, 或安装 `llvm-18-dev`
- `g++ 未找到` → 安装 `build-essential`

### Step 5: 编译 DDRD-syzkaller

```bash
source scripts/envsetup.sh

# 编译
bash scripts/build_syzkaller.sh

# 验证
ls -la bin/syz-manager
bin/syz-manager --help 2>&1 | head -3
```

### Step 6: 编译内核

```bash
source scripts/envsetup.sh

# 编译所有模块 (shared 模式, 约 1-3 小时取决于 CPU)
bash scripts/build_kernel.sh

# 或只编译特定模块
bash scripts/build_kernel.sh xfs btrfs f2fs

# 查看输出
ls -la kernels/output/*/vmlinux
```

**注意**: 内核编译需要 DDRD-Kernel 源码和 DDRD 工具链都就绪.

### Step 7: 更新模块配置中的路径

```bash
# 更新 overrides.json 中的绝对路径
# 如果新机器路径不同, 需批量替换:
cd ~/BASS/DDRD-syzkaller

# 查看当前路径引用
grep -r "/home/zzzccc" exp/*/overrides.json

# 批量替换 (将旧路径替换为新路径)
find exp/ -name "overrides.json" -exec sed -i \
  "s|/home/zzzccc/BASS/DDRD-syzkaller|$(pwd)|g" {} +

# 同样替换旧的 test/fs 路径
find exp/ -name "overrides.json" -exec sed -i \
  "s|/home/zzzccc/BASS/DDRD-syzkaller/test/fs|$(pwd)/images|g" {} +
find exp/ -name "overrides.json" -exec sed -i \
  "s|/home/zzzccc/BASS/DDRD-syzkaller/test/DDRD|$(pwd)/images|g" {} +
```

### Step 8: 生成实验配置

```bash
source scripts/envsetup.sh

# 生成所有模块的 fuzz.cfg + validate.cfg (覆盖旧的)
python3 scripts/generate_config.py --all --force

# 可选: 同时生成 vanilla 配置 (用于对比实验)
python3 scripts/generate_config.py --all --force --vanilla

# 验证配置中的路径
python3 -c "
import json, glob
for f in sorted(glob.glob('exp/*/fuzz.cfg')):
    d = json.load(open(f))
    print(f'{f}:')
    print(f'  image: {d[\"image\"]}')
    print(f'  sshkey: {d[\"sshkey\"]}')
    print(f'  kernel: {d[\"vm\"][\"kernel\"]}')
    print(f'  qemu_args: {d[\"vm\"][\"qemu_args\"]}')
    print()
"
```

### Step 9: 快速验证 (跑一个模块)

```bash
source scripts/envsetup.sh

# 启动单个模块 fuzzing (debug 模式, 前台运行, 方便排查问题)
bash scripts/run_fuzz.sh start --debug xfs

# 如果看到 "VMs XX, corpus XX" 等输出, 说明运行正常
# Ctrl+C 退出

# 或后台模式启动
bash scripts/run_fuzz.sh start xfs
bash scripts/run_fuzz.sh status
bash scripts/run_fuzz.sh log xfs
```

### Step 10: 正式启动实验

```bash
source scripts/envsetup.sh

# === Fuzz 阶段 ===
# 启动指定模块
bash scripts/run_fuzz.sh start xfs btrfs f2fs

# 带时间限制 (24小时)
bash scripts/run_fuzz.sh start -t 24h xfs btrfs f2fs

# 启动所有模块
bash scripts/run_fuzz.sh start --all

# 查看状态
bash scripts/run_fuzz.sh status

# 停止
bash scripts/run_fuzz.sh stop xfs

# === Validate 阶段 (fuzz 完成后) ===
bash scripts/run_validate.sh start xfs

# === 或使用完整实验流程 (fuzz → validate 自动衔接) ===
bash scripts/run_experiment.sh start xfs -t 24h
```

---

## 五、一键迁移脚本

项目提供了 `scripts/migrate_setup.sh` 一键迁移脚本, 但它只负责 `DDRD-syzkaller` 主环境:

```bash
# 完整一键设置 (从安装依赖到验收)
sudo DDRD_KERNEL_SRC=/path/to/DDRD-Kernel \
     DDRD_LLVM=/usr/lib/llvm-18 \
     MIRROR=aliyun \
     bash scripts/migrate_setup.sh --full

# 查看当前状态
bash scripts/migrate_setup.sh --status

# 分步执行
sudo bash scripts/migrate_setup.sh --install-deps
sudo bash scripts/migrate_setup.sh --create-images
bash scripts/migrate_setup.sh --build-tools
bash scripts/migrate_setup.sh --build-syzkaller
bash scripts/migrate_setup.sh --build-kernel
bash scripts/migrate_setup.sh --gen-config
sudo bash scripts/migrate_setup.sh --verify
```

如果你后续要直接继续三工具对比，在 DDRD 主环境完成后再执行:

```bash
export DDRD_HOME="$HOME/BASS/DDRD-syzkaller"
export CONZZER_HOME="$HOME/BASS/Conzzer"
export SEGFUZZ_HOME="$HOME/BASS/segfuzz"

bash exp/pair-count-comparison/run_comparison.sh status
```

---

## 六、常见问题排查

### Q1: QEMU 启动 VM 失败

```
"failed to start VM: qemu failed"
```

- 检查 KVM: `ls /dev/kvm`
- 检查镜像路径: `cat exp/xfs/fuzz.cfg | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['image']); print(d['vm']['kernel']); print(d['vm']['qemu_args'])"`
- 手动测试 QEMU: `qemu-system-x86_64 -enable-kvm -m 4096 -smp 2 -kernel kernels/output/xfs/bzImage -hda images/bookworm.img -hdb images/xfs-2G.qcow2 -nographic -append "root=/dev/sda console=ttyS0 net.ifnames=0"`

### Q2: SSH 连接 VM 失败

- 检查密钥权限: `ls -la images/bookworm.id_rsa` (应为 600)
- 检查 rootfs 中的 authorized_keys: `sudo mount -o loop images/bookworm.img /mnt && cat /mnt/root/.ssh/authorized_keys && sudo umount /mnt`

### Q3: 内核 panic / 文件系统挂载失败

- 检查 kccwf.service: `sudo mount -o loop images/bookworm.img /mnt && cat /mnt/etc/systemd/system/kccwf.service && sudo umount /mnt`
- 修复: `sudo bash scripts/create_image.sh --fix-kccwf`

### Q4: 配置文件路径错误

```bash
# 重新生成配置 (会自动使用当前 PROJECT_HOME)
python3 scripts/generate_config.py --all --force
```

### Q5: 内核编译失败

```bash
# 检查前置: 内核源码, 插桩工具链
ls $DDRD_KERNEL_SRC/Makefile
bash scripts/build_ddrd_tools.sh check

# 清理后重编
bash scripts/build_kernel.sh --no-clean xfs
```

### Q6: Go 版本过低

```bash
# 自动安装最新 Go
bash scripts/install_toolchain_ubuntu.sh --go-only
source scripts/envsetup.sh
go version  # 应 >= 1.24
```
