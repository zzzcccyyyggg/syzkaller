# DDRD 实验工作流

## 目录结构

```
DDRD-syzkaller/
├── scripts/                    # 所有工作流脚本
│   ├── envsetup.sh             # 环境变量初始化 (source 使用)
│   ├── functions.sh            # 共用辅助函数
│   ├── modules.conf            # 模块定义 (slug, 内核路径, QEMU 参数等)
│   ├── extract_module_data.py  # 从旧 test/ 配置提取模块数据
│   ├── generate_config.py      # 生成 fuzz.cfg / validate.cfg
│   ├── build_syzkaller.sh      # 编译 DDRD-syzkaller
│   ├── build_kernel.sh         # 编译内核 (shared/isolated 双模式)
│   ├── create_image.sh         # 创建/导入磁盘镜像
│   ├── run_fuzz.sh             # 启动/停止/查看 fuzz
│   ├── run_validate.sh         # 启动/停止/查看 validate
│   ├── config_bundle.sh        # 配置打包导出/导入 (跨设备迁移)
│   ├── manage_corpus.sh        # corpus 备份/导入/迁移/统计
│   └── Makefile                # 顶层快捷入口
├── exp/                        # 实验目录 (每个模块一个子目录)
│   ├── xfs/
│   │   ├── syscalls.txt        # 该模块的 syscall 列表
│   │   ├── overrides.json      # 模块特定参数 (QEMU, VM 资源等)
│   │   ├── fuzz.cfg            # [生成] fuzz 配置
│   │   ├── validate.cfg        # [生成] validate 配置
│   │   ├── workdir/            # [运行时] fuzz/validate 共享工作目录
│   │   └── logs/               # [运行时] 日志
│   ├── btrfs/
│   └── ...
├── kernels/                    # 内核相关
│   ├── builds/                 # out-of-tree 构建目录
│   ├── output/                 # 编译产物 (output/<slug>/vmlinux, bzImage)
│   ├── configs/                # .config 文件
│   └── images/                 # 磁盘镜像 + SSH key
├── bin/                        # syzkaller 编译产物
└── test/                       # 旧测试目录 (兼容保留)
```

## 快速开始

### 1. 首次设置

```bash
# 进入项目目录
cd /home/zzzccc/BASS/DDRD-syzkaller

# 初始化: 提取模块数据 + 导入镜像 + 生成配置
make -f scripts/Makefile setup
```

### 0. Ubuntu 一键安装工具链

```bash
# 完整安装 (推荐)
./scripts/install_toolchain_ubuntu.sh

# 最小安装
./scripts/install_toolchain_ubuntu.sh --minimal

# 仅安装/升级 Go 环境
./scripts/install_toolchain_ubuntu.sh --go-only

# 仅预览命令
./scripts/install_toolchain_ubuntu.sh --dry-run
```

### 2. 编译

```bash
# 编译 DDRD-syzkaller
make -f scripts/Makefile build-syzkaller

# 编译所有模块的内核 (较耗时)
make -f scripts/Makefile build-kernel

# 只编译指定模块
make -f scripts/Makefile build-kernel MODULES="xfs btrfs"
```

### 3. 运行 Fuzz

```bash
# 启动 xfs fuzz
make -f scripts/Makefile fuzz MODULES=xfs

# 查看状态
make -f scripts/Makefile fuzz-status

# 查看日志
make -f scripts/Makefile fuzz-log MODULES=xfs

# 停止
make -f scripts/Makefile fuzz-stop MODULES=xfs
```

### 4. 运行 Validate

```bash
# 启动 xfs validate
make -f scripts/Makefile validate MODULES=xfs

# 查看状态
make -f scripts/Makefile validate-status

# 停止
make -f scripts/Makefile validate-stop
```

## 直接使用脚本

如果不想通过 Makefile，可以直接调用脚本:

```bash
# 初始化环境 (每个 shell 会话执行一次)
source scripts/envsetup.sh

# 编译内核 (shared 模式, 默认)
./scripts/build_kernel.sh xfs btrfs

# 编译内核 (isolated 模式, 每个模块独立 out-of-tree build)
./scripts/build_kernel.sh --mode=isolated xfs btrfs

# 生成配置
python3 scripts/generate_config.py --all --force

# 启动 fuzz
./scripts/run_fuzz.sh start xfs
./scripts/run_fuzz.sh status
./scripts/run_fuzz.sh stop xfs

# 启动 validate
./scripts/run_validate.sh start --debug xfs
```

## Corpus 管理

```bash
# 查看各模块 corpus 大小和状态
./scripts/manage_corpus.sh stat
# 或: make corpus-stat

# 从旧 test/ 目录迁移 corpus 到新 exp/ workdir
./scripts/manage_corpus.sh migrate --include-uaf --force
# 或: make corpus-migrate

# 从 DDRD-Corpus 目录导入
./scripts/manage_corpus.sh import xfs btrfs
./scripts/manage_corpus.sh import --include-uaf          # 含 uaf-corpus
./scripts/manage_corpus.sh import --src /path/to/corpus   # 自定义源目录
# 或: make corpus-import MODULES="xfs btrfs"

# 备份当前 workdir 中的 corpus
./scripts/manage_corpus.sh backup --include-uaf
./scripts/manage_corpus.sh backup --all-db --fuzz xfs     # 仅 fuzz workdir 的所有 db
# 或: make corpus-backup
# 备份到: corpus-backup/<timestamp>/<slug>/<mode>-corpus.db
```

## 配置导入/导出 (跨设备)

```bash
# 导出所有模块配置到 bundle
./scripts/config_bundle.sh export /tmp/ddrd-configs.tar.gz --all

# 仅导出指定模块
./scripts/config_bundle.sh export /tmp/ddrd-configs.tar.gz xfs btrfs

# 在另一台机器导入并自动修复路径
./scripts/config_bundle.sh import /tmp/ddrd-configs.tar.gz

# 覆盖已存在配置
./scripts/config_bundle.sh import /tmp/ddrd-configs.tar.gz --force
```

导入时会自动修复配置中绝对路径（例如 `workdir`、`syzkaller`、`image`、`vmlinux`、`vm.kernel`、`qemu_args` 中的旧项目路径）。

## 配置定制

### 修改模块的 syscalls

编辑 `exp/<slug>/syscalls.txt`，每行一个 syscall:

```
ioctl$FIBMAP
ioctl$FIGETBSZ
fsync$kccwf
...
```

### 修改模块的 VM/QEMU 参数

编辑 `exp/<slug>/overrides.json`:

```json
{
    "artifact_name": "xfs",
    "qemu_args": "-enable-kvm -hdb /path/to/xfs-2G.qcow2",
    "procs": 2,
    "vm_count": 8,
    "vm_cpu": 2,
    "vm_mem": 4096,
    "vm_running_time": 6000
}
```

修改后重新生成配置:
```bash
python3 scripts/generate_config.py --force xfs
```

### 修改 experimental 参数

`overrides.json` 也可以包含 `experimental` 字段。生成器会将其完整写入 `fuzz.cfg`。  
`validate.cfg` 使用独立的默认 experimental 配置 (含 `uaf_validate` 段)。

如需调整 validate 的默认值，编辑 `scripts/generate_config.py` 中的 `VALIDATE_EXPERIMENTAL`。

## 添加新模块

1. 在 `scripts/modules.conf` 添加一行:
   ```
   new-mod|fs/newfs/|-hdb ${KERNEL_IMAGES_DIR}/newfs-2G.qcow2|newfs-2G.qcow2|new-mod
   ```
2. 创建 `exp/new-mod/syscalls.txt`
3. 创建 `exp/new-mod/overrides.json`
4. 运行:
   ```bash
   python3 scripts/generate_config.py new-mod
   ./scripts/build_kernel.sh new-mod
   ```

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DDRD_KERNEL_SRC` | `/home/zzzccc/Linux-Kernel/DDRD-Kernel` | 内核源码路径 |
| `DDRD_TOOLCHAIN` | `/home/zzzccc/BASS/DDRD` | DDRD 编译器工具链 |
| `DDRD_LLVM` | `/home/zzzccc/llvm-15/llvm-project/build` | LLVM 构建目录 |

可在 `source scripts/envsetup.sh` 前覆盖:
```bash
export DDRD_KERNEL_SRC=/path/to/other/kernel
source scripts/envsetup.sh
```
