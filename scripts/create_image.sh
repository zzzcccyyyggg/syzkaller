#!/usr/bin/env bash
# ============================================================================
# create_image.sh — DDRD 镜像全生命周期管理
#
# 用法:
#   ./scripts/create_image.sh                        # 显示帮助
#   ./scripts/create_image.sh --import               # 从 test/fs/ 导入现有镜像
#   ./scripts/create_image.sh --create-rootfs         # 从零创建 Debian rootfs 镜像
#   ./scripts/create_image.sh --create-rootfs --size 20G --mirror aliyun
#   ./scripts/create_image.sh --create-fs xfs 2G     # 创建 2G 的 xfs 文件系统镜像
#   ./scripts/create_image.sh --create-all            # 一键创建 rootfs + 全部 fs 镜像
#   ./scripts/create_image.sh --fix-kccwf             # 统一修复镜像中的 kccwf.service
#   ./scripts/create_image.sh --fix-kccwf /path/to/some.img  # 修复指定镜像
#   ./scripts/create_image.sh --verify                # 验证所有镜像完整性
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/envsetup.sh"
source "$SCRIPT_DIR/functions.sh"

ACTION="${1:-help}"

OLD_FS_DIR="$PROJECT_HOME/test/fs"

# ============================================================================
# 创建 rootfs 相关常量
# ============================================================================
RELEASE="bookworm"
DEFAULT_SIZE="20G"

# 镜像源
declare -A MIRRORS=(
    [tsinghua]="http://mirrors.tuna.tsinghua.edu.cn/debian/"
    [ustc]="http://mirrors.ustc.edu.cn/debian/"
    [aliyun]="http://mirrors.aliyun.com/debian/"
    [official]="http://deb.debian.org/debian"
)
DEFAULT_MIRROR="tsinghua"

# syzkaller 必需的基础包
PREINSTALL_PKGS="openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less"
PREINSTALL_PKGS+=",psmisc,selinux-utils,policycoreutils,checkpolicy"
PREINSTALL_PKGS+=",selinux-policy-default,firmware-atheros"
PREINSTALL_PKGS+=",debian-ports-archive-keyring"
# 额外实用包
EXTRA_PKGS="make,g++,cmake,openssl,fio,util-linux"

# 所有需要创建的文件系统类型 (从 modules.conf 中提取有 FS_IMAGE 的)
ALL_FS_TYPES=(xfs btrfs f2fs jfs ext4)
DEFAULT_FS_SIZE="2G"

do_import() {
    log_info "从 $OLD_FS_DIR 导入镜像到 $KERNEL_IMAGES_DIR"

    # 主镜像 (统一使用 bookworm.img)
    for f in bookworm.img; do
        src="$OLD_FS_DIR/$f"
        dst="$KERNEL_IMAGES_DIR/$f"
        if [[ -f "$src" ]]; then
            if [[ -f "$dst" ]]; then
                log_warn "  已存在: $f (跳过, 使用 --force 覆盖)"
            else
                ln -s "$src" "$dst" 2>/dev/null || cp "$src" "$dst"
                log_ok "  $f"
            fi
        fi
    done

    # SSH key — 复制而非符号链接, 修正权限
    for f in bookworm.id_rsa bookworm.id_rsa.pub; do
        src="$OLD_FS_DIR/$f"
        dst="$KERNEL_IMAGES_DIR/$f"
        if [[ -f "$src" ]]; then
            if [[ -f "$dst" && ! -L "$dst" ]]; then
                log_warn "  已存在: $f (跳过)"
            else
                rm -f "$dst"
                sudo cp "$src" "$dst"
                sudo chown "$(id -u):$(id -g)" "$dst"
                [[ "$f" == *.pub ]] && chmod 644 "$dst" || chmod 600 "$dst"
                log_ok "  $f (已修正权限)"
            fi
        fi
    done

    # 文件系统镜像
    for f in "$OLD_FS_DIR"/*-2G.qcow2 "$OLD_FS_DIR"/*-2G.raw "$OLD_FS_DIR"/floppy.img \
             "$OLD_FS_DIR"/btrfs.qcow2 "$OLD_FS_DIR"/btrfs.img; do
        [[ -f "$f" ]] || continue
        name=$(basename "$f")
        dst="$KERNEL_IMAGES_DIR/$name"
        [[ -f "$dst" ]] && continue
        ln -s "$f" "$dst" 2>/dev/null || cp "$f" "$dst"
        log_ok "  $name"
    done

    # validate 用的 snapshot 镜像
    for f in "$OLD_FS_DIR"/bookworm-validate-*.qcow2; do
        [[ -f "$f" ]] || continue
        name=$(basename "$f")
        dst="$KERNEL_IMAGES_DIR/$name"
        [[ -f "$dst" ]] && continue
        ln -s "$f" "$dst" 2>/dev/null || cp "$f" "$dst"
        log_ok "  $name"
    done

    log_ok "导入完成"
    ls -lh "$KERNEL_IMAGES_DIR/"
}

# ============================================================================
# 从零创建 Debian rootfs 镜像
# ============================================================================
do_create_rootfs() {
    local img_size="$DEFAULT_SIZE"
    local mirror_key="$DEFAULT_MIRROR"
    local proxy=""
    local force=false
    local with_extra=true

    # 解析参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --size)     img_size="$2"; shift 2 ;;
            --mirror)   mirror_key="$2"; shift 2 ;;
            --proxy)    proxy="$2"; shift 2 ;;
            --force)    force=true; shift ;;
            --minimal)  with_extra=false; shift ;;
            *)          die "create-rootfs: 未知参数 $1" ;;
        esac
    done

    local mirror_url="${MIRRORS[$mirror_key]:-}"
    [[ -n "$mirror_url" ]] || die "未知镜像源: $mirror_key (可选: ${!MIRRORS[*]})"

    local dst_img="$KERNEL_IMAGES_DIR/${RELEASE}.img"
    local dst_key="$KERNEL_IMAGES_DIR/${RELEASE}.id_rsa"

    if [[ -f "$dst_img" && "$force" != true ]]; then
        die "$dst_img 已存在 (使用 --force 覆盖)"
    fi

    # 依赖检查
    for cmd in debootstrap qemu-img mkfs.ext4 ssh-keygen; do
        command -v "$cmd" &>/dev/null || die "缺少命令: $cmd (请先安装)"
    done

    # 设置代理
    if [[ -n "$proxy" ]]; then
        export http_proxy="$proxy" https_proxy="$proxy"
        log_info "使用代理: $proxy"
    fi

    # 包列表
    local pkgs="$PREINSTALL_PKGS"
    if [[ "$with_extra" == true ]]; then
        pkgs="${pkgs},${EXTRA_PKGS}"
    fi

    local work_dir
    work_dir=$(mktemp -d)
    local bootstrap_dir="$work_dir/$RELEASE"
    local mnt_dir="$work_dir/mnt"

    log_info "========================================="
    log_info " 创建 Debian $RELEASE rootfs 镜像"
    log_info " 大小: $img_size"
    log_info " 镜像源: $mirror_key ($mirror_url)"
    log_info " 包含额外包: $with_extra"
    log_info " 工作目录: $work_dir"
    log_info "========================================="

    # 清理函数
    _cleanup_rootfs() {
        sudo umount "$mnt_dir" 2>/dev/null || true
        sudo rm -rf "$work_dir"
    }
    trap _cleanup_rootfs EXIT

    # ------- Step 1: debootstrap -------
    log_info "[1/6] debootstrap ($RELEASE)..."
    sudo mkdir -p "$bootstrap_dir"
    sudo chmod 0755 "$bootstrap_dir"

    local deboot_args="--arch=amd64 --include=$pkgs"
    deboot_args+=" --components=main,contrib,non-free,non-free-firmware"
    deboot_args+=" $RELEASE $bootstrap_dir $mirror_url"

    local ret=0
    sudo debootstrap $deboot_args || ret=$?

    # 失败时尝试备用源
    if [[ $ret -ne 0 && "$mirror_key" != "aliyun" ]]; then
        log_warn "debootstrap 失败, 尝试阿里云镜像..."
        sudo rm -rf "$bootstrap_dir"
        sudo mkdir -p "$bootstrap_dir"
        deboot_args="--arch=amd64 --include=$pkgs"
        deboot_args+=" --components=main,contrib,non-free,non-free-firmware"
        deboot_args+=" $RELEASE $bootstrap_dir ${MIRRORS[aliyun]}"
        sudo debootstrap $deboot_args || die "debootstrap 全部失败"
    elif [[ $ret -ne 0 ]]; then
        die "debootstrap 失败 (exit $ret)"
    fi
    log_ok "[1/6] debootstrap 完成"

    # ------- Step 2: 配置系统 -------
    log_info "[2/6] 配置系统..."

    # root 无密码 (syzkaller 需要)
    sudo sed -i '/^root/ { s/:x:/::/ }' "$bootstrap_dir/etc/passwd"

    # 串口控制台 (syzkaller/QEMU -nographic 需要)
    echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | \
        sudo tee -a "$bootstrap_dir/etc/inittab" > /dev/null

    # 网络 — 兼容 net.ifnames=0 (eth0) 和 predictable 命名 (enp0sX)
    cat <<'IFACE_EOF' | sudo tee "$bootstrap_dir/etc/network/interfaces" > /dev/null
# interfaces(5) file used by ifup(8) and ifdown(8)
source /etc/network/interfaces.d/*

allow-hotplug eth0
iface eth0 inet dhcp

allow-hotplug enp0s4
iface enp0s4 inet dhcp

allow-hotplug enp0s5
iface enp0s5 inet dhcp
IFACE_EOF

    # fstab — syzkaller 需要 debugfs; 虚拟文件系统加 nofail 防止 emergency mode
    cat <<'FSTAB_EOF' | sudo tee "$bootstrap_dir/etc/fstab" > /dev/null
/dev/root / ext4 defaults 0 0
debugfs /sys/kernel/debug debugfs defaults,nofail 0 0
securityfs /sys/kernel/security securityfs defaults,nofail 0 0
configfs /sys/kernel/config/ configfs defaults,nofail 0 0
binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults,nofail 0 0
FSTAB_EOF

    # DNS
    echo "nameserver 8.8.8.8" | sudo tee "$bootstrap_dir/etc/resolv.conf" > /dev/null
    echo -e "127.0.0.1\tlocalhost" | sudo tee "$bootstrap_dir/etc/hosts" > /dev/null
    echo "ccwf" | sudo tee "$bootstrap_dir/etc/hostname" > /dev/null

    # udev 规则 (vim2m 设备)
    echo 'ATTR{name}=="vim2m", SYMLINK+="vim2m"' | \
        sudo tee -a "$bootstrap_dir/etc/udev/rules.d/50-udev-default.rules" > /dev/null

    # kccwf.service — 挂载第二块磁盘
    sudo mkdir -p "$bootstrap_dir/mnt/kccwf"
    cat <<'SVC_EOF' | sudo tee "$bootstrap_dir/etc/systemd/system/kccwf.service" > /dev/null
[Unit]
Description=Mount /dev/sdb to /mnt/kccwf
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/mount /dev/sdb /mnt/kccwf
ExecStop=/usr/bin/umount /mnt/kccwf
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
SVC_EOF
    sudo chroot "$bootstrap_dir" systemctl enable kccwf.service 2>/dev/null || true

    log_ok "[2/6] 系统配置完成"

    # ------- Step 3: SSH key -------
    log_info "[3/6] 生成 SSH 密钥..."
    local key_path="$work_dir/${RELEASE}.id_rsa"
    ssh-keygen -f "$key_path" -t rsa -N '' -q
    sudo mkdir -p "$bootstrap_dir/root/.ssh"
    sudo cp "${key_path}.pub" "$bootstrap_dir/root/.ssh/authorized_keys"
    sudo chmod 700 "$bootstrap_dir/root/.ssh"
    sudo chmod 600 "$bootstrap_dir/root/.ssh/authorized_keys"
    log_ok "[3/6] SSH 密钥生成完成"

    # ------- Step 4: 构建磁盘镜像 -------
    log_info "[4/6] 构建磁盘镜像 ($img_size)..."
    local raw_img="$work_dir/${RELEASE}.img"
    local seek_mb
    seek_mb=$(parse_size_to_mb "$img_size")
    dd if=/dev/zero of="$raw_img" bs=1M seek=$((seek_mb - 1)) count=1 status=none
    sudo mkfs.ext4 -F "$raw_img" > /dev/null 2>&1
    mkdir -p "$mnt_dir"
    sudo mount -o loop "$raw_img" "$mnt_dir"
    sudo cp -a "$bootstrap_dir/." "$mnt_dir/."
    sudo umount "$mnt_dir"
    log_ok "[4/6] 磁盘镜像构建完成"

    # ------- Step 5: 安装到 images/ -------
    log_info "[5/6] 安装镜像到 $KERNEL_IMAGES_DIR/..."
    [[ "$force" == true ]] && rm -f "$dst_img" "$dst_key" "${dst_key}.pub"

    sudo mv "$raw_img" "$dst_img"
    sudo chown "$(id -u):$(id -g)" "$dst_img"
    chmod 644 "$dst_img"

    cp "$key_path" "$dst_key"
    cp "${key_path}.pub" "${dst_key}.pub"
    chmod 600 "$dst_key"
    chmod 644 "${dst_key}.pub"
    log_ok "[5/6] 安装完成"

    # ------- Step 6: 验证 -------
    log_info "[6/6] 验证镜像..."
    local img_actual_size
    img_actual_size=$(du -h "$dst_img" | cut -f1)
    log_ok "  rootfs:  $dst_img ($img_actual_size)"
    log_ok "  私钥:    $dst_key"
    log_ok "  公钥:    ${dst_key}.pub"

    # 快速 mount 验证
    local verify_dir
    verify_dir=$(mktemp -d)
    if sudo mount -o loop,ro "$dst_img" "$verify_dir" 2>/dev/null; then
        local has_ssh=false has_fstab=false has_iface=false
        [[ -f "$verify_dir/root/.ssh/authorized_keys" ]] && has_ssh=true
        [[ -f "$verify_dir/etc/fstab" ]] && has_fstab=true
        [[ -f "$verify_dir/etc/network/interfaces" ]] && has_iface=true
        sudo umount "$verify_dir"

        $has_ssh   && log_ok "  ✓ SSH authorized_keys" || log_error "  ✗ SSH authorized_keys 缺失"
        $has_fstab && log_ok "  ✓ fstab (debugfs)" || log_error "  ✗ fstab 缺失"
        $has_iface && log_ok "  ✓ network/interfaces" || log_error "  ✗ network/interfaces 缺失"
    else
        log_warn "  跳过 mount 验证"
    fi
    rmdir "$verify_dir" 2>/dev/null

    trap - EXIT
    sudo rm -rf "$work_dir"

    echo
    log_ok "========================================="
    log_ok " rootfs 镜像创建成功!"
    log_ok " 镜像:  $dst_img"
    log_ok " SSH:   $dst_key"
    log_ok "========================================="
}

# MB 大小解析: "20G" -> 20480, "2G" -> 2048, "512M" -> 512
parse_size_to_mb() {
    local s="$1"
    if [[ "$s" =~ ^([0-9]+)[Gg]$ ]]; then
        echo $(( ${BASH_REMATCH[1]} * 1024 ))
    elif [[ "$s" =~ ^([0-9]+)[Mm]$ ]]; then
        echo "${BASH_REMATCH[1]}"
    elif [[ "$s" =~ ^([0-9]+)$ ]]; then
        echo "$s"
    else
        die "无法解析大小: $s (示例: 2G, 512M, 2048)"
    fi
}

do_create_fs() {
    local fstype="${1:-xfs}"
    local size="${2:-$DEFAULT_FS_SIZE}"
    local name="${fstype}-${size}.qcow2"
    local raw_name="${fstype}-${size}.raw"
    local dst="$KERNEL_IMAGES_DIR/$name"

    if [[ -f "$dst" ]]; then
        log_warn "$name 已存在 (跳过)"
        return
    fi

    # 依赖检查
    command -v qemu-img &>/dev/null || die "缺少 qemu-img, 请安装 qemu-utils"
    local mkfs_cmd
    case "$fstype" in
        xfs)    mkfs_cmd="mkfs.xfs -f" ;;
        btrfs)  mkfs_cmd="mkfs.btrfs -f" ;;
        f2fs)   mkfs_cmd="mkfs.f2fs -f" ;;
        ext4)   mkfs_cmd="mkfs.ext4 -F" ;;
        jfs)    mkfs_cmd="mkfs.jfs -q" ;;
        *)      die "不支持的文件系统: $fstype (支持: xfs btrfs f2fs jfs ext4)" ;;
    esac

    command -v ${mkfs_cmd%% *} &>/dev/null || \
        die "缺少 ${mkfs_cmd%% *}, 请安装对应的 mkfs 工具"

    local raw_path="$KERNEL_IMAGES_DIR/$raw_name"
    log_info "创建 $raw_name ($size)..."
    truncate -s "$size" "$raw_path"
    $mkfs_cmd "$raw_path" > /dev/null 2>&1

    log_info "转换为 qcow2..."
    qemu-img convert -f raw -O qcow2 "$raw_path" "$dst"
    rm -f "$raw_path"

    local final_size
    final_size=$(du -h "$dst" | cut -f1)
    log_ok "$name 创建完成 ($final_size)"
}

# ============================================================================
# 一键创建全部: rootfs + 所有文件系统镜像
# ============================================================================
do_create_all() {
    local rootfs_args=()
    local fs_size="$DEFAULT_FS_SIZE"
    local skip_rootfs=false

    # 解析参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --fs-size)      fs_size="$2"; shift 2 ;;
            --skip-rootfs)  skip_rootfs=true; shift ;;
            *)              rootfs_args+=("$1"); shift ;;
        esac
    done

    echo
    log_info "╔════════════════════════════════════════╗"
    log_info "║     一键创建全部镜像                   ║"
    log_info "╚════════════════════════════════════════╝"
    echo

    # Step 1: rootfs
    if [[ "$skip_rootfs" == true ]]; then
        log_info "[SKIP] rootfs 创建 (--skip-rootfs)"
    else
        local rootfs_img="$KERNEL_IMAGES_DIR/${RELEASE}.img"
        if [[ -f "$rootfs_img" ]]; then
            log_info "[SKIP] rootfs 已存在: $rootfs_img (使用 --force 重建)"
        else
            log_info "===== 创建 rootfs 镜像 ====="
            do_create_rootfs "${rootfs_args[@]}"
        fi
    fi

    echo
    log_info "===== 创建文件系统镜像 ====="

    # Step 2: 所有文件系统镜像
    local created=0 skipped=0
    for fs in "${ALL_FS_TYPES[@]}"; do
        local name="${fs}-${fs_size}.qcow2"
        if [[ -f "$KERNEL_IMAGES_DIR/$name" ]]; then
            log_info "  [SKIP] $name (已存在)"
            ((skipped++))
        else
            do_create_fs "$fs" "$fs_size"
            ((created++))
        fi
    done

    echo
    log_ok "========================================="
    log_ok " 全部完成! 新建 $created, 跳过 $skipped"
    log_ok " 镜像目录: $KERNEL_IMAGES_DIR/"
    log_ok "========================================="
    echo
    ls -lhS "$KERNEL_IMAGES_DIR/"
}

# ============================================================================
# 验证镜像完整性
# ============================================================================
do_verify() {
    log_info "验证镜像完整性..."
    local errors=0

    # 1. rootfs
    local rootfs="$KERNEL_IMAGES_DIR/${RELEASE}.img"
    if [[ -f "$rootfs" ]]; then
        local real_rootfs
        real_rootfs=$(readlink -f "$rootfs")
        local rootfs_size
        rootfs_size=$(du -h "$real_rootfs" | cut -f1)
        log_ok "rootfs:     $rootfs ($rootfs_size)"
    else
        log_error "rootfs:     $rootfs 不存在"
        ((errors++))
    fi

    # 2. SSH key
    local key="$KERNEL_IMAGES_DIR/${RELEASE}.id_rsa"
    if [[ -f "$key" && -r "$key" ]]; then
        log_ok "SSH key:    $key (可读)"
    elif [[ -f "$key" ]]; then
        log_error "SSH key:    $key (存在但当前用户不可读!)"
        ((errors++))
    else
        log_error "SSH key:    $key 不存在"
        ((errors++))
    fi

    # 3. 文件系统镜像
    for fs in "${ALL_FS_TYPES[@]}"; do
        local name="${fs}-${DEFAULT_FS_SIZE}.qcow2"
        local path="$KERNEL_IMAGES_DIR/$name"
        if [[ -f "$path" ]]; then
            local fs_size
            fs_size=$(du -h "$(readlink -f "$path")" | cut -f1)
            log_ok "fs 镜像:    $name ($fs_size)"
        else
            log_warn "fs 镜像:    $name 不存在"
        fi
    done

    # 4. rootfs 内容检查
    if [[ -f "$rootfs" ]]; then
        local verify_dir
        verify_dir=$(mktemp -d)
        if sudo mount -o loop,ro "$(readlink -f "$rootfs")" "$verify_dir" 2>/dev/null; then
            local checks=(
                "/root/.ssh/authorized_keys:SSH authorized_keys"
                "/etc/fstab:fstab"
                "/etc/network/interfaces:network/interfaces"
                "/etc/systemd/system/kccwf.service:kccwf.service"
                "/usr/sbin/sshd:sshd"
            )
            for check in "${checks[@]}"; do
                local path="${check%%:*}"
                local label="${check#*:}"
                if [[ -e "$verify_dir$path" ]]; then
                    log_ok "  内容:     ✓ $label"
                else
                    log_warn "  内容:     ✗ $label 缺失"
                fi
            done

            # 检查 eth0 配置
            if grep -q "eth0" "$verify_dir/etc/network/interfaces" 2>/dev/null; then
                log_ok "  网络:     ✓ eth0 (net.ifnames=0 兼容)"
            else
                log_warn "  网络:     ✗ 未配置 eth0 (需要 --fix-kccwf)"
                ((errors++))
            fi

            sudo umount "$verify_dir"
        else
            log_warn "  无法挂载 rootfs 进行内容检查 (需要 sudo)"
        fi
        rmdir "$verify_dir" 2>/dev/null
    fi

    echo
    if [[ $errors -eq 0 ]]; then
        log_ok "全部验证通过"
    else
        log_error "发现 $errors 个问题"
    fi
}

# ============================================================================
# kccwf.service + network 修复 (保留原有逻辑)
# ============================================================================

KCCWF_SERVICE_CONTENT='[Unit]
Description=Mount /dev/sdb to /mnt/kccwf
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/mount /dev/sdb /mnt/kccwf
ExecStop=/usr/bin/umount /mnt/kccwf
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target'

NETWORK_INTERFACES_CONTENT='# interfaces(5) file used by ifup(8) and ifdown(8)
# Include files from /etc/network/interfaces.d:
source /etc/network/interfaces.d/*

# 兼容 net.ifnames=0 (传统命名 eth0) 和 predictable 命名 (enp0sX)
# allow-hotplug: 硬件存在才尝试, 不存在静默跳过
allow-hotplug eth0
iface eth0 inet dhcp

allow-hotplug enp0s4
iface enp0s4 inet dhcp

allow-hotplug enp0s5
iface enp0s5 inet dhcp'

do_fix_kccwf() {
    local target_imgs=()

    if [[ $# -gt 0 ]]; then
        target_imgs=("$@")
    else
        for f in "$OLD_FS_DIR"/bookworm*.img "$KERNEL_IMAGES_DIR"/bookworm*.img; do
            [[ -f "$f" ]] || continue
            local real
            real=$(readlink -f "$f")
            local found=false
            for existing in "${target_imgs[@]:-}"; do
                [[ "$(readlink -f "$existing")" == "$real" ]] && { found=true; break; }
            done
            $found || target_imgs+=("$real")
        done
    fi

    if [[ ${#target_imgs[@]} -eq 0 ]]; then
        die "未找到 bookworm*.img 镜像"
    fi

    local mnt_point
    mnt_point=$(mktemp -d)
    trap "sudo umount '$mnt_point' 2>/dev/null; rmdir '$mnt_point' 2>/dev/null" RETURN

    for img in "${target_imgs[@]}"; do
        log_info "修复: $img"
        sudo mount -o loop "$img" "$mnt_point" || { log_error "  挂载失败: $img"; continue; }

        # 修复 kccwf.service
        local svc="$mnt_point/etc/systemd/system/kccwf.service"
        if [[ -f "$svc" ]]; then
            local old_content
            old_content=$(cat "$svc")
            echo "$KCCWF_SERVICE_CONTENT" | sudo tee "$svc" > /dev/null
            if [[ "$old_content" != "$KCCWF_SERVICE_CONTENT" ]]; then
                log_ok "  kccwf.service 已更新"
            else
                log_info "  kccwf.service 已是最新"
            fi
        else
            log_warn "  无 kccwf.service, 跳过"
        fi

        # 修复 network/interfaces
        local iface="$mnt_point/etc/network/interfaces"
        if [[ -f "$iface" ]]; then
            local old_iface
            old_iface=$(cat "$iface")
            echo "$NETWORK_INTERFACES_CONTENT" | sudo tee "$iface" > /dev/null
            if [[ "$old_iface" != "$NETWORK_INTERFACES_CONTENT" ]]; then
                log_ok "  network/interfaces 已更新 (兼容 eth0/enp0s4/enp0s5)"
            else
                log_info "  network/interfaces 已是最新"
            fi
        fi

        sudo mkdir -p "$mnt_point/mnt/kccwf"
        sudo umount "$mnt_point"
        log_ok "  完成: $(basename "$img")"
    done
}

# ============================================================================
# 帮助信息
# ============================================================================
do_help() {
    cat <<'HELP'
create_image.sh — DDRD 镜像全生命周期管理

用法:
  ./scripts/create_image.sh <命令> [参数...]

命令:
  --create-rootfs [选项]     从零创建 Debian bookworm rootfs 镜像
      --size <大小>            镜像大小 (默认 20G)
      --mirror <源>            镜像源: tsinghua/ustc/aliyun/official (默认 tsinghua)
      --proxy <URL>            HTTP 代理 (如 http://127.0.0.1:7890)
      --minimal                不安装额外包 (仅 syzkaller 必需)
      --force                  覆盖已有镜像

  --create-fs <类型> [大小]  创建文件系统镜像
      类型: xfs, btrfs, f2fs, jfs, ext4
      大小: 默认 2G

  --create-all [选项]        一键创建 rootfs + 全部文件系统镜像
      --skip-rootfs            跳过 rootfs 创建
      --fs-size <大小>         文件系统镜像大小 (默认 2G)
      (其余选项传递给 --create-rootfs)

  --import                   从 test/fs/ 导入已有镜像到 images/
  --fix-kccwf [镜像...]      修复 kccwf.service + 网络配置
  --verify                   验证所有镜像完整性

示例:
  # 最简单: 一键创建全部
  sudo ./scripts/create_image.sh --create-all

  # 指定镜像源和代理
  sudo ./scripts/create_image.sh --create-rootfs --mirror aliyun --proxy http://127.0.0.1:7890

  # 只创建文件系统镜像 (rootfs 已存在)
  ./scripts/create_image.sh --create-all --skip-rootfs

  # 单独创建 xfs 镜像
  ./scripts/create_image.sh --create-fs xfs 2G

  # 验证
  sudo ./scripts/create_image.sh --verify
HELP
}

# ============================================================================
# 入口
# ============================================================================
case "$ACTION" in
    --import)
        do_import
        ;;
    --create-rootfs)
        shift
        do_create_rootfs "$@"
        ;;
    --create-fs)
        shift
        do_create_fs "$@"
        ;;
    --create-all)
        shift
        do_create_all "$@"
        ;;
    --fix-kccwf)
        shift
        do_fix_kccwf "$@"
        ;;
    --verify)
        do_verify
        ;;
    help|--help|-h)
        do_help
        ;;
    *)
        die "未知命令: $ACTION (使用 --help 查看帮助)"
        ;;
esac
