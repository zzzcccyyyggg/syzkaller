#!/bin/zsh

# 同步 DDRD 文件夹到远程服务器
# 目标服务器: lwq-server (111.228.63.84)

REMOTE_USER="sonera"
REMOTE_HOST="111.228.63.84"
REMOTE_PORT="6666"
TEST_DIR="/home/zzzccc/BASS/DDRD-syzkaller/test"
REMOTE_BASE="/home/sonera/ZZZCCC/syzkaller/test"

echo "开始同步到 ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PORT}..."

# 同步 DDRD 文件夹（只包含 cfg, sh, corpus.db, corpus/）
echo "=== 同步 DDRD ==="
rsync -avz --progress \
    -e "ssh -p ${REMOTE_PORT}" \
    --include="*/" \
    --include="*.cfg" \
    --include="*.sh" \
    --include="corpus.db" \
    --include="corpus/" \
    --include="corpus/**" \
    --exclude="*" \
    "${TEST_DIR}/DDRD/" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_BASE}/DDRD/"

# 同步 fs 文件夹
echo "=== 同步 fs ==="
rsync -avz --progress \
    -e "ssh -p ${REMOTE_PORT}" \
    "${TEST_DIR}/fs/" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_BASE}/fs/"

# 同步 usb 文件夹
echo "=== 同步 usb ==="
rsync -avz --progress \
    -e "ssh -p ${REMOTE_PORT}" \
    "${TEST_DIR}/usb/" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_BASE}/usb/"

# 同步 img 文件夹（针对大镜像文件优化传输）
echo "=== 同步 img ==="
rsync -av --progress \
    --no-compress \
    --block-size=131072 \
    -e "ssh -p ${REMOTE_PORT} -c aes128-ctr -o Compression=no" \
    "${TEST_DIR}/img/" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_BASE}/img/"

if [ $? -eq 0 ]; then
    echo "全部同步完成！"
else
    echo "同步失败！"
    exit 1
fi
