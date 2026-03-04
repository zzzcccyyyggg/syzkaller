 # =========================================================
#  請修改成你想要的 commit 哈希值
COMMIT_HASH="09234a632be42573d9743ac5ff6773622d233ad0"
# =========================================================

# 專案的 Git URL
REPO_URL="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"

# 存放程式碼的資料夾名稱
DIR_NAME="/home/zzzccc/sbhw/linux-09234a632be42573d9743ac5ff6773622d233ad0-checkout"


# --- 開始執行 ---
echo "正在建立資料夾 ${DIR_NAME}..."
mkdir "${DIR_NAME}"
cd "${DIR_NAME}"

echo "正在初始化 Git 倉庫..."
git init
git remote add origin "${REPO_URL}"

echo "正在抓取指定的 commit: ${COMMIT_HASH}"
git fetch --depth 1 origin "${COMMIT_HASH}"

echo "正在切換到抓取下來的程式碼..."
git checkout FETCH_HEAD

echo "完成！"