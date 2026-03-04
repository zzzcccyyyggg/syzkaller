import os
import sys
import subprocess
import stat
# 工具路径
syz_db = "/home/zzzccc/go-work/syzkaller-old/syzkaller/bin/syz-db"
syz_prog2c = "/home/zzzccc/go-work/syzkaller-old/syzkaller/bin/syz-prog2c"
compiler = "gcc"  # 可换成 clang

def run_cmd(cmd, **kwargs):
    print("运行命令:", " ".join(cmd))
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        print(f"命令失败: {' '.join(cmd)}")
        sys.exit(result.returncode)

def batch_compile_c_to_bin(c_dir, bin_dir):
    os.makedirs(bin_dir, exist_ok=True)
    count = 0
    for fname in os.listdir(c_dir):
        if not fname.endswith(".c"):
            continue
        c_path = os.path.join(c_dir, fname)
        bin_name = os.path.splitext(fname)[0]
        bin_path = os.path.join(bin_dir, bin_name)
        print(f"编译: {c_path} -> {bin_path}")
        run_cmd([compiler, c_path, "-o", bin_path])
        st = os.stat(bin_path)
        os.chmod(bin_path, st.st_mode | stat.S_IEXEC | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        count += 1
    print(f"编译完成！共 {count} 个可执行文件，已输出到：{bin_dir}")

def full_pipeline(db_path, raw_dir, c_dir, bin_dir):
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(c_dir, exist_ok=True)
    os.makedirs(bin_dir, exist_ok=True)

    run_cmd([syz_db, "unpack", db_path, raw_dir])

    for fname in os.listdir(raw_dir):
        fpath = os.path.join(raw_dir, fname)
        if not os.path.isfile(fpath):
            continue
        c_out = os.path.join(c_dir, fname + ".c")
        with open(c_out, "w") as fout:
            run_cmd([syz_prog2c, "-prog", fpath], stdout=fout)

    print("C 文件已全部生成到：", c_dir)
    batch_compile_c_to_bin(c_dir, bin_dir)

if __name__ == "__main__":
    # 支持两种模式
    if len(sys.argv) == 5:
        # 全流程：corpus.db raw_dir c_dir bin_dir
        db_path = sys.argv[1]
        raw_dir = sys.argv[2]
        c_dir = sys.argv[3]
        bin_dir = sys.argv[4]
        full_pipeline(db_path, raw_dir, c_dir, bin_dir)
    elif len(sys.argv) == 3:
        # 仅编译：c_source_dir bin_dir
        c_dir = sys.argv[1]
        bin_dir = sys.argv[2]
        batch_compile_c_to_bin(c_dir, bin_dir)
    else:
        print("用法：")
        print(f"  1. python3 {sys.argv[0]} corpus.db corpus_raw_dir corpus_c_dir corpus_bin_dir")
        print(f"  2. python3 {sys.argv[0]} corpus_c_dir corpus_bin_dir   # 只编译 C 源码为 bin")
        sys.exit(1)
