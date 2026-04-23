# ============================================================================
# DDRD Experiment Workflow — 顶层 Makefile
#
# 完整工作流:
#   make setup            # 首次: 导入镜像 + 生成所有配置
#   make build-syzkaller  # 编译 syzkaller
#   make build-kernel     # 编译所有模块的内核 (耗时)
#   make build-kernel MODULES="xfs btrfs"  # 只编译指定模块
#   make config           # 生成 fuzz + validate 配置
#   make fuzz MODULES="xfs"    # 启动 xfs fuzz
#   make validate MODULES="xfs" # 启动 xfs validate
#   make status           # 查看运行状态
#   make stop             # 停止所有
#
# 快捷组合:
#   make all-xfs          # 编译+config+fuzz xfs (不含内核)
# ============================================================================

SCRIPTS := scripts
MODULES ?=

# 模块参数 (空格分隔转为命令参数)
MOD_ARGS := $(if $(MODULES),$(MODULES),)

.PHONY: help setup install-toolchain install-toolchain-min install-go install-go-dryrun build-syzkaller build-tools build-kernel config \
        fuzz fuzz-stop fuzz-status fuzz-log \
        validate validate-stop validate-status validate-log \
        corpus-stat corpus-backup corpus-import corpus-migrate \
        capability-check capability-prepare capability-start-shared capability-start-batch1 capability-start-batch2 capability-status capability-stop \
        status stop list extract-data clean-config

help:
	@echo "DDRD Experiment Workflow"
	@echo "======================="
	@echo ""
	@echo "  make install-toolchain      Ubuntu 一键安装完整工具链"
	@echo "  make install-toolchain-min  Ubuntu 一键安装最小工具链"
	@echo "  make install-go             仅安装/升级 Go 环境"
	@echo "  make install-go-dryrun      预览 Go-only 安装命令"
	@echo ""
	@echo "  make setup                 首次设置: 导入镜像 + 提取模块数据 + 生成配置"
	@echo "  make build-tools           编译 DDRD 插桩工具链 (instrumenter + compiler)"
	@echo "  make build-syzkaller       编译 DDRD-syzkaller"
	@echo "  make build-kernel          编译所有模块的内核 (shared 模式)"
	@echo '  make build-kernel MODULES="xfs btrfs"  只编译指定模块'
	@echo '  make build-kernel-isolated MODULES="xfs"  isolated 模式编译'
	@echo "  make config                生成所有 fuzz/validate 配置"
	@echo '  make config MODULES="xfs"  只生成指定模块配置'
	@echo ""
	@echo "  make fuzz MODULES=xfs      启动 fuzz"
	@echo "  make fuzz-stop             停止所有 fuzz"
	@echo "  make fuzz-status           查看 fuzz 运行状态"
	@echo "  make fuzz-log MODULES=xfs  查看 fuzz 实时日志"
	@echo ""
	@echo "  make validate MODULES=xfs  启动 validate"
	@echo "  make validate-stop         停止所有 validate"
	@echo "  make validate-status       查看 validate 运行状态"
	@echo ""
	@echo "  make corpus-stat           查看各模块 corpus 大小和状态"
	@echo "  make corpus-backup         备份所有 corpus 到 corpus-backup/"
	@echo '  make corpus-import MODULES="xfs"  从 DDRD-Corpus 导入'
	@echo "  make corpus-migrate        从旧 test/ 目录迁移 corpus"
	@echo ""
	@echo "  make capability-check      检查 8 模块 24h 主实验环境"
	@echo "  make capability-prepare    清理旧状态 + 导入统一 corpus + 重生成配置"
	@echo "  make capability-start-shared   启动 8 模块共享槽位模式"
	@echo "  make capability-start-batch1   启动严格 2+2 模式第一批"
	@echo "  make capability-start-batch2   启动严格 2+2 模式第二批"
	@echo "  make capability-status     查看 8 模块主实验状态"
	@echo "  make capability-stop       停止 8 模块主实验"
	@echo ""
	@echo "  make status                查看所有运行状态"
	@echo "  make stop                  停止所有 fuzz + validate"
	@echo "  make list                  列出可用模块"
	@echo ""

# ---- 首次设置 ----
install-toolchain:
	bash $(SCRIPTS)/install_toolchain_ubuntu.sh

install-toolchain-min:
	bash $(SCRIPTS)/install_toolchain_ubuntu.sh --minimal

install-go:
	bash $(SCRIPTS)/install_toolchain_ubuntu.sh --go-only

install-go-dryrun:
	bash $(SCRIPTS)/install_toolchain_ubuntu.sh --go-only --dry-run

setup: extract-data import-images config
	@echo "[setup] 完成! 接下来可以:"
	@echo "  1. make build-syzkaller    # 编译 fuzzer"
	@echo "  2. make build-kernel       # 编译内核 (耗时)"
	@echo "  3. make fuzz MODULES=xfs   # 开始 fuzz"

extract-data:
	python3 $(SCRIPTS)/extract_module_data.py

import-images:
	bash $(SCRIPTS)/create_image.sh --import

# ---- 编译 ----
build-tools:
	bash $(SCRIPTS)/build_ddrd_tools.sh

build-tools-compiler:
	bash $(SCRIPTS)/build_ddrd_tools.sh compiler

build-syzkaller:
	bash $(SCRIPTS)/build_syzkaller.sh

build-kernel:
	bash $(SCRIPTS)/build_kernel.sh $(MOD_ARGS)

build-kernel-isolated:
	bash $(SCRIPTS)/build_kernel.sh --mode=isolated $(MOD_ARGS)

build-kernel-clean:
	bash $(SCRIPTS)/build_kernel.sh --no-clean $(MOD_ARGS)

# ---- 配置 ----
config:
	@if [ -n "$(MOD_ARGS)" ]; then \
		python3 $(SCRIPTS)/generate_config.py --force $(MOD_ARGS); \
	else \
		python3 $(SCRIPTS)/generate_config.py --all --force; \
	fi

clean-config:
	find exp -name "fuzz.cfg" -o -name "validate.cfg" | xargs rm -f
	@echo "已清理所有生成的配置文件"

# ---- Fuzz ----
fuzz:
	@if [ -z "$(MOD_ARGS)" ]; then \
		echo "请指定模块: make fuzz MODULES=xfs"; exit 1; \
	fi
	bash $(SCRIPTS)/run_fuzz.sh start $(MOD_ARGS)

fuzz-all:
	bash $(SCRIPTS)/run_fuzz.sh start --all

fuzz-stop:
	@if [ -n "$(MOD_ARGS)" ]; then \
		bash $(SCRIPTS)/run_fuzz.sh stop $(MOD_ARGS); \
	else \
		bash $(SCRIPTS)/run_fuzz.sh stop; \
	fi

fuzz-status:
	bash $(SCRIPTS)/run_fuzz.sh status

fuzz-log:
	@if [ -z "$(MOD_ARGS)" ]; then \
		echo "请指定模块: make fuzz-log MODULES=xfs"; exit 1; \
	fi
	bash $(SCRIPTS)/run_fuzz.sh log $(firstword $(MOD_ARGS))

# ---- Validate ----
validate:
	@if [ -z "$(MOD_ARGS)" ]; then \
		echo "请指定模块: make validate MODULES=xfs"; exit 1; \
	fi
	bash $(SCRIPTS)/run_validate.sh start $(MOD_ARGS)

validate-all:
	bash $(SCRIPTS)/run_validate.sh start --all

validate-stop:
	@if [ -n "$(MOD_ARGS)" ]; then \
		bash $(SCRIPTS)/run_validate.sh stop $(MOD_ARGS); \
	else \
		bash $(SCRIPTS)/run_validate.sh stop; \
	fi

validate-status:
	bash $(SCRIPTS)/run_validate.sh status

validate-log:
	@if [ -z "$(MOD_ARGS)" ]; then \
		echo "请指定模块: make validate-log MODULES=xfs"; exit 1; \
	fi
	bash $(SCRIPTS)/run_validate.sh log $(firstword $(MOD_ARGS))

# ---- Corpus 管理 ----
corpus-stat:
	bash $(SCRIPTS)/manage_corpus.sh stat $(MOD_ARGS)

corpus-backup:
	bash $(SCRIPTS)/manage_corpus.sh backup --include-uaf $(MOD_ARGS)

corpus-import:
	@if [ -n "$(MOD_ARGS)" ]; then \
		bash $(SCRIPTS)/manage_corpus.sh import --force $(MOD_ARGS); \
	else \
		bash $(SCRIPTS)/manage_corpus.sh import --force; \
	fi

corpus-migrate:
	bash $(SCRIPTS)/manage_corpus.sh migrate --include-uaf --force

# ---- 8 模块 24h 主实验 ----
capability-check:
	bash $(SCRIPTS)/run_capability_24h.sh check

capability-prepare:
	bash $(SCRIPTS)/run_capability_24h.sh prepare

capability-start-shared:
	bash $(SCRIPTS)/run_capability_24h.sh start-shared

capability-start-batch1:
	bash $(SCRIPTS)/run_capability_24h.sh start-batch1

capability-start-batch2:
	bash $(SCRIPTS)/run_capability_24h.sh start-batch2

capability-status:
	bash $(SCRIPTS)/run_capability_24h.sh status

capability-stop:
	bash $(SCRIPTS)/run_capability_24h.sh stop

# ---- 通用 ----
status:
	@echo "===== Fuzz ======"
	@bash $(SCRIPTS)/run_fuzz.sh status 2>/dev/null || true
	@echo ""
	@echo "===== Validate ====="
	@bash $(SCRIPTS)/run_validate.sh status 2>/dev/null || true

stop: fuzz-stop validate-stop

list:
	@python3 $(SCRIPTS)/generate_config.py --list 2>/dev/null || \
		(echo "可用模块:" && ls -d exp/*/syscalls.txt 2>/dev/null | xargs -I{} dirname {} | xargs -I{} basename {} | sort | sed 's/^/  /')
