# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# syz-race-collector Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
CFLAGS += -I../../executor/ddrd
CFLAGS += -I../../executor

# Debug 模式
ifdef DEBUG
CFLAGS += -g -DDEBUG -O0
endif

# 源文件
SRCS = main.c collector.c analyzer.c reporter.c
OBJS = $(SRCS:.c=.o)
TARGET = syz-race-collector

# 安装目录
BINDIR = ../../bin

.PHONY: all clean install debug help

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

# 编译单个目标文件（用于调试）
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

debug:
	$(MAKE) DEBUG=1 all

clean:
	rm -f $(TARGET) $(OBJS)

install: $(TARGET)
	@mkdir -p $(BINDIR)
	cp $(TARGET) $(BINDIR)/
	@echo "Installed $(TARGET) to $(BINDIR)/"

# 帮助信息
help:
	@echo "syz-race-collector build targets:"
	@echo "  all      - Build the tool (default)"
	@echo "  debug    - Build with debug symbols and DEBUG macro"
	@echo "  install  - Build and install to bin/"
	@echo "  clean    - Remove build artifacts"
	@echo "  help     - Show this help"
	@echo ""
	@echo "Usage after building:"
	@echo "  sudo ./$(TARGET) --help"
	@echo ""
	@echo "Examples:"
	@echo "  sudo ./$(TARGET) -o races.csv &"
	@echo "  iozone -a -i 0 -i 1"
	@echo "  kill %1"
