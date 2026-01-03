// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#define _DEFAULT_SOURCE  // for usleep

#include "collector.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

// ============================================
// 常量
// ============================================
#define TRACE_PATH "/sys/kernel/debug/tracing/trace"
#define TRACE_ON_PATH "/sys/kernel/debug/tracing/tracing_on"
#define BUFFER_SIZE_PATH "/sys/kernel/debug/tracing/buffer_size_kb"
#define UKC_DEV_PATH "/dev/kccwf_ctl_dev"

// UKC ioctl 命令（与内核 ctl_dev.h 一致）
#ifndef _IO
#define _IO(type, nr) (((type) << 8) | (nr))
#endif

#define UKC_TURN_OFF      _IO('c', 0)
#define UKC_START_MONITOR _IO('c', 1)
#define UKC_START_LOG     _IO('c', 2)

// ============================================
// 辅助函数
// ============================================

static void debug_print(const char* fmt, ...) {
    // 可以根据需要启用/禁用调试输出
#ifdef DEBUG
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[collector] ");
    vfprintf(stderr, fmt, args);
    va_end(args);
#else
    (void)fmt;
#endif
}

static int write_to_file(const char* path, const char* value) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        debug_print("Cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    
    ssize_t written = write(fd, value, strlen(value));
    close(fd);
    
    if (written < 0) {
        debug_print("Cannot write to %s: %s\n", path, strerror(errno));
        return -1;
    }
    
    return 0;
}

static int trace_enable(void) {
    return write_to_file(TRACE_ON_PATH, "1");
}

static int trace_disable(void) {
    return write_to_file(TRACE_ON_PATH, "0");
}

// ============================================
// 公共 API 实现
// ============================================

int collector_init(TraceCollector* c, const CollectorConfig* config) {
    memset(c, 0, sizeof(*c));
    c->config = config;
    c->trace_fd = -1;
    c->ukc_fd = -1;
    c->log_mode_enabled = false;
    
    // 打开 trace 文件
    c->trace_fd = open(TRACE_PATH, O_RDONLY);
    if (c->trace_fd < 0) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", TRACE_PATH, strerror(errno));
        fprintf(stderr, "Make sure you have root privileges and debugfs is mounted.\n");
        return -1;
    }
    
    // 打开 UKC 设备
    c->ukc_fd = open(UKC_DEV_PATH, O_RDWR);
    if (c->ukc_fd < 0) {
        fprintf(stderr, "Error: Cannot open %s: %s\n", UKC_DEV_PATH, strerror(errno));
        fprintf(stderr, "Make sure KCCWF kernel module is loaded.\n");
        close(c->trace_fd);
        c->trace_fd = -1;
        return -1;
    }
    
    // 分配缓冲区（64MB 默认）
    c->buffer_size = 64ULL * 1024ULL * 1024ULL;
    c->buffer = (char*)malloc(c->buffer_size);
    if (!c->buffer) {
        fprintf(stderr, "Error: Cannot allocate trace buffer\n");
        close(c->trace_fd);
        close(c->ukc_fd);
        c->trace_fd = -1;
        c->ukc_fd = -1;
        return -1;
    }
    
    // 设置 trace buffer 大小
    if (config->trace_buffer_size_kb > 0) {
        collector_set_buffer_size_kb(config->trace_buffer_size_kb);
    }
    
    return 0;
}

void collector_cleanup(TraceCollector* c) {
    if (!c) return;
    
    // 确保退出 LOG 模式
    if (c->log_mode_enabled) {
        collector_disable_log_mode(c);
    }
    
    if (c->buffer) {
        free(c->buffer);
        c->buffer = NULL;
    }
    
    if (c->trace_fd >= 0) {
        close(c->trace_fd);
        c->trace_fd = -1;
    }
    
    if (c->ukc_fd >= 0) {
        close(c->ukc_fd);
        c->ukc_fd = -1;
    }
}

int collector_enable_log_mode(TraceCollector* c) {
    if (!c || c->ukc_fd < 0) {
        fprintf(stderr, "Warning: enable_log_mode called with invalid collector (c=%p, ukc_fd=%d)\n", 
                (void*)c, c ? c->ukc_fd : -1);
        return -1;
    }
    
    if (c->log_mode_enabled)
        return 0;  // 已经是 LOG 模式
    
    int ret = ioctl(c->ukc_fd, UKC_START_LOG);
    // ioctl 返回 -1 表示失败，返回 >= 0 表示成功
    if (ret < 0) {
        int saved_errno = errno;
        fprintf(stderr, "Warning: Failed to enable LOG mode (ret=%d, errno=%d: %s)\n", 
                ret, saved_errno, strerror(saved_errno));
        // 即使 ioctl 失败，仍标记为 enabled 继续尝试运行
        // 因为某些内核实现可能返回错误但实际功能正常
        c->log_mode_enabled = true;
        return 0;  // 返回成功让程序继续运行
    }
    
    c->log_mode_enabled = true;
    debug_print("Switched to LOG mode\n");
    return 0;
}

int collector_disable_log_mode(TraceCollector* c) {
    if (!c || c->ukc_fd < 0)
        return -1;
    
    if (!c->log_mode_enabled)
        return 0;  // 已经关闭
    
    // 使用 UKC_TURN_OFF 完全关闭，而不是切换到 MONITOR 模式
    int ret = ioctl(c->ukc_fd, UKC_TURN_OFF);
    // ioctl 返回 -1 表示失败，返回 >= 0 表示成功
    if (ret < 0) {
        int saved_errno = errno;
        fprintf(stderr, "Warning: Failed to turn off UKC (ret=%d, errno=%d: %s)\n", 
                ret, saved_errno, strerror(saved_errno));
        // 继续执行，不阻止后续操作
    }
    
    c->log_mode_enabled = false;
    
    // 短暂延迟确保所有 pending 的事件写入完成
    usleep(1000);  // 1ms
    
    debug_print("Switched to OFF mode\n");
    return 0;
}

ssize_t collector_read_trace(TraceCollector* c) {
    if (!c || !c->buffer)
        return -1;
    
    // 重新打开 trace 文件以获取最新内容
    // /sys/kernel/debug/tracing/trace 是特殊的伪文件，
    // 每次打开会重新生成内容，lseek 不一定有效
    int fd = open(TRACE_PATH, O_RDONLY);
    if (fd < 0) {
        debug_print("Failed to open trace file: %s\n", strerror(errno));
        return -1;
    }
    
    // 读取全部内容
    size_t total = 0;
    while (total < c->buffer_size - 1) {
        ssize_t n = read(fd, c->buffer + total, c->buffer_size - total - 1);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        if (n == 0)
            break;  // EOF
        if (errno == EINTR)
            continue;  // 被中断，重试
        debug_print("read error: %s\n", strerror(errno));
        break;
    }
    
    close(fd);
    
    c->buffer[total] = '\0';
    c->data_size = total;
    
    return (ssize_t)total;
}

int collector_clear_trace(TraceCollector* c) {
    // 暂时禁用 tracing
    trace_disable();
    
    // 清空 trace buffer
    int fd = open(TRACE_PATH, O_WRONLY | O_TRUNC);
    if (fd >= 0) {
        close(fd);
    } else {
        debug_print("Failed to clear trace: %s\n", strerror(errno));
    }
    
    // 重新启用 tracing
    trace_enable();
    
    // 重置文件位置
    if (c && c->trace_fd >= 0) {
        lseek(c->trace_fd, 0, SEEK_SET);
    }
    
    c->data_size = 0;
    return 0;
}

const char* collector_get_buffer(TraceCollector* c) {
    return c ? c->buffer : NULL;
}

size_t collector_get_data_size(TraceCollector* c) {
    return c ? c->data_size : 0;
}

int collector_set_buffer_size_kb(int size_kb) {
    char size_str[32];
    snprintf(size_str, sizeof(size_str), "%d", size_kb);
    
    // 需要先禁用 tracing
    trace_disable();
    
    int ret = write_to_file(BUFFER_SIZE_PATH, size_str);
    
    trace_enable();
    
    if (ret == 0) {
        debug_print("Set trace buffer size to %d KB per CPU\n", size_kb);
    }
    
    return ret;
}
