// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef RACE_COLLECTOR_COLLECTOR_H
#define RACE_COLLECTOR_COLLECTOR_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include "config.h"

// ============================================
// Trace 数据收集器
// ============================================
typedef struct {
    const CollectorConfig* config;
    
    int trace_fd;           // /sys/kernel/debug/tracing/trace 文件描述符
    int ukc_fd;             // /dev/kccwf_ctl_dev 设备描述符
    
    char* buffer;           // trace 数据缓冲区
    size_t buffer_size;     // 缓冲区大小
    size_t data_size;       // 当前读取的数据大小
    
    bool log_mode_enabled;  // 当前是否处于 LOG 模式
} TraceCollector;

// ============================================
// API
// ============================================

// 初始化收集器
int collector_init(TraceCollector* c, const CollectorConfig* config);

// 清理收集器
void collector_cleanup(TraceCollector* c);

// 启用 LOG 模式
int collector_enable_log_mode(TraceCollector* c);

// 禁用 LOG 模式（切回 MONITOR 模式）
int collector_disable_log_mode(TraceCollector* c);

// 读取 trace buffer
// 返回读取的字节数，-1 表示错误
ssize_t collector_read_trace(TraceCollector* c);

// 清空 trace buffer
int collector_clear_trace(TraceCollector* c);

// 获取缓冲区指针
const char* collector_get_buffer(TraceCollector* c);

// 获取数据大小
size_t collector_get_data_size(TraceCollector* c);

// 设置 trace buffer 大小
int collector_set_buffer_size_kb(int size_kb);

#endif // RACE_COLLECTOR_COLLECTOR_H
