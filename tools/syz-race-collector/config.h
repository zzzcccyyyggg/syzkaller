// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef RACE_COLLECTOR_CONFIG_H
#define RACE_COLLECTOR_CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// ============================================
// LRU 缓存大小（用于减少重复 signal 输出）
// 50000 entries × 8 bytes = 400KB
// ============================================
#define SIGNAL_LRU_SIZE 50000

// ============================================
// 可配置参数结构
// ============================================
typedef struct {
    // 采样参数
    int interval_ms;              // 采样间隔（毫秒），默认 1000
    int duration_sec;             // 运行时长（秒），0 表示一直运行直到 Ctrl+C
    
    // Race pair 检测阈值
    uint64_t race_time_threshold_ns;   // race pair 时间阈值（纳秒），默认 4270000 (~4.27ms)
    uint64_t uaf_time_threshold_ns;    // UAF 时间阈值（纳秒），默认 10000000000 (10s)
    
    // 缓冲区大小
    int trace_buffer_size_kb;     // trace buffer 大小（KB），默认 16384 (16MB)
    int max_records;              // 最大访问记录数，默认 65536
    int max_race_pairs;           // 最大 race pair 数，默认 8192
    
    // 输出选项
    const char* output_file;      // 统计输出文件路径，NULL 表示不输出到文件
    const char* signals_file;     // signals 输出文件路径（详细 race pair 信息）
    const char* output_format;    // 输出格式: "csv" 或 "json"
    bool verbose;                 // 详细输出
    bool quiet;                   // 静默模式（只输出最终统计）
    bool realtime;                // 实时输出每个采样
    
    // 高级选项
    bool skip_locked_pairs;       // 跳过有公共锁保护的 pair（默认 true）
    bool collect_uaf;             // 同时收集 UAF pair（默认 false）
    bool dedup_signals;           // 对 race signal 去重（默认 true）
    bool output_signals;          // 输出详细 signals 到文件（默认 true）
    bool no_lru_filter;           // 禁用 LRU 过滤，输出所有 signals（默认 false，用于外部去重场景）
    int lru_cache_size;           // LRU 缓存大小（默认 SIGNAL_LRU_SIZE）
} CollectorConfig;

// 默认配置
static inline void config_set_defaults(CollectorConfig* cfg) {
    cfg->interval_ms = 1000;
    cfg->duration_sec = 0;
    
    cfg->race_time_threshold_ns = 10000000ULL;     // 10ms (unified with executor)
    cfg->uaf_time_threshold_ns = 10000000000ULL;   // 10s
    
    cfg->trace_buffer_size_kb = 16384;             // 16MB per CPU
    cfg->max_records = 65536;
    cfg->max_race_pairs = 8192;
    
    cfg->output_file = NULL;
    cfg->signals_file = NULL;
    cfg->output_format = "csv";
    cfg->verbose = false;
    cfg->quiet = false;
    cfg->realtime = true;
    
    cfg->skip_locked_pairs = true;
    cfg->collect_uaf = false;           // 默认关闭 UAF 检测，只收集 race pair
    cfg->dedup_signals = true;
    cfg->output_signals = true;         // 默认输出 signals
    cfg->no_lru_filter = false;         // 默认启用 LRU 过滤
    cfg->lru_cache_size = SIGNAL_LRU_SIZE;  // 默认 50000 entries
}

// ============================================
// 日志宏（输出到 stderr，方便重定向到日志文件）
// ============================================
#define LOG_DEBUG(fmt, ...) \
    do { \
        struct timespec _ts; \
        clock_gettime(CLOCK_REALTIME, &_ts); \
        struct tm _tm; \
        localtime_r(&_ts.tv_sec, &_tm); \
        fprintf(stderr, "[%02d:%02d:%02d.%03ld] DEBUG: " fmt "\n", \
                _tm.tm_hour, _tm.tm_min, _tm.tm_sec, _ts.tv_nsec / 1000000, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)

#define LOG_INFO(fmt, ...) \
    do { \
        struct timespec _ts; \
        clock_gettime(CLOCK_REALTIME, &_ts); \
        struct tm _tm; \
        localtime_r(&_ts.tv_sec, &_tm); \
        fprintf(stderr, "[%02d:%02d:%02d.%03ld] INFO: " fmt "\n", \
                _tm.tm_hour, _tm.tm_min, _tm.tm_sec, _ts.tv_nsec / 1000000, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)

#define LOG_ERROR(fmt, ...) \
    do { \
        struct timespec _ts; \
        clock_gettime(CLOCK_REALTIME, &_ts); \
        struct tm _tm; \
        localtime_r(&_ts.tv_sec, &_tm); \
        fprintf(stderr, "[%02d:%02d:%02d.%03ld] ERROR: " fmt "\n", \
                _tm.tm_hour, _tm.tm_min, _tm.tm_sec, _ts.tv_nsec / 1000000, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)

#endif // RACE_COLLECTOR_CONFIG_H
