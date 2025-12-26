// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef RACE_COLLECTOR_ANALYZER_H
#define RACE_COLLECTOR_ANALYZER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "config.h"
#include "reporter.h"

// ============================================
// 分析器结构
// ============================================
typedef struct RaceAnalyzer RaceAnalyzer;

// ============================================
// API
// ============================================

// 创建分析器
RaceAnalyzer* analyzer_create(const CollectorConfig* config);

// 销毁分析器
void analyzer_destroy(RaceAnalyzer* a);

// 设置 signals 输出文件（用于输出详细 race pair 信息）
void analyzer_set_signals_file(RaceAnalyzer* a, FILE* fp);

// 分析 trace buffer 内容
// 返回检测到的 race pair 总数
int analyzer_process(RaceAnalyzer* a, const char* buffer, size_t size, SampleResult* result);

// 重置统计（但保留去重集合）
void analyzer_reset_stats(RaceAnalyzer* a);

// 完全重置（包括去重集合）
void analyzer_reset_all(RaceAnalyzer* a);

// 获取当前配置
const CollectorConfig* analyzer_get_config(RaceAnalyzer* a);

// 获取 LRU 命中统计
void analyzer_get_lru_stats(RaceAnalyzer* a, uint64_t* hits, uint64_t* misses);

#endif // RACE_COLLECTOR_ANALYZER_H
