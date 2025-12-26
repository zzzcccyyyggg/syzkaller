// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef RACE_COLLECTOR_REPORTER_H
#define RACE_COLLECTOR_REPORTER_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "config.h"

// ============================================
// 单次采样结果
// ============================================
typedef struct {
    uint64_t iteration;           // 迭代次数
    time_t timestamp;             // 时间戳
    int access_count;             // 本次采样的访问记录数
    int free_count;               // 本次采样的 free 操作数
    int race_pair_count;          // 本次检测到的 race pair 数
    int unique_race_count;        // 本次新发现的唯一 race 数
    int total_unique_races;       // 累计唯一 race 总数
    int uaf_pair_count;           // 本次检测到的 UAF pair 数
    int unique_uaf_count;         // 本次新发现的唯一 UAF 数
    int total_unique_uaf;         // 累计唯一 UAF 总数
} SampleResult;

// ============================================
// 报告器结构
// ============================================
typedef struct {
    const CollectorConfig* config;
    FILE* output_fp;
    time_t start_time;
    
    // 累计统计
    uint64_t sample_count;
    uint64_t total_accesses;
    uint64_t total_frees;
    uint64_t total_race_pairs;
    uint64_t total_uaf_pairs;
    int last_unique_races;
    int last_unique_uaf;
    
    // 用于 JSON 格式的标记
    bool first_sample;
} Reporter;

// ============================================
// API
// ============================================
void reporter_init(Reporter* r, const CollectorConfig* config);
void reporter_add_sample(Reporter* r, const SampleResult* sample);
void reporter_generate_summary(Reporter* r);
void reporter_cleanup(Reporter* r);

#endif // RACE_COLLECTOR_REPORTER_H
