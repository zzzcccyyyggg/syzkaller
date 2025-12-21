// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// ============================================
// 这个文件直接复用 executor/ddrd 的代码
// ============================================

#include "analyzer.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================
// 复用 executor/ddrd 的核心代码
// ============================================

// 首先包含类型定义
#include "types.h"
#include "utils.h"

// 直接包含源文件以内联编译
// 这样可以完全复用现有代码，无需修改
#include "access_record.c"
#include "lock.c"
#include "utils.c"

// access_context.c 需要特殊处理，因为我们要使用可配置的阈值
// 所以我们复制其核心逻辑并使用配置的阈值

// ============================================
// 从 access_context.c 复制的辅助函数（本地版本）
// ============================================

bool access_context_check_data_race_validity(AccessContext* record_ctx, 
                                           const AccessRecord* a, 
                                           const AccessRecord* b)
{
    uint64_t min_time = (a->access_time <= b->access_time) ? a->access_time : b->access_time;
    uint64_t max_time = (a->access_time > b->access_time) ? a->access_time : b->access_time;

    for (int i = 0; i < record_ctx->free_count; i++) {
        const AccessRecord* free_rec = &record_ctx->free_records[i];
        if (free_rec->access_time > min_time && free_rec->access_time < max_time) {
            if (access_record_addresses_overlap(a, free_rec) || 
                access_record_addresses_overlap(b, free_rec))
                return false;
        }
    }
    return true;
}

// ============================================
// 内部结构定义
// ============================================

#define SIGNAL_HASHSET_SIZE 0x10000

typedef struct {
    uint64_t* signals;
    int count;
    int capacity;
} SignalSet;

struct RaceAnalyzer {
    const CollectorConfig* config;
    
    // 访问记录存储
    AccessRecord* records;
    AccessRecord* free_records;
    RacePair* race_pairs;
    UAFPair* uaf_pairs;
    
    // 去重集合
    SignalSet race_signals;
    SignalSet uaf_signals;
};

// ============================================
// SignalSet 操作
// ============================================

static void signalset_init(SignalSet* s, int capacity) {
    s->signals = (uint64_t*)malloc(sizeof(uint64_t) * capacity);
    s->count = 0;
    s->capacity = capacity;
}

static void signalset_destroy(SignalSet* s) {
    if (s->signals) {
        free(s->signals);
        s->signals = NULL;
    }
    s->count = 0;
    s->capacity = 0;
}

static bool signalset_contains(SignalSet* s, uint64_t signal) {
    for (int i = 0; i < s->count; i++) {
        if (s->signals[i] == signal)
            return true;
    }
    return false;
}

static bool signalset_add(SignalSet* s, uint64_t signal) {
    if (signalset_contains(s, signal))
        return false;  // 已存在
    
    if (s->count < s->capacity) {
        s->signals[s->count++] = signal;
        return true;  // 新增成功
    }
    return false;  // 容量已满
}

static void signalset_clear(SignalSet* s) {
    s->count = 0;
}

// ============================================
// 自定义的 race pair 分析（使用可配置阈值）
// ============================================

static int analyze_race_pairs_with_config(
    AccessContext* ctx, 
    RacePair* pairs, 
    int max_pairs,
    const CollectorConfig* config)
{
    uint64_t time_threshold = config->race_time_threshold_ns;
    bool skip_locked = config->skip_locked_pairs;
    int pair_count = 0;

    for (int i = 0; i < ctx->record_count && pair_count < max_pairs; i++) {
        for (int j = i + 1; j < ctx->record_count && pair_count < max_pairs; j++) {
            AccessRecord* a = &ctx->records[i];
            AccessRecord* b = &ctx->records[j];

            // 条件1: 不同线程
            if (a->tid == b->tid)
                continue;
            
            // 条件2: 至少一个是写操作
            if (!(a->access_type == 'W' || b->access_type == 'W'))
                continue;
            
            // 条件3: 地址重叠
            if (!access_record_addresses_overlap(a, b))
                continue;

            // 条件4: 时间差在阈值内
            uint64_t time_diff = (a->access_time > b->access_time) ?
                (a->access_time - b->access_time) : (b->access_time - a->access_time);

            if (time_diff > time_threshold)
                continue;

            // 条件5: 检查中间是否有 free
            if (!access_context_check_data_race_validity(ctx, a, b))
                continue;

            // 条件6: 锁状态检查
            if (skip_locked) {
                LockStatus lock_status = determine_lock_status(a, b);
                if (lock_status == LOCK_SYNC_WITH_COMMON_LOCK)
                    continue;
            }

            // 记录 race pair
            RacePair* pair = &pairs[pair_count];
            if (a->access_time <= b->access_time) {
                pair->first = *a;
                pair->second = *b;
            } else {
                pair->first = *b;
                pair->second = *a;
            }
            pair->access_time_diff = time_diff;
            pair->trigger_counts = 1;
            pair->lock_status = determine_lock_status(a, b);
            pair->thread1_history = NULL;
            pair->thread2_history = NULL;
            pair->first_access_index = -1;
            pair->second_access_index = -1;

            pair_count++;
        }
    }

    return pair_count;
}

static int analyze_uaf_pairs_with_config(
    AccessContext* ctx,
    UAFPair* uaf_pairs,
    int max_pairs,
    const CollectorConfig* config)
{
    uint64_t time_threshold = config->uaf_time_threshold_ns;
    bool skip_locked = config->skip_locked_pairs;
    int pair_count = 0;

    for (int i = 0; i < ctx->record_count && pair_count < max_pairs; i++) {
        AccessRecord* use_access = &ctx->records[i];
        AccessRecord* closest_free = NULL;
        uint64_t closest_time_diff = UINT64_MAX;

        for (int j = 0; j < ctx->free_count; j++) {
            AccessRecord* free_op = &ctx->free_records[j];

            // 不同线程
            if (use_access->tid == free_op->tid)
                continue;

            // 地址重叠
            uint64_t use_end = use_access->address + use_access->size;
            uint64_t free_end = free_op->address + free_op->size;
            if (!((use_access->address < free_end) && (free_op->address < use_end)))
                continue;

            // Free 发生在 Use 之前（时间上）
            if (free_op->access_time >= use_access->access_time)
                continue;

            uint64_t time_diff = use_access->access_time - free_op->access_time;
            if (time_diff > time_threshold)
                continue;

            if (time_diff < closest_time_diff) {
                closest_free = free_op;
                closest_time_diff = time_diff;
            }
        }

        if (closest_free) {
            // 锁检查
            if (skip_locked) {
                LockStatus lock_status = determine_lock_status(use_access, closest_free);
                if (lock_status == LOCK_SYNC_WITH_COMMON_LOCK)
                    continue;
            }

            UAFPair* uaf_pair = &uaf_pairs[pair_count];
            uaf_pair->use_access = *use_access;
            uaf_pair->free_access = *closest_free;
            uaf_pair->time_diff = closest_time_diff;
            uaf_pair->lock_status = determine_lock_status(use_access, closest_free);
            uaf_pair->trigger_count = 1;
            uaf_pair->use_thread_history = NULL;
            uaf_pair->free_thread_history = NULL;
            uaf_pair->use_access_index = -1;
            uaf_pair->free_access_index = -1;

            pair_count++;
        }
    }

    return pair_count;
}

// ============================================
// 公共 API 实现
// ============================================

RaceAnalyzer* analyzer_create(const CollectorConfig* config) {
    RaceAnalyzer* a = (RaceAnalyzer*)calloc(1, sizeof(RaceAnalyzer));
    if (!a) return NULL;
    
    a->config = config;
    
    // 分配存储空间
    a->records = (AccessRecord*)malloc(sizeof(AccessRecord) * config->max_records);
    a->free_records = (AccessRecord*)malloc(sizeof(AccessRecord) * (config->max_records / 4));
    a->race_pairs = (RacePair*)malloc(sizeof(RacePair) * config->max_race_pairs);
    a->uaf_pairs = (UAFPair*)malloc(sizeof(UAFPair) * config->max_race_pairs);
    
    if (!a->records || !a->free_records || !a->race_pairs || !a->uaf_pairs) {
        analyzer_destroy(a);
        return NULL;
    }
    
    // 初始化去重集合
    signalset_init(&a->race_signals, SIGNAL_HASHSET_SIZE);
    signalset_init(&a->uaf_signals, SIGNAL_HASHSET_SIZE);
    
    return a;
}

void analyzer_destroy(RaceAnalyzer* a) {
    if (!a) return;
    
    if (a->records) free(a->records);
    if (a->free_records) free(a->free_records);
    if (a->race_pairs) free(a->race_pairs);
    if (a->uaf_pairs) free(a->uaf_pairs);
    
    signalset_destroy(&a->race_signals);
    signalset_destroy(&a->uaf_signals);
    
    free(a);
}

int analyzer_process(RaceAnalyzer* a, const char* buffer, size_t size, SampleResult* result) {
    memset(result, 0, sizeof(*result));
    
    if (!buffer || size == 0)
        return 0;
    
    // 构建 AccessContext
    AccessContext ctx = {
        .records = a->records,
        .free_records = a->free_records,
        .record_count = 0,
        .free_count = 0,
        .thread_histories = NULL,
        .thread_count = 0,
        .max_threads = 0,
        .enable_history = false
    };
    
    // 解析 trace buffer（复用 access_record.c 的代码）
    int max_records = a->config->max_records;
    int max_frees = max_records / 4;
    
    // 需要复制 buffer 因为 strtok 会修改它
    char* buffer_copy = my_strdup(buffer);
    if (!buffer_copy)
        return 0;
    
    int record_count = 0;
    int free_count = 0;
    
    char* line = strtok(buffer_copy, "\n");
    AccessRecord current_record = {0};
    bool has_current = false;

    while (line) {
        AccessRecord access = access_record_init_from_line(line);
        if (access.valid) {
            if (has_current && record_count < max_records) {
                if (current_record.access_type == 'F' && free_count < max_frees) {
                    ctx.free_records[free_count++] = current_record;
                } else if (current_record.access_type != 'F') {
                    ctx.records[record_count++] = current_record;
                }
            }
            current_record = access;
            current_record.lock_count = 0;
            has_current = true;
        } else {
            LockRecord lock = parse_lock_line(line);
            if (lock.valid && has_current && current_record.lock_count < 8)
                current_record.held_locks[current_record.lock_count++] = lock;
        }
        line = strtok(NULL, "\n");
    }

    // 处理最后一条记录
    if (has_current && record_count < max_records) {
        if (current_record.access_type == 'F' && free_count < max_frees) {
            ctx.free_records[free_count++] = current_record;
        } else if (current_record.access_type != 'F') {
            ctx.records[record_count++] = current_record;
        }
    }

    ctx.record_count = record_count;
    ctx.free_count = free_count;
    
    free(buffer_copy);
    
    result->access_count = record_count;
    result->free_count = free_count;
    
    if (record_count == 0)
        return 0;
    
    // 分析 race pairs（使用可配置阈值）
    int race_count = analyze_race_pairs_with_config(&ctx, a->race_pairs, 
                                                     a->config->max_race_pairs, 
                                                     a->config);
    result->race_pair_count = race_count;
    
    // 统计唯一 race
    int unique_this_interval = 0;
    if (a->config->dedup_signals) {
        for (int i = 0; i < race_count; i++) {
            uint64_t signal = hash_uaf_signal(
                (char*)&a->race_pairs[i].first.var_name,
                (char*)&a->race_pairs[i].first.call_stack_hash,
                (char*)&a->race_pairs[i].second.var_name,
                (char*)&a->race_pairs[i].second.call_stack_hash
            );
            
            if (signalset_add(&a->race_signals, signal)) {
                unique_this_interval++;
            }
        }
    } else {
        unique_this_interval = race_count;
    }
    result->unique_race_count = unique_this_interval;
    result->total_unique_races = a->race_signals.count;
    
    // 分析 UAF pairs
    if (a->config->collect_uaf && ctx.free_count > 0) {
        int uaf_count = analyze_uaf_pairs_with_config(&ctx, a->uaf_pairs,
                                                       a->config->max_race_pairs,
                                                       a->config);
        result->uaf_pair_count = uaf_count;
        
        // 统计唯一 UAF
        int unique_uaf_this_interval = 0;
        if (a->config->dedup_signals) {
            for (int i = 0; i < uaf_count; i++) {
                uint64_t signal = hash_uaf_signal(
                    (char*)&a->uaf_pairs[i].use_access.var_name,
                    (char*)&a->uaf_pairs[i].use_access.call_stack_hash,
                    (char*)&a->uaf_pairs[i].free_access.var_name,
                    (char*)&a->uaf_pairs[i].free_access.call_stack_hash
                );
                
                if (signalset_add(&a->uaf_signals, signal)) {
                    unique_uaf_this_interval++;
                }
            }
        } else {
            unique_uaf_this_interval = uaf_count;
        }
        result->unique_uaf_count = unique_uaf_this_interval;
        result->total_unique_uaf = a->uaf_signals.count;
    }
    
    return race_count + result->uaf_pair_count;
}

void analyzer_reset_stats(RaceAnalyzer* a) {
    // 保留去重集合，只重置其他状态
    (void)a;
}

void analyzer_reset_all(RaceAnalyzer* a) {
    if (!a) return;
    signalset_clear(&a->race_signals);
    signalset_clear(&a->uaf_signals);
}

const CollectorConfig* analyzer_get_config(RaceAnalyzer* a) {
    return a ? a->config : NULL;
}
