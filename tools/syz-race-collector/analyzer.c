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

// LRU 缓存，用于减少重复 signal 输出
typedef struct {
    uint64_t* entries;      // 环形缓冲区
    int capacity;           // 容量
    int write_index;        // 下一个写入位置
    uint64_t hits;          // 命中次数
    uint64_t misses;        // 未命中次数
} SignalLRU;

struct RaceAnalyzer {
    const CollectorConfig* config;
    
    // 访问记录存储
    AccessRecord* records;
    AccessRecord* free_records;
    RacePair* race_pairs;
    UAFPair* uaf_pairs;
    
    // 去重集合（用于统计唯一数量）
    SignalSet race_signals;
    SignalSet uaf_signals;
    
    // LRU 缓存（用于减少输出重复）
    SignalLRU signal_lru;
    
    // signals 输出文件
    FILE* signals_fp;
};

// ============================================
// 信号哈希计算（针对 uint64_t 类型）
// ============================================

static uint64_t hash_race_pair_signal(uint64_t var1, uint64_t stack1,
                                       uint64_t var2, uint64_t stack2)
{
    // 组合两个访问的信息
    uint64_t pair1 = var1 ^ (stack1 << 1);
    uint64_t pair2 = var2 ^ (stack2 << 1);

    // 排序以确保 (A,B) 和 (B,A) 生成相同的哈希
    if (pair1 > pair2) {
        uint64_t tmp = pair1;
        pair1 = pair2;
        pair2 = tmp;
    }

    return pair1 * 1315423911ULL ^ pair2;
}

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
// LRU 缓存操作（用于减少重复 signal 输出）
// ============================================

static void signal_lru_init(SignalLRU* lru, int capacity) {
    lru->entries = (uint64_t*)calloc(capacity, sizeof(uint64_t));
    lru->capacity = capacity;
    lru->write_index = 0;
    lru->hits = 0;
    lru->misses = 0;
}

static void signal_lru_destroy(SignalLRU* lru) {
    if (lru->entries) {
        free(lru->entries);
        lru->entries = NULL;
    }
    lru->capacity = 0;
}

// 检查 signal 是否在 LRU 中，如果不在则添加
// 返回 true 表示是新 signal（应该输出），false 表示重复
static bool signal_lru_check_and_add(SignalLRU* lru, uint64_t signal) {
    // 线性搜索（对于 50K entries，仍然可接受）
    // 可以用哈希表优化，但目前足够
    for (int i = 0; i < lru->capacity; i++) {
        if (lru->entries[i] == signal) {
            lru->hits++;
            return false;  // 已存在，重复
        }
    }
    
    // 不存在，添加到 LRU
    lru->entries[lru->write_index] = signal;
    lru->write_index = (lru->write_index + 1) % lru->capacity;
    lru->misses++;
    return true;  // 新 signal
}

static void signal_lru_clear(SignalLRU* lru) {
    memset(lru->entries, 0, lru->capacity * sizeof(uint64_t));
    lru->write_index = 0;
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
    a->signals_fp = NULL;
    
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
    
    // 初始化 LRU 缓存 (使用配置的大小，如果有的话)
    int lru_size = (config && config->lru_cache_size > 0) ? config->lru_cache_size : SIGNAL_LRU_SIZE;
    signal_lru_init(&a->signal_lru, lru_size);
    
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
    signal_lru_destroy(&a->signal_lru);
    
    // 注意：不关闭 signals_fp，由调用者负责
    
    free(a);
}

void analyzer_set_signals_file(RaceAnalyzer* a, FILE* fp) {
    if (a) {
        a->signals_fp = fp;
    }
}

void analyzer_get_lru_stats(RaceAnalyzer* a, uint64_t* hits, uint64_t* misses) {
    if (a) {
        if (hits) *hits = a->signal_lru.hits;
        if (misses) *misses = a->signal_lru.misses;
    }
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
    
    // 统计唯一 race 并输出 signals
    int unique_this_interval = 0;
    int signals_output = 0;
    
    for (int i = 0; i < race_count; i++) {
        uint64_t signal = hash_race_pair_signal(
            a->race_pairs[i].first.var_name,
            a->race_pairs[i].first.call_stack_hash,
            a->race_pairs[i].second.var_name,
            a->race_pairs[i].second.call_stack_hash
        );
        
        // 统计去重（用于计数）
        if (a->config->dedup_signals) {
            if (signalset_add(&a->race_signals, signal)) {
                unique_this_interval++;
            }
        } else {
            unique_this_interval++;
        }
        
        // 输出 signal 到文件（使用 LRU 减少重复）
        if (a->signals_fp && a->config->output_signals) {
            if (signal_lru_check_and_add(&a->signal_lru, signal)) {
                // 输出格式: signal_hash,var1,stack1,var2,stack2,addr1,addr2,delta_ns,type
                fprintf(a->signals_fp, "%lu,%lu,%lu,%lu,%lu,%lu,%lu,%ld,R\n",
                        (unsigned long)signal,
                        (unsigned long)a->race_pairs[i].first.var_name,
                        (unsigned long)a->race_pairs[i].first.call_stack_hash,
                        (unsigned long)a->race_pairs[i].second.var_name,
                        (unsigned long)a->race_pairs[i].second.call_stack_hash,
                        (unsigned long)a->race_pairs[i].first.address,
                        (unsigned long)a->race_pairs[i].second.address,
                        (long)a->race_pairs[i].access_time_diff);
                signals_output++;
            }
        }
    }
    
    // 刷新 signals 文件
    if (a->signals_fp && signals_output > 0) {
        fflush(a->signals_fp);
    }
    
    result->unique_race_count = unique_this_interval;
    result->total_unique_races = a->race_signals.count;
    
    // 分析 UAF pairs
    if (a->config->collect_uaf && ctx.free_count > 0) {
        int uaf_count = analyze_uaf_pairs_with_config(&ctx, a->uaf_pairs,
                                                       a->config->max_race_pairs,
                                                       a->config);
        result->uaf_pair_count = uaf_count;
        
        // 统计唯一 UAF 并输出 signals
        int unique_uaf_this_interval = 0;
        int uaf_signals_output = 0;
        
        for (int i = 0; i < uaf_count; i++) {
            uint64_t signal = hash_race_pair_signal(
                a->uaf_pairs[i].use_access.var_name,
                a->uaf_pairs[i].use_access.call_stack_hash,
                a->uaf_pairs[i].free_access.var_name,
                a->uaf_pairs[i].free_access.call_stack_hash
            );
            
            if (a->config->dedup_signals) {
                if (signalset_add(&a->uaf_signals, signal)) {
                    unique_uaf_this_interval++;
                }
            } else {
                unique_uaf_this_interval++;
            }
            
            // 输出 UAF signal 到文件
            if (a->signals_fp && a->config->output_signals) {
                if (signal_lru_check_and_add(&a->signal_lru, signal)) {
                    fprintf(a->signals_fp, "%lu,%lu,%lu,%lu,%lu,%lu,%lu,%ld,U\n",
                            (unsigned long)signal,
                            (unsigned long)a->uaf_pairs[i].use_access.var_name,
                            (unsigned long)a->uaf_pairs[i].use_access.call_stack_hash,
                            (unsigned long)a->uaf_pairs[i].free_access.var_name,
                            (unsigned long)a->uaf_pairs[i].free_access.call_stack_hash,
                            (unsigned long)a->uaf_pairs[i].use_access.address,
                            (unsigned long)a->uaf_pairs[i].free_access.address,
                            (long)a->uaf_pairs[i].time_diff);
                    uaf_signals_output++;
                }
            }
        }
        
        if (a->signals_fp && uaf_signals_output > 0) {
            fflush(a->signals_fp);
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
