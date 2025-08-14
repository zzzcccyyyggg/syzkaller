// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "ddrd.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
struct PairSyscallSharedData;

// 锁记录结构
typedef struct {
    char name[64];              // 锁名称
    uint64_t ptr;               // 锁指针
    int attr;                   // 锁属性
    bool valid;                 // 记录是否有效
} LockRecord;

// 访问记录结构
typedef struct {
    int tid;                    // 线程ID
    uint64_t var_name;          // 变量名哈希
    uint64_t address;           // 内存地址
    char access_type;           // 访问类型：'R'=读, 'W'=写, 'F'=释放
    uint64_t size;              // 访问大小
    uint64_t call_stack_hash;   // 调用栈哈希
    uint64_t access_time;       // 访问时间 (nanoseconds since boot)
    int sn;                     // 序列号
    LockRecord held_locks[8];   // 持有的锁（最多8个）
    int lock_count;             // 持有锁的数量
    bool valid;                 // 记录是否有效
} AccessRecord;

// Race Pair结构
typedef struct {
    AccessRecord first;         // 第一个访问
    AccessRecord second;        // 第二个访问
    uint64_t access_time_diff;  // 访问时间差 (nanoseconds)
    int trigger_counts;         // 触发次数
    LockStatus lock_status;     // 锁状态
} RacePair;

// Free操作记录结构（用于优化race检测）
typedef struct {
    uint64_t address;           // Free的内存地址
    uint64_t size;              // Free的内存大小
    uint64_t access_time;       // Free的时间 (nanoseconds)
    int tid;                    // 执行Free的线程ID
} FreeRecord;

// 访问记录集合结构（包含优化的free记录）
typedef struct {
    AccessRecord* records;      // 访问记录数组
    int record_count;           // 访问记录数量
    FreeRecord* free_records;   // Free操作记录数组
    int free_count;             // Free操作数量
} AccessRecordSet;

// UAF检测结果结构
typedef struct {
    AccessRecord use_access;     // Use操作（读/写访问）
    FreeRecord free_operation;   // Free操作  
    uint64_t time_diff;          // 时间差
    LockStatus lock_status;      // 锁状态
    int trigger_count;           // 触发次数
} UAFPair;

// UAF统计结构
typedef struct {
    int no_locks_count;
    int one_sided_lock_count;
    int unsync_locks_count;
    int sync_with_common_lock_count;
    int total_uaf_pairs;
} UAFStatistics;

// Syscall时间记录结构（用于race pair映射）
typedef struct {
    int call_index;             // syscall在程序中的索引
    int call_num;               // syscall编号
    uint64_t start_time;        // syscall开始时间 (nanoseconds)
    uint64_t end_time;          // syscall结束时间 (nanoseconds)
    int thread_id;              // 执行的线程ID
    bool valid;                 // 记录是否有效
} SyscallTimeRecord;


// 函数声明
void init_race_detector();
void cleanup_race_detector();
int analyze_and_generate_may_race_infos(may_race_pair_t* signals_buffer, int max_signals);
int parse_access_records_to_set(const char* buffer, AccessRecordSet* record_set, int max_records, int max_frees);
int analyze_race_pairs_from_set(AccessRecordSet* record_set, RacePair* pairs, int max_pairs);
LockStatus determine_lock_status(const AccessRecord* a, const AccessRecord* b);
bool addresses_overlap(const AccessRecord* a, const AccessRecord* b);
bool in_same_valid_interval_optimized(const AccessRecord* a, const AccessRecord* b, FreeRecord* free_records, int free_count);
int analyze_uaf_pairs_from_set(AccessRecordSet* record_set, UAFPair* uaf_pairs, int max_pairs, UAFStatistics* stats);
bool check_uaf_validity(const AccessRecord* use_access, const FreeRecord* free_op, FreeRecord* all_frees, int free_count);
LockStatus determine_uaf_lock_status(const AccessRecord* use_access, const FreeRecord* free_op);
void reset_race_detector();
bool is_race_detector_available();

// ===============DDRD====================

SyscallTimeRecord* find_matching_syscall(uint64_t access_time,int tid);

// Race pairs export (currently used instead of full mapping)
int export_race_pairs_to_buffer(char* buffer, int buffer_size);

// Function to access pair syscall shared memory data
struct PairSyscallSharedData* get_pair_shared_data();


// ===============DDRD====================

#ifdef __cplusplus
}
#endif
