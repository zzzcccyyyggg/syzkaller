// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
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

// 线程访问历史结构
#define MAX_THREAD_HISTORY 0x2000
typedef struct {
    int tid;                           // 线程ID
    AccessRecord accesses[MAX_THREAD_HISTORY]; // 历史访问记录
    int access_count;                  // 访问记录数量
    int access_index;                  // 当前写入位置（环形缓冲区）
    bool buffer_full;                  // 缓冲区是否已满
} ThreadAccessHistory;

// Race Pair结构（包含历史访问信息）
typedef struct {
    AccessRecord first;         // 第一个访问
    AccessRecord second;        // 第二个访问
    uint64_t access_time_diff;  // 访问时间差 (nanoseconds)
    int trigger_counts;         // 触发次数
    LockStatus lock_status;     // 锁状态
    
    // 历史访问信息用于延时调度
    ThreadAccessHistory* thread1_history; // 第一个线程的访问历史
    ThreadAccessHistory* thread2_history; // 第二个线程的访问历史
    int first_access_index;     // 第一个访问在历史中的索引
    int second_access_index;    // 第二个访问在历史中的索引
} RacePair;

// Free操作记录结构（用于优化race检测）
typedef struct {
    uint64_t address;           // Free的内存地址
    uint64_t size;              // Free的内存大小
    uint64_t access_time;       // Free的时间 (nanoseconds)
	uint64_t call_stack_hash;   // 调用栈哈希
    int tid;                    // 执行Free的线程ID
    LockRecord held_locks[8];   // 持有的锁（最多8个）
    int lock_count;             // 持有锁的数量
} FreeRecord;

// 访问记录集合结构（包含优化的free记录和线程历史）
#define MAX_THREADS 16
typedef struct {
    AccessRecord* records;      // 访问记录数组
    int record_count;           // 访问记录数量
    AccessRecord* free_records;   // Free操作记录数组
    int free_count;             // Free操作数量
    ThreadAccessHistory* thread_histories; // 线程访问历史（动态分配）
    int thread_count;           // 活跃线程数量
    int max_threads;            // 最大线程数量
} AccessRecordSet;

// UAF检测结果结构（包含历史访问信息）
typedef struct {
    AccessRecord use_access;     // Use操作（读/写访问）
    AccessRecord free_access;   // Free操作  
    uint64_t time_diff;          // 时间差
    LockStatus lock_status;      // 锁状态
    int trigger_count;           // 触发次数
    
    // 历史访问信息用于延时调度
    ThreadAccessHistory* use_thread_history;  // Use线程的访问历史
    ThreadAccessHistory* free_thread_history; // Free线程的访问历史
    int use_access_index;        // Use访问在历史中的索引
    int free_access_index;       // Free访问在历史中的索引
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

int analyze_and_generate_may_uaf_infos(may_uaf_pair_t* uaf_buffer, int max_uaf_pairs);
int analyze_and_generate_extended_uaf_infos(may_uaf_pair_t* uaf_signals_buffer, int uaf_count,
                                           extended_uaf_pair_t* extended_buffer, int max_extended);

// 优化版本：一次性生成基本和扩展UAF信息，避免重复解析
int analyze_and_generate_uaf_infos_combined(may_uaf_pair_t* uaf_buffer, int max_uaf_pairs,
                                           extended_uaf_pair_t* extended_pairs, int max_extended_pairs,
                                           AccessRecordSet** record_set_out);
int parse_access_records_to_set(const char* buffer, AccessRecordSet* record_set, int max_records, int max_frees);
LockStatus determine_lock_status(const AccessRecord* a, const AccessRecord* b);
bool addresses_overlap(const AccessRecord* a, const AccessRecord* b);
int analyze_uaf_pairs_from_set(AccessRecordSet* record_set, UAFPair* uaf_pairs, int max_pairs, UAFStatistics* stats);
bool check_uaf_validity(const AccessRecord* use_access, const AccessRecord* free_op, AccessRecord* all_frees, int free_count);
LockStatus determine_uaf_lock_status(const AccessRecord* use_access, const AccessRecord* free_op);
void reset_race_detector();
bool is_race_detector_available();

// 路径距离感知调度相关函数
ThreadAccessHistory* find_thread_history(AccessRecordSet* record_set, int tid);
ThreadAccessHistory* create_thread_history(AccessRecordSet* record_set, int tid);
void add_access_to_history(ThreadAccessHistory* history, const AccessRecord* access);
int calculate_path_distance(const AccessRecord* target, const AccessRecord* current);
double calculate_delay_probability(int distance);
// 扩展的race和UAF分析函数，支持历史访问信息
int generate_extended_uaf_info(may_uaf_pair_t* uaf_pairs, int uaf_count,
                              AccessRecordSet* record_set,
                              extended_uaf_pair_t* extended_uaf_pairs);
typedef struct {
    RacePair pair;              // 基本race pair信息
    AccessRecord thread1_before_accesses[100]; // 线程1在race事件前的访问
    AccessRecord thread2_before_accesses[100]; // 线程2在race事件前的访问
    int thread1_before_count;   // 线程1前置访问数量
    int thread2_before_count;   // 线程2前置访问数量
} ExtendedRacePair;

typedef struct {
    UAFPair pair;               // 基本UAF pair信息
    AccessRecord use_thread_before_accesses[100];  // Use线程在UAF事件前的访问
    AccessRecord free_thread_before_accesses[100]; // Free线程在UAF事件前的访问
    int use_thread_before_count;    // Use线程前置访问数量
    int free_thread_before_count;   // Free线程前置访问数量
} ExtendedUAFPair;

// ===============DDRD====================

SyscallTimeRecord* find_matching_syscall(uint64_t access_time,int tid);
// Function to access pair syscall shared memory data
struct PairSyscallSharedData* get_pair_shared_data();

// =============== Trace Buffer Management Functions ===============
// 注意：大部分trace buffer管理函数是内部使用的静态函数
// 这里只声明需要外部访问的函数

// High-level configuration functions (these are the main public interfaces)
bool configure_race_trace_environment(int buffer_size_kb, const char* tracer_type, 
                                     const int* target_pids, int pid_count,
                                     const char* function_filter);
bool reset_race_trace_environment(void);


// ftrace_ioctl.c functions

bool set_buffer_size_kb(int size_kb);
bool enable_tracing(void);
bool disable_tracing(void);
int get_buffer_size_kb(void);
bool is_tracing_enabled(void);
void clear_trace_buffer(void);

#ifdef __cplusplus
}
#endif
