#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Should match the MaxAccessHistoryRecords in pkg/ddrd/types.go
#define MAX_ACCESS_HISTORY_RECORDS 100

typedef struct {
    uint64_t varName1;
    uint64_t varName2;
    uint64_t call_stack1;
    uint64_t call_stack2;
    uint64_t signal;
    uint64_t time_diff;
    int sn1;
    int sn2;
    int syscall1_idx;
    int syscall2_idx;
    int syscall1_num;
    int syscall2_num;
    int tid1;
    int tid2;
    uint32_t lock_type;
    uint32_t access_type1;
    uint32_t access_type2;
} may_race_pair_t;

typedef struct {
    uint64_t free_access_name;
    uint64_t use_access_name;
    uint64_t free_call_stack;
    uint64_t use_call_stack;
    uint64_t signal;
    uint64_t time_diff;
    int free_sn;
    int use_sn;
    int free_tid;
    int use_tid;
    uint32_t lock_type;
    uint32_t use_access_type;
} may_uaf_pair_t;

typedef struct {
    uint64_t var_name;
    uint64_t call_stack_hash;
    uint64_t access_time;
    uint32_t sn;
    uint32_t access_type;
} serialized_access_record_t;

typedef struct {
    may_race_pair_t basic_info;
    uint32_t thread1_history_count;
    uint32_t thread2_history_count;
    uint64_t thread1_target_time;
    uint64_t thread2_target_time;
    double path_distance1;
    double path_distance2;
    serialized_access_record_t access_history[];
} extended_race_pair_t;

typedef struct {
    may_uaf_pair_t basic_info;
    uint32_t use_thread_history_count;
    uint32_t free_thread_history_count;
    uint64_t use_target_time;
    uint64_t free_target_time;
    double path_distance_use;
    double path_distance_free;
    serialized_access_record_t access_history[];
} extended_uaf_pair_t;

uint64_t hash_race_signal(const char* use_var, const char* use_stack,
                          const char* free_var, const char* free_stack);

#ifdef __cplusplus
}
#endif
