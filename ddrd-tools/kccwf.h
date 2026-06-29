#ifndef KCCWF_H_INCLUDED
#define KCCWF_H_INCLUDED

#include <cstdint>
#include <cstddef>
#define MAX_LOG_ENTRIES 6553600 // 维持原条目数
#define KCCWF_DEBUG 0
#define TIME_MEASUREMENT 0

#define KCCWF_DISABLE_MODE      0x00000000
#define KCCWF_MONITOR_MODE      0x00000004
#define KCCWF_LOG_MODE      0x1
#define KCCWF_CHECK_MODE      0x2
#define KCCWF_VALIDATE_MODE      0x3
#define KCCWF_NOLOCKREPRODUCE_MODE  0x5
#define KCCWF_ONESIDEDREPRODUCE_MODE 0x6



typedef unsigned int tid_t;

#define KCCWF_MAX_TESTING_TID_NUM 0X2
typedef struct {
    tid_t tids[KCCWF_MAX_TESTING_TID_NUM];
    int num;
} kccwf_testing_tids_t;

typedef struct {
    int mode;
    kccwf_testing_tids_t testing_tids;
    uint64_t bbs_state[KCCWF_MAX_TESTING_TID_NUM];
} kccwf_current_t;


typedef struct {
    unsigned long var_name_1;
    unsigned long var_name_2;
    unsigned long call_stack_hash_1;
    unsigned long call_stack_hash_2;
    bool is_synchronized;
} may_race_pair_t;

#define MAX_RACE_PAIR_NUM 0x1000
typedef struct {
    uint32_t num;
    may_race_pair_t *pairs;
} may_race_pair_list_t;

typedef struct {
    uint64_t var_name;
    uint32_t testing_tid;
} check_phase_info_t;


typedef struct {
    unsigned long var_name;
    unsigned long stack_hash;
    int tid;
    int sn;
} nolockreproduce_info_t;

typedef struct {
    unsigned long var_name;
    unsigned long stack_hash;
    int no_lock_tid;       // 无锁访问的线程ID
    int with_lock_tid;     // 有锁访问的线程ID
    int sn;
} onesidedreproduce_info_t;

#define KCCWF_TRACE_RECORD_VERSION 1
#define KCCWF_TRACE_MAX_LOCKS 8
#define KCCWF_TRACE_ACCESS_READ 0
#define KCCWF_TRACE_ACCESS_WRITE 1
#define KCCWF_TRACE_ACCESS_FREE 2

typedef struct {
    uint64_t ptr;
    int32_t attr;
    int32_t reserved;
} kccwf_trace_lock_record_t;

typedef struct {
    uint32_t version;
    uint8_t access_type;
    uint8_t lock_count;
    uint16_t size;
    int32_t tid;
    int32_t sn;
    int32_t file_line;
    uint64_t var_name;
    uint64_t var_addr;
    uint64_t call_stack_hash;
    uint64_t access_time;
    kccwf_trace_lock_record_t locks[KCCWF_TRACE_MAX_LOCKS];
} kccwf_trace_record_t;

typedef struct {
    uint32_t version;
    uint32_t capacity;
    uint32_t count;
    uint32_t dropped;
    uint32_t record_size;
    uint32_t flags;
    uint64_t write_seq;
    uint64_t records;
} kccwf_trace_read_t;
#endif
