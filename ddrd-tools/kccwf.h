#ifndef KCCWF_H_INCLUDED
#define KCCWF_H_INCLUDED

#include <cstdint>
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
#endif