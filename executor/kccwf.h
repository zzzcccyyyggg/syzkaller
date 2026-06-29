#ifndef KCCWF_UAPI_H
#define KCCWF_UAPI_H

#include <stdbool.h>
#include <stdint.h>

#include "kccwf_trace.h"

// 和内核定义保持一致：最多支持两个 testing TID
#define KCCWF_MAX_TESTING_TID_NUM 0x2
#define KCCWF_UAF_DELAY_BOTH 0
#define KCCWF_UAF_DELAY_USE 1
#define KCCWF_UAF_DELAY_FREE 2
#define KCCWF_UAF_DELAY_NONE 3
#define KCCWF_UAF_DELAY_MODE_SLEEP 0
#define KCCWF_UAF_DELAY_MODE_NONBLOCKING 1

// 内核里 tid_t 本质上是 32 位的 pid_t，这里用 int32_t 对齐大小即可
typedef int32_t tid_t;

typedef struct {
	tid_t tids[KCCWF_MAX_TESTING_TID_NUM];
	int num;
} kccwf_testing_tids_t;

// 可能存在数据竞争的变量对
typedef struct {
	unsigned long var_name_1;
	unsigned long var_name_2;
	unsigned long call_stack_hash_1;
	unsigned long call_stack_hash_2;
	bool is_synchronized;
} may_race_pair_t;

// 可能存在数据竞争的变量对列表
#define MAX_RACE_PAIR_NUM 0x100000

typedef struct {
	uint32_t num; // 实际 pair 个数
	may_race_pair_t* pairs; // 用户态指向数组的指针
} may_race_pair_list_t;

// CHECK 阶段信息
typedef struct {
	uint64_t var_name;
	uint32_t testing_tid;
} check_phase_info_t;

// NOLOCKREPRODUCE 模式信息
typedef struct {
	unsigned long var_name;
	unsigned long stack_hash;
	int tid;
	int sn;
} nolockreproduce_info_t;

// ONESIDEDREPRODUCE 模式信息
typedef struct {
	unsigned long var_name;
	unsigned long stack_hash;
	int no_lock_tid; // 无锁访问线程 ID
	int with_lock_tid; // 有锁访问线程 ID
	int sn;
} onesidedreproduce_info_t;

// 可能存在 UAF 的 use/free 对
typedef struct {
	unsigned long use_name;
	unsigned long use_stack;
	int use_sn;
	int use_sn_min;
	int use_sn_max;
	int use_tid;
	unsigned long free_name;
	unsigned long free_stack;
	int free_sn;
	int free_sn_min;
	int free_sn_max;
	int free_tid;
	int use_access_delay_time;
	int target_delay_side;
	int target_delay_mode;
	bool is_valid;
	bool use_triggered;
	bool free_triggered;
} may_uaf_pair_t;

#endif /* KCCWF_UAPI_H */
