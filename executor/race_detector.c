// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Race detector for syzkaller - C implementation
#include "race_detector.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// 简单的strdup实现（防止某些系统没有）
static char* my_strdup(const char* str)
{
	if (!str)
		return NULL;
	size_t len = strlen(str);
	char* dup = malloc(len + 1);
	if (dup) {
		strcpy(dup, str);
	}
	return dup;
}

// debug函数声明 (从executor.cc引入)
#if defined(SYZ_EXECUTOR) || defined(SYZ_THREADED)
void debug(const char* msg, ...);
#else
#define debug(...)
#endif

// Shared memory structures for pair syscall timing (from executor.cc)
#define MAX_PAIR_SYSCALLS 1024

struct PairSyscallSharedData {
	SyscallTimeRecord prog1_syscalls[MAX_PAIR_SYSCALLS];
	SyscallTimeRecord prog2_syscalls[MAX_PAIR_SYSCALLS];
	volatile int prog1_syscall_count;
	volatile int prog2_syscall_count;
	volatile bool initialized;
};

// Access to shared memory data from executor
extern struct PairSyscallSharedData* get_pair_shared_data();

// 全局状态
static bool race_collection_enabled = false;
static int race_trace_fd = -1;

// race信号存储结构
#define MAX_RACE_SIGNALS 1024
static int race_signals_count = 0;

// 简单的字符串哈希函数
static uint64_t hash_string(const char* str)
{
	uint64_t hash = 5381;
	int c;
	while ((c = *str++)) {
		hash = ((hash << 5) + hash) + c; // hash * 33 + c
	}
	return hash;
}

// 生成race信号的哈希
static uint64_t hash_race_signal(const char* var1, const char* stack1,
				 const char* var2, const char* stack2)
{
	uint64_t h1 = hash_string(var1 ? var1 : "");
	uint64_t h2 = hash_string(stack1 ? stack1 : "");
	uint64_t h3 = hash_string(var2 ? var2 : "");
	uint64_t h4 = hash_string(stack2 ? stack2 : "");

	// 将 (var, stack) 两对先分别合成
	uint64_t pair1 = h1 ^ (h2 << 1);
	uint64_t pair2 = h3 ^ (h4 << 1);

	// 顺序无关组合：用加法或 commutative 异或
	// 为减少碰撞，可以用 pair1 < pair2 排序后再组合
	if (pair1 > pair2) {
		uint64_t tmp = pair1;
		pair1 = pair2;
		pair2 = tmp;
	}

	return pair1 * 1315423911u ^ pair2;
}

// 解析access log行并提取访问信息
static AccessRecord parse_access_line(const char* line)
{
	AccessRecord record = {0};

	if (!line || strlen(line) < 20) {
		return record;
	}

	// 查找 "[KCCWF] log access:" 标记
	const char* marker = "[KCCWF] log access:";
	const char* content = strstr(line, marker);
	if (!content) {
		return record;
	}

	content += strlen(marker);

	// 解析各个字段
	const char* pos = content;
	char key[32], value[64];

	while (*pos) {
		// 跳过空格和逗号
		while (*pos == ' ' || *pos == ',')
			pos++;
		if (*pos == '\0')
			break;

		// 解析 key=value 对
		const char* eq = strchr(pos, '=');
		if (!eq)
			break;

		int key_len = eq - pos;
		if (key_len >= sizeof(key))
			key_len = sizeof(key) - 1;
		strncpy(key, pos, key_len);
		key[key_len] = '\0';

		pos = eq + 1;

		// 提取value
		const char* value_end = pos;
		while (*value_end && *value_end != ',' && *value_end != ' ')
			value_end++;

		int value_len = value_end - pos;
		if (value_len >= sizeof(value))
			value_len = sizeof(value) - 1;
		strncpy(value, pos, value_len);
		value[value_len] = '\0';

		// 根据key设置对应字段
		if (strcmp(key, "tid") == 0) {
			record.tid = atoi(value);
		} else if (strcmp(key, "var_name") == 0) {
			record.var_name = strtoull(value, NULL, 10);
		} else if (strcmp(key, "var_addr") == 0) {
			// 地址值通常是十六进制格式（可能有或没有0x前缀）
			if (strncmp(value, "0x", 2) == 0 || strncmp(value, "0X", 2) == 0) {
				record.address = strtoull(value, NULL, 0); // 有0x前缀，自动检测
			} else {
				record.address = strtoull(value, NULL, 16); // 没有0x前缀，强制十六进制
			}
		} else if (strcmp(key, "type") == 0) {
			int type_val = atoi(value);
			record.access_type = (type_val == 1) ? 'W' : (type_val == 2) ? 'F'
										     : 'R';
		} else if (strcmp(key, "size") == 0) {
			record.size = strtoull(value, NULL, 10);
		} else if (strcmp(key, "call_stack_hash") == 0) {
			record.call_stack_hash = strtoull(value, NULL, 10);
		} else if (strcmp(key, "access_time") == 0) {
			record.access_time = strtoull(value, NULL, 10);
		} else if (strcmp(key, "sn") == 0) {
			record.sn = atoi(value);
		}

		pos = value_end;
	}

	// 检查是否解析到有效数据
	if (record.tid > 0 && record.var_name > 0) {
		record.valid = true;
		record.lock_count = 0; // 初始化锁计数
	}

	return record;
}

// 解析lock信息行
static LockRecord parse_lock_line(const char* line)
{
	LockRecord lock = {0};

	if (!line) {
		return lock;
	}

	// 查找 "Held Lock:" 标记
	const char* marker = "Held Lock:";
	const char* content = strstr(line, marker);
	if (!content) {
		return lock;
	}

	content += strlen(marker);

	// 解析name='...'
	const char* name_start = strstr(content, "name='");
	if (name_start) {
		name_start += 6; // 跳过 "name='"
		const char* name_end = strchr(name_start, '\'');
		if (name_end) {
			int name_len = name_end - name_start;
			if (name_len >= sizeof(lock.name))
				name_len = sizeof(lock.name) - 1;
			strncpy(lock.name, name_start, name_len);
			lock.name[name_len] = '\0';
		}
	}

	// 解析ptr=0x...
	const char* ptr_pos = strstr(content, "ptr=");
	if (ptr_pos) {
		lock.ptr = strtoull(ptr_pos + 4, NULL, 0);
	}

	// 解析attr=...
	const char* attr_pos = strstr(content, "attr=");
	if (attr_pos) {
		lock.attr = atoi(attr_pos + 5);
	}

	if (strlen(lock.name) > 0 || lock.ptr > 0) {
		lock.valid = true;
	}

	return lock;
}

// 优化版本：解析访问记录到记录集合，同时分离free操作
int parse_access_records_to_set(const char* buffer, AccessRecordSet* record_set, int max_records, int max_frees)
{
	if (!buffer || !record_set || max_records <= 0 || max_frees <= 0) {
		return 0;
	}

	int record_count = 0;
	int free_count = 0;
	char* buffer_copy = my_strdup(buffer);
	if (!buffer_copy) {
		return 0;
	}

	char* line = strtok(buffer_copy, "\n");
	AccessRecord current_record = {0};
	bool has_current = false;

	while (line && record_count < max_records && free_count < max_frees) {
		// 尝试解析访问记录
		AccessRecord access = parse_access_line(line);
		if (access.valid) {
			// 如果有当前记录，处理它
			if (has_current) {
				if (current_record.access_type == 'F') {
					// 这是一个free操作，添加到free记录中
					FreeRecord* free_rec = &record_set->free_records[free_count];
					free_rec->address = current_record.address;
					free_rec->size = current_record.size;
					free_rec->access_time = current_record.access_time;
					free_rec->tid = current_record.tid;
					free_count++;
				} else {
					// 这是一个普通访问，添加到访问记录中
					record_set->records[record_count++] = current_record;
				}
			}

			current_record = access;
			current_record.lock_count = 0; // 初始化锁计数
			has_current = true;
		} else {
			// 尝试解析锁信息
			LockRecord lock = parse_lock_line(line);
			if (lock.valid && has_current && current_record.lock_count < 8) {
				// 将锁信息添加到当前访问记录
				current_record.held_locks[current_record.lock_count] = lock;
				current_record.lock_count++;
			}
		}
		line = strtok(NULL, "\n");
	}

	// 保存最后一个记录
	if (has_current) {
		if (current_record.access_type == 'F' && free_count < max_frees) {
			FreeRecord* free_rec = &record_set->free_records[free_count];
			free_rec->address = current_record.address;
			free_rec->size = current_record.size;
			free_rec->access_time = current_record.access_time;
			free_rec->tid = current_record.tid;
			free_count++;
		} else if (current_record.access_type != 'F' && record_count < max_records) {
			record_set->records[record_count++] = current_record;
		}
	}

	record_set->record_count = record_count;
	record_set->free_count = free_count;

	free(buffer_copy);
	return record_count;
}

// 判断两个地址是否重叠
bool addresses_overlap(const AccessRecord* a, const AccessRecord* b)
{
	return (a->address < b->address + b->size) && (b->address < a->address + a->size);
}

// 判断访问记录与free记录是否重叠
static bool access_overlaps_free(const AccessRecord* access, const FreeRecord* free_rec)
{
	return (access->address < free_rec->address + free_rec->size) &&
	       (free_rec->address < access->address + access->size);
}

// 优化版本：使用预分离的free记录检查有效区间
bool in_same_valid_interval_optimized(const AccessRecord* a, const AccessRecord* b, FreeRecord* free_records, int free_count)
{
	uint64_t min_time = (a->access_time <= b->access_time) ? a->access_time : b->access_time;
	uint64_t max_time = (a->access_time > b->access_time) ? a->access_time : b->access_time;

	// 检查时间区间内是否有free操作影响这两个访问的地址范围
	for (int i = 0; i < free_count; i++) {
		const FreeRecord* free_rec = &free_records[i];
		if (free_rec->access_time > min_time &&
		    free_rec->access_time < max_time) {

			// 检查free操作是否与访问a或访问b的地址范围重叠
			if (access_overlaps_free(a, free_rec) || access_overlaps_free(b, free_rec)) {
				return false;
			}
		}
	}

	return true;
}

// 确定两个访问之间的锁状态
LockStatus determine_lock_status(const AccessRecord* a, const AccessRecord* b)
{
	if (a->lock_count == 0 && b->lock_count == 0) {
		return LOCK_NO_LOCKS;
	}

	if (a->lock_count == 0 || b->lock_count == 0) {
		return LOCK_ONE_SIDED_LOCK;
	}

	// 检查是否有公共锁
	for (int i = 0; i < a->lock_count; i++) {
		for (int j = 0; j < b->lock_count; j++) {
			if (a->held_locks[i].ptr == b->held_locks[j].ptr) {
				return LOCK_SYNC_WITH_COMMON_LOCK;
			}
		}
	}

	return LOCK_UNSYNC_LOCKS;
}

// 优化版本：从访问记录集合分析race pairs（使用预分离的free记录）
int analyze_race_pairs_from_set(AccessRecordSet* record_set, RacePair* pairs, int max_pairs)
{
	// ===============DDRD====================
	// Use nanosecond precision for precise race detection and syscall correlation
	const uint64_t TIME_THRESHOLD = 1000000; // 1ms = 1,000,000ns (nanoseconds) - basic threshold
	const uint64_t FAST_THRESHOLD = 100000; // 100us = 100,000ns for very close accesses
	// const uint64_t SLOW_THRESHOLD = 10000000;  // 10ms = 10,000,000ns for slower operations (unused)
	// ===============DDRD====================
	int pair_count = 0;

	debug("Analyzing %d access records and %d free records for race pairs (optimized)\n",
	      record_set->record_count, record_set->free_count);

	for (int i = 0; i < record_set->record_count && pair_count < max_pairs; i++) {
		for (int j = i + 1; j < record_set->record_count && pair_count < max_pairs; j++) {
			AccessRecord* a = &record_set->records[i];
			AccessRecord* b = &record_set->records[j];

			// 应用DDRD的过滤条件

			// 1. 跳过相同线程的访问
			if (a->tid == b->tid) {
				continue;
			}

			// 2. 至少一个必须是写操作（free操作已经在解析时分离了）
			if (!(a->access_type == 'W' || b->access_type == 'W')) {
				continue;
			}

			// 3. 检查地址重叠
			if (!addresses_overlap(a, b)) {
				continue;
			}

			// 4. 检查时间阈值（使用微秒精度进行更精确的检测）
			uint64_t time_diff = (a->access_time > b->access_time) ? (a->access_time - b->access_time) : (b->access_time - a->access_time);

			// ===============DDRD====================
			// Use adaptive time threshold based on access types
			uint64_t threshold = TIME_THRESHOLD;
			if (a->access_type == 'W' && b->access_type == 'W') {
				threshold = FAST_THRESHOLD; // Write-write races are more critical
			}

			if (time_diff > threshold) {
				debug("Time diff %lluus exceeds threshold %lluus for TID %d->%d\n",
				      time_diff, threshold, a->tid, b->tid);
				continue;
			}
			// ===============DDRD====================

			// 5. 使用优化版本检查是否在同一个有效区间内
			if (!in_same_valid_interval_optimized(a, b, record_set->free_records, record_set->free_count)) {
				continue;
			}

			// 确定锁状态
			LockStatus lock_status = determine_lock_status(a, b);

			// 创建race pair（确保时间顺序）
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
			pair->lock_status = lock_status;

			// ===============DDRD====================
			// Debug information for race pair detection
			debug("Race pair detected (optimized): TID %d(%c) <-> TID %d(%c), time_diff=%lluus, lock_status=%d\n",
			      a->tid, a->access_type, b->tid, b->access_type, time_diff, lock_status);
			debug("  Addresses: 0x%llx(size %llu) <-> 0x%llx(size %llu)\n",
			      a->address, a->size, b->address, b->size);
			// ===============DDRD====================

			pair_count++;
		}
	}

	// ===============DDRD====================
	debug("Optimized race pair analysis complete: found %d pairs from %d records, %d free operations\n",
	      pair_count, record_set->record_count, record_set->free_count);
	// ===============DDRD====================

	return pair_count;
}

// 检查UAF的有效性：确保use和free之间没有其他free操作使这个use无效
bool check_uaf_validity(const AccessRecord* use_access, const FreeRecord* free_op, FreeRecord* all_frees, int free_count)
{
	uint64_t use_time = use_access->access_time;
	uint64_t free_time = free_op->access_time;
	uint64_t use_addr = use_access->address;
	uint64_t use_end = use_addr + use_access->size;

	// 检查是否有在这个free操作之前，但时间上更接近use操作的free操作
	// 这样的free操作会使当前的free->use组合无效
	for (int i = 0; i < free_count; i++) {
		const FreeRecord* other_free = &all_frees[i];

		// 跳过当前的free操作
		if (other_free->access_time == free_time &&
		    other_free->address == free_op->address &&
		    other_free->tid == free_op->tid) {
			continue;
		}

		// 检查是否有更晚的free操作（在当前free之后，use之前）
		if (other_free->access_time > free_time &&
		    other_free->access_time < use_time) {

			// 检查地址是否重叠
			uint64_t other_addr = other_free->address;
			uint64_t other_end = other_addr + other_free->size;

			if ((other_addr < use_end) && (use_addr < other_end)) {
				debug("UAF invalidated by later free: TID %d at time %llu (between %llu and %llu)\n",
				      other_free->tid, (unsigned long long)other_free->access_time,
				      (unsigned long long)free_time, (unsigned long long)use_time);
				return false; // 有后续的free操作使这个UAF无效
			}
		}
	}

	return true;
}

// 确定UAF的锁状态
LockStatus determine_uaf_lock_status(const AccessRecord* use_access, const FreeRecord* free_op)
{
	// 注意：FreeRecord没有锁信息，这里需要从原始AccessRecord中获取
	// 为了简化，我们假设free_op来自相应的AccessRecord

	// 简化实现：由于FreeRecord结构限制，我们只能基于use_access的锁状态
	if (use_access->lock_count == 0) {
		return LOCK_NO_LOCKS; // 假设free操作也没有锁
	} else {
		return LOCK_ONE_SIDED_LOCK; // 保守估计
	}
}

// 从访问记录集合分析UAF pairs
int analyze_uaf_pairs_from_set(AccessRecordSet* record_set, UAFPair* uaf_pairs, int max_pairs, UAFStatistics* stats)
{
	// ===============DDRD====================
	// UAF检测时间阈值（微秒）
	const uint64_t TIME_THRESHOLD = 10000; // 10ms
	// ===============DDRD====================

	int pair_count = 0;

	// 初始化统计
	if (stats) {
		memset(stats, 0, sizeof(UAFStatistics));
	}

	debug("Analyzing %d access records and %d free records for UAF pairs\n",
	      record_set->record_count, record_set->free_count);

	// 遍历所有访问记录
	for (int i = 0; i < record_set->record_count && pair_count < max_pairs; i++) {
		AccessRecord* use_access = &record_set->records[i];

		// 找到最近的、在use_access之前的free操作
		FreeRecord* closest_free = NULL;
		uint64_t closest_time_diff = UINT64_MAX;

		for (int j = 0; j < record_set->free_count; j++) {
			FreeRecord* free_op = &record_set->free_records[j];

			// 1. 跳过相同线程的操作
			if (use_access->tid == free_op->tid) {
				continue;
			}

			// 2. UAF条件：use操作必须在free操作之后
			if (use_access->access_time <= free_op->access_time) {
				continue;
			}

			// 3. 检查地址重叠
			uint64_t use_end = use_access->address + use_access->size;
			uint64_t free_end = free_op->address + free_op->size;

			if (!((use_access->address < free_end) && (free_op->address < use_end))) {
				continue;
			}

			// 4. 检查时间阈值
			uint64_t time_diff = use_access->access_time - free_op->access_time;
			if (time_diff > TIME_THRESHOLD) {
				continue;
			}

			// 找到时间上最接近的free操作
			if (time_diff < closest_time_diff) {
				closest_free = free_op;
				closest_time_diff = time_diff;
			}
		}

		// 如果找到了最近的free操作，创建UAF pair
		if (closest_free) {
			// 5. 检查UAF的有效性（中间没有其他free操作）
			if (!check_uaf_validity(use_access, closest_free, record_set->free_records, record_set->free_count)) {
				continue;
			}

			// 6. 确定锁状态
			LockStatus lock_status = determine_uaf_lock_status(use_access, closest_free);

			// 创建UAF pair
			UAFPair* uaf_pair = &uaf_pairs[pair_count];
			uaf_pair->use_access = *use_access;
			uaf_pair->free_operation = *closest_free;
			uaf_pair->time_diff = closest_time_diff;
			uaf_pair->lock_status = lock_status;
			uaf_pair->trigger_count = 1;

			// 更新统计
			if (stats) {
				switch (lock_status) {
				case LOCK_NO_LOCKS:
					stats->no_locks_count++;
					break;
				case LOCK_ONE_SIDED_LOCK:
					stats->one_sided_lock_count++;
					break;
				case LOCK_UNSYNC_LOCKS:
					stats->unsync_locks_count++;
					break;
				case LOCK_SYNC_WITH_COMMON_LOCK:
					stats->sync_with_common_lock_count++;
					break;
				}
				stats->total_uaf_pairs++;
			}

			// ===============DDRD====================
			// Debug information for UAF detection
			debug("UAF detected: TID %d(%c) uses memory freed by TID %d at time %llu, use_time=%llu, time_diff=%lluus\n",
			      use_access->tid, use_access->access_type, closest_free->tid,
			      (unsigned long long)closest_free->access_time, (unsigned long long)use_access->access_time,
			      (unsigned long long)closest_time_diff);
			debug("  Use address: 0x%llx(size %llu), Free address: 0x%llx(size %llu)\n",
			      (unsigned long long)use_access->address, (unsigned long long)use_access->size,
			      (unsigned long long)closest_free->address, (unsigned long long)closest_free->size);
			// ===============DDRD====================

			pair_count++;
		}
	}

	// ===============DDRD====================
	debug("UAF analysis complete: found %d UAF pairs from %d access records and %d free records\n",
	      pair_count, record_set->record_count, record_set->free_count);
	// ===============DDRD====================

	return pair_count;
}

// 初始化race检测器
void init_race_detector()
{
	race_collection_enabled = false;
	race_trace_fd = -1;
	race_signals_count = 0;

	// 尝试打开trace文件
	race_trace_fd = open("/sys/kernel/debug/tracing/trace", O_RDONLY);
	if (race_trace_fd >= 0) {
		race_collection_enabled = true;
		debug("Race detector initialized successfully with nanosecond precision\n");
		lseek(race_trace_fd, 0, SEEK_CUR);
	} else {
		debug("Race detector initialization failed\n");
	}
}

// 清理race检测器
void cleanup_race_detector()
{
	if (race_trace_fd >= 0) {
		close(race_trace_fd);
		race_trace_fd = -1;
	}
	race_collection_enabled = false;
	race_signals_count = 0;
}


// 重置race检测状态
void reset_race_detector()
{
	if (!race_collection_enabled || race_trace_fd < 0) {
		return;
	}

	// 重新定位到文件开始
	lseek(race_trace_fd, 0, SEEK_SET);
	race_signals_count = 0;
}

// 检查race检测是否可用
bool is_race_detector_available()
{
	return race_collection_enabled && race_trace_fd >= 0;
}

// If the access time is within the occurrence time of a certain syscall,
// then it means that the variable access occurs within this syscall.
SyscallTimeRecord* find_matching_syscall(uint64_t access_time, int tid)
{
	struct PairSyscallSharedData* pair_shared_data = get_pair_shared_data();
	if (pair_shared_data->prog1_syscall_count > 0) {
		if (tid == pair_shared_data->prog1_syscalls[0].thread_id) {
			for (int i = 0; i < pair_shared_data->prog1_syscall_count; i++) {
				if (pair_shared_data->prog1_syscalls[i].valid &&
				    pair_shared_data->prog1_syscalls[i].start_time <= access_time &&
				    pair_shared_data->prog1_syscalls[i].end_time >= access_time) {
					return &pair_shared_data->prog1_syscalls[i];
				}
			}
		}
	}
	if (pair_shared_data->prog2_syscall_count > 0) {
		if (tid == pair_shared_data->prog2_syscalls[0].thread_id) {
			for (int i = 0; i < pair_shared_data->prog2_syscall_count; i++) {
				if (pair_shared_data->prog2_syscalls[i].valid &&
				    pair_shared_data->prog2_syscalls[i].start_time <= access_time &&
				    pair_shared_data->prog2_syscalls[i].end_time >= access_time) {
					return &pair_shared_data->prog2_syscalls[i];
				}
			}
		}
	}
    return NULL; // No matching syscall found
}

// 分析并生成race信号
int analyze_and_generate_may_race_infos(may_race_pair_t* may_race_pair_buffer, int max_race_pairs)
{
	if (!race_collection_enabled || race_trace_fd < 0 || !may_race_pair_buffer || max_race_pairs <= 0) {
		return 0;
	}

#define MAX_RECORDS 0X5000 // 20480 RECORDS
#define MAX_RACE_PAIRS 0X200 // 2048 PAIRS

	size_t buffer_size = sizeof(AccessRecord) * (MAX_RECORDS + 1);
	char* buffer = malloc(buffer_size);

	if (!buffer) {
		return 0;
	}

	ssize_t bytes_read = read(race_trace_fd, buffer, buffer_size - 1);
	if (bytes_read <= 0) {
		debug("Failed to read trace data: %zd bytes\n", bytes_read);
		free(buffer);
		return 0;
	}

	buffer[bytes_read] = '\0';

	debug("Read %zd bytes from trace (buffer size: %zu)\n", bytes_read, buffer_size);

	// 使用动态分配减少栈空间使用
	AccessRecord* records = malloc(sizeof(AccessRecord) * MAX_RECORDS);
	FreeRecord* free_records = malloc(sizeof(FreeRecord) * (MAX_RECORDS / 4)); // 假设free操作不超过总操作的25%
	RacePair* pairs = malloc(sizeof(RacePair) * MAX_RACE_PAIRS);

	if (!records || !free_records || !pairs) {
		free(buffer);
		free(records);
		free(free_records);
		free(pairs);
		return 0;
	}

	AccessRecordSet record_set = {
	    .records = records,
	    .record_count = 0,
	    .free_records = free_records,
	    .free_count = 0};

	parse_access_records_to_set(buffer, &record_set, MAX_RECORDS, MAX_RECORDS / 4);

	int pair_count = analyze_race_pairs_from_set(&record_set, pairs, MAX_RACE_PAIRS);

	int i = 0;
	for (i = 0; i < pair_count && i < max_race_pairs; i++) {
		RacePair* pair = &pairs[i];
		may_race_pair_buffer[i].varName1 = pair->first.var_name;
		may_race_pair_buffer[i].varName2 = pair->second.var_name;
		may_race_pair_buffer[i].call_stack1 = pair->first.call_stack_hash;
		may_race_pair_buffer[i].call_stack2 = pair->second.call_stack_hash;
		may_race_pair_buffer[i].sn1 = pair->first.sn;
		may_race_pair_buffer[i].sn2 = pair->second.sn;
        may_race_pair_buffer[i].lock_type = pair->lock_status;
		may_race_pair_buffer[i].signal = hash_race_signal(
		    (char*)&pair->first.var_name,
		    (char*)&pair->first.call_stack_hash,
		    (char*)&pair->second.var_name,
		    (char*)&pair->second.call_stack_hash);
		may_race_pair_buffer[i].access_type1 = pair->first.access_type;
		may_race_pair_buffer[i].access_type2 = pair->second.access_type;
		may_race_pair_buffer[i].time_diff = pair->access_time_diff;
		SyscallTimeRecord* matching_syscall1 = find_matching_syscall(pair->first.access_time, pair->first.tid);
		SyscallTimeRecord* matching_syscall2 = find_matching_syscall(pair->second.access_time, pair->second.tid);
        may_race_pair_buffer[i].syscall1_idx = matching_syscall1->call_index;
        may_race_pair_buffer[i].syscall1_num = matching_syscall1->call_num;
        may_race_pair_buffer[i].syscall2_idx = matching_syscall2->call_index;
        may_race_pair_buffer[i].syscall2_num = matching_syscall2->call_num;
	}

	// 更新全局计数器
	race_signals_count += i;

	free(buffer);
	free(records);
	free(free_records);
	free(pairs);
	return i;
}
// ===============DDRD====================
