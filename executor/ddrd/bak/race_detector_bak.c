// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Race detector for syzkaller - C implementation
#include "race_detector.h"
#include "data_race_analyse.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

__attribute__((format(printf, 1, 2))) static void debug(const char* msg, ...);
static char* my_strdup(const char* str);

// Shared memory structures for pair syscall timing (from executor.cc)
#define MAX_PAIR_SYSCALLS 1024

struct PairSyscallSharedData {
	SyscallTimeRecord prog1_syscalls[MAX_PAIR_SYSCALLS];
	SyscallTimeRecord prog2_syscalls[MAX_PAIR_SYSCALLS];
	volatile int prog1_syscall_count;
	volatile int prog2_syscall_count;
	volatile bool initialized;
};

// Access to shared memory data from executor, implement like this for race_detector.c can get the global data from excutor.c
extern struct PairSyscallSharedData* get_pair_shared_data();

static bool race_collection_enabled = false;
static int race_trace_fd = -1;

// race信号存储结构
#define MAX_RACE_SIGNALS 1024

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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// 读取 trace buffer 到用户传入的 buffer，返回实际读取的字节数
// 使用全局的 race_trace_fd 避免重复打开文件
static ssize_t read_trace_buffer(char* buffer, size_t size)
{
	if (!buffer || size == 0)
		return -1;

	// 检查全局文件描述符是否有效
	if (race_trace_fd < 0) {
		debug("read_trace_buffer: race_trace_fd is not initialized\n");
		buffer[0] = '\0';
		return -1;
	}

	size_t total = 0;
	
	// 从头读（重置文件位置）
	if (lseek(race_trace_fd, 0, SEEK_SET) == (off_t)-1) {
		debug("read_trace_buffer: lseek failed (errno=%d)\n", errno);
		// 有些 pseudo 文件不支持 lseek，不算致命，继续读取
	}

	for (;;) {
		if (total >= size - 1) // 预留 1 字节放 '\0'
			break;
		size_t want = size - 1 - total;
		ssize_t n = read(race_trace_fd, buffer + total, want);
		if (n > 0) {
			total += (size_t)n;
			continue;
		}
		if (n == 0) { // EOF
			break;
		}
		if (errno == EINTR)
			continue;
		// 其他错误
		debug("read_trace_buffer: read error (errno=%d)\n", errno);
		break;
	}
	buffer[total] = '\0'; // 保证以 null 结尾

	// debug("read_trace_buffer read %zu bytes\n", total);
	return (ssize_t)total;
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
	// debug("%s\n", line);
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
		// 添加调试输出
		// debug("Parsed access record: tid=%d, var_name=%llu, address=0x%llx, type='%c', size=%llu, time=%llu, sn=%d\n",
		//       record.tid, (unsigned long long)record.var_name, (unsigned long long)record.address, 
		//       record.access_type, (unsigned long long)record.size, (unsigned long long)record.access_time, record.sn);
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
	
	// 初始化线程历史
	record_set->thread_count = 0;
	for (int i = 0; i < MAX_THREADS; i++) {
		record_set->thread_histories[i].tid = -1;
		record_set->thread_histories[i].access_count = 0;
		record_set->thread_histories[i].access_index = 0;
		record_set->thread_histories[i].buffer_full = false;
	}
	
	char* buffer_copy = my_strdup(buffer);
	if (!buffer_copy) {
		return 0;
	}

	char* line = strtok(buffer_copy, "\n");
	AccessRecord current_record = {0};
	bool has_current = false;

	while (line) {
		AccessRecord access = parse_access_line(line);
		if (access.valid) {
			// 如果有当前记录，处理它（但不立即保存，让它先收集锁信息）
			if (has_current) {
				// debug("Saving previous record: type='%c', locks=%d\n", current_record.access_type, current_record.lock_count);
				
				// 添加到线程历史
				ThreadAccessHistory* thread_history = find_thread_history(record_set, current_record.tid);
				if (!thread_history) {
					thread_history = create_thread_history(record_set, current_record.tid);
				}
				if (thread_history) {
					add_access_to_history(thread_history, &current_record);
				}
				
				if (current_record.access_type == 'F') {
					// 这是一个free操作，添加到free记录中
					AccessRecord* free_rec = &record_set->free_records[free_count];
					free_rec->address = current_record.address;
					free_rec->size = current_record.size;
					free_rec->access_time = current_record.access_time;
					free_rec->tid = current_record.tid;
					// 复制锁信息到FreeRecord
					free_rec->lock_count = current_record.lock_count;
					for (int k = 0; k < current_record.lock_count && k < 8; k++) {
						free_rec->held_locks[k] = current_record.held_locks[k];
					}
					// debug("Added free record #%d with %d locks\n", free_count, free_rec->lock_count);
					free_count++;
				} else {
					// 这是一个普通访问，添加到访问记录中
					// debug("Added access record #%d with %d locks\n", record_count, current_record.lock_count);
					record_set->records[record_count++] = current_record;
				}
			}

			// debug("Starting new record: type='%c'\n", access.access_type);
			current_record = access;
			current_record.lock_count = 0; // 初始化锁计数
			has_current = true;
		} else {
			LockRecord lock = parse_lock_line(line);
			if (lock.valid && has_current && current_record.lock_count < 8) {
				current_record.held_locks[current_record.lock_count] = lock;
				current_record.lock_count++;
			}
		}
		line = strtok(NULL, "\n");
	}

	if (record_count >= max_records) {
		debug("Reached max_records limit (%d), stopping parsing\n", max_records);
	}
	if (free_count >= max_frees) {
		debug("Reached max_frees limit (%d), stopping parsing\n", max_frees);
	}
	// 保存最后一个记录（确保包含所有收集到的锁信息）
	if (has_current) {
		// debug("Saving final record: type='%c', locks=%d\n", current_record.access_type, current_record.lock_count);
		
		// 添加到线程历史
		ThreadAccessHistory* thread_history = find_thread_history(record_set, current_record.tid);
		if (!thread_history) {
			thread_history = create_thread_history(record_set, current_record.tid);
		}
		if (thread_history) {
			add_access_to_history(thread_history, &current_record);
		}
		
		if (current_record.access_type == 'F' && free_count < max_frees) {
			AccessRecord* free_rec = &record_set->free_records[free_count];
			free_rec->address = current_record.address;
			free_rec->size = current_record.size;
			free_rec->access_time = current_record.access_time;
			free_rec->tid = current_record.tid;
			// 复制锁信息到FreeRecord
			free_rec->lock_count = current_record.lock_count;
			for (int k = 0; k < current_record.lock_count && k < 8; k++) {
				free_rec->held_locks[k] = current_record.held_locks[k];
			}
			// debug("Added final free record #%d with %d locks\n", free_count, free_rec->lock_count);
			free_count++;
		} else if (current_record.access_type != 'F' && record_count < max_records) {
			// debug("Added final access record #%d with %d locks\n", record_count, current_record.lock_count);
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
static bool access_overlaps_free(const AccessRecord* access, const AccessRecord* free_rec)
{
	return (access->address < free_rec->address + free_rec->size) &&
	       (free_rec->address < access->address + access->size);
}

// 优化版本：使用预分离的free记录检查有效区间
bool check_data_race_validity(const AccessRecord* a, const AccessRecord* b, AccessRecord* free_records, int free_count)
{
	uint64_t min_time = (a->access_time <= b->access_time) ? a->access_time : b->access_time;
	uint64_t max_time = (a->access_time > b->access_time) ? a->access_time : b->access_time;

	// 检查时间区间内是否有free操作影响这两个访问的地址范围
	for (int i = 0; i < free_count; i++) {
		const AccessRecord* free_rec = &free_records[i];
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
				// debug("Time diff %luus exceeds threshold %luus for TID %d->%d\n",
				//       (unsigned long)time_diff, (unsigned long)threshold, a->tid, b->tid);
				continue;
			}
			// ===============DDRD====================
			if (!check_data_race_validity(a, b, record_set->free_records, record_set->free_count)) {
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
			
			// 添加历史访问信息
			pair->thread1_history = find_thread_history(record_set, pair->first.tid);
			pair->thread2_history = find_thread_history(record_set, pair->second.tid);
			
			// 查找访问在历史中的索引位置
			pair->first_access_index = -1;
			pair->second_access_index = -1;
			
			if (pair->thread1_history) {
				// 在线程1历史中查找第一个访问的索引
				int total_accesses1 = pair->thread1_history->buffer_full ? MAX_THREAD_HISTORY : pair->thread1_history->access_count;
				for (int k = 0; k < total_accesses1; k++) {
					int actual_index = pair->thread1_history->buffer_full ? 
					                  (pair->thread1_history->access_index + k) % MAX_THREAD_HISTORY : k;
					if (pair->thread1_history->accesses[actual_index].access_time == pair->first.access_time &&
					    pair->thread1_history->accesses[actual_index].address == pair->first.address) {
						pair->first_access_index = actual_index;
						break;
					}
				}
			}
			
			if (pair->thread2_history) {
				// 在线程2历史中查找第二个访问的索引
				int total_accesses2 = pair->thread2_history->buffer_full ? MAX_THREAD_HISTORY : pair->thread2_history->access_count;
				for (int k = 0; k < total_accesses2; k++) {
					int actual_index = pair->thread2_history->buffer_full ? 
					                  (pair->thread2_history->access_index + k) % MAX_THREAD_HISTORY : k;
					if (pair->thread2_history->accesses[actual_index].access_time == pair->second.access_time &&
					    pair->thread2_history->accesses[actual_index].address == pair->second.address) {
						pair->second_access_index = actual_index;
						break;
					}
				}
			}

			// ===============DDRD====================
			// Debug information for race pair detection
			debug("Race pair detected (optimized): TID %d(%c) <-> TID %d(%c), time_diff=%luus, lock_status=%d\n",
			      a->tid, a->access_type, b->tid, b->access_type, (unsigned long)time_diff, lock_status);
			debug("  Addresses: 0x%lx(size %lu) <-> 0x%lx(size %lu)\n",
			      (unsigned long)a->address, (unsigned long)a->size, (unsigned long)b->address, (unsigned long)b->size);
			debug("  History indices: thread1[%d], thread2[%d]\n", 
			      pair->first_access_index, pair->second_access_index);
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
bool check_uaf_validity(const AccessRecord* use_access, const AccessRecord* free_op, AccessRecord* all_frees, int free_count)
{
	uint64_t use_time = use_access->access_time;
	uint64_t free_time = free_op->access_time;

	// 检查是否有在这个free操作之前，但时间上更接近use操作的free操作
	// 这样的free操作会使当前的free->use组合无效
	for (int i = 0; i < free_count; i++) {
		const AccessRecord* other_free = &all_frees[i];

		// 跳过当前的free操作
		if (other_free->access_time == free_time &&
		    other_free->address == free_op->address &&
		    other_free->tid == free_op->tid) {
			continue;
		}

		// 检查是否有更晚的free操作（在当前free之后，use之前）
		if (other_free->access_time > free_time &&
		    other_free->access_time < use_time) {
			if (addresses_overlap(other_free, use_access)) {
				return false;
			}
		}
	}
	return true;
}

// 确定UAF的锁状态
LockStatus determine_uaf_lock_status(const AccessRecord* use_access, const AccessRecord* free_op)
{
	// 现在FreeRecord包含锁信息，可以进行准确的锁状态分析
	if (use_access->lock_count == 0 && free_op->lock_count == 0) {
		return LOCK_NO_LOCKS;
	}
	
	if (use_access->lock_count == 0 || free_op->lock_count == 0) {
		return LOCK_ONE_SIDED_LOCK;
	}
	
	// 检查是否有公共锁
	for (int i = 0; i < use_access->lock_count; i++) {
		for (int j = 0; j < free_op->lock_count; j++) {
			if (use_access->held_locks[i].ptr == free_op->held_locks[j].ptr) {
				return LOCK_SYNC_WITH_COMMON_LOCK;
			}
		}
	}
	
	return LOCK_UNSYNC_LOCKS;
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
		AccessRecord* closest_free = NULL;
		uint64_t closest_time_diff = UINT64_MAX;

		for (int j = 0; j < record_set->free_count; j++) {
			AccessRecord* free_op = &record_set->free_records[j];

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
			uaf_pair->free_access = *closest_free;
			uaf_pair->time_diff = closest_time_diff;
			uaf_pair->lock_status = lock_status;
			uaf_pair->trigger_count = 1;
			
			// 添加历史访问信息
			uaf_pair->use_thread_history = find_thread_history(record_set, use_access->tid);
			uaf_pair->free_thread_history = find_thread_history(record_set, closest_free->tid);
			
			// 查找访问在历史中的索引位置
			uaf_pair->use_access_index = -1;
			uaf_pair->free_access_index = -1;
			
			if (uaf_pair->use_thread_history) {
				// 在use线程历史中查找访问的索引
				int total_accesses = uaf_pair->use_thread_history->buffer_full ? 
				                    MAX_THREAD_HISTORY : uaf_pair->use_thread_history->access_count;
				for (int k = 0; k < total_accesses; k++) {
					int actual_index = uaf_pair->use_thread_history->buffer_full ? 
					                  (uaf_pair->use_thread_history->access_index + k) % MAX_THREAD_HISTORY : k;
					if (uaf_pair->use_thread_history->accesses[actual_index].access_time == use_access->access_time &&
					    uaf_pair->use_thread_history->accesses[actual_index].address == use_access->address) {
						uaf_pair->use_access_index = actual_index;
						break;
					}
				}
			}
			
			if (uaf_pair->free_thread_history) {
				// 在free线程历史中查找free操作的索引
				int total_accesses = uaf_pair->free_thread_history->buffer_full ? 
				                    MAX_THREAD_HISTORY : uaf_pair->free_thread_history->access_count;
				for (int k = 0; k < total_accesses; k++) {
					int actual_index = uaf_pair->free_thread_history->buffer_full ? 
					                  (uaf_pair->free_thread_history->access_index + k) % MAX_THREAD_HISTORY : k;
					if (uaf_pair->free_thread_history->accesses[actual_index].access_time == closest_free->access_time &&
					    uaf_pair->free_thread_history->accesses[actual_index].address == closest_free->address &&
					    uaf_pair->free_thread_history->accesses[actual_index].access_type == 'F') {
						uaf_pair->free_access_index = actual_index;
						break;
					}
				}
			}

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
			debug("UAF detected: TID %d(%c) uses memory freed by TID %d at time %lu, use_time=%lu, time_diff=%luus\n",
			      use_access->tid, use_access->access_type, closest_free->tid,
			      (unsigned long)closest_free->access_time, (unsigned long)use_access->access_time,
			      (unsigned long)closest_time_diff);
			debug("  Use address: 0x%lx(size %lu), Free address: 0x%lx(size %lu)\n",
			      (unsigned long)use_access->address, (unsigned long)use_access->size,
			      (unsigned long)closest_free->address, (unsigned long)closest_free->size);
			debug("  History indices: use[%d], free[%d]\n", 
			      uaf_pair->use_access_index, uaf_pair->free_access_index);
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

	debug("Initializing race detector...\n");
	
	// 检查trace系统状态
	int current_buffer_size = get_buffer_size_kb();
	bool tracing_status = is_tracing_enabled();
	
	debug("Current trace system status:\n");
	debug("  Buffer size per CPU: %d KB\n", current_buffer_size);
	debug("  Tracing enabled: %s\n", tracing_status ? "yes" : "no");
	

	// 尝试打开trace文件
	race_trace_fd = open("/sys/kernel/debug/tracing/trace", O_RDONLY);
	if (race_trace_fd >= 0) {
		race_collection_enabled = true;
		debug("Race detector initialized successfully (fd=%d) with nanosecond precision\n", race_trace_fd);
		
		// 测试文件是否可以正常定位（某些pseudo文件不支持lseek）
		if (lseek(race_trace_fd, 0, SEEK_CUR) == (off_t)-1) {
			debug("Warning: trace file does not support lseek (errno=%d), but continuing\n", errno);
		}
		
		bool was_tracing = tracing_status;
		if (was_tracing) {
			debug("Temporarily disabling tracing for buffer configuration\n");
			disable_tracing();
		}

		if (current_buffer_size < 1024*16) { // 如果小于16MB，增加到16MB
			debug("Increasing trace buffer size from %d KB to 16384 KB\n", current_buffer_size);
			set_buffer_size_kb(1024*16);
		}
		
		if (was_tracing || !tracing_status) {
			debug("Enabling tracing for race detection\n");
			enable_tracing();
		}
		
	} else {
		debug("Race detector initialization failed: cannot open trace file (errno=%d)\n", errno);
	}
}

// 清理race检测器
void cleanup_race_detector()
{
	debug("Cleaning up race detector...\n");
	
	if (race_trace_fd >= 0) {
		debug("Closing race trace fd=%d\n", race_trace_fd);
		close(race_trace_fd);
		race_trace_fd = -1;
	}
	
	reset_race_detector();
	
	race_collection_enabled = false;
	debug("Race detector cleanup completed\n");
}

// 检查race_trace_fd状态并提供诊断信息
static bool validate_race_trace_fd(const char* context)
{
	if (race_trace_fd < 0) {
		debug("%s: race_trace_fd is invalid (%d)\n", context, race_trace_fd);
		return false;
	}
	
	// 简单的文件描述符有效性测试
	int flags = fcntl(race_trace_fd, F_GETFL);
	if (flags == -1) {
		debug("%s: race_trace_fd (%d) is not valid (fcntl failed: %d)\n", 
		      context, race_trace_fd, errno);
		return false;
	}
	
	return true;
}

// 重置race检测状态
void reset_race_detector()
{
	if (!race_collection_enabled || !validate_race_trace_fd("reset_race_detector")) {
		return;
	}
	clear_trace_buffer();
}

// 检查race检测是否可用
bool is_race_detector_available()
{
	return race_collection_enabled && validate_race_trace_fd("is_race_detector_available");
}

// If the access time is within the occurrence time of a certain syscall,
// then it means that the variable access occurs within this syscall.
// But due to the existence of background threads, we may not find the suitable syscall for an access_record
SyscallTimeRecord* find_matching_syscall(uint64_t access_time, int tid)
{
	struct PairSyscallSharedData* pair_shared_data = get_pair_shared_data();
	// 检查prog1的syscalls - 优化：先检查第一个syscall的thread_id来确定是否属于这个程序
	if (pair_shared_data->prog1_syscall_count > 0) {
		if (tid == pair_shared_data->prog1_syscalls[0].thread_id) {
			for (int i = 0; i < pair_shared_data->prog1_syscall_count; i++) {
				// debug("  prog1[%d]: valid=%d, start_time=%llu, end_time=%llu\n", 
				//       i, pair_shared_data->prog1_syscalls[i].valid,
				//       (unsigned long long)pair_shared_data->prog1_syscalls[i].start_time,
				//       (unsigned long long)pair_shared_data->prog1_syscalls[i].end_time);
				      
				if (pair_shared_data->prog1_syscalls[i].valid &&
				    pair_shared_data->prog1_syscalls[i].start_time <= access_time &&
				    pair_shared_data->prog1_syscalls[i].end_time >= access_time) {
				    // debug("  found matching syscall in prog1[%d]: call_index=%d, call_num=%d\n",
				    //       i, pair_shared_data->prog1_syscalls[i].call_index,
				    //       pair_shared_data->prog1_syscalls[i].call_num);
					return &pair_shared_data->prog1_syscalls[i];
				}
			}
		}
	}
	
	// 检查prog2的syscalls - 优化：先检查第一个syscall的thread_id来确定是否属于这个程序
	if (pair_shared_data->prog2_syscall_count > 0) {
		// debug("  checking prog2 syscalls, first TID=%d\n", pair_shared_data->prog2_syscalls[0].thread_id);
		if (tid == pair_shared_data->prog2_syscalls[0].thread_id) {
			for (int i = 0; i < pair_shared_data->prog2_syscall_count; i++) {
				// debug("  prog2[%d]: valid=%d, start_time=%llu, end_time=%llu\n", 
				//       i, pair_shared_data->prog2_syscalls[i].valid,
				//       (unsigned long long)pair_shared_data->prog2_syscalls[i].start_time,
				//       (unsigned long long)pair_shared_data->prog2_syscalls[i].end_time);
				      
				if (pair_shared_data->prog2_syscalls[i].valid &&
				    pair_shared_data->prog2_syscalls[i].start_time <= access_time &&
				    pair_shared_data->prog2_syscalls[i].end_time >= access_time) {
				    // debug("  found matching syscall in prog2[%d]: call_index=%d, call_num=%d\n",
				    //       i, pair_shared_data->prog2_syscalls[i].call_index,
				    //       pair_shared_data->prog2_syscalls[i].call_num);
					return &pair_shared_data->prog2_syscalls[i];
				}
			}
		}
	}

	debug("  no matching syscall found for TID=%d, access_time=%llu\n", tid, (unsigned long long)access_time);
	return NULL; // No matching syscall found
}


// 生成UAF信号的哈希
static uint64_t hash_uaf_signal(const char* var_name, const char* free_stack, const char* use_stack)
{
	uint64_t h1 = hash_string(var_name ? var_name : "");
	uint64_t h2 = hash_string(free_stack ? free_stack : "");
	uint64_t h3 = hash_string(use_stack ? use_stack : "");

	// 组合free和use的调用栈信息
	return h1 ^ (h2 << 1) ^ (h3 << 2);
}

// 分析并生成UAF信号
int analyze_and_generate_may_uaf_infos(may_uaf_pair_t* may_uaf_pair_buffer, int max_uaf_pairs)
{
	if (!race_collection_enabled || !validate_race_trace_fd("analyze_and_generate_may_uaf_infos") || 
	    !may_uaf_pair_buffer || max_uaf_pairs <= 0) {
		debug("Invalid parameters for UAF analysis\n");
		debug("  race_collection_enabled: %d\n", race_collection_enabled);
		debug("  may_uaf_pair_buffer: %p\n", may_uaf_pair_buffer);
		debug("  max_uaf_pairs: %d\n", max_uaf_pairs);
		return 0;
	}

#define MAX_RECORDS 0X5000 // 20480 RECORDS
#define MAX_UAF_PAIRS 0X200 // 512 PAIRS

	size_t buffer_size = sizeof(AccessRecord) * (MAX_RECORDS + 1);
	char* buffer = malloc(buffer_size);

	if (!buffer) {
		return 0;
	}

	ssize_t bytes_read = read_trace_buffer(buffer, buffer_size);

	if (bytes_read <= 0) {
		debug("Failed to read trace buffer for UAF analysis (bytes_read=%zd, errno=%d)\n", bytes_read, errno);
		free(buffer);
		return 0;
	}
	
	debug("Successfully read %zd bytes from trace buffer for UAF analysis\n", bytes_read);

	// 使用动态分配减少栈空间使用
	AccessRecord* records = malloc(sizeof(AccessRecord) * MAX_RECORDS);
	AccessRecord* free_records = malloc(sizeof(AccessRecord) * (MAX_RECORDS / 4)); // 假设free操作不超过总操作的25%
	UAFPair* uaf_pairs = malloc(sizeof(UAFPair) * MAX_UAF_PAIRS);

	if (!records || !free_records || !uaf_pairs) {
		free(buffer);
		free(records);
		free(free_records);
		free(uaf_pairs);
		return 0;
	}

	AccessRecordSet record_set = {
		.records = records,
		.record_count = 0,
		.free_records = free_records,
		.free_count = 0,
		.thread_histories = NULL,
		.thread_count = 0,
		.max_threads = 0
	};

	// 初始化线程历史的动态分配
	record_set.thread_histories = (ThreadAccessHistory*)calloc(MAX_THREADS, sizeof(ThreadAccessHistory));
	record_set.max_threads = MAX_THREADS;
	if (!record_set.thread_histories) {
		debug("Failed to allocate memory for thread histories in UAF analysis\n");
		free(buffer);
		free(records);
		free(free_records);
		free(uaf_pairs);
		return 0;
	}
	
	// 初始化线程历史
	for (int h = 0; h < MAX_THREADS; h++) {
		record_set.thread_histories[h].tid = 0;
		record_set.thread_histories[h].access_count = 0;
		record_set.thread_histories[h].access_index = 0;
		record_set.thread_histories[h].buffer_full = false;
	}

	parse_access_records_to_set(buffer, &record_set, MAX_RECORDS, MAX_RECORDS / 4);
	debug("Successfully parsed %d access records and %d free records for UAF analysis\n", 
	      record_set.record_count, record_set.free_count);

	UAFStatistics stats;
	int uaf_pair_count = analyze_uaf_pairs_from_set(&record_set, uaf_pairs, MAX_UAF_PAIRS, &stats);

	// 转换UAF pairs到传输格式
	int i = 0;
	for (i = 0; i < uaf_pair_count && i < max_uaf_pairs; i++) {
		UAFPair* uaf_pair = &uaf_pairs[i];
		
		may_uaf_pair_buffer[i].free_access_name = uaf_pair->use_access.var_name;
		may_uaf_pair_buffer[i].use_access_name = uaf_pair->use_access.var_name;
		may_uaf_pair_buffer[i].free_call_stack = uaf_pair->free_access.call_stack_hash; // 临时用锁信息代替调用栈
		may_uaf_pair_buffer[i].use_call_stack = uaf_pair->use_access.call_stack_hash;
		may_uaf_pair_buffer[i].free_sn = uaf_pair->free_access.sn; // FreeRecord没有sn字段，设为0
		may_uaf_pair_buffer[i].use_sn = uaf_pair->use_access.sn;
		may_uaf_pair_buffer[i].free_tid = uaf_pair->free_access.tid;
		may_uaf_pair_buffer[i].use_tid = uaf_pair->use_access.tid;
		may_uaf_pair_buffer[i].lock_type = uaf_pair->lock_status;
		may_uaf_pair_buffer[i].signal = hash_uaf_signal(
			(char*)&uaf_pair->use_access.var_name,
			(char*)&uaf_pair->free_access.held_locks[0].ptr,
			(char*)&uaf_pair->use_access.call_stack_hash);
		may_uaf_pair_buffer[i].use_access_type = uaf_pair->use_access.access_type;
		may_uaf_pair_buffer[i].time_diff = uaf_pair->time_diff;

		// 查找匹配的syscall
		SyscallTimeRecord* free_syscall = find_matching_syscall(uaf_pair->free_access.access_time, uaf_pair->free_access.tid);
		SyscallTimeRecord* use_syscall = find_matching_syscall(uaf_pair->use_access.access_time, uaf_pair->use_access.tid);
		
		if (free_syscall) {
			may_uaf_pair_buffer[i].free_syscall_idx = free_syscall->call_index;
			may_uaf_pair_buffer[i].free_syscall_num = free_syscall->call_num;
		} else {
			may_uaf_pair_buffer[i].free_syscall_idx = 0;
			may_uaf_pair_buffer[i].free_syscall_num = 0;
		}
		
		if (use_syscall) {
			may_uaf_pair_buffer[i].use_syscall_idx = use_syscall->call_index;
			may_uaf_pair_buffer[i].use_syscall_num = use_syscall->call_num;
		} else {
			may_uaf_pair_buffer[i].use_syscall_idx = 0;
			may_uaf_pair_buffer[i].use_syscall_num = 0;
		}
	}

	debug("UAF analysis complete: found %d UAF pairs, stats: no_locks=%d, one_sided=%d, unsync=%d, sync=%d\n",
	      i, stats.no_locks_count, stats.one_sided_lock_count, stats.unsync_locks_count, stats.sync_with_common_lock_count);

	free(buffer);
	free(records);
	free(free_records);
	free(record_set.thread_histories);  // 清理线程历史的动态分配
	free(uaf_pairs);
	return i;
}

// 优化版本：一次性生成基本和扩展UAF信息，避免重复解析
int analyze_and_generate_uaf_infos_combined(may_uaf_pair_t* uaf_buffer, int max_uaf_pairs,
                                           extended_uaf_pair_t* extended_pairs, int max_extended_pairs,
                                           AccessRecordSet** record_set_out)
{
	if (!race_collection_enabled || !validate_race_trace_fd("analyze_and_generate_uaf_infos_combined") || 
	    !uaf_buffer || max_uaf_pairs <= 0) {
		debug("Invalid parameters for combined UAF analysis\n");
		return 0;
	}

#define MAX_RECORDS 0X5000 // 20480 RECORDS
#define MAX_UAF_PAIRS 0X200 // 512 PAIRS

	size_t buffer_size = sizeof(AccessRecord) * (MAX_RECORDS + 1);
	char* buffer = malloc(buffer_size);
	if (!buffer) {
		return 0;
	}

	ssize_t bytes_read = read_trace_buffer(buffer, buffer_size);
	if (bytes_read <= 0) {
		debug("Failed to read trace buffer for combined UAF analysis (bytes_read=%zd, errno=%d)\n", bytes_read, errno);
		free(buffer);
		return 0;
	}
	
	debug("Successfully read %zd bytes from trace buffer for combined UAF analysis\n", bytes_read);

	// 分配所有需要的数据结构
	AccessRecord* records = malloc(sizeof(AccessRecord) * MAX_RECORDS);
	AccessRecord* free_records = malloc(sizeof(AccessRecord) * (MAX_RECORDS / 4));
	UAFPair* uaf_pairs = malloc(sizeof(UAFPair) * MAX_UAF_PAIRS);

	if (!records || !free_records || !uaf_pairs) {
		free(buffer);
		free(records);
		free(free_records);
		free(uaf_pairs);
		return 0;
	}

	// 创建持久的AccessRecordSet，在函数返回后仍然有效
	AccessRecordSet* record_set = malloc(sizeof(AccessRecordSet));
	if (!record_set) {
		free(buffer);
		free(records);
		free(free_records);
		free(uaf_pairs);
		return 0;
	}

	*record_set = (AccessRecordSet){
		.records = records,
		.record_count = 0,
		.free_records = free_records,
		.free_count = 0,
		.thread_histories = NULL,
		.thread_count = 0,
		.max_threads = 0
	};

	// 初始化线程历史
	record_set->thread_histories = (ThreadAccessHistory*)calloc(MAX_THREADS, sizeof(ThreadAccessHistory));
	record_set->max_threads = MAX_THREADS;
	if (!record_set->thread_histories) {
		debug("Failed to allocate memory for thread histories in combined UAF analysis\n");
		free(buffer);
		free(records);
		free(free_records);
		free(uaf_pairs);
		free(record_set);
		return 0;
	}

	// 解析访问记录
	parse_access_records_to_set(buffer, record_set, MAX_RECORDS, MAX_RECORDS / 4);
	debug("Successfully parsed %d access records and %d free records for combined UAF analysis\n", 
	      record_set->record_count, record_set->free_count);

	// 分析基本UAF pairs
	UAFStatistics stats;
	int uaf_pair_count = analyze_uaf_pairs_from_set(record_set, uaf_pairs, MAX_UAF_PAIRS, &stats);

	// 生成基本UAF信息
	int basic_count = 0;
	for (basic_count = 0; basic_count < uaf_pair_count && basic_count < max_uaf_pairs; basic_count++) {
		UAFPair* uaf_pair = &uaf_pairs[basic_count];
		
		uaf_buffer[basic_count].free_access_name = uaf_pair->use_access.var_name;
		uaf_buffer[basic_count].use_access_name = uaf_pair->use_access.var_name;
		uaf_buffer[basic_count].free_call_stack = uaf_pair->free_access.call_stack_hash;
		uaf_buffer[basic_count].use_call_stack = uaf_pair->use_access.call_stack_hash;
		uaf_buffer[basic_count].free_sn = uaf_pair->free_access.sn;
		uaf_buffer[basic_count].use_sn = uaf_pair->use_access.sn;
		uaf_buffer[basic_count].free_tid = uaf_pair->free_access.tid;
		uaf_buffer[basic_count].use_tid = uaf_pair->use_access.tid;
		uaf_buffer[basic_count].free_syscall_idx = 0;
		uaf_buffer[basic_count].use_syscall_idx = 0;
		uaf_buffer[basic_count].free_syscall_num = 0;
		uaf_buffer[basic_count].use_syscall_num = 0;
		uaf_buffer[basic_count].lock_type = uaf_pair->lock_status;
		uaf_buffer[basic_count].use_access_type = uaf_pair->use_access.access_type;
		uaf_buffer[basic_count].signal = hash_uaf_signal(
			(char*)&uaf_pair->use_access.var_name,
			(char*)&uaf_pair->free_access.held_locks[0].ptr,
			(char*)&uaf_pair->use_access.call_stack_hash);
		uaf_buffer[basic_count].time_diff = uaf_pair->time_diff;

		// 查找匹配的syscall
		SyscallTimeRecord* free_syscall = find_matching_syscall(uaf_pair->free_access.access_time, uaf_pair->free_access.tid);
		SyscallTimeRecord* use_syscall = find_matching_syscall(uaf_pair->use_access.access_time, uaf_pair->use_access.tid);
		
		if (free_syscall) {
			uaf_buffer[basic_count].free_syscall_idx = free_syscall->call_index;
			uaf_buffer[basic_count].free_syscall_num = free_syscall->call_num;
		}
		
		if (use_syscall) {
			uaf_buffer[basic_count].use_syscall_idx = use_syscall->call_index;
			uaf_buffer[basic_count].use_syscall_num = use_syscall->call_num;
		}
	}

	// 生成扩展UAF信息（如果需要）
	int extended_count = 0;
	if (extended_pairs && max_extended_pairs > 0) {
		extended_count = generate_extended_uaf_info(uaf_buffer, basic_count, record_set, extended_pairs);
		if (extended_count > max_extended_pairs) {
			extended_count = max_extended_pairs;
		}
	}

	// 将record_set返回给调用者，让调用者决定何时释放
	if (record_set_out) {
		*record_set_out = record_set;
	} else {
		// 如果调用者不需要record_set，立即释放
		free(record_set->thread_histories);
		free(record_set);
	}

	free(buffer);
	free(uaf_pairs); // UAFPair是临时的，可以释放
	
	debug("Combined UAF analysis complete: generated %d basic pairs and %d extended pairs\n", 
	      basic_count, extended_count);
	
	return basic_count;
}

// ===============扩展Race/UAF分析功能====================

// 分析并生成扩展的race信息（包含历史数据）
int analyze_and_generate_extended_race_infos(may_race_pair_t* race_signals_buffer, int race_count,
                                            extended_race_pair_t* extended_buffer, int max_extended)
{
	if (!race_collection_enabled || !validate_race_trace_fd("analyze_and_generate_extended_race_infos") || 
	    !race_signals_buffer || !extended_buffer || race_count <= 0 || max_extended <= 0) {
		debug("Invalid parameters for extended race analysis\n");
		return 0;
	}

	debug("Generating extended information for %d existing races...\n", race_count);

	// 重新读取trace数据进行扩展分析
	size_t buffer_size = sizeof(AccessRecord) * (MAX_RECORDS + 1);
	char* buffer = malloc(buffer_size);
	if (!buffer) {
		debug("Failed to allocate buffer for extended race analysis\n");
		return 0;
	}

	ssize_t bytes_read = read_trace_buffer(buffer, buffer_size);
	if (bytes_read <= 0) {
		debug("Failed to read trace buffer for extended race analysis\n");
		free(buffer);
		return 0;
	}

	// 动态分配内存
	AccessRecord* records = malloc(sizeof(AccessRecord) * MAX_RECORDS);
	AccessRecord* free_records = malloc(sizeof(AccessRecord) * (MAX_RECORDS / 4));

	if (!records || !free_records) {
		free(buffer);
		free(records);
		free(free_records);
		return 0;
	}

	AccessRecordSet record_set = {
		.records = records,
		.record_count = 0,
		.free_records = free_records,
		.free_count = 0,
		.thread_histories = NULL,
		.thread_count = 0,
		.max_threads = 0
	};

	// 初始化线程历史
	record_set.thread_histories = (ThreadAccessHistory*)calloc(MAX_THREADS, sizeof(ThreadAccessHistory));
	record_set.max_threads = MAX_THREADS;
	if (!record_set.thread_histories) {
		debug("Failed to allocate memory for thread histories in extended race analysis\n");
		free(buffer);
		free(records);
		free(free_records);
		return 0;
	}

	// 初始化线程历史
	for (int h = 0; h < MAX_THREADS; h++) {
		record_set.thread_histories[h].tid = 0;
		record_set.thread_histories[h].access_count = 0;
		record_set.thread_histories[h].access_index = 0;
		record_set.thread_histories[h].buffer_full = false;
	}

	parse_access_records_to_set(buffer, &record_set, MAX_RECORDS, MAX_RECORDS / 4);
	debug("Successfully parsed %d access records for extended race analysis\n", record_set.record_count);

	// 调用扩展race信息生成函数
	int extended_count = generate_extended_race_info(race_signals_buffer, race_count, 
	                                                &record_set, extended_buffer);

	// 清理
	free(buffer);
	free(records);
	free(free_records);
	free(record_set.thread_histories);

	debug("Extended race analysis completed: %d extended race pairs generated\n", extended_count);
	return extended_count;
}

// 分析并生成扩展的UAF信息（包含历史数据）
int analyze_and_generate_extended_uaf_infos(may_uaf_pair_t* uaf_signals_buffer, int uaf_count,
                                           extended_uaf_pair_t* extended_buffer, int max_extended)
{
	if (!race_collection_enabled || !validate_race_trace_fd("analyze_and_generate_extended_uaf_infos") || 
	    !uaf_signals_buffer || !extended_buffer || uaf_count <= 0 || max_extended <= 0) {
		debug("Invalid parameters for extended UAF analysis\n");
		return 0;
	}

	debug("Generating extended information for %d existing UAF pairs...\n", uaf_count);

	// 重新读取trace数据进行扩展分析
	size_t buffer_size = sizeof(AccessRecord) * (MAX_RECORDS + 1);
	char* buffer = malloc(buffer_size);
	if (!buffer) {
		debug("Failed to allocate buffer for extended UAF analysis\n");
		return 0;
	}

	ssize_t bytes_read = read_trace_buffer(buffer, buffer_size);
	if (bytes_read <= 0) {
		debug("Failed to read trace buffer for extended UAF analysis\n");
		free(buffer);
		return 0;
	}

	// 动态分配内存
	AccessRecord* records = malloc(sizeof(AccessRecord) * MAX_RECORDS);
	AccessRecord* free_records = malloc(sizeof(AccessRecord) * (MAX_RECORDS / 4));

	if (!records || !free_records) {
		free(buffer);
		free(records);
		free(free_records);
		return 0;
	}

	AccessRecordSet record_set = {
		.records = records,
		.record_count = 0,
		.free_records = free_records,
		.free_count = 0,
		.thread_histories = NULL,
		.thread_count = 0,
		.max_threads = 0
	};

	// 初始化线程历史
	record_set.thread_histories = (ThreadAccessHistory*)calloc(MAX_THREADS, sizeof(ThreadAccessHistory));
	record_set.max_threads = MAX_THREADS;
	if (!record_set.thread_histories) {
		debug("Failed to allocate memory for thread histories in extended UAF analysis\n");
		free(buffer);
		free(records);
		free(free_records);
		return 0;
	}

	// 初始化线程历史
	for (int h = 0; h < MAX_THREADS; h++) {
		record_set.thread_histories[h].tid = 0;
		record_set.thread_histories[h].access_count = 0;
		record_set.thread_histories[h].access_index = 0;
		record_set.thread_histories[h].buffer_full = false;
	}

	parse_access_records_to_set(buffer, &record_set, MAX_RECORDS, MAX_RECORDS / 4);
	debug("Successfully parsed %d access records for extended UAF analysis\n", record_set.record_count);

	// 调用扩展UAF信息生成函数
	int extended_count = generate_extended_uaf_info(uaf_signals_buffer, uaf_count,
	                                               &record_set, extended_buffer);

	// 清理
	free(buffer);
	free(records);
	free(free_records);
	free(record_set.thread_histories);

	debug("Extended UAF analysis completed: %d extended UAF pairs generated\n", extended_count);
	return extended_count;
}

// ===============DDRD====================

// ===============线程历史管理函数====================
// 查找线程历史记录
ThreadAccessHistory* find_thread_history(AccessRecordSet* record_set, int tid)
{
	for (int i = 0; i < record_set->thread_count; i++) {
		if (record_set->thread_histories[i].tid == tid) {
			return &record_set->thread_histories[i];
		}
	}
	return NULL;
}

// 创建新的线程历史记录
ThreadAccessHistory* create_thread_history(AccessRecordSet* record_set, int tid)
{
	if (record_set->thread_count >= MAX_THREADS) {
		debug("Warning: Maximum thread count reached, cannot create history for TID %d\n", tid);
		return NULL;
	}
	
	ThreadAccessHistory* history = &record_set->thread_histories[record_set->thread_count];
	history->tid = tid;
	history->access_count = 0;
	history->access_index = 0;
	history->buffer_full = false;
	record_set->thread_count++;
	
	debug("Created thread history for TID %d (thread_count=%d)\n", tid, record_set->thread_count);
	return history;
}

// 添加访问记录到线程历史（环形缓冲区）
void add_access_to_history(ThreadAccessHistory* history, const AccessRecord* access)
{
	if (!history || !access) {
		return;
	}
	
	// 复制访问记录到历史缓冲区
	history->accesses[history->access_index] = *access;
	
	// 更新索引（环形缓冲区）
	history->access_index = (history->access_index + 1) % MAX_THREAD_HISTORY;
	
	// 更新计数
	if (history->access_count < MAX_THREAD_HISTORY) {
		history->access_count++;
	} else {
		history->buffer_full = true;
		// debug("Thread history buffer full for TID %d, overwriting oldest records\n", history->tid);
	}
	
	// debug("Added access to history for TID %d: count=%d, index=%d, type='%c'\n", 
	//       history->tid, history->access_count, history->access_index, access->access_type);
}

// 计算简化的路径距离：返回current相对于target的位置距离
int calculate_path_distance(const AccessRecord* target, const AccessRecord* current)
{
	if (!target || !current) {
		return INT_MAX;
	}
	
	// 如果是不同线程，距离无限大
	if (target->tid != current->tid) {
		return INT_MAX;
	}
	
	// 简化的距离计算：基于序列号的相对位置
	// 如果current在target之前，返回它们之间的距离（第几个记录）
	// 如果current在target之后，返回一个较大的值表示不相关
	if (current->sn <= target->sn) {
		return target->sn - current->sn;  // target前第几个记录
	} else {
		return INT_MAX;  // target之后的记录不考虑
	}
}

// 计算基于距离的延时概率：P(delay) ≈ 1/(d+1)
double calculate_delay_probability(int distance)
{
	if (distance <= 0) {
		return 1.0; // 距离为0时，100%概率
	}
	
	return 1.0 / (distance + 1);
}


// 生成扩展race信息（直接内存传输，不使用文件）
int generate_extended_race_info(may_race_pair_t* race_pairs, int race_count, 
                               AccessRecordSet* record_set, 
                               extended_race_pair_t* extended_pairs)
{
	// 直接填充扩展race pairs，无需文件操作
	for (int i = 0; i < race_count; i++) {
		extended_race_pair_t* ext_pair = &extended_pairs[i];
		ext_pair->basic_info = race_pairs[i];
		
		// 查找对应的线程历史信息
		ThreadAccessHistory* thread1_history = NULL;
		ThreadAccessHistory* thread2_history = NULL;
		
		// 直接通过线程ID查找线程历史，无需复杂的序列号匹配
		for (int j = 0; j < record_set->thread_count; j++) {
			ThreadAccessHistory* thread_hist = &record_set->thread_histories[j];
			if (thread_hist->tid == race_pairs[i].tid1 && !thread1_history) {
				thread1_history = thread_hist;
				ext_pair->thread1_history_count = thread1_history->access_count;
				// 限制访问历史数量以避免内存溢出
				if (ext_pair->thread1_history_count > MAX_ACCESS_HISTORY_RECORDS) {
					ext_pair->thread1_history_count = MAX_ACCESS_HISTORY_RECORDS;
				}
			}
			if (thread_hist->tid == race_pairs[i].tid2 && !thread2_history) {
				thread2_history = thread_hist;
				ext_pair->thread2_history_count = thread2_history->access_count;
				// 限制访问历史数量以避免内存溢出
				if (ext_pair->thread2_history_count > MAX_ACCESS_HISTORY_RECORDS) {
					ext_pair->thread2_history_count = MAX_ACCESS_HISTORY_RECORDS;
				}
			}
			// 如果两个线程历史都找到了，可以提前退出
			if (thread1_history && thread2_history) {
				break;
			}
		}
		
		// 设置目标时间（基于race的基本信息）
		ext_pair->thread1_target_time = race_pairs[i].time_diff; // 使用time_diff作为参考
		ext_pair->thread2_target_time = 0; // 第二个线程作为基准时间点
		
		// 计算路径距离
		// 为thread1和thread2分别计算路径距离
		if (thread1_history && thread1_history->access_count > 0) {
			// 路径距离定义为：线程1目标操作前有多少个访问记录
			ext_pair->path_distance1 = (double)(thread1_history->access_count - 1);
		} else {
			ext_pair->path_distance1 = 0.0;
		}
		
		if (thread2_history && thread2_history->access_count > 0) {
			// 路径距离定义为：线程2目标操作前有多少个访问记录
			ext_pair->path_distance2 = (double)(thread2_history->access_count - 1);
		} else {
			ext_pair->path_distance2 = 0.0;
		}
		
		// 填充历史访问记录数据到柔性数组
		uint32_t record_index = 0;
		
		// 先填充thread1的历史记录
		if (thread1_history) {
			for (uint32_t j = 0; j < ext_pair->thread1_history_count; j++) {
				if (j < thread1_history->access_count && record_index < (ext_pair->thread1_history_count + ext_pair->thread2_history_count)) {
					AccessRecord* src = &thread1_history->accesses[j];
					serialized_access_record_t* dst = &ext_pair->access_history[record_index++];
					
					dst->var_name = src->var_name;
					dst->call_stack_hash = src->call_stack_hash;
					dst->access_time = src->access_time;
					dst->sn = src->sn;
					dst->access_type = src->access_type;
				}
			}
		}
		
		// 然后填充thread2的历史记录
		if (thread2_history) {
			for (uint32_t j = 0; j < ext_pair->thread2_history_count; j++) {
				if (j < thread2_history->access_count && record_index < (ext_pair->thread1_history_count + ext_pair->thread2_history_count)) {
					AccessRecord* src = &thread2_history->accesses[j];
					serialized_access_record_t* dst = &ext_pair->access_history[record_index++];
					
					dst->var_name = src->var_name;
					dst->call_stack_hash = src->call_stack_hash;
					dst->access_time = src->access_time;
					dst->sn = src->sn;
					dst->access_type = src->access_type;
				}
			}
		}
	}
	
	debug("Generated extended race info (direct memory transmission)\n");
	return 0;
}

// 生成扩展UAF信息（直接内存传输，不使用文件）
int generate_extended_uaf_info(may_uaf_pair_t* uaf_pairs, int uaf_count,
                              AccessRecordSet* record_set,
                              extended_uaf_pair_t* extended_uaf_pairs)
{
	// 直接填充扩展UAF pairs，无需文件操作
	for (int i = 0; i < uaf_count; i++) {
		extended_uaf_pair_t* ext_uaf_pair = &extended_uaf_pairs[i];
		ext_uaf_pair->basic_info = uaf_pairs[i];
		
		// 查找对应的线程历史信息
		ThreadAccessHistory* use_thread_history = NULL;
		ThreadAccessHistory* free_thread_history = NULL;
		
		// 直接通过线程ID查找线程历史，无需复杂的序列号匹配
		for (int j = 0; j < record_set->thread_count; j++) {
			ThreadAccessHistory* thread_hist = &record_set->thread_histories[j];
			if (thread_hist->tid == uaf_pairs[i].use_tid && !use_thread_history) {
				use_thread_history = thread_hist;
				ext_uaf_pair->use_thread_history_count = use_thread_history->access_count;
				// 限制访问历史数量以避免内存溢出
				if (ext_uaf_pair->use_thread_history_count > MAX_ACCESS_HISTORY_RECORDS) {
					ext_uaf_pair->use_thread_history_count = MAX_ACCESS_HISTORY_RECORDS;
				}
			}
			if (thread_hist->tid == uaf_pairs[i].free_tid && !free_thread_history) {
				free_thread_history = thread_hist;
				ext_uaf_pair->free_thread_history_count = free_thread_history->access_count;
				// 限制访问历史数量以避免内存溢出
				if (ext_uaf_pair->free_thread_history_count > MAX_ACCESS_HISTORY_RECORDS) {
					ext_uaf_pair->free_thread_history_count = MAX_ACCESS_HISTORY_RECORDS;
				}
			}
			// 如果两个线程历史都找到了，可以提前退出
			if (use_thread_history && free_thread_history) {
				break;
			}
		}
		
		// 设置目标时间（基于UAF的基本信息）
		ext_uaf_pair->use_target_time = uaf_pairs[i].time_diff;  // 使用time_diff作为参考时间
		ext_uaf_pair->free_target_time = 0; // Free事件作为基准时间点
		
		// 计算路径距离
		// 为use和free线程分别计算路径距离
		if (use_thread_history && use_thread_history->access_count > 0) {
			// 路径距离定义为：use操作前有多少个访问记录
			ext_uaf_pair->path_distance_use = (double)(use_thread_history->access_count - 1);
		} else {
			ext_uaf_pair->path_distance_use = 0.0;
		}
		
		if (free_thread_history && free_thread_history->access_count > 0) {
			// 路径距离定义为：free操作前有多少个访问记录
			ext_uaf_pair->path_distance_free = (double)(free_thread_history->access_count - 1);
		} else {
			ext_uaf_pair->path_distance_free = 0.0;
		}
		
		// 填充历史访问记录数据到柔性数组
		uint32_t uaf_record_index = 0;
		
		// 先填充use线程的历史记录
		if (use_thread_history) {
			for (uint32_t j = 0; j < ext_uaf_pair->use_thread_history_count; j++) {
				if (j < use_thread_history->access_count && uaf_record_index < (ext_uaf_pair->use_thread_history_count + ext_uaf_pair->free_thread_history_count)) {
					AccessRecord* src = &use_thread_history->accesses[j];
					serialized_access_record_t* dst = &ext_uaf_pair->access_history[uaf_record_index++];
					
					dst->var_name = src->var_name;
					dst->call_stack_hash = src->call_stack_hash;
					dst->access_time = src->access_time;
					dst->sn = src->sn;
					dst->access_type = src->access_type;
				}
			}
		}
		
		// 然后填充free线程的历史记录
		if (free_thread_history) {
			for (uint32_t j = 0; j < ext_uaf_pair->free_thread_history_count; j++) {
				if (j < free_thread_history->access_count && uaf_record_index < (ext_uaf_pair->use_thread_history_count + ext_uaf_pair->free_thread_history_count)) {
					AccessRecord* src = &free_thread_history->accesses[j];
					serialized_access_record_t* dst = &ext_uaf_pair->access_history[uaf_record_index++];
					
					dst->var_name = src->var_name;
					dst->call_stack_hash = src->call_stack_hash;
					dst->access_time = src->access_time;
					dst->sn = src->sn;
					dst->access_type = src->access_type;
				}
			}
		}
	}
	
	debug("Generated extended UAF info\n");
	return 0;
}
// ===============DDRD====================

__attribute__((format(printf, 1, 2))) static void debug(const char* msg, ...)
{
	int err = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fflush(stderr);
	errno = err;
}

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