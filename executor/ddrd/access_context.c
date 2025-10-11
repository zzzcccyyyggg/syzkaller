#include "types.h"
#include "utils.h"

static void debug(const char* fmt, ...);

int parse_access_records_to_set(AccessContext* record_ctx, const char* buffer, int max_records, int max_frees)
{
	if (!buffer || !record_ctx || max_records <= 0 || max_frees <= 0) {
		return 0;
	}

	int record_count = 0;
	int free_count = 0;
	
	// 初始化线程历史
	record_ctx->thread_count = 0;
	for (int i = 0; i < MAX_THREADS; i++) {
		record_ctx->thread_histories[i].tid = -1;
		record_ctx->thread_histories[i].access_count = 0;
		record_ctx->thread_histories[i].access_index = 0;
		record_ctx->thread_histories[i].buffer_full = false;
	}
	
	char* buffer_copy = my_strdup(buffer);
	if (!buffer_copy) {
		return 0;
	}

	char* line = strtok(buffer_copy, "\n");
	AccessRecord current_record = {0};
	bool has_current = false;

	while (line) {
		AccessRecord access = access_record_init_from_line(line);
		if (access.valid) {
			// 如果有当前记录，处理它（但不立即保存，让它先收集锁信息）
			if (has_current) {
				// debug("Saving previous record: type='%c', locks=%d\n", current_record.access_type, current_record.lock_count);
				
				// 添加到线程历史
				ThreadAccessHistory* thread_history = access_context_find_thread(record_ctx, current_record.tid);
				if (!thread_history) {
					thread_history = access_context_create_thread_history(record_ctx, current_record.tid);
				}
				if (thread_history) {
					add_access_to_history(thread_history, &current_record);
				}
				
				if (current_record.access_type == 'F') {
					// 这是一个free操作，添加到free记录中
					AccessRecord* free_rec = &record_ctx->free_records[free_count];
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
					record_ctx->records[record_count++] = current_record;
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
		ThreadAccessHistory* thread_history = access_context_find_thread(record_ctx, current_record.tid);
		if (!thread_history) {
			thread_history = access_context_create_thread_history(record_ctx, current_record.tid);
		}
		if (thread_history) {
			add_access_to_history(thread_history, &current_record);
		}
		
		if (current_record.access_type == 'F' && free_count < max_frees) {
			AccessRecord* free_rec = &record_ctx->free_records[free_count];
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
			record_ctx->records[record_count++] = current_record;
		}
	}

	record_ctx->record_count = record_count;
	record_ctx->free_count = free_count;

	free(buffer_copy);
	return record_count;
}

int access_context_analyze_race_pairs(AccessContext* record_ctx, RacePair* pairs, int max_pairs)
{
	// ===============DDRD====================
	// Use nanosecond precision for precise race detection and syscall correlation
	const uint64_t TIME_THRESHOLD = 1000000; // 1ms = 1,000,000ns (nanoseconds) - basic threshold
	const uint64_t FAST_THRESHOLD = 100000; // 100us = 100,000ns for very close accesses
	// const uint64_t SLOW_THRESHOLD = 10000000;  // 10ms = 10,000,000ns for slower operations (unused)
	// ===============DDRD====================
	int pair_count = 0;

	debug("Analyzing %d access records and %d free records for race pairs (optimized)\n",
	      record_ctx->record_count, record_ctx->free_count);

	for (int i = 0; i < record_ctx->record_count && pair_count < max_pairs; i++) {
		for (int j = i + 1; j < record_ctx->record_count && pair_count < max_pairs; j++) {
			AccessRecord* a = &record_ctx->records[i];
			AccessRecord* b = &record_ctx->records[j];

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
			if (!access_record_addresses_overlap(a, b)) {
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
			if (!access_context_check_data_race_validity(record_ctx, a, b)) {
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
			pair->thread1_history = access_context_find_thread(record_ctx, pair->first.tid);
			pair->thread2_history = access_context_find_thread(record_ctx, pair->second.tid);
			
			// 查找访问在历史中的索引位置
			pair->first_access_index = -1;
			pair->second_access_index = -1;
			
			if (pair->thread1_history) {
				// 在线程1历史中查找第一个访问的索引
				int total_accesses1 = pair->thread1_history->buffer_full ? SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : pair->thread1_history->access_count;
				for (int k = 0; k < total_accesses1; k++) {
					int actual_index = pair->thread1_history->buffer_full ? 
					                  (pair->thread1_history->access_index + k) % SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : k;
					if (pair->thread1_history->accesses[actual_index].access_time == pair->first.access_time &&
					    pair->thread1_history->accesses[actual_index].address == pair->first.address) {
						pair->first_access_index = actual_index;
						break;
					}
				}
			}
			
			if (pair->thread2_history) {
				// 在线程2历史中查找第二个访问的索引
				int total_accesses2 = pair->thread2_history->buffer_full ? SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : pair->thread2_history->access_count;
				for (int k = 0; k < total_accesses2; k++) {
					int actual_index = pair->thread2_history->buffer_full ? 
					                  (pair->thread2_history->access_index + k) % SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : k;
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
	      pair_count, record_ctx->record_count, record_ctx->free_count);
	// ===============DDRD====================

	return pair_count;
}

int access_context_analyze_uaf_pairs(AccessContext* record_ctx, UAFPair* uaf_pairs, int max_pairs)
{
	// ===============DDRD====================
	// UAF检测时间阈值（微秒）
	const uint64_t TIME_THRESHOLD = 1000000; // 10ms
	// ===============DDRD====================

	int pair_count = 0;


	debug("Analyzing %d access records and %d free records for UAF pairs\n",
	      record_ctx->record_count, record_ctx->free_count);

	// 遍历所有访问记录
	for (int i = 0; i < record_ctx->record_count && pair_count < max_pairs; i++) {
		AccessRecord* use_access = &record_ctx->records[i];
		AccessRecord* closest_free = NULL;
		uint64_t closest_time_diff = UINT64_MAX;

		for (int j = 0; j < record_ctx->free_count; j++) {
			AccessRecord* free_op = &record_ctx->free_records[j];

			// 1. 跳过相同线程的操作
			if (use_access->tid == free_op->tid) {
				continue;
			}

			// 3. 检查地址重叠
			uint64_t use_end = use_access->address + use_access->size;
			uint64_t free_end = free_op->address + free_op->size;

			if (!((use_access->address < free_end) && (free_op->address < use_end))) {
				continue;
			}

			// 4. 检查时间阈值
			uint64_t time_diff = free_op->access_time - use_access->access_time;
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
			if (!access_context_check_uaf_validity(record_ctx,use_access, closest_free)) {
				continue;
			}

			// 6. 确定锁状态
			LockStatus lock_status = determine_lock_status(use_access, closest_free);

			// 创建UAF pair
			UAFPair* uaf_pair = &uaf_pairs[pair_count];
			uaf_pair->use_access = *use_access;
			uaf_pair->free_access = *closest_free;
			uaf_pair->time_diff = closest_time_diff;
			uaf_pair->lock_status = lock_status;
			uaf_pair->trigger_count = 1;
			
			// 添加历史访问信息
			uaf_pair->use_thread_history = access_context_find_thread(record_ctx, use_access->tid);
			uaf_pair->free_thread_history = access_context_find_thread(record_ctx, closest_free->tid);
			
			// 查找访问在历史中的索引位置
			uaf_pair->use_access_index = -1;
			uaf_pair->free_access_index = -1;
			
			if (uaf_pair->use_thread_history) {
				// 在use线程历史中查找访问的索引
				int total_accesses = uaf_pair->use_thread_history->buffer_full ? 
				                    SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : uaf_pair->use_thread_history->access_count;
				for (int k = 0; k < total_accesses; k++) {
					int actual_index = uaf_pair->use_thread_history->buffer_full ? 
					                  (uaf_pair->use_thread_history->access_index + k) % SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : k;
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
				                    SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : uaf_pair->free_thread_history->access_count;
				for (int k = 0; k < total_accesses; k++) {
					int actual_index = uaf_pair->free_thread_history->buffer_full ? 
					                  (uaf_pair->free_thread_history->access_index + k) % SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : k;
					if (uaf_pair->free_thread_history->accesses[actual_index].access_time == closest_free->access_time &&
					    uaf_pair->free_thread_history->accesses[actual_index].address == closest_free->address &&
					    uaf_pair->free_thread_history->accesses[actual_index].access_type == 'F') {
						uaf_pair->free_access_index = actual_index;
						break;
					}
				}
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
	      pair_count, record_ctx->record_count, record_ctx->free_count);
	// ===============DDRD====================

	return pair_count;
}


bool access_context_check_data_race_validity(AccessContext* record_ctx, const AccessRecord* a, const AccessRecord* b)
{
	uint64_t min_time = (a->access_time <= b->access_time) ? a->access_time : b->access_time;
	uint64_t max_time = (a->access_time > b->access_time) ? a->access_time : b->access_time;

	// 检查时间区间内是否有free操作影响这两个访问的地址范围
	for (int i = 0; i < record_ctx->free_count; i++) {
		const AccessRecord* free_rec = &record_ctx->free_records[i];
		if (free_rec->access_time > min_time &&
		    free_rec->access_time < max_time) {

			// 检查free操作是否与访问a或访问b的地址范围重叠
			if (access_record_addresses_overlap(a, free_rec) || access_record_addresses_overlap(b, free_rec)) {
				return false;
			}
		}
	}

	return true;
}


bool access_context_check_uaf_validity(AccessContext* record_ctx, const AccessRecord* use_access, const AccessRecord* free_op)
{
	uint64_t use_time = use_access->access_time;
	uint64_t free_time = free_op->access_time;

	// 检查是否有在这个free操作之前，但时间上更接近use操作的free操作
	// 这样的free操作会使当前的free->use组合无效
	for (int i = 0; i < record_ctx->free_count; i++) {
		const AccessRecord* other_free = &record_ctx->free_records[i];

		// 跳过当前的free操作
		if (other_free->access_time == free_time &&
		    other_free->address == free_op->address &&
		    other_free->tid == free_op->tid) {
			continue;
		}

		// 检查是否有更晚的free操作（在当前free之后，use之前）
		if (other_free->access_time > free_time &&
		    other_free->access_time < use_time) {
			if (access_record_addresses_overlap(other_free, use_access)) {
				return false;
			}
		}
	}
	return true;
}


ThreadAccessHistory* access_context_find_thread(AccessContext* record_set, int tid)
{
	for (int i = 0; i < record_set->thread_count; i++) {
		if (record_set->thread_histories[i].tid == tid) {
			return &record_set->thread_histories[i];
		}
	}
	return NULL;
}

ThreadAccessHistory* access_context_create_thread_history(AccessContext* record_set, int tid)
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

static void debug(const char* fmt, ...)
{
    int err = errno;

    // 打印前缀
    fprintf(stderr, "[access_context]: ");

    // 打印实际消息
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fflush(stderr);
    errno = err;
}
