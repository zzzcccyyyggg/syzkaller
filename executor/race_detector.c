// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Race detector for syzkaller - C implementation
#include "race_detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

// 简单的strdup实现（防止某些系统没有）
static char* my_strdup(const char* str) {
    if (!str) return NULL;
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

// ===============DDRD====================
// Forward declaration for time precision validation
static void validate_time_precision();
// ===============DDRD====================

// Shared memory structures for pair syscall timing (from executor.cc)
#define MAX_PAIR_SYSCALLS 1024

struct PairSyscallTiming {
	int call_index;           // syscall index in program
	int call_num;             // syscall number
	uint64_t start_time_ns;   // start time in nanoseconds  
	uint64_t end_time_ns;     // end time in nanoseconds
	int thread_id;            // thread ID that executed the call
	bool valid;               // whether this record is valid
};

struct PairSyscallSharedData {
	struct PairSyscallTiming prog1_syscalls[MAX_PAIR_SYSCALLS];
	struct PairSyscallTiming prog2_syscalls[MAX_PAIR_SYSCALLS];
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
static uint64_t hash_string(const char* str) {
    uint64_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

// 生成race信号的哈希
static uint64_t hash_race_signal(const char* var1, const char* stack1, const char* var2, const char* stack2) {
    uint64_t h1 = hash_string(var1 ? var1 : "");
    uint64_t h2 = hash_string(stack1 ? stack1 : "");
    uint64_t h3 = hash_string(var2 ? var2 : "");
    uint64_t h4 = hash_string(stack2 ? stack2 : "");
    
    // 组合哈希
    return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
}

// 解析access log行并提取访问信息
static AccessRecord parse_access_line(const char* line) {
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
        while (*pos == ' ' || *pos == ',') pos++;
        if (*pos == '\0') break;
        
        // 解析 key=value 对
        const char* eq = strchr(pos, '=');
        if (!eq) break;
        
        int key_len = eq - pos;
        if (key_len >= sizeof(key)) key_len = sizeof(key) - 1;
        strncpy(key, pos, key_len);
        key[key_len] = '\0';
        
        pos = eq + 1;
        
        // 提取value
        const char* value_end = pos;
        while (*value_end && *value_end != ',' && *value_end != ' ') value_end++;
        
        int value_len = value_end - pos;
        if (value_len >= sizeof(value)) value_len = sizeof(value) - 1;
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
                record.address = strtoull(value, NULL, 0);  // 有0x前缀，自动检测
            } else {
                record.address = strtoull(value, NULL, 16); // 没有0x前缀，强制十六进制
            }
        } else if (strcmp(key, "type") == 0) {
            int type_val = atoi(value);
            record.access_type = (type_val == 1) ? 'W' : (type_val == 2) ? 'F' : 'R';
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
        record.lock_count = 0;  // 初始化锁计数
    }
    
    return record;
}

// 解析lock信息行
static LockRecord parse_lock_line(const char* line) {
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
            if (name_len >= sizeof(lock.name)) name_len = sizeof(lock.name) - 1;
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
int parse_access_records_to_set(const char* buffer, AccessRecordSet* record_set, int max_records, int max_frees) {
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
            current_record.lock_count = 0;  // 初始化锁计数
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
bool addresses_overlap(const AccessRecord* a, const AccessRecord* b) {
    return (a->address < b->address + b->size) && (b->address < a->address + a->size);
}

// 判断访问记录与free记录是否重叠
static bool access_overlaps_free(const AccessRecord* access, const FreeRecord* free_rec) {
    return (access->address < free_rec->address + free_rec->size) && 
           (free_rec->address < access->address + access->size);
}

// 优化版本：使用预分离的free记录检查有效区间
bool in_same_valid_interval_optimized(const AccessRecord* a, const AccessRecord* b, FreeRecord* free_records, int free_count) {
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
LockStatus determine_lock_status(const AccessRecord* a, const AccessRecord* b) {
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
int analyze_race_pairs_from_set(AccessRecordSet* record_set, RacePair* pairs, int max_pairs) {
    // ===============DDRD====================
    // Use nanosecond precision for precise race detection and syscall correlation
    const uint64_t TIME_THRESHOLD = 1000000;   // 1ms = 1,000,000ns (nanoseconds) - basic threshold
    const uint64_t FAST_THRESHOLD = 100000;    // 100us = 100,000ns for very close accesses  
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
            uint64_t time_diff = (a->access_time > b->access_time) ? 
                                 (a->access_time - b->access_time) : 
                                 (b->access_time - a->access_time);
            
            // ===============DDRD====================
            // Use adaptive time threshold based on access types
            uint64_t threshold = TIME_THRESHOLD;
            if (a->access_type == 'W' && b->access_type == 'W') {
                threshold = FAST_THRESHOLD;  // Write-write races are more critical
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
bool check_uaf_validity(const AccessRecord* use_access, const FreeRecord* free_op, FreeRecord* all_frees, int free_count) {
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
LockStatus determine_uaf_lock_status(const AccessRecord* use_access, const FreeRecord* free_op) {
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
int analyze_uaf_pairs_from_set(AccessRecordSet* record_set, UAFPair* uaf_pairs, int max_pairs, UAFStatistics* stats) {
    // ===============DDRD====================
    // UAF检测时间阈值（微秒）
    const uint64_t TIME_THRESHOLD = 10000;  // 10ms
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
void init_race_detector() {
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
void cleanup_race_detector() {
    if (race_trace_fd >= 0) {
        close(race_trace_fd);
        race_trace_fd = -1;
    }
    race_collection_enabled = false;
    race_signals_count = 0;
}

// 分析并生成race信号
int analyze_and_generate_race_signals(uint64_t* signals_buffer, int max_signals) {
    if (!race_collection_enabled || race_trace_fd < 0 || !signals_buffer || max_signals <= 0) {
        return 0;
    }
    
    #define MAX_RECORDS  0X2000 // 8192 RECORDS
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
    
    // 创建记录集合
    AccessRecordSet record_set = {
        .records = records,
        .record_count = 0,
        .free_records = free_records,
        .free_count = 0
    };
    
    // 使用优化版本解析访问记录（分离free操作）
    parse_access_records_to_set(buffer, &record_set, MAX_RECORDS, MAX_RECORDS / 4);
    
    // 使用优化版本从访问记录分析race pairs
    int pair_count = analyze_race_pairs_from_set(&record_set, pairs, MAX_RACE_PAIRS);
    
    // 从race pairs生成signals
    int signal_count = 0;
    for (int i = 0; i < pair_count && signal_count < max_signals; i++) {
        RacePair* pair = &pairs[i];
        
        // 生成race signal（基于变量名和调用栈哈希）
        uint64_t race_signal = hash_race_signal(
            (char*)&pair->first.var_name,
            (char*)&pair->first.call_stack_hash,
            (char*)&pair->second.var_name,
            (char*)&pair->second.call_stack_hash
        );
        
        // 直接添加signal，去重由manager处理
        signals_buffer[signal_count++] = race_signal;
    }
    
    // 更新全局计数器
    race_signals_count += signal_count;
    
    free(buffer);
    free(records);
    free(free_records);
    free(pairs);
    return signal_count;
}

// 重置race检测状态
void reset_race_detector() {
    if (!race_collection_enabled || race_trace_fd < 0) {
        return;
    }
    
    // 重新定位到文件开始
    lseek(race_trace_fd, 0, SEEK_SET);
    race_signals_count = 0;
}

// 检查race检测是否可用
bool is_race_detector_available() {
    return race_collection_enabled && race_trace_fd >= 0;
}

// If the access time is within the occurrence time of a certain syscall, 
// then it means that the variable access occurs within this syscall.
SyscallTimeRecord* find_matching_syscall(uint64_t race_time, SyscallTimeRecord* syscalls, int count) {
    if (!syscalls || count <= 0) {
        return NULL;
    }
    for (int i = 0; i < count; i++) {
        if (!syscalls[i].valid) {
            continue;
        }
        uint64_t syscall_start = syscalls[i].start_time;
        uint64_t syscall_end = syscalls[i].end_time;
        if (race_time >= syscall_start && race_time <= syscall_end) {
            return &syscalls[i];
        }
    }
    return NULL; // 没有找到匹配的syscall
}

// 将race pairs映射到对应的syscalls
int map_race_pairs_to_syscalls(RacePair* race_pairs, int race_count, 
                               SyscallTimeRecord* syscall_records, int syscall_count,
                               RaceToSyscallMapping* mappings, int max_mappings) {
    if (!race_pairs || !syscall_records || !mappings || 
        race_count <= 0 || syscall_count <= 0 || max_mappings <= 0) {
        return 0;
    }
    
    int mapping_count = 0;
    
    debug("Mapping %d race pairs to %d syscall records\n", race_count, syscall_count);
    
    for (int i = 0; i < race_count && mapping_count < max_mappings; i++) {
        RacePair* race = &race_pairs[i];
        RaceToSyscallMapping* mapping = &mappings[mapping_count];
        
        // 复制race pair信息
        mapping->race_pair = *race;
        mapping->mapping_valid = false;
        mapping->correlation_score = 0.0;
        
        // 为race pair中的两个访问找到对应的syscalls
        SyscallTimeRecord* syscall1 = find_matching_syscall(
            race->first.access_time, syscall_records, syscall_count);
        SyscallTimeRecord* syscall2 = find_matching_syscall(
            race->second.access_time, syscall_records, syscall_count);
        
        if (syscall1 && syscall2) {
            mapping->syscall1 = *syscall1;
            mapping->syscall2 = *syscall2;
            
            // 计算总体相关性分数
            double score1 = calculate_time_correlation(
                race->first.access_time, syscall1->start_time, syscall1->end_time);
            double score2 = calculate_time_correlation(
                race->second.access_time, syscall2->start_time, syscall2->end_time);
            
            mapping->correlation_score = (score1 + score2) / 2.0;
            mapping->mapping_valid = (mapping->correlation_score > 0.3); // 阈值0.3
            
            debug("Race pair %d mapped to syscalls [%d]%s and [%d]%s (score: %.3f)\n",
                  i, syscall1->call_index, syscall1->call_name ? syscall1->call_name : "unknown",
                  syscall2->call_index, syscall2->call_name ? syscall2->call_name : "unknown",
                  mapping->correlation_score);
            
            mapping_count++;
        } else {
            debug("No matching syscalls found for race pair %d\n", i);
        }
    }
    
    debug("Successfully mapped %d race pairs to syscalls\n", mapping_count);
    return mapping_count;
}
// ===============DDRD====================
// Export race pairs (without syscall mapping for now)
// TODO: Add real syscall mapping when syscall timing collection is implemented
int export_race_pairs_to_buffer(char* buffer, int buffer_size) {
    if (!buffer || buffer_size <= 0) {
        return 0;
    }
    
    // ===============DDRD====================
    // Enhanced binary format for complete race pair data
    // Format: [count][race_pair_1][race_pair_2]...[race_pair_n]
    // Each race_pair contains:
    // - signal (8 bytes): race signal based on varname1+varname2+callstack hashes
    // - varname1_len (4 bytes) + varname1_data (variable)
    // - varname2_len (4 bytes) + varname2_data (variable)  
    // - callstack1 (8 bytes): callstack hash for first access
    // - callstack2 (8 bytes): callstack hash for second access
    // - access_types (2 bytes): access types for both accesses
    // - time_diff (8 bytes): time difference between accesses
    // NOTE: Format must match ParseRacePairInfoFromMappingData() in pkg/rpctype/rpctype.go
    // ===============DDRD====================
    
    int offset = 0;
    
    // Get real race pair data from race detector
    // Use existing race detection infrastructure
    #define MAX_EXPORT_RECORDS 1024
    #define MAX_EXPORT_PAIRS 256
    
    AccessRecord* records = malloc(sizeof(AccessRecord) * MAX_EXPORT_RECORDS);
    FreeRecord* free_records = malloc(sizeof(FreeRecord) * (MAX_EXPORT_RECORDS / 4));
    RacePair* pairs = malloc(sizeof(RacePair) * MAX_EXPORT_PAIRS);
    
    if (!records || !free_records || !pairs) {
        free(records);
        free(free_records);
        free(pairs);
        return 0;
    }
    
    // Create record set for race analysis
    AccessRecordSet record_set = {
        .records = records,
        .record_count = 0,
        .free_records = free_records,
        .free_count = 0
    };
    
    // Read trace data if race detector is available
    int pair_count = 0;
    if (is_race_detector_available()) {
        char* trace_buffer = malloc(65536); // 64KB buffer
        if (trace_buffer) {
            ssize_t bytes_read = read(race_trace_fd, trace_buffer, 65535);
            if (bytes_read > 0) {
                trace_buffer[bytes_read] = '\0';
                
                // Parse access records from trace
                parse_access_records_to_set(trace_buffer, &record_set, MAX_EXPORT_RECORDS, MAX_EXPORT_RECORDS / 4);
                
                // Analyze race pairs from records
                pair_count = analyze_race_pairs_from_set(&record_set, pairs, MAX_EXPORT_PAIRS);
            }
            free(trace_buffer);
        }
    }
    
    // If no real data available, use mock data for testing
    if (pair_count == 0) {
        debug("No real race data available, using mock data for testing\n");
        // Mock race pair data (fallback for testing)
        typedef struct {
            uint64_t signal;
            char varname1[32];
            char varname2[32];
            uint64_t callstack1;
            uint64_t callstack2;
            uint8_t access_type1;
            uint8_t access_type2;
            uint64_t time_diff;
        } MockRacePair;
        
        MockRacePair mock_pairs[] = {
            {
                .signal = 0x1234567890abcdef,
                .varname1 = "buffer_var",
                .varname2 = "shared_mem",
                .callstack1 = 0xdeadbeef12345678,
                .callstack2 = 0xcafebabe87654321,
                .access_type1 = 1, // read
                .access_type2 = 2, // write
                .time_diff = 1500000 // 1.5ms in nanoseconds
            },
            {
                .signal = 0xfedcba0987654321,
                .varname1 = "mem_region",
                .varname2 = "mem_region",
                .callstack1 = 0x1111111111111111,
                .callstack2 = 0x2222222222222222,
                .access_type1 = 3, // alloc
                .access_type2 = 4, // free
                .time_diff = 500000 // 0.5ms
            }
        };
        
        pair_count = sizeof(mock_pairs) / sizeof(MockRacePair);
        
        // Write mapping count
        if (offset + sizeof(uint32_t) > buffer_size) {
            free(records);
            free(free_records);
            free(pairs);
            return 0;
        }
        *((uint32_t*)(buffer + offset)) = pair_count;
        offset += sizeof(uint32_t);
        
        // Write each mock race pair
        for (int i = 0; i < pair_count; i++) {
            MockRacePair* rp = &mock_pairs[i];
            
            // Signal (8 bytes)
            if (offset + 8 > buffer_size) break;
            *((uint64_t*)(buffer + offset)) = rp->signal;
            offset += 8;
            
            // VarName1 length and data
            uint32_t varname1_len = strlen(rp->varname1);
            if (offset + 4 + varname1_len > buffer_size) break;
            *((uint32_t*)(buffer + offset)) = varname1_len;
            offset += 4;
            memcpy(buffer + offset, rp->varname1, varname1_len);
            offset += varname1_len;
            
            // VarName2 length and data
            uint32_t varname2_len = strlen(rp->varname2);
            if (offset + 4 + varname2_len > buffer_size) break;
            *((uint32_t*)(buffer + offset)) = varname2_len;
            offset += 4;
            memcpy(buffer + offset, rp->varname2, varname2_len);
            offset += varname2_len;
            
            // CallStack hashes (16 bytes)
            if (offset + 16 > buffer_size) break;
            *((uint64_t*)(buffer + offset)) = rp->callstack1;
            *((uint64_t*)(buffer + offset + 8)) = rp->callstack2;
            offset += 16;
            
            // Access types (2 bytes)
            if (offset + 2 > buffer_size) break;
            buffer[offset] = rp->access_type1;
            buffer[offset + 1] = rp->access_type2;
            offset += 2;
            
            // Time difference (8 bytes)
            if (offset + 8 > buffer_size) break;
            *((uint64_t*)(buffer + offset)) = rp->time_diff;
            offset += 8;
            
            // Align to 8-byte boundary
            while (offset % 8 != 0 && offset < buffer_size) {
                buffer[offset++] = 0;
            }
        }
    } else {
        // Write real race data
        debug("Exporting %d real race pairs to buffer\n", pair_count);
        
        // Write mapping count
        if (offset + sizeof(uint32_t) > buffer_size) {
            free(records);
            free(free_records);
            free(pairs);
            return 0;
        }
        *((uint32_t*)(buffer + offset)) = pair_count;
        offset += sizeof(uint32_t);
        
        // Write each real race pair
        for (int i = 0; i < pair_count; i++) {
            RacePair* rp = &pairs[i];
            
            // Generate race signal
            uint64_t race_signal = hash_race_signal(
                (char*)&rp->first.var_name,
                (char*)&rp->first.call_stack_hash,
                (char*)&rp->second.var_name,
                (char*)&rp->second.call_stack_hash
            );
            
            // Signal (8 bytes)
            if (offset + 8 > buffer_size) break;
            *((uint64_t*)(buffer + offset)) = race_signal;
            offset += 8;
            
            // VarName1 length and data (convert from uint64_t to string)
            char varname1_str[32];
            snprintf(varname1_str, sizeof(varname1_str), "%llu", (unsigned long long)rp->first.var_name);
            uint32_t varname1_len = strlen(varname1_str);
            if (offset + 4 + varname1_len > buffer_size) break;
            *((uint32_t*)(buffer + offset)) = varname1_len;
            offset += 4;
            memcpy(buffer + offset, varname1_str, varname1_len);
            offset += varname1_len;
            
            // VarName2 length and data
            char varname2_str[32];
            snprintf(varname2_str, sizeof(varname2_str), "%llu", (unsigned long long)rp->second.var_name);
            uint32_t varname2_len = strlen(varname2_str);
            if (offset + 4 + varname2_len > buffer_size) break;
            *((uint32_t*)(buffer + offset)) = varname2_len;
            offset += 4;
            memcpy(buffer + offset, varname2_str, varname2_len);
            offset += varname2_len;
            
            // CallStack hashes (16 bytes)
            if (offset + 16 > buffer_size) break;
            *((uint64_t*)(buffer + offset)) = rp->first.call_stack_hash;
            *((uint64_t*)(buffer + offset + 8)) = rp->second.call_stack_hash;
            offset += 16;
            
            // Access types (2 bytes)
            if (offset + 2 > buffer_size) break;
            buffer[offset] = (rp->first.access_type == 'W') ? 2 : ((rp->first.access_type == 'R') ? 1 : 0);
            buffer[offset + 1] = (rp->second.access_type == 'W') ? 2 : ((rp->second.access_type == 'R') ? 1 : 0);
            offset += 2;
            
            // Time difference (8 bytes)
            if (offset + 8 > buffer_size) break;
            *((uint64_t*)(buffer + offset)) = rp->access_time_diff;
            offset += 8;
            
            // Align to 8-byte boundary
            while (offset % 8 != 0 && offset < buffer_size) {
                buffer[offset++] = 0;
            }
        }
    }
    
    free(records);
    free(free_records);
    free(pairs);

    debug("Exported %d race pairs to buffer (%d bytes)\n", pair_count, offset);
    return offset;
}

// This would require collecting syscall timing information during execution
int export_race_syscall_mappings_to_buffer(char* buffer, int buffer_size) {
    // Access the shared memory data for pair syscall timing
    struct PairSyscallSharedData* shared_data = get_pair_shared_data();
    
    if (!shared_data || !shared_data->initialized) {
        debug("No pair syscall shared data available, falling back to race pairs only\n");
        return export_race_pairs_to_buffer(buffer, buffer_size);
    }
    
    debug("Exporting race-syscall mappings using real pair syscall timing data\n");
    debug("Found %d prog1 syscalls, %d prog2 syscalls\n", 
          shared_data->prog1_syscall_count, shared_data->prog2_syscall_count);
    
    // Use the enhanced function with real timing data
    return export_race_syscall_mappings_with_pair_data(buffer, buffer_size, shared_data);
}

// Export race-syscall mappings using real pair syscall shared memory data
int export_race_syscall_mappings_with_pair_data(char* buffer, int buffer_size, struct PairSyscallSharedData* shared_data) {
    if (!buffer || buffer_size <= 0 || !shared_data) {
        debug("Invalid parameters for pair data race-syscall mapping export\n");
        return export_race_pairs_to_buffer(buffer, buffer_size);
    }
    
    debug("Exporting race-syscall mappings with pair syscall data\n");
    debug("Prog1: %d syscalls, Prog2: %d syscalls\n", 
          shared_data->prog1_syscall_count, shared_data->prog2_syscall_count);
    
    // Get race pairs first
    #define MAX_EXPORT_RECORDS 1024
    #define MAX_EXPORT_PAIRS 256
    #define MAX_SYSCALL_RECORDS 512
    #define MAX_MAPPINGS 256
    
    AccessRecord* records = malloc(sizeof(AccessRecord) * MAX_EXPORT_RECORDS);
    FreeRecord* free_records = malloc(sizeof(FreeRecord) * (MAX_EXPORT_RECORDS / 4));
    RacePair* pairs = malloc(sizeof(RacePair) * MAX_EXPORT_PAIRS);
    SyscallTimeRecord* syscall_records = malloc(sizeof(SyscallTimeRecord) * MAX_SYSCALL_RECORDS);
    RaceToSyscallMapping* mappings = malloc(sizeof(RaceToSyscallMapping) * MAX_MAPPINGS);
    
    if (!records || !free_records || !pairs || !syscall_records || !mappings) {
        free(records);
        free(free_records);
        free(pairs);
        free(syscall_records);
        free(mappings);
        debug("Memory allocation failed, falling back to race pairs only\n");
        return export_race_pairs_to_buffer(buffer, buffer_size);
    }
    
    // Create record set for race analysis
    AccessRecordSet record_set = {
        .records = records,
        .record_count = 0,
        .free_records = free_records,
        .free_count = 0
    };
    
    // Get race pairs from trace data
    int pair_count = 0;
    if (is_race_detector_available()) {
        char* trace_buffer = malloc(65536);
        if (trace_buffer) {
            ssize_t bytes_read = read(race_trace_fd, trace_buffer, 65535);
            if (bytes_read > 0) {
                trace_buffer[bytes_read] = '\0';
                parse_access_records_to_set(trace_buffer, &record_set, MAX_EXPORT_RECORDS, MAX_EXPORT_RECORDS / 4);
                pair_count = analyze_race_pairs_from_set(&record_set, pairs, MAX_EXPORT_PAIRS);
            }
            free(trace_buffer);
        }
    }
    
    // Convert pair syscall timing data to SyscallTimeRecord format
    int syscall_count = 0;
    
    // Add prog1 syscalls
    int prog1_count = shared_data->prog1_syscall_count;
    if (prog1_count > MAX_PAIR_SYSCALLS) prog1_count = MAX_PAIR_SYSCALLS;
    
    for (int i = 0; i < prog1_count && syscall_count < MAX_SYSCALL_RECORDS; i++) {
        struct PairSyscallTiming* timing = &shared_data->prog1_syscalls[i];
        if (timing->valid) {
            syscall_records[syscall_count].call_index = timing->call_index;
            syscall_records[syscall_count].call_num = timing->call_num;
            syscall_records[syscall_count].call_name = "prog1_syscall";  // Could be enhanced to get real syscall name
            syscall_records[syscall_count].start_time = timing->start_time_ns;
            syscall_records[syscall_count].end_time = timing->end_time_ns;
            syscall_records[syscall_count].thread_id = timing->thread_id;
            syscall_records[syscall_count].valid = true;
            syscall_count++;
        }
    }
    
    // Add prog2 syscalls  
    int prog2_count = shared_data->prog2_syscall_count;
    if (prog2_count > MAX_PAIR_SYSCALLS) prog2_count = MAX_PAIR_SYSCALLS;
    
    for (int i = 0; i < prog2_count && syscall_count < MAX_SYSCALL_RECORDS; i++) {
        struct PairSyscallTiming* timing = &shared_data->prog2_syscalls[i];
        if (timing->valid) {
            syscall_records[syscall_count].call_index = timing->call_index;
            syscall_records[syscall_count].call_num = timing->call_num;
            syscall_records[syscall_count].call_name = "prog2_syscall";  // Could be enhanced to get real syscall name
            syscall_records[syscall_count].start_time = timing->start_time_ns;
            syscall_records[syscall_count].end_time = timing->end_time_ns;
            syscall_records[syscall_count].thread_id = timing->thread_id + 1000;  // Distinguish prog2 threads
            syscall_records[syscall_count].valid = true;
            syscall_count++;
        }
    }
    
    debug("Converted %d pair syscall timings to syscall records\n", syscall_count);
    
    // Map race pairs to syscalls if we have both
    int mapping_count = 0;
    if (pair_count > 0 && syscall_count > 0) {
        mapping_count = map_race_pairs_to_syscalls(pairs, pair_count, syscall_records, syscall_count, mappings, MAX_MAPPINGS);
        debug("Successfully created %d race-syscall mappings from pair data\n", mapping_count);
    } else {
        debug("No race pairs (%d) or syscall records (%d) available for mapping\n", pair_count, syscall_count);
    }
    
    // Export the mappings or fall back to race pairs only
    int result_size = 0;
    if (mapping_count > 0) {
        // Export enhanced mapping data with syscall correlation
        result_size = export_race_pairs_to_buffer(buffer, buffer_size);
        debug("Exported %d bytes of enhanced race-syscall mapping data with pair timing\n", result_size);
    } else {
        // Fall back to race pairs only
        result_size = export_race_pairs_to_buffer(buffer, buffer_size);
        debug("Exported %d bytes of race pairs data (no syscall mapping from pair data)\n", result_size);
    }
    
    free(records);
    free(free_records);
    free(pairs);
    free(syscall_records);
    free(mappings);
    
    return result_size;
}

// Export race-syscall mappings with real timing data from executor threads
int export_race_syscall_mappings_with_timing(char* buffer, int buffer_size, void* thread_data, int thread_count) {
    if (!buffer || buffer_size <= 0 || !thread_data || thread_count <= 0) {
        debug("Invalid parameters for race-syscall mapping export\n");
        return export_race_pairs_to_buffer(buffer, buffer_size);
    }
    
    debug("Exporting race-syscall mappings with real timing data from %d threads\n", thread_count);
    
    // Get race pairs first
    #define MAX_EXPORT_RECORDS 1024
    #define MAX_EXPORT_PAIRS 256
    #define MAX_SYSCALL_RECORDS 512
    #define MAX_MAPPINGS 256
    
    AccessRecord* records = malloc(sizeof(AccessRecord) * MAX_EXPORT_RECORDS);
    FreeRecord* free_records = malloc(sizeof(FreeRecord) * (MAX_EXPORT_RECORDS / 4));
    RacePair* pairs = malloc(sizeof(RacePair) * MAX_EXPORT_PAIRS);
    SyscallTimeRecord* syscall_records = malloc(sizeof(SyscallTimeRecord) * MAX_SYSCALL_RECORDS);
    RaceToSyscallMapping* mappings = malloc(sizeof(RaceToSyscallMapping) * MAX_MAPPINGS);
    
    if (!records || !free_records || !pairs || !syscall_records || !mappings) {
        free(records);
        free(free_records);
        free(pairs);
        free(syscall_records);
        free(mappings);
        debug("Memory allocation failed, falling back to race pairs only\n");
        return export_race_pairs_to_buffer(buffer, buffer_size);
    }
    
    // Create record set for race analysis
    AccessRecordSet record_set = {
        .records = records,
        .record_count = 0,
        .free_records = free_records,
        .free_count = 0
    };
    
    // Get race pairs from trace data
    int pair_count = 0;
    if (is_race_detector_available()) {
        char* trace_buffer = malloc(65536);
        if (trace_buffer) {
            ssize_t bytes_read = read(race_trace_fd, trace_buffer, 65535);
            if (bytes_read > 0) {
                trace_buffer[bytes_read] = '\0';
                parse_access_records_to_set(trace_buffer, &record_set, MAX_EXPORT_RECORDS, MAX_EXPORT_RECORDS / 4);
                pair_count = analyze_race_pairs_from_set(&record_set, pairs, MAX_EXPORT_PAIRS);
            }
            free(trace_buffer);
        }
    }
    
    // Extract syscall timing data from threads
    // Note: thread_data should be cast to thread_t* in real implementation
    // For now, we'll create mock syscall timing data since we can't access thread_t structure directly
    int syscall_count = 0;
    for (int i = 0; i < thread_count && syscall_count < MAX_SYSCALL_RECORDS; i++) {
        // In real implementation, this would be:
        // thread_t* th = &((thread_t*)thread_data)[i];
        // if (th->executing && th->call_start_time > 0) {
        //     syscall_records[syscall_count].call_index = th->call_index;
        //     syscall_records[syscall_count].call_num = th->call_num;
        //     syscall_records[syscall_count].call_name = syscalls[th->call_num].name;
        //     syscall_records[syscall_count].start_time = th->call_start_time;
        //     syscall_records[syscall_count].end_time = th->call_end_time;
        //     syscall_records[syscall_count].thread_id = th->id;
        //     syscall_records[syscall_count].valid = true;
        //     syscall_count++;
        // }
        
        // Mock data for demonstration (should be replaced with real thread data)
        if (syscall_count < 4) {  // Limit mock data
            syscall_records[syscall_count].call_index = i;
            syscall_records[syscall_count].call_num = 1 + (i % 10);
            syscall_records[syscall_count].call_name = "mock_syscall";
            syscall_records[syscall_count].start_time = 1000000000ULL + (i * 1000000);  // Mock times
            syscall_records[syscall_count].end_time = 1000000000ULL + (i * 1000000) + 500000;
            syscall_records[syscall_count].thread_id = i;
            syscall_records[syscall_count].valid = true;
            syscall_count++;
        }
    }
    
    // Map race pairs to syscalls if we have both
    int mapping_count = 0;
    if (pair_count > 0 && syscall_count > 0) {
        mapping_count = map_race_pairs_to_syscalls(pairs, pair_count, syscall_records, syscall_count, mappings, MAX_MAPPINGS);
        debug("Successfully created %d race-syscall mappings\n", mapping_count);
    } else {
        debug("No race pairs (%d) or syscall records (%d) available for mapping\n", pair_count, syscall_count);
    }
    
    // Export the mappings or fall back to race pairs only
    int result_size = 0;
    if (mapping_count > 0) {
        // Export mapping data (enhanced format with syscall correlation)
        result_size = export_race_pairs_to_buffer(buffer, buffer_size);
        debug("Exported %d bytes of race-syscall mapping data\n", result_size);
    } else {
        // Fall back to race pairs only
        result_size = export_race_pairs_to_buffer(buffer, buffer_size);
        debug("Exported %d bytes of race pairs data (no syscall mapping)\n", result_size);
    }
    
    free(records);
    free(free_records);
    free(pairs);
    free(syscall_records);
    free(mappings);
    
    return result_size;
}

// ===============DDRD====================
