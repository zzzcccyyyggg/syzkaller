#include "race_detector.h"
#include "trace_manager.h"
#include "utils.h"
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// saame with executor.cc
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

// 外部函数声明，来自 access_context.c
extern int parse_access_records_to_set(AccessContext* record_ctx, const char* buffer, int max_records, int max_frees);
extern int access_context_analyze_race_pairs(AccessContext* record_ctx, RacePair* pairs, int max_pairs);
extern int access_context_analyze_uaf_pairs(AccessContext* record_ctx, UAFPair* uaf_pairs, int max_pairs);

// ================== 辅助函数定义 ==================
static void debug(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[race_detector]: ");
    vfprintf(stderr, fmt, args);
    va_end(args);
}

// ================== 面向对象 RaceDetector 方法 ==================
void race_detector_init(RaceDetector* detector) {
    if (!detector) return;
    
    detector->enabled = false;
    detector->trace_fd = -1;
    
    // 初始化 AccessContext
    detector->context.thread_count = 0;
    detector->context.max_threads = MAX_THREADS;
    detector->context.records = NULL;
    detector->context.free_records = NULL;
    detector->context.thread_histories = NULL;
    detector->context.record_count = 0;
    detector->context.free_count = 0;
    detector->context.enable_history = false;  // 默认禁用历史记录功能
    
    debug("Initializing race detector...\n");
    
    // 使用 TraceManager 检查trace系统状态
    int current_buffer_size = trace_manager_get_buffer_size_kb();
    bool tracing_status = trace_manager_is_enabled();
    
    debug("Current trace system status:\n");
    debug("  Buffer size per CPU: %d KB\n", current_buffer_size);
    debug("  Tracing enabled: %s\n", tracing_status ? "yes" : "no");
    
    // 尝试打开trace文件
    detector->trace_fd = open("/sys/kernel/debug/tracing/trace", O_RDONLY);
    if (detector->trace_fd >= 0) {
        detector->enabled = true;
        debug("Race detector initialized successfully (fd=%d) with nanosecond precision\n", detector->trace_fd);
        
        // 测试文件是否可以正常定位（某些pseudo文件不支持lseek）
        if (lseek(detector->trace_fd, 0, SEEK_CUR) == (off_t)-1) {
            debug("Warning: trace file does not support lseek (errno=%d), but continuing\n", errno);
        }
        
        bool was_tracing = tracing_status;
        if (was_tracing) {
            debug("Temporarily disabling tracing for buffer configuration\n");
            trace_manager_disable();
        }

        if (current_buffer_size < 1024*16) { // 如果小于16MB，增加到16MB
            debug("Increasing trace buffer size from %d KB to 16384 KB\n", current_buffer_size);
            trace_manager_set_buffer_size_kb(1024*16);
        }
        
        if (was_tracing || !tracing_status) {
            debug("Enabling tracing for race detection\n");
            trace_manager_enable();
        }
    } else {
        debug("Race detector initialization failed: cannot open trace file (errno=%d)\n", errno);
    }
}

void race_detector_cleanup(RaceDetector* detector) {
    if (!detector) return;
    
    debug("Cleaning up race detector...\n");
    
    if (detector->trace_fd >= 0) {
        debug("Closing race trace fd=%d\n", detector->trace_fd);
        close(detector->trace_fd);
        detector->trace_fd = -1;
    }
    
    // 清理 AccessContext 资源
    if (detector->context.records) {
        free(detector->context.records);
        detector->context.records = NULL;
    }
    if (detector->context.free_records) {
        free(detector->context.free_records);
        detector->context.free_records = NULL;
    }
    if (detector->context.thread_histories) {
        free(detector->context.thread_histories);
        detector->context.thread_histories = NULL;
    }
    
    detector->enabled = false;
    debug("Race detector cleanup completed\n");
}

void race_detector_reset(RaceDetector* detector) {
    if (!detector) return;
    
    debug("Resetting race detector state...\n");
    
    // 重置统计信息
    detector->context.record_count = 0;
    detector->context.free_count = 0;
    detector->context.thread_count = 0;
    
    // 清理线程历史
    if (detector->context.thread_histories) {
        for (int i = 0; i < detector->context.max_threads; i++) {
            detector->context.thread_histories[i].access_count = 0;
            detector->context.thread_histories[i].access_index = 0;
            detector->context.thread_histories[i].buffer_full = false;
        }
    }
    
    debug("Race detector reset completed\n");
}

bool race_detector_is_available(RaceDetector* detector) {
    if (!detector) return false;
    return detector->enabled && detector->trace_fd >= 0;
}

// 从 trace buffer 读取数据
ssize_t race_detector_read_trace_buffer(RaceDetector* detector, char* buffer, size_t buffer_size) {
    if (!detector || !buffer || buffer_size == 0 || detector->trace_fd < 0) {
        return -1;
    }
    
    // 重置文件位置到开始
    if (lseek(detector->trace_fd, 0, SEEK_SET) == (off_t)-1) {
        // 某些 pseudo 文件不支持 lseek，忽略错误
        debug("Warning: trace file lseek failed, continuing anyway\n");
    }
    
    size_t total_read = 0;
    while (total_read < buffer_size - 1) {
        ssize_t bytes_read = read(detector->trace_fd, buffer + total_read, buffer_size - total_read - 1);
        if (bytes_read <= 0) break;
        total_read += bytes_read;
    }
    
    buffer[total_read] = '\0';
    return total_read;
}

// 解析 trace buffer 到 AccessContext
int race_detector_parse_trace_buffer(RaceDetector* detector, int max_records, int max_frees) {
    if (!detector) return 0;
    
    // 分配 buffer 读取 trace 数据
    const size_t buffer_size = 1024 * 1024 * 64; // 64MB buffer
    char* buffer = malloc(buffer_size);
    if (!buffer) return 0;
    
    ssize_t bytes_read = race_detector_read_trace_buffer(detector, buffer, buffer_size);
    if (bytes_read <= 0) {
        free(buffer);
        return 0;
    }
    
    debug("Read %zd bytes from trace buffer, parsing...\n", bytes_read);
    
    // 分配 AccessContext 的记录数组
    if (!detector->context.records) {
        detector->context.records = malloc(sizeof(AccessRecord) * max_records);
        if (!detector->context.records) {
            debug("Failed to allocate memory for records\n");
            free(buffer);
            return 0;
        }
        debug("Allocated memory for %d access records\n", max_records);
    }
    
    if (!detector->context.free_records) {
        detector->context.free_records = malloc(sizeof(AccessRecord) * max_frees);
        if (!detector->context.free_records) {
            debug("Failed to allocate memory for free_records\n");
            free(buffer);
            return 0;
        }
        debug("Allocated memory for %d free records\n", max_frees);
    }
    
    if (!detector->context.thread_histories && detector->context.enable_history) {
        detector->context.thread_histories = calloc(MAX_THREADS, sizeof(ThreadAccessHistory));
        if (!detector->context.thread_histories) {
            debug("Failed to allocate memory for thread_histories\n");
            free(buffer);
            return 0;
        }
        detector->context.max_threads = MAX_THREADS;
        debug("Allocated memory for %d thread histories\n", MAX_THREADS);
    }
    
    // 解析 buffer 到 AccessContext
    int result = parse_access_records_to_set(&detector->context, buffer, max_records, max_frees);
    
    free(buffer);
    debug("Parsed %d access records from trace buffer\n", result);
    return result;
}

int race_detector_analyze_race_pairs(RaceDetector* detector, RacePair* pairs, int max_pairs) {
    if (!detector || !pairs || max_pairs <= 0) return 0;
    return access_context_analyze_race_pairs(&detector->context, pairs, max_pairs);
}

int race_detector_analyze_uaf_pairs(RaceDetector* detector, UAFPair* pairs, int max_pairs) {
    if (!detector || !pairs || max_pairs <= 0) return 0;
    return access_context_analyze_uaf_pairs(&detector->context, pairs, max_pairs);
}

// ================== 线程历史管理方法 ==================
ThreadAccessHistory* race_detector_find_thread_history(RaceDetector* detector, int tid) {
    if (!detector) return NULL;
    return access_context_find_thread(&detector->context, tid);
}

ThreadAccessHistory* race_detector_create_thread_history(RaceDetector* detector, int tid) {
    if (!detector) return NULL;
    return access_context_create_thread_history(&detector->context, tid);
}

void race_detector_add_access_to_history(RaceDetector* detector, int tid, const AccessRecord* access) {
    if (!detector || !access) return;
    
    ThreadAccessHistory* history = race_detector_find_thread_history(detector, tid);
    if (!history) {
        history = race_detector_create_thread_history(detector, tid);
    }
    if (history) {
        add_access_to_history(history, access);
    }
}

// ================== 辅助计算方法 ==================
int race_detector_calculate_path_distance(const AccessRecord* target, const AccessRecord* current) {
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

double race_detector_calculate_delay_probability(int distance) {
    if (distance <= 0) {
        return 1.0; // 距离为0时，100%概率
    }
    
    return 1.0 / (distance + 1);
}

// ================== 历史记录功能控制方法 ==================
void race_detector_enable_history(RaceDetector* detector) {
    if (!detector) return;
    detector->context.enable_history = true;
    debug("Thread access history tracking enabled\n");
}

void race_detector_disable_history(RaceDetector* detector) {
    if (!detector) return;
    detector->context.enable_history = false;
    debug("Thread access history tracking disabled\n");
}

bool race_detector_is_history_enabled(RaceDetector* detector) {
    if (!detector) return false;
    return detector->context.enable_history;
}
int race_detector_analyze_and_generate_uaf_infos(RaceDetector* detector,
                                                         may_uaf_pair_t* uaf_buffer, int max_uaf_pairs) {
    if (!detector || !race_detector_is_available(detector) || !uaf_buffer || max_uaf_pairs <= 0) {
        debug("Invalid parameters for combined UAF analysis\n");
        return 0;
    }

    #define MAX_RECORDS 0x10000 // 20480 RECORDS
    #define MAX_UAF_PAIRS 0x200 // 512 PAIRS

    // 解析trace buffer到当前context
    int parsed_count = race_detector_parse_trace_buffer(detector, MAX_RECORDS, MAX_RECORDS / 16);
    if (parsed_count <= 0) {
        debug("Failed to parse trace buffer for combined UAF analysis\n");
        return 0;
    }
    
    debug("Successfully parsed %d access records for combined UAF analysis\n", parsed_count);

    // 动态分配UAF pairs用于分析
    UAFPair* uaf_pairs = malloc(sizeof(UAFPair) * MAX_UAF_PAIRS);
    if (!uaf_pairs) {
        return 0;
    }
    int uaf_pair_count = access_context_analyze_uaf_pairs(&detector->context, uaf_pairs, MAX_UAF_PAIRS);

    int basic_count = 0;
    for (basic_count = 0; basic_count < uaf_pair_count && basic_count < max_uaf_pairs; basic_count++) {
        UAFPair* uaf_pair = &uaf_pairs[basic_count];
        
        uaf_buffer[basic_count].free_access_name = uaf_pair->free_access.var_name;
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
        uaf_buffer[basic_count].signal = hash_race_signal(
		    (char*)&uaf_pair->use_access.var_name,
		    (char*)&uaf_pair->use_access.call_stack_hash,
		    (char*)&uaf_pair->free_access.var_name,
		    (char*)&uaf_pair->free_access.call_stack_hash);
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

    free(uaf_pairs);
    
    return basic_count;
}

int race_detector_analyze_and_generate_uaf_pairs_with_extend_infos(RaceDetector* detector,
                                                         may_uaf_pair_t* uaf_buffer, int max_uaf_pairs,
                                                         extended_uaf_pair_t* extended_pairs, int max_extended_pairs) {
    if (!detector || !race_detector_is_available(detector) || !uaf_buffer || max_uaf_pairs <= 0) {
        debug("Invalid parameters for combined UAF analysis\n");
        return 0;
    }

    // 解析trace buffer到当前context
    int parsed_count = race_detector_parse_trace_buffer(detector, MAX_RECORDS, MAX_RECORDS / 4);
    if (parsed_count <= 0) {
        debug("Failed to parse trace buffer for combined UAF analysis\n");
        return 0;
    }
    
    debug("Successfully parsed %d access records for combined UAF analysis\n", parsed_count);

    // 动态分配UAF pairs用于分析
    UAFPair* uaf_pairs = malloc(sizeof(UAFPair) * MAX_UAF_PAIRS);
    if (!uaf_pairs) {
        return 0;
    }

    // 分析UAF pairs

    int uaf_pair_count = access_context_analyze_uaf_pairs(&detector->context, uaf_pairs, MAX_UAF_PAIRS);

    // 生成基本UAF信息
    int basic_count = 0;
    for (basic_count = 0; basic_count < uaf_pair_count && basic_count < max_uaf_pairs; basic_count++) {
        UAFPair* uaf_pair = &uaf_pairs[basic_count];
        
        uaf_buffer[basic_count].free_access_name = uaf_pair->free_access.var_name;
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
        uaf_buffer[basic_count].signal = hash_race_signal(
		    (char*)&uaf_pair->use_access.var_name,
		    (char*)&uaf_pair->use_access.call_stack_hash,
		    (char*)&uaf_pair->free_access.var_name,
		    (char*)&uaf_pair->free_access.call_stack_hash);
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
        extended_count = race_detector_generate_extended_uaf_info(detector, uaf_buffer, basic_count, extended_pairs);
        if (extended_count > max_extended_pairs) {
            extended_count = max_extended_pairs;
        }
    }

    free(uaf_pairs); // UAFPair是临时的，可以释放
    
    debug("Combined UAF analysis complete: generated %d basic pairs and %d extended pairs\n", 
          basic_count, extended_count);
    
    return basic_count;
}

// 生成扩展race信息
int race_detector_generate_extended_race_info(RaceDetector* detector, may_race_pair_t* race_pairs, int race_count, 
                                             extended_race_pair_t* extended_pairs) {
    if (!detector || !race_pairs || !extended_pairs || race_count <= 0) {
        return 0;
    }

    // 直接填充扩展race pairs
    for (int i = 0; i < race_count; i++) {
        extended_race_pair_t* ext_pair = &extended_pairs[i];
        ext_pair->basic_info = race_pairs[i];
        
        // 查找对应的线程历史信息
        ThreadAccessHistory* thread1_history = race_detector_find_thread_history(detector, race_pairs[i].tid1);
        ThreadAccessHistory* thread2_history = race_detector_find_thread_history(detector, race_pairs[i].tid2);
        
        if (thread1_history) {
            ext_pair->thread1_history_count = thread1_history->access_count;
            if (ext_pair->thread1_history_count > MAX_ACCESS_HISTORY_RECORDS) {
                ext_pair->thread1_history_count = MAX_ACCESS_HISTORY_RECORDS;
            }
            ext_pair->path_distance1 = (double)(thread1_history->access_count - 1);
        } else {
            ext_pair->thread1_history_count = 0;
            ext_pair->path_distance1 = 0.0;
        }
        
        if (thread2_history) {
            ext_pair->thread2_history_count = thread2_history->access_count;
            if (ext_pair->thread2_history_count > MAX_ACCESS_HISTORY_RECORDS) {
                ext_pair->thread2_history_count = MAX_ACCESS_HISTORY_RECORDS;
            }
            ext_pair->path_distance2 = (double)(thread2_history->access_count - 1);
        } else {
            ext_pair->thread2_history_count = 0;
            ext_pair->path_distance2 = 0.0;
        }
        
        // 设置目标时间
        ext_pair->thread1_target_time = race_pairs[i].time_diff;
        ext_pair->thread2_target_time = 0;
        
        // 填充历史访问记录数据
        uint32_t record_index = 0;
        
        // 填充thread1的历史记录
        if (thread1_history) {
            for (uint32_t j = 0; j < ext_pair->thread1_history_count; j++) {
                if (j < (uint32_t)thread1_history->access_count) {
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
        
        // 填充thread2的历史记录
        if (thread2_history) {
            for (uint32_t j = 0; j < ext_pair->thread2_history_count; j++) {
                if (j < (uint32_t)thread2_history->access_count) {
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
    
    debug("Generated extended race info for %d pairs\n", race_count);
    return race_count;
}

// 生成扩展UAF信息
int race_detector_generate_extended_uaf_info(RaceDetector* detector, may_uaf_pair_t* uaf_pairs, int uaf_count,
                                            extended_uaf_pair_t* extended_uaf_pairs) {
    if (!detector || !uaf_pairs || !extended_uaf_pairs || uaf_count <= 0) {
        return 0;
    }

    // 直接填充扩展UAF pairs
    for (int i = 0; i < uaf_count; i++) {
        extended_uaf_pair_t* ext_uaf_pair = &extended_uaf_pairs[i];
        ext_uaf_pair->basic_info = uaf_pairs[i];
        
        // 查找对应的线程历史信息
        ThreadAccessHistory* use_thread_history = race_detector_find_thread_history(detector, uaf_pairs[i].use_tid);
        ThreadAccessHistory* free_thread_history = race_detector_find_thread_history(detector, uaf_pairs[i].free_tid);
        
        if (use_thread_history) {
            ext_uaf_pair->use_thread_history_count = use_thread_history->access_count;
            if (ext_uaf_pair->use_thread_history_count > MAX_ACCESS_HISTORY_RECORDS) {
                ext_uaf_pair->use_thread_history_count = MAX_ACCESS_HISTORY_RECORDS;
            }
            ext_uaf_pair->path_distance_use = (double)(use_thread_history->access_count - 1);
        } else {
            ext_uaf_pair->use_thread_history_count = 0;
            ext_uaf_pair->path_distance_use = 0.0;
        }
        
        if (free_thread_history) {
            ext_uaf_pair->free_thread_history_count = free_thread_history->access_count;
            if (ext_uaf_pair->free_thread_history_count > MAX_ACCESS_HISTORY_RECORDS) {
                ext_uaf_pair->free_thread_history_count = MAX_ACCESS_HISTORY_RECORDS;
            }
            ext_uaf_pair->path_distance_free = (double)(free_thread_history->access_count - 1);
        } else {
            ext_uaf_pair->free_thread_history_count = 0;
            ext_uaf_pair->path_distance_free = 0.0;
        }
        
        // 设置目标时间
        ext_uaf_pair->use_target_time = uaf_pairs[i].time_diff;
        ext_uaf_pair->free_target_time = 0;
        
        // 填充历史访问记录数据
        uint32_t uaf_record_index = 0;
        
        // 填充use线程的历史记录
        if (use_thread_history) {
            for (uint32_t j = 0; j < ext_uaf_pair->use_thread_history_count; j++) {
                if (j < (uint32_t)use_thread_history->access_count) {
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
        
        // 填充free线程的历史记录
        if (free_thread_history) {
            for (uint32_t j = 0; j < ext_uaf_pair->free_thread_history_count; j++) {
                if (j < (uint32_t)free_thread_history->access_count) {
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
    
    debug("Generated extended UAF info for %d pairs\n", uaf_count);
    return uaf_count;
}

// 分析并生成扩展的race信息（包含历史数据）
int race_detector_analyze_and_generate_extended_race_infos(RaceDetector* detector,
                                                          may_race_pair_t* race_signals_buffer, int race_count,
                                                          extended_race_pair_t* extended_buffer, int max_extended) {
    if (!detector || !race_detector_is_available(detector) || 
        !race_signals_buffer || !extended_buffer || race_count <= 0 || max_extended <= 0) {
        debug("Invalid parameters for extended race analysis\n");
        return 0;
    }

    debug("Generating extended information for %d existing races...\n", race_count);

    int parsed_count = race_detector_parse_trace_buffer(detector, MAX_RECORDS, MAX_RECORDS / 4);
    if (parsed_count <= 0) {
        debug("Failed to parse trace buffer for extended race analysis\n");
        return 0;
    }

    debug("Successfully parsed %d access records for extended race analysis\n", parsed_count);

    // 调用扩展race信息生成函数
    int extended_count = race_detector_generate_extended_race_info(detector, race_signals_buffer, race_count, extended_buffer);

    debug("Extended race analysis completed: %d extended race pairs generated\n", extended_count);
    return extended_count;
}

// 分析并生成扩展的UAF信息（包含历史数据）
int race_detector_analyze_and_generate_extended_uaf_infos(RaceDetector* detector,
                                                         may_uaf_pair_t* uaf_signals_buffer, int uaf_count,
                                                         extended_uaf_pair_t* extended_buffer, int max_extended) {
    if (!detector || !race_detector_is_available(detector) || 
        !uaf_signals_buffer || !extended_buffer || uaf_count <= 0 || max_extended <= 0) {
        debug("Invalid parameters for extended UAF analysis\n");
        return 0;
    }

    debug("Generating extended information for %d existing UAF pairs...\n", uaf_count);

    int parsed_count = race_detector_parse_trace_buffer(detector, MAX_RECORDS, MAX_RECORDS / 4);
    if (parsed_count <= 0) {
        debug("Failed to parse trace buffer for extended UAF analysis\n");
        return 0;
    }

    debug("Successfully parsed %d access records for extended UAF analysis\n", parsed_count);

    // 调用扩展UAF信息生成函数
    int extended_count = race_detector_generate_extended_uaf_info(detector, uaf_signals_buffer, uaf_count, extended_buffer);

    debug("Extended UAF analysis completed: %d extended UAF pairs generated\n", extended_count);
    return extended_count;
}

SyscallTimeRecord* find_matching_syscall(uint64_t access_time, int tid)
{
	struct PairSyscallSharedData* pair_shared_data = get_pair_shared_data();
	
	// 必须先检查shared_data是否可用，否则会导致SIGSEGV
	if (!pair_shared_data) {
		return NULL;
	}
	
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
