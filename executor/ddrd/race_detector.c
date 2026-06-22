#include "race_detector.h"
#include "trace_manager.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DDRD_TRACE_BUFFER_SIZE (64ULL * 1024ULL * 1024ULL)
#define DDRD_MAX_RECORDS 0x10000
#define DDRD_MAX_UAF_PAIRS 0x200

static void debug(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[race_detector]: ");
    vfprintf(stderr, fmt, args);
    va_end(args);
}

void race_detector_init(RaceDetector* detector)
{
    if (!detector)
        return;

    detector->enabled = false;
    detector->trace_fd = -1;

    detector->context.thread_count = 0;
    detector->context.max_threads = MAX_THREADS;
    detector->context.records = NULL;
    detector->context.free_records = NULL;
    detector->context.thread_histories = NULL;
    detector->context.record_count = 0;
    detector->context.free_count = 0;
    detector->context.enable_history = false;

    debug("Initializing race detector...\n");

    int current_buffer_size = trace_manager_get_buffer_size_kb();
    bool tracing_status = trace_manager_is_enabled();

    debug("Current trace system status:\n");
    debug("  Buffer size per CPU: %d KB\n", current_buffer_size);
    debug("  Tracing enabled: %s\n", tracing_status ? "yes" : "no");

    detector->trace_fd = open("/sys/kernel/debug/tracing/trace", O_RDONLY);
    if (detector->trace_fd >= 0) {
        detector->enabled = true;
        debug("Race detector initialized successfully (fd=%d) with nanosecond precision\n", detector->trace_fd);

        if (lseek(detector->trace_fd, 0, SEEK_CUR) == (off_t)-1)
            debug("Warning: trace file does not support lseek (errno=%d), but continuing\n", errno);

        bool was_tracing = tracing_status;
        if (was_tracing) {
            debug("Temporarily disabling tracing for buffer configuration\n");
            trace_manager_disable();
        }

        if (current_buffer_size < 1024 * 16) {
            debug("Increasing trace buffer size from %d KB to 16384 KB\n", current_buffer_size);
            trace_manager_set_buffer_size_kb(1024 * 16);
        }

        if (was_tracing || !tracing_status) {
            debug("Enabling tracing for race detection\n");
            trace_manager_enable();
        }
    } else {
        debug("Race detector initialization failed: cannot open trace file (errno=%d)\n", errno);
    }
}

void race_detector_cleanup(RaceDetector* detector)
{
    if (!detector)
        return;

    debug("Cleaning up race detector...\n");

    if (detector->trace_fd >= 0) {
        debug("Closing race trace fd=%d\n", detector->trace_fd);
        close(detector->trace_fd);
        detector->trace_fd = -1;
    }

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

void race_detector_reset(RaceDetector* detector)
{
    if (!detector)
        return;

    debug("Resetting race detector state...\n");

    detector->context.record_count = 0;
    detector->context.free_count = 0;
    detector->context.thread_count = 0;

    if (detector->context.thread_histories) {
        for (int i = 0; i < detector->context.max_threads; i++) {
            detector->context.thread_histories[i].access_count = 0;
            detector->context.thread_histories[i].access_index = 0;
            detector->context.thread_histories[i].buffer_full = false;
        }
    }

    debug("Race detector reset completed\n");
}

bool race_detector_is_available(RaceDetector* detector)
{
    if (!detector)
        return false;
    return detector->enabled && detector->trace_fd >= 0;
}

ssize_t race_detector_read_trace_buffer(RaceDetector* detector, char* buffer, size_t buffer_size)
{
    if (!detector || !buffer || buffer_size == 0 || detector->trace_fd < 0)
        return -1;

    if (lseek(detector->trace_fd, 0, SEEK_SET) == (off_t)-1)
        debug("Warning: trace file lseek failed, continuing anyway\n");

    size_t total_read = 0;
    while (total_read < buffer_size - 1) {
        ssize_t bytes_read = read(detector->trace_fd, buffer + total_read, buffer_size - total_read - 1);
        if (bytes_read <= 0)
            break;
        total_read += (size_t)bytes_read;
    }

    buffer[total_read] = '\0';
    return (ssize_t)total_read;
}

// 持续读取 trace buffer 直到日志稳定（没有新内容出现）
// poll_interval_ms: 每次检查的间隔（毫秒）
// max_stable_checks: 连续多少次大小不变才认为稳定
// max_wait_ms: 最大等待时间（毫秒），防止无限等待
ssize_t race_detector_read_trace_buffer_until_stable(RaceDetector* detector, 
    char* buffer, size_t buffer_size,
    int poll_interval_ms, int max_stable_checks, int max_wait_ms)
{
    if (!detector || !buffer || buffer_size == 0 || detector->trace_fd < 0)
        return -1;

    ssize_t last_size = -1;
    int stable_count = 0;
    int total_wait_ms = 0;
    
    debug("Starting stable trace read: poll=%dms, stable_threshold=%d, max_wait=%dms\n",
          poll_interval_ms, max_stable_checks, max_wait_ms);
    
    while (stable_count < max_stable_checks && total_wait_ms < max_wait_ms) {
        // Seek to beginning and read current content
        if (lseek(detector->trace_fd, 0, SEEK_SET) == (off_t)-1) {
            debug("Warning: trace file lseek failed during stable read\n");
        }
        
        size_t current_size = 0;
        while (current_size < buffer_size - 1) {
            ssize_t bytes_read = read(detector->trace_fd, buffer + current_size, 
                                      buffer_size - current_size - 1);
            if (bytes_read <= 0)
                break;
            current_size += (size_t)bytes_read;
        }
        
        if ((ssize_t)current_size == last_size) {
            stable_count++;
            debug("Trace size stable at %zu bytes (check %d/%d)\n", 
                  current_size, stable_count, max_stable_checks);
        } else {
            if (last_size >= 0) {
                debug("Trace size changed: %zd -> %zu bytes, resetting stable count\n",
                      last_size, current_size);
            }
            stable_count = 0;
            last_size = (ssize_t)current_size;
        }
        
        if (stable_count < max_stable_checks) {
            usleep(poll_interval_ms * 1000);
            total_wait_ms += poll_interval_ms;
        }
    }
    
    if (total_wait_ms >= max_wait_ms) {
        debug("Warning: max wait time reached (%dms), using current buffer\n", max_wait_ms);
    } else {
        debug("Trace buffer stabilized after %dms with %zd bytes\n", total_wait_ms, last_size);
    }
    
    buffer[last_size >= 0 ? last_size : 0] = '\0';
    return last_size >= 0 ? last_size : 0;
}

int race_detector_parse_trace_buffer(RaceDetector* detector, int max_records, int max_frees)
{
    if (!detector)
        return 0;

    const size_t buffer_size = DDRD_TRACE_BUFFER_SIZE;
    char* buffer = (char*)malloc(buffer_size);
    if (!buffer)
        return 0;

    ssize_t bytes_read = race_detector_read_trace_buffer(detector, buffer, buffer_size);
    if (bytes_read <= 0) {
        free(buffer);
        return 0;
    }

    debug("Read %zd bytes from trace buffer, parsing...\n", bytes_read);

    if (!detector->context.records) {
        detector->context.records = (AccessRecord*)malloc(sizeof(AccessRecord) * max_records);
        if (!detector->context.records) {
            debug("Failed to allocate memory for records\n");
            free(buffer);
            return 0;
        }
        debug("Allocated memory for %d access records\n", max_records);
    }

    if (!detector->context.free_records) {
        detector->context.free_records = (AccessRecord*)malloc(sizeof(AccessRecord) * max_frees);
        if (!detector->context.free_records) {
            debug("Failed to allocate memory for free_records\n");
            free(buffer);
            return 0;
        }
        debug("Allocated memory for %d free records\n", max_frees);
    }

    if (!detector->context.thread_histories && detector->context.enable_history) {
        detector->context.thread_histories = (ThreadAccessHistory*)calloc(MAX_THREADS, sizeof(ThreadAccessHistory));
        if (!detector->context.thread_histories) {
            debug("Failed to allocate memory for thread_histories\n");
            free(buffer);
            return 0;
        }
        detector->context.max_threads = MAX_THREADS;
        debug("Allocated memory for %d thread histories\n", MAX_THREADS);
    }

    int result = access_context_init_from_buffer(&detector->context, buffer, max_records, max_frees);

    free(buffer);
    debug("Parsed %d access records from trace buffer\n", result);
    return result;
}

// 使用稳定读取模式解析 trace buffer（等待日志不再增长）
int race_detector_parse_trace_buffer_stable(RaceDetector* detector, int max_records, int max_frees)
{
    if (!detector)
        return 0;

    const size_t buffer_size = DDRD_TRACE_BUFFER_SIZE;
    char* buffer = (char*)malloc(buffer_size);
    if (!buffer)
        return 0;

    // 使用稳定读取：每 50ms 检查一次，连续 3 次不变则认为稳定，最多等待 2000ms
    ssize_t bytes_read = race_detector_read_trace_buffer_until_stable(
        detector, buffer, buffer_size,
        50,    // poll_interval_ms
        3,     // max_stable_checks
        2000   // max_wait_ms
    );
    if (bytes_read <= 0) {
        free(buffer);
        return 0;
    }

    debug("Stable read got %zd bytes from trace buffer, parsing...\n", bytes_read);

    if (!detector->context.records) {
        detector->context.records = (AccessRecord*)malloc(sizeof(AccessRecord) * max_records);
        if (!detector->context.records) {
            debug("Failed to allocate memory for records\n");
            free(buffer);
            return 0;
        }
        debug("Allocated memory for %d access records\n", max_records);
    }

    if (!detector->context.free_records) {
        detector->context.free_records = (AccessRecord*)malloc(sizeof(AccessRecord) * max_frees);
        if (!detector->context.free_records) {
            debug("Failed to allocate memory for free_records\n");
            free(buffer);
            return 0;
        }
        debug("Allocated memory for %d free records\n", max_frees);
    }

    if (!detector->context.thread_histories && detector->context.enable_history) {
        detector->context.thread_histories = (ThreadAccessHistory*)calloc(MAX_THREADS, sizeof(ThreadAccessHistory));
        if (!detector->context.thread_histories) {
            debug("Failed to allocate memory for thread_histories\n");
            free(buffer);
            return 0;
        }
        detector->context.max_threads = MAX_THREADS;
        debug("Allocated memory for %d thread histories\n", MAX_THREADS);
    }

    int result = access_context_init_from_buffer(&detector->context, buffer, max_records, max_frees);

    free(buffer);
    debug("Parsed %d access records from trace buffer (stable mode)\n", result);
    return result;
}

int race_detector_analyze_race_pairs(RaceDetector* detector, RacePair* pairs, int max_pairs)
{
    if (!detector || !pairs || max_pairs <= 0)
        return 0;
    return access_context_analyze_race_pairs(&detector->context, pairs, max_pairs);
}

int race_detector_analyze_uaf_pairs(RaceDetector* detector, UAFPair* pairs, int max_pairs)
{
    if (!detector || !pairs || max_pairs <= 0)
        return 0;
    return access_context_analyze_uaf_pairs(&detector->context, pairs, max_pairs);
}

ThreadAccessHistory* race_detector_find_thread_history(RaceDetector* detector, int tid)
{
    if (!detector)
        return NULL;
    return access_context_find_thread(&detector->context, tid);
}

ThreadAccessHistory* race_detector_create_thread_history(RaceDetector* detector, int tid)
{
    if (!detector)
        return NULL;
    return access_context_create_thread_history(&detector->context, tid);
}

void race_detector_add_access_to_history(RaceDetector* detector, int tid, const AccessRecord* access)
{
    if (!detector || !access)
        return;

    ThreadAccessHistory* history = race_detector_find_thread_history(detector, tid);
    if (!history)
        history = race_detector_create_thread_history(detector, tid);
    if (history)
        add_access_to_history(history, access);
}

int race_detector_calculate_path_distance(const AccessRecord* target, const AccessRecord* current)
{
    if (!target || !current)
        return INT_MAX;

    if (target->tid != current->tid)
        return INT_MAX;

    if (current->sn <= target->sn)
        return target->sn - current->sn;
    return INT_MAX;
}

double race_detector_calculate_delay_probability(int distance)
{
    if (distance <= 0)
        return 1.0;
    return 1.0 / (distance + 1);
}

void race_detector_enable_history(RaceDetector* detector)
{
    if (!detector)
        return;
    detector->context.enable_history = true;
    debug("Thread access history tracking enabled\n");
}

void race_detector_disable_history(RaceDetector* detector)
{
    if (!detector)
        return;
    detector->context.enable_history = false;
    // debug("Thread access history tracking disabled\n");
}

bool race_detector_is_history_enabled(RaceDetector* detector)
{
    if (!detector)
        return false;
    return detector->context.enable_history;
}

int race_detector_analyze_and_generate_uaf_infos(RaceDetector* detector, may_uaf_pair_t* uaf_buffer, int max_uaf_pairs)
{
    if (!detector || !race_detector_is_available(detector) || !uaf_buffer || max_uaf_pairs <= 0) {
        debug("Invalid parameters for combined UAF analysis\n");
        return 0;
    }

    int parsed_count = race_detector_parse_trace_buffer(detector, DDRD_MAX_RECORDS, DDRD_MAX_RECORDS / 16);
    if (parsed_count <= 0) {
        debug("Failed to parse trace buffer for combined UAF analysis\n");
        return 0;
    }

    debug("Successfully parsed %d access records for combined UAF analysis\n", parsed_count);

    UAFPair* uaf_pairs = (UAFPair*)malloc(sizeof(UAFPair) * DDRD_MAX_UAF_PAIRS);
    if (!uaf_pairs)
        return 0;
    int uaf_pair_count = access_context_analyze_uaf_pairs(&detector->context, uaf_pairs, DDRD_MAX_UAF_PAIRS);
    debug("Successfully parsed %d uaf pairs\n",uaf_pair_count);
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
        uaf_buffer[basic_count].lock_type = uaf_pair->lock_status;
        uaf_buffer[basic_count].use_access_type = uaf_pair->use_access.access_type;
        uaf_buffer[basic_count].signal = hash_race_signal((char*)&uaf_pair->use_access.var_name,
            (char*)&uaf_pair->use_access.call_stack_hash,
            (char*)&uaf_pair->free_access.var_name,
            (char*)&uaf_pair->free_access.call_stack_hash);
        uaf_buffer[basic_count].time_diff = uaf_pair->time_diff;

        // Lookup syscall call_index using tid and access_time from history
        SyscallLookupResult free_result = syscall_context_lookup_with_time(
            &g_syscall_context, 
            uaf_pair->free_access.tid, 
            uaf_pair->free_access.access_time);
        SyscallLookupResult use_result = syscall_context_lookup_with_time(
            &g_syscall_context, 
            uaf_pair->use_access.tid, 
            uaf_pair->use_access.access_time);
        uaf_buffer[basic_count].free_call_idx = free_result.call_idx;
        uaf_buffer[basic_count].free_prog_idx = free_result.prog_idx;
        uaf_buffer[basic_count].use_call_idx = use_result.call_idx;
        uaf_buffer[basic_count].use_prog_idx = use_result.prog_idx;
    }

    free(uaf_pairs);

    return basic_count;
}

int race_detector_analyze_and_generate_uaf_pairs_with_extend_infos(RaceDetector* detector,
    may_uaf_pair_t* uaf_buffer, int max_uaf_pairs,
    extended_uaf_pair_t* extended_pairs, int max_extended_pairs)
{
    if (!detector || !race_detector_is_available(detector) || !uaf_buffer || max_uaf_pairs <= 0) {
        debug("Invalid parameters for combined UAF analysis\n");
        return 0;
    }

    int parsed_count = race_detector_parse_trace_buffer(detector, DDRD_MAX_RECORDS, DDRD_MAX_RECORDS / 4);
    if (parsed_count <= 0) {
        debug("Failed to parse trace buffer for combined UAF analysis\n");
        return 0;
    }

    debug("Successfully parsed %d access records for combined UAF analysis\n", parsed_count);

    UAFPair* uaf_pairs = (UAFPair*)malloc(sizeof(UAFPair) * DDRD_MAX_UAF_PAIRS);
    if (!uaf_pairs)
        return 0;

    int uaf_pair_count = access_context_analyze_uaf_pairs(&detector->context, uaf_pairs, DDRD_MAX_UAF_PAIRS);

    bool fill_extended = extended_pairs && max_extended_pairs > 0;
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
        uaf_buffer[basic_count].lock_type = uaf_pair->lock_status;
        uaf_buffer[basic_count].use_access_type = uaf_pair->use_access.access_type;
        uaf_buffer[basic_count].signal = hash_race_signal((char*)&uaf_pair->use_access.var_name,
            (char*)&uaf_pair->use_access.call_stack_hash,
            (char*)&uaf_pair->free_access.var_name,
            (char*)&uaf_pair->free_access.call_stack_hash);
        uaf_buffer[basic_count].time_diff = uaf_pair->time_diff;

        // Lookup syscall call_index using tid and access_time from history
        SyscallLookupResult free_result = syscall_context_lookup_with_time(
            &g_syscall_context, 
            uaf_pair->free_access.tid, 
            uaf_pair->free_access.access_time);
        SyscallLookupResult use_result = syscall_context_lookup_with_time(
            &g_syscall_context, 
            uaf_pair->use_access.tid, 
            uaf_pair->use_access.access_time);
        uaf_buffer[basic_count].free_call_idx = free_result.call_idx;
        uaf_buffer[basic_count].free_prog_idx = free_result.prog_idx;
        uaf_buffer[basic_count].use_call_idx = use_result.call_idx;
        uaf_buffer[basic_count].use_prog_idx = use_result.prog_idx;

        if (fill_extended) {
            extended_pairs[basic_count].basic_info = uaf_buffer[basic_count];
            extended_pairs[basic_count].use_thread_history_count = 0;
            extended_pairs[basic_count].free_thread_history_count = 0;
            extended_pairs[basic_count].use_target_time = uaf_pair->time_diff;
            extended_pairs[basic_count].free_target_time = 0;
            extended_pairs[basic_count].path_distance_use = 0.0;
            extended_pairs[basic_count].path_distance_free = 0.0;
        }
    }

    free(uaf_pairs);

    debug("Combined UAF analysis complete: generated %d basic pairs and %d extended pairs\n", basic_count,
        fill_extended && max_extended_pairs < basic_count ? max_extended_pairs : basic_count);

    if (!fill_extended)
        return basic_count;

    int extended_count = race_detector_generate_extended_uaf_info(detector, uaf_buffer, basic_count, extended_pairs);
    if (extended_count > max_extended_pairs)
        extended_count = max_extended_pairs;

    return basic_count;
}

// 为了减少改动 先将uaf模型暂用到race上
// With configurable threshold (in microseconds). If threshold_us=0, uses default 10ms.
int race_detector_analyze_and_generate_race_infos_with_threshold(RaceDetector* detector,
   may_uaf_pair_t* uaf_buffer, int max_uaf_pairs, SyscallContextTable* syscall_ctx, uint64_t threshold_us)
{
    // Use provided syscall_ctx, or fall back to global g_syscall_context if NULL
    SyscallContextTable* ctx = syscall_ctx ? syscall_ctx : &g_syscall_context;
    
    if (!detector || !race_detector_is_available(detector) ||
        !uaf_buffer || max_uaf_pairs <= 0) {
        debug("Invalid parameters for combined race analysis\n");
        return 0;
    }

    // 1. 先从 trace 里解析出 AccessRecord，填充 detector->context
    int parsed_count = race_detector_parse_trace_buffer_stable(detector,
        DDRD_MAX_RECORDS, DDRD_MAX_RECORDS / 16);
    if (parsed_count <= 0) {
        debug("Failed to parse trace buffer for combined race analysis\n");
        return 0;
    }

    debug("Successfully parsed %d access records for combined race analysis\n",
        parsed_count);

    // 2. 调用底层的 data race 分析逻辑，拿到 RacePair 列表
    int max_internal_pairs = DDRD_MAX_RECORDS;
    RacePair* race_pairs = (RacePair*)malloc(sizeof(RacePair) * max_internal_pairs);
    if (!race_pairs)
        return 0;

    // Use configurable threshold
    int race_pair_count = access_context_analyze_race_pairs_with_threshold(
        &detector->context, race_pairs, max_internal_pairs, threshold_us);

    debug("Successfully parsed %d race pairs (threshold=%llu us)\n", race_pair_count, (unsigned long long)threshold_us);

    // 3. 把 RacePair 压缩/映射为对外的 may_race_pair_t
    int basic_count = 0;
    
    // Debug: check if syscall context has any history
    // fprintf(stderr, "[SYSCALL-CTX] Using context with history_count=%d for call_idx lookup\\n",
    //     ctx->history_count);
    // for (int dbg_i = 0; dbg_i < ctx->history_count && dbg_i < 8; dbg_i++) {
    //     fprintf(stderr, "[SYSCALL-CTX]   history[%d]: tid=%d call_idx=%d time=[%llu-%llu]\\n",
    //         dbg_i, ctx->history[dbg_i].tid, ctx->history[dbg_i].call_index,
    //         (unsigned long long)ctx->history[dbg_i].start_time,
    //         (unsigned long long)ctx->history[dbg_i].end_time);
    // }
    
    for (basic_count = 0;
         basic_count < race_pair_count && basic_count < max_uaf_pairs;
         basic_count++) {
        RacePair* race_pair = &race_pairs[basic_count];
        uaf_buffer[basic_count].use_access_name  = race_pair->first.var_name;
        uaf_buffer[basic_count].free_access_name  = race_pair->second.var_name;
        uaf_buffer[basic_count].use_call_stack   = race_pair->first.call_stack_hash;
        uaf_buffer[basic_count].free_call_stack   = race_pair->second.call_stack_hash;
        uaf_buffer[basic_count].use_sn           = race_pair->first.sn;
        uaf_buffer[basic_count].free_sn          = race_pair->second.sn;
        // Add missing tid fields
        uaf_buffer[basic_count].use_tid          = race_pair->first.tid;
        uaf_buffer[basic_count].free_tid         = race_pair->second.tid;
        uaf_buffer[basic_count].lock_type     = race_pair->lock_status;
        uaf_buffer[basic_count].use_access_type  = race_pair->first.access_type;
        uaf_buffer[basic_count].time_diff     = race_pair->access_time_diff;
        uaf_buffer[basic_count].signal = hash_uaf_signal(
            (char*)&race_pair->first.var_name,
            (char*)&race_pair->first.call_stack_hash,
            (char*)&race_pair->second.var_name,
            (char*)&race_pair->second.call_stack_hash);
        
        // Lookup syscall call_index using tid and access_time from provided context
        SyscallLookupResult use_result = syscall_context_lookup_with_time(
            ctx, 
            race_pair->first.tid, 
            race_pair->first.access_time);
        SyscallLookupResult free_result = syscall_context_lookup_with_time(
            ctx, 
            race_pair->second.tid, 
            race_pair->second.access_time);
        uaf_buffer[basic_count].use_call_idx = use_result.call_idx;
        uaf_buffer[basic_count].use_prog_idx = use_result.prog_idx;
        uaf_buffer[basic_count].free_call_idx = free_result.call_idx;
        uaf_buffer[basic_count].free_prog_idx = free_result.prog_idx;
        
        // fprintf(stderr, "[RACE-PAIR] idx=%d use_tid=%d free_tid=%d use_call_idx=%d(prog%d) free_call_idx=%d(prog%d) access_time=[%llu,%llu]\\n",
        //     basic_count, uaf_buffer[basic_count].use_tid, uaf_buffer[basic_count].free_tid,
        //     uaf_buffer[basic_count].use_call_idx, uaf_buffer[basic_count].use_prog_idx,
        //     uaf_buffer[basic_count].free_call_idx, uaf_buffer[basic_count].free_prog_idx,
        //     (unsigned long long)race_pair->first.access_time,
        //     (unsigned long long)race_pair->second.access_time);
    }

    free(race_pairs);

    return basic_count;
}

// Backward-compatible wrapper: uses default threshold (0 = 10ms)
int race_detector_analyze_and_generate_race_infos(RaceDetector* detector,
   may_uaf_pair_t* uaf_buffer, int max_uaf_pairs, SyscallContextTable* syscall_ctx)
{
    return race_detector_analyze_and_generate_race_infos_with_threshold(
        detector, uaf_buffer, max_uaf_pairs, syscall_ctx, 0);
}


int race_detector_generate_extended_race_info(RaceDetector* detector, may_race_pair_t* race_pairs, int race_count,
    extended_race_pair_t* extended_pairs)
{
    if (!detector || !race_pairs || !extended_pairs || race_count <= 0)
        return 0;

    for (int i = 0; i < race_count; i++) {
        extended_race_pair_t* ext_pair = &extended_pairs[i];
        ext_pair->basic_info = race_pairs[i];

        ThreadAccessHistory* thread1_history = race_detector_find_thread_history(detector, race_pairs[i].tid1);
        ThreadAccessHistory* thread2_history = race_detector_find_thread_history(detector, race_pairs[i].tid2);

        if (thread1_history) {
            ext_pair->thread1_history_count = thread1_history->access_count;
            if (ext_pair->thread1_history_count > MAX_ACCESS_HISTORY_RECORDS)
                ext_pair->thread1_history_count = MAX_ACCESS_HISTORY_RECORDS;
            ext_pair->path_distance1 = (double)(thread1_history->access_count - 1);
        } else {
            ext_pair->thread1_history_count = 0;
            ext_pair->path_distance1 = 0.0;
        }

        if (thread2_history) {
            ext_pair->thread2_history_count = thread2_history->access_count;
            if (ext_pair->thread2_history_count > MAX_ACCESS_HISTORY_RECORDS)
                ext_pair->thread2_history_count = MAX_ACCESS_HISTORY_RECORDS;
            ext_pair->path_distance2 = (double)(thread2_history->access_count - 1);
        } else {
            ext_pair->thread2_history_count = 0;
            ext_pair->path_distance2 = 0.0;
        }

        ext_pair->thread1_target_time = race_pairs[i].time_diff;
        ext_pair->thread2_target_time = 0;

        uint32_t record_index = 0;

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

int race_detector_generate_extended_uaf_info(RaceDetector* detector, may_uaf_pair_t* uaf_pairs, int uaf_count,
    extended_uaf_pair_t* extended_uaf_pairs)
{
    if (!detector || !uaf_pairs || !extended_uaf_pairs || uaf_count <= 0)
        return 0;

    for (int i = 0; i < uaf_count; i++) {
        extended_uaf_pair_t* ext_uaf_pair = &extended_uaf_pairs[i];
        ext_uaf_pair->basic_info = uaf_pairs[i];

        ThreadAccessHistory* use_thread_history = race_detector_find_thread_history(detector, uaf_pairs[i].use_tid);
        ThreadAccessHistory* free_thread_history = race_detector_find_thread_history(detector, uaf_pairs[i].free_tid);

        if (use_thread_history) {
            ext_uaf_pair->use_thread_history_count = use_thread_history->access_count;
            if (ext_uaf_pair->use_thread_history_count > MAX_ACCESS_HISTORY_RECORDS)
                ext_uaf_pair->use_thread_history_count = MAX_ACCESS_HISTORY_RECORDS;
            ext_uaf_pair->path_distance_use = (double)(use_thread_history->access_count - 1);
        } else {
            ext_uaf_pair->use_thread_history_count = 0;
            ext_uaf_pair->path_distance_use = 0.0;
        }

        if (free_thread_history) {
            ext_uaf_pair->free_thread_history_count = free_thread_history->access_count;
            if (ext_uaf_pair->free_thread_history_count > MAX_ACCESS_HISTORY_RECORDS)
                ext_uaf_pair->free_thread_history_count = MAX_ACCESS_HISTORY_RECORDS;
            ext_uaf_pair->path_distance_free = (double)(free_thread_history->access_count - 1);
        } else {
            ext_uaf_pair->free_thread_history_count = 0;
            ext_uaf_pair->path_distance_free = 0.0;
        }

        ext_uaf_pair->use_target_time = uaf_pairs[i].time_diff;
        ext_uaf_pair->free_target_time = 0;

        uint32_t uaf_record_index = 0;

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

int race_detector_analyze_and_generate_extended_race_infos(RaceDetector* detector,
    may_race_pair_t* race_signals_buffer, int race_count,
    extended_race_pair_t* extended_buffer, int max_extended)
{
    if (!detector || !race_detector_is_available(detector) || !race_signals_buffer || !extended_buffer || race_count <= 0
        || max_extended <= 0) {
        debug("Invalid parameters for extended race analysis\n");
        return 0;
    }

    debug("Generating extended information for %d existing races...\n", race_count);

    int parsed_count = race_detector_parse_trace_buffer(detector, DDRD_MAX_RECORDS, DDRD_MAX_RECORDS / 4);
    if (parsed_count <= 0) {
        debug("Failed to parse trace buffer for extended race analysis\n");
        return 0;
    }

    debug("Successfully parsed %d access records for extended race analysis\n", parsed_count);

    int extended_count = race_detector_generate_extended_race_info(detector, race_signals_buffer, race_count, extended_buffer);

    debug("Extended race analysis completed: %d extended race pairs generated\n", extended_count);
    return extended_count;
}

int race_detector_analyze_and_generate_extended_uaf_infos(RaceDetector* detector,
    may_uaf_pair_t* uaf_signals_buffer, int uaf_count,
    extended_uaf_pair_t* extended_buffer, int max_extended)
{
    if (!detector || !race_detector_is_available(detector) || !uaf_signals_buffer || !extended_buffer || uaf_count <= 0
        || max_extended <= 0) {
        debug("Invalid parameters for extended UAF analysis\n");
        return 0;
    }

    debug("Generating extended information for %d existing UAF pairs...\n", uaf_count);

    int parsed_count = race_detector_parse_trace_buffer(detector, DDRD_MAX_RECORDS, DDRD_MAX_RECORDS / 4);
    if (parsed_count <= 0) {
        debug("Failed to parse trace buffer for extended UAF analysis\n");
        return 0;
    }

    debug("Successfully parsed %d access records for extended UAF analysis\n", parsed_count);

    int extended_count = race_detector_generate_extended_uaf_info(detector, uaf_signals_buffer, uaf_count, extended_buffer);

    debug("Extended UAF analysis completed: %d extended UAF pairs generated\n", extended_count);
    return extended_count;
}

// ============================================================================
// Syscall Context Tracking Implementation
// ============================================================================

// Global syscall context table
SyscallContextTable g_syscall_context = {0};

// Helper: get current monotonic time in nanoseconds
static uint64_t get_current_time_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }
    return 0;
}

void syscall_context_init(SyscallContextTable* table)
{
    if (!table)
        return;
    memset(table, 0, sizeof(SyscallContextTable));
    table->count = 0;
    table->history_count = 0;
    for (int i = 0; i < MAX_TRACKED_THREADS; i++) {
        table->entries[i].tid = -1;
        table->entries[i].call_index = -1;
        table->entries[i].call_num = -1;
        table->entries[i].start_time = 0;
        table->entries[i].active = false;
    }
}

void syscall_context_enter(SyscallContextTable* table, int tid, int call_index, int call_num)
{
    if (!table || tid < 0)
        return;
    
    uint64_t now = get_current_time_ns();
    // fprintf(stderr, "[TIME-TRACK] syscall_context_enter: tid=%d call_idx=%d start_time=%llu (CLOCK_MONOTONIC ns)\\n",
    //     tid, call_index, (unsigned long long)now);
    
    // Find existing entry or empty slot
    int empty_slot = -1;
    for (int i = 0; i < MAX_TRACKED_THREADS; i++) {
        if (table->entries[i].tid == tid) {
            // Update existing entry
            table->entries[i].call_index = call_index;
            table->entries[i].call_num = call_num;
            table->entries[i].start_time = now;
            table->entries[i].active = true;
            return;
        }
        if (empty_slot < 0 && !table->entries[i].active) {
            empty_slot = i;
        }
    }
    
    // Add new entry
    if (empty_slot >= 0) {
        table->entries[empty_slot].tid = tid;
        table->entries[empty_slot].call_index = call_index;
        table->entries[empty_slot].call_num = call_num;
        table->entries[empty_slot].start_time = now;
        table->entries[empty_slot].active = true;
        table->count++;
    }
}

void syscall_context_exit(SyscallContextTable* table, int tid)
{
    if (!table || tid < 0)
        return;
    
    uint64_t now = get_current_time_ns();
    // fprintf(stderr, "[TIME-TRACK] syscall_context_exit: tid=%d end_time=%llu (CLOCK_MONOTONIC ns)\\n",
    //     tid, (unsigned long long)now);
    
    for (int i = 0; i < MAX_TRACKED_THREADS; i++) {
        if (table->entries[i].tid == tid && table->entries[i].active) {
            // Record to history before clearing
            if (table->history_count < MAX_SYSCALL_HISTORY && 
                table->entries[i].call_index >= 0 &&
                table->entries[i].start_time > 0) {
                SyscallHistoryEntry* hist = &table->history[table->history_count];
                hist->tid = tid;
                hist->call_index = table->entries[i].call_index;
                hist->start_time = table->entries[i].start_time;
                hist->end_time = now;
                table->history_count++;
            }
            
            table->entries[i].call_index = -1;
            table->entries[i].call_num = -1;
            table->entries[i].start_time = 0;
            // Keep tid and active for reuse, just mark call_index as -1
            return;
        }
    }
}

int syscall_context_lookup(SyscallContextTable* table, int tid)
{
    if (!table || tid < 0)
        return -1;
    
    for (int i = 0; i < MAX_TRACKED_THREADS; i++) {
        if (table->entries[i].tid == tid && table->entries[i].active) {
            return table->entries[i].call_index;
        }
    }
    
    return -1; // Not found or kernel background thread
}

SyscallLookupResult syscall_context_lookup_with_time(SyscallContextTable* table, int tid, uint64_t access_time)
{
    SyscallLookupResult result = {-1, -1};
    
    if (!table || access_time == 0) {
        // fprintf(stderr, "[CTX-LOOKUP] SKIP: table=%p access_time=%llu\\n", (void*)table, (unsigned long long)access_time);
        return result;
    }
    
    // fprintf(stderr, "[CTX-LOOKUP] Looking up tid=%d access_time=%llu in table with %d history entries\\n",
    //     tid, (unsigned long long)access_time, table->history_count);
    
    // Search history for matching time range (ignore tid, use time only)
    // Select the best match based on how close access_time is to the center of [start, end]
    uint64_t best_match_diff = UINT64_MAX;
    
    for (int i = 0; i < table->history_count; i++) {
        SyscallHistoryEntry* hist = &table->history[i];
        
        // Check if access_time falls within [start_time, end_time]
        if (access_time >= hist->start_time && access_time <= hist->end_time) {
            // Calculate how close to the center of the time range
            uint64_t mid_time = (hist->start_time + hist->end_time) / 2;
            uint64_t diff = (access_time > mid_time) ? (access_time - mid_time) : (mid_time - access_time);
            if (diff < best_match_diff) {
                best_match_diff = diff;
                result.call_idx = hist->call_index;
                result.prog_idx = hist->prog_idx;
            }
        }
    }
    
    if (result.call_idx >= 0) {
        // fprintf(stderr, "[M3-LOOKUP] Found call_idx=%d prog_idx=%d for tid=%d at time=%llu (best match from %d entries)\\n",
        //     result.call_idx, result.prog_idx, tid, (unsigned long long)access_time, table->history_count);
    } else {
        // fprintf(stderr, "[M3-LOOKUP] NOT FOUND: tid=%d access_time=%llu did not match any of %d history entries\\n",
        //     tid, (unsigned long long)access_time, table->history_count);
        // // Print history entries for debugging
        // for (int dbg = 0; dbg < table->history_count && dbg < 4; dbg++) {
        //     fprintf(stderr, "[M3-LOOKUP]   history[%d]: tid=%d call_idx=%d prog_idx=%d time=[%llu-%llu]\\n",
        //         dbg, table->history[dbg].tid, table->history[dbg].call_index, table->history[dbg].prog_idx,
        //         (unsigned long long)table->history[dbg].start_time,
        //         (unsigned long long)table->history[dbg].end_time);
        // }
    }
    
    return result;
}
