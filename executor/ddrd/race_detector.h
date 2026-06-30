#pragma once

#include "../kccwf_trace.h"
#include "ddrd.h"
#include "types.h"

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	AccessContext context;
	bool enabled;
	int trace_fd;
	char* trace_buffer;
	size_t trace_buffer_size;
	kccwf_trace_record_t* binary_records;
	size_t binary_record_capacity;
	AccessRecord* binary_access_records;
	size_t binary_access_capacity;
	bool binary_trace_supported;
	bool binary_trace_unsupported;
} RaceDetector;

typedef struct {
	int call_index;
	int call_num;
	uint64_t start_time;
	uint64_t end_time;
	int thread_id;
	bool valid;
} SyscallTimeRecord;

// ============================================================================
// Syscall Context Tracking for Race Pair Attribution
// ============================================================================

#define MAX_TRACKED_THREADS 64
#define MAX_SYSCALL_HISTORY 128  // Max syscalls to track per execution

typedef struct {
	int tid;
	int call_index;      // Current syscall index being executed (-1 if none)
	int call_num;        // Current syscall number
	uint64_t start_time; // Syscall start time (nanoseconds)
	bool active;         // Whether this slot is in use
} SyscallContextEntry;

// Record of a completed syscall for time-based lookup
typedef struct {
	int tid;
	int call_index;
	int prog_idx;        // Which program/executor this belongs to (0 or 1 in barrier mode)
	uint64_t start_time;
	uint64_t end_time;
} SyscallHistoryEntry;

typedef struct {
	SyscallContextEntry entries[MAX_TRACKED_THREADS];
	int count;
	// History of completed syscalls for time-based lookup
	SyscallHistoryEntry history[MAX_SYSCALL_HISTORY];
	int history_count;
} SyscallContextTable;

// Result of syscall context lookup (call_idx + prog_idx)
typedef struct {
    int call_idx;   // Matched syscall index (-1 if not found)
    int prog_idx;   // Which program (0 or 1) this belongs to (-1 if not found)
} SyscallLookupResult;

// Initialize the syscall context table
void syscall_context_init(SyscallContextTable* table);

// Called when a syscall starts executing
void syscall_context_enter(SyscallContextTable* table, int tid, int call_index, int call_num);

// Called when a syscall finishes executing
void syscall_context_exit(SyscallContextTable* table, int tid);

// Lookup current call_index for a given tid (-1 if not found or kernel bg)
int syscall_context_lookup(SyscallContextTable* table, int tid);

// Lookup with time fallback: if tid not found, use access_time to match against history
// Returns (call_idx, prog_idx) pair
SyscallLookupResult syscall_context_lookup_with_time(SyscallContextTable* table, int tid, uint64_t access_time);

// Global syscall context table (managed by executor)
extern SyscallContextTable g_syscall_context;

void race_detector_init(RaceDetector* detector);
void race_detector_cleanup(RaceDetector* detector);
void race_detector_reset(RaceDetector* detector);
bool race_detector_is_available(RaceDetector* detector);
bool race_detector_binary_trace_supported(RaceDetector* detector);

ssize_t race_detector_read_trace_buffer(RaceDetector* detector, char* buffer, size_t buffer_size);
// 持续读取 trace buffer 直到日志稳定（没有新内容出现）
ssize_t race_detector_read_trace_buffer_until_stable(RaceDetector* detector, 
    char* buffer, size_t buffer_size,
    int poll_interval_ms, int max_stable_checks, int max_wait_ms);
int race_detector_parse_trace_buffer(RaceDetector* detector, int max_records, int max_frees);
// 使用稳定读取模式解析 trace buffer
int race_detector_parse_trace_buffer_stable(RaceDetector* detector, int max_records, int max_frees);

int race_detector_analyze_race_pairs(RaceDetector* detector, RacePair* pairs, int max_pairs);
int race_detector_analyze_uaf_pairs(RaceDetector* detector, UAFPair* pairs, int max_pairs);

int race_detector_analyze_and_generate_uaf_pairs_with_extend_infos(RaceDetector* detector,
								   may_uaf_pair_t* uaf_buffer, int max_uaf_pairs,
								   extended_uaf_pair_t* extended_pairs, int max_extended_pairs);
int race_detector_analyze_and_generate_uaf_infos(RaceDetector* detector,
						 may_uaf_pair_t* uaf_buffer, int max_uaf_pairs);
int race_detector_analyze_and_generate_race_infos(RaceDetector* detector,
						 may_uaf_pair_t* uaf_buffer, int max_uaf_pairs,
						 SyscallContextTable* syscall_ctx);
// With configurable threshold (in microseconds). If threshold_us=0, uses default 10ms.
int race_detector_analyze_and_generate_race_infos_with_threshold(RaceDetector* detector,
						 may_uaf_pair_t* uaf_buffer, int max_uaf_pairs,
						 SyscallContextTable* syscall_ctx, uint64_t threshold_us);
int race_detector_analyze_and_generate_extended_race_infos(RaceDetector* detector,
							   may_race_pair_t* race_signals_buffer, int race_count,
							   extended_race_pair_t* extended_buffer, int max_extended);
int race_detector_analyze_and_generate_extended_uaf_infos(RaceDetector* detector,
							  may_uaf_pair_t* uaf_signals_buffer, int uaf_count,
							  extended_uaf_pair_t* extended_buffer, int max_extended);

int race_detector_generate_extended_race_info(RaceDetector* detector, may_race_pair_t* race_pairs, int race_count,
					      extended_race_pair_t* extended_pairs);
int race_detector_generate_extended_uaf_info(RaceDetector* detector, may_uaf_pair_t* uaf_pairs, int uaf_count,
					     extended_uaf_pair_t* extended_uaf_pairs);

ThreadAccessHistory* race_detector_find_thread_history(RaceDetector* detector, int tid);
ThreadAccessHistory* race_detector_create_thread_history(RaceDetector* detector, int tid);
void race_detector_add_access_to_history(RaceDetector* detector, int tid, const AccessRecord* access);

void race_detector_enable_history(RaceDetector* detector);
void race_detector_disable_history(RaceDetector* detector);
bool race_detector_is_history_enabled(RaceDetector* detector);

int race_detector_calculate_path_distance(const AccessRecord* target, const AccessRecord* current);
double race_detector_calculate_delay_probability(int distance);

#ifdef __cplusplus
}
#endif
