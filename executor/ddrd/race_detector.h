#pragma once

#include "types.h"
#include "ddrd.h"

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    AccessContext context;
    bool enabled;
    int trace_fd;
} RaceDetector;

typedef struct {
    int call_index;
    int call_num;
    uint64_t start_time;
    uint64_t end_time;
    int thread_id;
    bool valid;
} SyscallTimeRecord;

void race_detector_init(RaceDetector* detector);
void race_detector_cleanup(RaceDetector* detector);
void race_detector_reset(RaceDetector* detector);
bool race_detector_is_available(RaceDetector* detector);

ssize_t race_detector_read_trace_buffer(RaceDetector* detector, char* buffer, size_t buffer_size);
int race_detector_parse_trace_buffer(RaceDetector* detector, int max_records, int max_frees);

int race_detector_analyze_race_pairs(RaceDetector* detector, RacePair* pairs, int max_pairs);
int race_detector_analyze_uaf_pairs(RaceDetector* detector, UAFPair* pairs, int max_pairs);

int race_detector_analyze_and_generate_uaf_pairs_with_extend_infos(RaceDetector* detector,
    may_uaf_pair_t* uaf_buffer, int max_uaf_pairs,
    extended_uaf_pair_t* extended_pairs, int max_extended_pairs);
int race_detector_analyze_and_generate_uaf_infos(RaceDetector* detector,
    may_uaf_pair_t* uaf_buffer, int max_uaf_pairs);
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
