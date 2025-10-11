#ifndef RACE_DETECTOR_H
#define RACE_DETECTOR_H

#include "types.h"
#include "./ddrd.h"

#include <sys/types.h>  // for ssize_t
#include <stddef.h>     // for size_t

#ifdef __cplusplus
extern "C" {
#endif

struct PairSyscallSharedData;

// RaceDetector 类式结构
typedef struct {
	AccessContext context;
	bool enabled;
	int trace_fd;
} RaceDetector;

// RaceDetector 核心方法
void race_detector_init(RaceDetector* detector);
void race_detector_cleanup(RaceDetector* detector);
void race_detector_reset(RaceDetector* detector);
bool race_detector_is_available(RaceDetector* detector);

typedef struct {
    int call_index;             // syscall在程序中的索引
    int call_num;               // syscall编号
    uint64_t start_time;        // syscall开始时间 (nanoseconds)
    uint64_t end_time;          // syscall结束时间 (nanoseconds)
    int thread_id;              // 执行的线程ID
    bool valid;                 // 记录是否有效
} SyscallTimeRecord;

// 数据读取和解析
ssize_t race_detector_read_trace_buffer(RaceDetector* detector, char* buffer, size_t buffer_size);
int race_detector_parse_trace_buffer(RaceDetector* detector, int max_records, int max_frees);

// 分析方法
int race_detector_analyze_race_pairs(RaceDetector* detector, RacePair* pairs, int max_pairs);
int race_detector_analyze_uaf_pairs(RaceDetector* detector, UAFPair* pairs, int max_pairs);

// 高级分析方法（如果相应类型已定义）

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

// 扩展信息生成方法
int race_detector_generate_extended_race_info(RaceDetector* detector, may_race_pair_t* race_pairs, int race_count,
                                             extended_race_pair_t* extended_pairs);
int race_detector_generate_extended_uaf_info(RaceDetector* detector, may_uaf_pair_t* uaf_pairs, int uaf_count,
                                            extended_uaf_pair_t* extended_uaf_pairs);


// 线程历史管理方法
ThreadAccessHistory* race_detector_find_thread_history(RaceDetector* detector, int tid);
ThreadAccessHistory* race_detector_create_thread_history(RaceDetector* detector, int tid);
void race_detector_add_access_to_history(RaceDetector* detector, int tid, const AccessRecord* access);

// 历史记录功能控制
void race_detector_enable_history(RaceDetector* detector);
void race_detector_disable_history(RaceDetector* detector);
bool race_detector_is_history_enabled(RaceDetector* detector);

// 辅助计算方法
int race_detector_calculate_path_distance(const AccessRecord* target, const AccessRecord* current);
double race_detector_calculate_delay_probability(int distance);

SyscallTimeRecord* find_matching_syscall(uint64_t access_time, int tid);

#ifdef __cplusplus
}
#endif

#endif // RACE_DETECTOR_H