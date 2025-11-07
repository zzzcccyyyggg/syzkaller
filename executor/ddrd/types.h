#ifndef RACE_TYPES_H
#define RACE_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_LOCK_NAME 64

// 锁记录结构
typedef struct {
    char name[64];              // 锁名称
    uint64_t ptr;               // 锁指针
    int attr;                   // 锁属性
    bool valid;                 // 记录是否有效
} LockRecord;
LockRecord parse_lock_line(const char* line);

typedef struct {
    int tid;                    // 线程ID
    uint64_t var_name;          // 变量名哈希
    uint64_t address;           // 内存地址
    char access_type;           // 访问类型：'R'=读, 'W'=写, 'F'=释放
    uint64_t size;              // 访问大小
    uint64_t call_stack_hash;   // 调用栈哈希
    uint64_t access_time;       // 访问时间 (nanoseconds since boot)
    int sn;                     // 序列号
    LockRecord held_locks[8];   // 持有的锁（最多8个）
    int lock_count;             // 持有锁的数量
    bool valid;                 // 记录是否有效
} AccessRecord;

AccessRecord access_record_init_from_line(const char* line);
bool access_record_addresses_overlap(const AccessRecord* a, const AccessRecord* b);

#define SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM 0x2000
typedef struct {
    int tid;                           // 线程ID
    AccessRecord accesses[SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM]; // 历史访问记录
    int access_count;                  // 访问记录数量
    int access_index;                  // 当前写入位置（环形缓冲区）
    bool buffer_full;                  // 缓冲区是否已满
} ThreadAccessHistory;

void add_access_to_history(ThreadAccessHistory* history, const AccessRecord* access);


#define MAX_THREADS 32
typedef struct {
    AccessRecord* records;      // 访问记录数组
    int record_count;           // 访问记录数量
    AccessRecord* free_records;   // Free操作记录数组
    int free_count;             // Free操作数量
    ThreadAccessHistory* thread_histories; // 线程访问历史（动态分配）
    int thread_count;           // 活跃线程数量
    int max_threads;            // 最大线程数量
    bool enable_history;        // 是否启用线程访问历史记录功能
} AccessContext;
int access_context_init_from_buffer(AccessContext* record_ctx, const char* buffer, int max_records, int max_frees);
ThreadAccessHistory* access_context_find_thread(AccessContext* ctx, int tid);
ThreadAccessHistory* access_context_create_thread_history(AccessContext* record_ctx, int tid);
bool access_context_check_data_race_validity(AccessContext* record_ctx, const AccessRecord* a, const AccessRecord* b);
bool access_context_check_uaf_validity(AccessContext* record_ctx, const AccessRecord* use_access, const AccessRecord* free_op);

typedef enum {
    LOCK_NO_LOCKS = 0,              // 双方都无锁
    LOCK_ONE_SIDED_LOCK = 1,        // 一方有锁，一方无锁
    LOCK_UNSYNC_LOCKS = 2,          // 双方有锁，但无公共锁
    LOCK_SYNC_WITH_COMMON_LOCK = 3  // 双方有锁，且有公共锁
} LockStatus;
LockStatus determine_lock_status(const AccessRecord* a, const AccessRecord* b);

typedef struct {
    AccessRecord first;         // 第一个访问
    AccessRecord second;        // 第二个访问
    uint64_t access_time_diff;  // 访问时间差 (nanoseconds)
    int trigger_counts;         // 触发次数
    LockStatus lock_status;     // 锁状态
    
    // 历史访问信息用于延时调度
    ThreadAccessHistory* thread1_history; // 第一个线程的访问历史
    ThreadAccessHistory* thread2_history; // 第二个线程的访问历史
    int first_access_index;     // 第一个访问在历史中的索引
    int second_access_index;    // 第二个访问在历史中的索引
} RacePair;
int access_context_analyze_race_pairs(AccessContext* record_ctx, RacePair* pairs, int max_pairs);

typedef struct {
    AccessRecord use_access;     // Use操作（读/写访问）
    AccessRecord free_access;   // Free操作  
    uint64_t time_diff;          // 时间差
    LockStatus lock_status;      // 锁状态
    int trigger_count;           // 触发次数
    
    // 历史访问信息用于延时调度
    ThreadAccessHistory* use_thread_history;  // Use线程的访问历史
    ThreadAccessHistory* free_thread_history; // Free线程的访问历史
    int use_access_index;        // Use访问在历史中的索引
    int free_access_index;       // Free访问在历史中的索引
} UAFPair;
int access_context_analyze_uaf_pairs(AccessContext* record_ctx, UAFPair* uaf_pairs, int max_pairs);

#endif
