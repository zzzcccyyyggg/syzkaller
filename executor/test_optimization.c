#include "race_detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>

// 简单的debug函数实现
void debug(const char* msg, ...) {
    va_list args;
    va_start(args, msg);
    printf("[DEBUG] ");
    vprintf(msg, args);
    va_end(args);
}

#define MAX_RECORDS 1000
#define MAX_FREES 100
#define MAX_PAIRS 200

// 测试数据：包含多个free操作的复杂场景
const char* test_data_with_frees = 
"[KCCWF] log access: tid=100, var_name=1111111111111111111, var_addr=0000000010000000, type=1, size=8, call_stack_hash=2222222222222222222, access_time=1000000000, sn=1\n"
"[KCCWF] log access: tid=101, var_name=1111111111111111111, var_addr=0000000010000000, type=0, size=8, call_stack_hash=3333333333333333333, access_time=1000000050, sn=1\n"
"[KCCWF] log access: tid=102, var_name=1111111111111111111, var_addr=0000000010000000, type=2, size=8, call_stack_hash=4444444444444444444, access_time=1000000100, sn=1\n"
"[KCCWF] log access: tid=103, var_name=1111111111111111111, var_addr=0000000010000000, type=0, size=8, call_stack_hash=5555555555555555555, access_time=1000000200, sn=1\n"
"[KCCWF] log access: tid=100, var_name=7777777777777777777, var_addr=0000000020000000, type=1, size=4, call_stack_hash=8888888888888888888, access_time=1000001000, sn=1\n"
"[KCCWF] log access: tid=101, var_name=7777777777777777777, var_addr=0000000020000000, type=0, size=4, call_stack_hash=9999999999999999999, access_time=1000001050, sn=1\n"
"[KCCWF] log access: tid=102, var_name=9999999999999999999, var_addr=0000000030000000, type=2, size=4, call_stack_hash=1010101010101010101, access_time=1000002000, sn=1\n"
"[KCCWF] log access: tid=103, var_name=9999999999999999999, var_addr=0000000030000000, type=1, size=4, call_stack_hash=1111111111111111111, access_time=1000002100, sn=1\n";

// 性能测试函数
void performance_test() {
    printf("=== Performance Comparison Test ===\n");
    
    // 分配内存
    AccessRecord* records = malloc(sizeof(AccessRecord) * MAX_RECORDS);
    AccessRecord* records_opt = malloc(sizeof(AccessRecord) * MAX_RECORDS);
    FreeRecord* free_records = malloc(sizeof(FreeRecord) * MAX_FREES);
    RacePair* pairs_old = malloc(sizeof(RacePair) * MAX_PAIRS);
    RacePair* pairs_new = malloc(sizeof(RacePair) * MAX_PAIRS);
    
    if (!records || !records_opt || !free_records || !pairs_old || !pairs_new) {
        printf("❌ Memory allocation failed\n");
        return;
    }
    
    // 解析数据 - 旧版本
    clock_t start = clock();
    int record_count_old = parse_access_records_from_buffer(test_data_with_frees, records, MAX_RECORDS);
    int pairs_old_count = analyze_race_pairs_from_records(records, record_count_old, pairs_old, MAX_PAIRS);
    clock_t end_old = clock();
    double time_old = ((double)(end_old - start)) / CLOCKS_PER_SEC;
    
    // 解析数据 - 新版本（优化）
    AccessRecordSet record_set = {
        .records = records_opt,
        .record_count = 0,
        .free_records = free_records,
        .free_count = 0
    };
    
    start = clock();
    int record_count_new = parse_access_records_to_set(test_data_with_frees, &record_set, MAX_RECORDS, MAX_FREES);
    int pairs_new_count = analyze_race_pairs_from_set(&record_set, pairs_new, MAX_PAIRS);
    clock_t end_new = clock();
    double time_new = ((double)(end_new - start)) / CLOCKS_PER_SEC;
    
    // 输出结果
    printf("Original method:\n");
    printf("  - Parsed %d access records\n", record_count_old);
    printf("  - Found %d race pairs\n", pairs_old_count);
    printf("  - Time: %.6f seconds\n", time_old);
    
    printf("Optimized method:\n");
    printf("  - Parsed %d access records, %d free records\n", record_set.record_count, record_set.free_count);
    printf("  - Found %d race pairs\n", pairs_new_count);
    printf("  - Time: %.6f seconds\n", time_new);
    
    if (time_old > 0) {
        printf("Speed improvement: %.2fx\n", time_old / time_new);
    }
    
    // 验证结果一致性
    bool results_match = true;
    if (pairs_old_count != pairs_new_count) {
        printf("⚠️  Race pair counts differ: %d vs %d\n", pairs_old_count, pairs_new_count);
        results_match = false;
    }
    
    if (results_match) {
        printf("✅ Results are consistent between methods\n");
    } else {
        printf("❌ Results differ between methods\n");
    }
    
    // 清理内存
    free(records);
    free(records_opt);
    free(free_records);
    free(pairs_old);
    free(pairs_new);
}

// 正确性测试函数
void correctness_test() {
    printf("=== Correctness Test ===\n");
    
    // 分配内存
    AccessRecord* records = malloc(sizeof(AccessRecord) * MAX_RECORDS);
    FreeRecord* free_records = malloc(sizeof(FreeRecord) * MAX_FREES);
    
    if (!records || !free_records) {
        printf("❌ Memory allocation failed\n");
        return;
    }
    
    AccessRecordSet record_set = {
        .records = records,
        .record_count = 0,
        .free_records = free_records,
        .free_count = 0
    };
    
    // 解析测试数据
    int record_count = parse_access_records_to_set(test_data_with_frees, &record_set, MAX_RECORDS, MAX_FREES);
    
    printf("Parsed %d access records and %d free records\n", record_set.record_count, record_set.free_count);
    
    // 显示分离的记录
    printf("\n--- Access Records (non-free) ---\n");
    for (int i = 0; i < record_set.record_count; i++) {
        AccessRecord* rec = &record_set.records[i];
        printf("  Record %d: TID=%d, Type=%c, Addr=0x%lx, Size=%lu, Time=%lu\n",
               i, rec->tid, rec->access_type, (unsigned long)rec->address, (unsigned long)rec->size, (unsigned long)rec->access_time);
    }
    
    printf("\n--- Free Records ---\n");
    for (int i = 0; i < record_set.free_count; i++) {
        FreeRecord* free_rec = &record_set.free_records[i];
        printf("  Free %d: TID=%d, Addr=0x%lx, Size=%lu, Time=%lu\n",
               i, free_rec->tid, (unsigned long)free_rec->address, (unsigned long)free_rec->size, (unsigned long)free_rec->access_time);
    }
    
    // 测试有效区间检查
    printf("\n--- Testing Valid Interval Check ---\n");
    if (record_set.record_count >= 2) {
        AccessRecord* a = &record_set.records[0];
        AccessRecord* b = &record_set.records[1];
        
        bool valid = in_same_valid_interval_optimized(a, b, record_set.free_records, record_set.free_count);
        printf("Valid interval check for records 0 and 1: %s\n", valid ? "true" : "false");
        
        // 如果有free记录，测试被free分隔的情况
        if (record_set.free_count > 0 && record_set.record_count >= 4) {
            AccessRecord* c = &record_set.records[2]; // 这应该是在free之后的访问
            AccessRecord* d = &record_set.records[3];
            
            bool valid2 = in_same_valid_interval_optimized(a, c, record_set.free_records, record_set.free_count);
            printf("Valid interval check across free (records 0 and 2): %s\n", valid2 ? "true" : "false");
        }
    }
    
    // 清理内存
    free(records);
    free(free_records);
}

int main() {
    printf("🚀 Testing DDRD Race Detector Optimization\n\n");
    
    correctness_test();
    printf("\n");
    performance_test();
    
    printf("\n🎉 Optimization test completed!\n");
    return 0;
}
