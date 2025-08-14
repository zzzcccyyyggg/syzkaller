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
#define MAX_UAF_PAIRS 200

// 测试数据：包含UAF场景的复杂数据
const char* test_data_with_uaf = 
// 正常的访问 -> free -> 随后的use (应该检测为UAF)
"[KCCWF] log access: tid=100, var_name=1111111111111111111, var_addr=0000000010000000, type=1, size=8, call_stack_hash=2222222222222222222, access_time=1000000000, sn=1\n"
"[KCCWF] log access: tid=101, var_name=1111111111111111111, var_addr=0000000010000000, type=2, size=8, call_stack_hash=3333333333333333333, access_time=1000000100, sn=1\n"
"[KCCWF] log access: tid=102, var_name=1111111111111111111, var_addr=0000000010000000, type=0, size=8, call_stack_hash=4444444444444444444, access_time=1000000200, sn=1\n"

// 第二个UAF场景：malloc -> free -> read
"[KCCWF] log access: tid=200, var_name=7777777777777777777, var_addr=0000000020000000, type=1, size=4, call_stack_hash=8888888888888888888, access_time=1000001000, sn=1\n"
"[KCCWF] log access: tid=201, var_name=7777777777777777777, var_addr=0000000020000000, type=2, size=4, call_stack_hash=9999999999999999999, access_time=1000001100, sn=1\n"
"[KCCWF] log access: tid=202, var_name=7777777777777777777, var_addr=0000000020000000, type=0, size=4, call_stack_hash=1010101010101010101, access_time=1000001200, sn=1\n"

// 非UAF场景：use在free之前（应该不被检测）
"[KCCWF] log access: tid=300, var_name=3333333333333333333, var_addr=0000000030000000, type=0, size=8, call_stack_hash=1212121212121212121, access_time=1000002000, sn=1\n"
"[KCCWF] log access: tid=301, var_name=3333333333333333333, var_addr=0000000030000000, type=2, size=8, call_stack_hash=1313131313131313131, access_time=1000002100, sn=1\n"

// 时间差过大的UAF（应该被过滤）
"[KCCWF] log access: tid=400, var_name=5555555555555555555, var_addr=0000000040000000, type=2, size=4, call_stack_hash=1414141414141414141, access_time=1000003000, sn=1\n"
"[KCCWF] log access: tid=401, var_name=5555555555555555555, var_addr=0000000040000000, type=1, size=4, call_stack_hash=1515151515151515151, access_time=1000020000, sn=1\n"

// 中间有其他free的UAF（应该被过滤）
"[KCCWF] log access: tid=500, var_name=6666666666666666666, var_addr=0000000050000000, type=2, size=8, call_stack_hash=1616161616161616161, access_time=1000004000, sn=1\n"
"[KCCWF] log access: tid=501, var_name=6666666666666666666, var_addr=0000000050000000, type=2, size=8, call_stack_hash=1717171717171717171, access_time=1000004500, sn=1\n"
"[KCCWF] log access: tid=502, var_name=6666666666666666666, var_addr=0000000050000000, type=0, size=8, call_stack_hash=1818181818181818181, access_time=1000005000, sn=1\n";

// UAF检测测试函数
void test_uaf_detection() {
    printf("=== UAF Detection Test ===\n");
    
    // 分配内存
    AccessRecord* records = malloc(sizeof(AccessRecord) * MAX_RECORDS);
    FreeRecord* free_records = malloc(sizeof(FreeRecord) * MAX_FREES);
    UAFPair* uaf_pairs = malloc(sizeof(UAFPair) * MAX_UAF_PAIRS);
    
    if (!records || !free_records || !uaf_pairs) {
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
    int record_count = parse_access_records_to_set(test_data_with_uaf, &record_set, MAX_RECORDS, MAX_FREES);
    
    printf("Parsed %d access records and %d free records\n", record_set.record_count, record_set.free_count);
    
    // 显示解析的记录
    printf("\n--- Access Records ---\n");
    for (int i = 0; i < record_set.record_count; i++) {
        AccessRecord* rec = &record_set.records[i];
        printf("  Record %d: TID=%d, Type=%c, Addr=0x%lx, Size=%lu, Time=%lu\n",
               i, rec->tid, rec->access_type, (unsigned long)rec->address, 
               (unsigned long)rec->size, (unsigned long)rec->access_time);
    }
    
    printf("\n--- Free Records ---\n");
    for (int i = 0; i < record_set.free_count; i++) {
        FreeRecord* free_rec = &record_set.free_records[i];
        printf("  Free %d: TID=%d, Addr=0x%lx, Size=%lu, Time=%lu\n",
               i, free_rec->tid, (unsigned long)free_rec->address, 
               (unsigned long)free_rec->size, (unsigned long)free_rec->access_time);
    }
    
    // 进行UAF检测
    UAFStatistics stats;
    int uaf_count = analyze_uaf_pairs_from_set(&record_set, uaf_pairs, MAX_UAF_PAIRS, &stats);
    
    printf("\n--- UAF Detection Results ---\n");
    printf("Found %d UAF pairs\n", uaf_count);
    
    // 打印统计信息
    print_uaf_statistics(&stats);
    
    // 显示所有检测到的UAF
    printf("--- Detected UAF Pairs ---\n");
    for (int i = 0; i < uaf_count; i++) {
        UAFPair* uaf = &uaf_pairs[i];
        printf("UAF Pair %d:\n", i + 1);
        printf("  Free: TID=%d, Addr=0x%lx, Size=%lu, Time=%lu\n",
               uaf->free_operation.tid, (unsigned long)uaf->free_operation.address,
               (unsigned long)uaf->free_operation.size, (unsigned long)uaf->free_operation.access_time);
        printf("  Use:  TID=%d, Type=%c, Addr=0x%lx, Size=%lu, Time=%lu\n",
               uaf->use_access.tid, uaf->use_access.access_type, (unsigned long)uaf->use_access.address,
               (unsigned long)uaf->use_access.size, (unsigned long)uaf->use_access.access_time);
        printf("  Time Diff: %lu us, Lock Status: %d\n", 
               (unsigned long)uaf->time_diff, uaf->lock_status);
        printf("\n");
    }
    
    // 预期结果验证
    printf("--- Expected Results Validation ---\n");
    printf("Expected to find 3 UAF pairs:\n");
    printf("1. TID 102 uses memory freed by TID 101 (addr 0x10000000)\n");
    printf("2. TID 202 uses memory freed by TID 201 (addr 0x20000000)\n");
    printf("3. TID 502 uses memory freed by TID 501 (addr 0x50000000) - closest free\n");
    printf("\nShould NOT find:\n");
    printf("- TID 300 access (happens before free)\n");
    printf("- TID 401 access (time diff too large)\n");
    printf("- TID 502 with TID 500 (TID 501 is closer in time)\n");
    
    if (uaf_count == 3) {
        printf("✅ UAF detection count matches expected results\n");
    } else {
        printf("⚠️  UAF detection count: %d (expected: 3)\n", uaf_count);
    }
    
    // 清理内存
    free(records);
    free(free_records);
    free(uaf_pairs);
}

// 性能测试函数
void test_uaf_performance() {
    printf("\n=== UAF Performance Test ===\n");
    
    // 创建大量测试数据
    const int PERF_RECORDS = 1000;
    const int PERF_FREES = 100;
    const int PERF_UAF_PAIRS = 500;
    
    AccessRecord* records = malloc(sizeof(AccessRecord) * PERF_RECORDS);
    FreeRecord* free_records = malloc(sizeof(FreeRecord) * PERF_FREES);
    UAFPair* uaf_pairs = malloc(sizeof(UAFPair) * PERF_UAF_PAIRS);
    
    if (!records || !free_records || !uaf_pairs) {
        printf("❌ Memory allocation failed\n");
        return;
    }
    
    // 生成模拟数据
    AccessRecordSet record_set = {
        .records = records,
        .record_count = PERF_RECORDS / 2,  // 模拟一半是访问记录
        .free_records = free_records,
        .free_count = PERF_FREES
    };
    
    // 简单填充一些模拟数据
    for (int i = 0; i < record_set.record_count; i++) {
        records[i].tid = 100 + (i % 10);
        records[i].access_type = (i % 3 == 0) ? 'W' : 'R';
        records[i].address = 0x10000000 + (i * 0x1000);
        records[i].size = 8;
        records[i].access_time = 1000000000 + (i * 1000);
        records[i].valid = true;
        records[i].lock_count = 0;
    }
    
    for (int i = 0; i < record_set.free_count; i++) {
        free_records[i].tid = 200 + (i % 5);
        free_records[i].address = 0x10000000 + (i * 0x2000);
        free_records[i].size = 8;
        free_records[i].access_time = 1000000000 + (i * 500);
    }
    
    // 测量性能
    clock_t start = clock();
    UAFStatistics stats;
    int uaf_count = analyze_uaf_pairs_from_set(&record_set, uaf_pairs, PERF_UAF_PAIRS, &stats);
    clock_t end = clock();
    
    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("Performance test completed:\n");
    printf("- Processed %d access records and %d free records\n", record_set.record_count, record_set.free_count);
    printf("- Found %d UAF pairs\n", uaf_count);
    printf("- Time taken: %.6f seconds\n", time_taken);
    printf("- Throughput: %.0f operations/second\n", 
           (record_set.record_count * record_set.free_count) / time_taken);
    
    free(records);
    free(free_records);
    free(uaf_pairs);
}

int main() {
    printf("🔍 Testing DDRD UAF Detection\n\n");
    
    test_uaf_detection();
    test_uaf_performance();
    
    printf("\n🎉 UAF detection test completed!\n");
    return 0;
}
