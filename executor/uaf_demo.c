#include "race_detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

// 简单的debug函数实现
void debug(const char* msg, ...) {
    // 在实际使用中可以关闭debug输出
    // va_list args;
    // va_start(args, msg);
    // printf("[DEBUG] ");
    // vprintf(msg, args);
    // va_end(args);
}

/**
 * 示例：使用DDRD UAF检测接口分析内存访问记录
 */
void demonstrate_uaf_detection_api() {
    printf("=== DDRD UAF Detection API Demo ===\n\n");
    
    // 示例日志数据：模拟内核trace输出
    const char* kernel_trace_data = 
        "[KCCWF] log access: tid=1001, var_name=123456789, var_addr=0000000020000000, type=1, size=8, call_stack_hash=987654321, access_time=1000100000, sn=1\n"
        "[KCCWF] log access: tid=1002, var_name=123456789, var_addr=0000000020000000, type=2, size=8, call_stack_hash=111111111, access_time=1000100200, sn=1\n"
        "[KCCWF] log access: tid=1003, var_name=123456789, var_addr=0000000020000000, type=0, size=8, call_stack_hash=222222222, access_time=1000100500, sn=1\n"
        "[KCCWF] log access: tid=1004, var_name=555555555, var_addr=0000000030000000, type=1, size=4, call_stack_hash=333333333, access_time=1000200000, sn=1\n"
        "[KCCWF] log access: tid=1005, var_name=555555555, var_addr=0000000030000000, type=2, size=4, call_stack_hash=444444444, access_time=1000200100, sn=1\n"
        "[KCCWF] log access: tid=1006, var_name=555555555, var_addr=0000000030000000, type=0, size=4, call_stack_hash=555555555, access_time=1000200300, sn=1\n";
    
    // 步骤1：分配内存和数据结构
    const int MAX_RECORDS = 100;
    const int MAX_FREES = 50;
    const int MAX_UAF_PAIRS = 50;
    
    AccessRecord* records = malloc(sizeof(AccessRecord) * MAX_RECORDS);
    FreeRecord* free_records = malloc(sizeof(FreeRecord) * MAX_FREES);
    UAFPair* uaf_pairs = malloc(sizeof(UAFPair) * MAX_UAF_PAIRS);
    
    if (!records || !free_records || !uaf_pairs) {
        printf("❌ 内存分配失败\n");
        return;
    }
    
    // 步骤2：创建记录集合
    AccessRecordSet record_set = {
        .records = records,
        .record_count = 0,
        .free_records = free_records,
        .free_count = 0
    };
    
    // 步骤3：解析内核trace数据
    printf("1. 解析内核trace数据...\n");
    int record_count = parse_access_records_to_set(kernel_trace_data, &record_set, MAX_RECORDS, MAX_FREES);
    printf("   解析完成：%d 个访问记录，%d 个free记录\n\n", record_set.record_count, record_set.free_count);
    
    // 步骤4：执行UAF检测
    printf("2. 执行UAF检测...\n");
    UAFStatistics stats;
    int uaf_count = analyze_uaf_pairs_from_set(&record_set, uaf_pairs, MAX_UAF_PAIRS, &stats);
    printf("   检测完成：发现 %d 个UAF\n\n", uaf_count);
    
    // 步骤5：显示统计结果
    printf("3. UAF检测统计：\n");
    print_uaf_statistics(&stats);
    
    // 步骤6：分析检测到的UAF
    printf("4. UAF详细分析：\n");
    for (int i = 0; i < uaf_count; i++) {
        UAFPair* uaf = &uaf_pairs[i];
        printf("   UAF #%d:\n", i + 1);
        printf("   ├─ Free操作: TID %d 在时间 %lu 释放地址 0x%lx (size %lu)\n",
               uaf->free_operation.tid, (unsigned long)uaf->free_operation.access_time,
               (unsigned long)uaf->free_operation.address, (unsigned long)uaf->free_operation.size);
        printf("   ├─ Use操作:  TID %d 在时间 %lu %s地址 0x%lx (size %lu)\n",
               uaf->use_access.tid, (unsigned long)uaf->use_access.access_time,
               (uaf->use_access.access_type == 'R') ? "读取" : "写入",
               (unsigned long)uaf->use_access.address, (unsigned long)uaf->use_access.size);
        printf("   ├─ 时间差:   %lu 微秒\n", (unsigned long)uaf->time_diff);
        printf("   └─ 锁状态:   %s\n", 
               (uaf->lock_status == LOCK_NO_LOCKS) ? "无锁" :
               (uaf->lock_status == LOCK_ONE_SIDED_LOCK) ? "单侧锁" :
               (uaf->lock_status == LOCK_UNSYNC_LOCKS) ? "非同步锁" : "同步锁");
        printf("\n");
    }
    
    // 步骤7：风险评估
    printf("5. 风险评估：\n");
    int high_risk = 0, medium_risk = 0, low_risk = 0;
    
    for (int i = 0; i < uaf_count; i++) {
        UAFPair* uaf = &uaf_pairs[i];
        if (uaf->lock_status == LOCK_NO_LOCKS && uaf->time_diff < 1000) {
            high_risk++;
        } else if (uaf->lock_status == LOCK_ONE_SIDED_LOCK || uaf->time_diff < 5000) {
            medium_risk++;
        } else {
            low_risk++;
        }
    }
    
    printf("   ├─ 高风险UAF: %d 个（无锁保护且时间窗口小）\n", high_risk);
    printf("   ├─ 中风险UAF: %d 个（部分锁保护或中等时间窗口）\n", medium_risk);
    printf("   └─ 低风险UAF: %d 个（有锁保护或时间窗口大）\n", low_risk);
    
    // 清理内存
    free(records);
    free(free_records);
    free(uaf_pairs);
    
    printf("\n✅ UAF检测演示完成！\n");
}

/**
 * 展示如何集成到现有的race检测流程中
 */
void demonstrate_integrated_analysis() {
    printf("\n=== 集成分析演示 ===\n");
    
    const char* complex_trace = 
        "[KCCWF] log access: tid=2001, var_name=777777777, var_addr=0000000040000000, type=1, size=8, call_stack_hash=111111111, access_time=2000000000, sn=1\n"
        "[KCCWF] log access: tid=2002, var_name=777777777, var_addr=0000000040000000, type=1, size=8, call_stack_hash=222222222, access_time=2000000050, sn=1\n"
        "[KCCWF] log access: tid=2003, var_name=777777777, var_addr=0000000040000000, type=2, size=8, call_stack_hash=333333333, access_time=2000000100, sn=1\n"
        "[KCCWF] log access: tid=2004, var_name=777777777, var_addr=0000000040000000, type=0, size=8, call_stack_hash=444444444, access_time=2000000200, sn=1\n";
    
    // 分配内存
    AccessRecord* records = malloc(sizeof(AccessRecord) * 100);
    FreeRecord* free_records = malloc(sizeof(FreeRecord) * 50);
    RacePair* race_pairs = malloc(sizeof(RacePair) * 50);
    UAFPair* uaf_pairs = malloc(sizeof(UAFPair) * 50);
    
    AccessRecordSet record_set = {
        .records = records,
        .record_count = 0,
        .free_records = free_records,
        .free_count = 0
    };
    
    // 解析数据
    parse_access_records_to_set(complex_trace, &record_set, 100, 50);
    
    // 同时进行race检测和UAF检测
    printf("执行综合分析...\n");
    
    // Race检测
    int race_count = analyze_race_pairs_from_set(&record_set, race_pairs, 50);
    printf("发现 %d 个数据竞争\n", race_count);
    
    // UAF检测
    UAFStatistics uaf_stats;
    int uaf_count = analyze_uaf_pairs_from_set(&record_set, uaf_pairs, 50, &uaf_stats);
    printf("发现 %d 个UAF\n", uaf_count);
    
    printf("\n分析结果：该内存区域存在数据竞争和UAF风险\n");
    
    // 清理
    free(records);
    free(free_records);
    free(race_pairs);
    free(uaf_pairs);
}

int main() {
    printf("🔍 DDRD UAF检测接口使用示例\n");
    printf("============================\n\n");
    
    demonstrate_uaf_detection_api();
    demonstrate_integrated_analysis();
    
    printf("\n📖 API使用总结：\n");
    printf("1. 使用 parse_access_records_to_set() 解析trace数据\n");
    printf("2. 使用 analyze_uaf_pairs_from_set() 检测UAF\n");
    printf("3. 使用 print_uaf_statistics() 显示统计信息\n");
    printf("4. 可与 analyze_race_pairs_from_set() 结合使用\n");
    
    return 0;
}
