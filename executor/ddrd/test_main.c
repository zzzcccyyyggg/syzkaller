#include <stdio.h>
#include "race_detector.h"
#include "trace_manager.h"

int main() {
    printf("Race Detector Test Program\n");
    printf("==========================\n");
    
    // 测试 RaceDetector 初始化
    RaceDetector detector;
    printf("Initializing RaceDetector...\n");
    race_detector_init(&detector);
    
    // 检查可用性
    bool available = race_detector_is_available(&detector);
    printf("RaceDetector available: %s\n", available ? "Yes" : "No");
    
    // 测试 TraceManager
    TraceManager tm;
    printf("Initializing TraceManager...\n");
    trace_manager_init(&tm);
    printf("TraceManager valid: %s\n", tm.valid ? "Yes" : "No");
    
    // 测试基本数据结构
    printf("Testing data structures...\n");
    
    // 测试 AccessRecord
    const char* test_line = "[KCCWF] log access: tid=123, var_name=456789, var_addr=0x7fff12345678, type=1, size=8, call_stack_hash=987654321, access_time=1000000000, sn=1";
    AccessRecord record = access_record_init_from_line(test_line);
    printf("AccessRecord parsed: valid=%s, tid=%d, var_name=%llu\n", 
           record.valid ? "Yes" : "No", record.tid, (unsigned long long)record.var_name);
    
    // 测试 LockRecord
    const char* lock_line = "Held Lock: name='test_lock' ptr=0x12345678 attr=1";
    LockRecord lock = parse_lock_line(lock_line);
    printf("LockRecord parsed: valid=%s, name='%s', ptr=0x%llx\n",
           lock.valid ? "Yes" : "No", lock.name, (unsigned long long)lock.ptr);
    
    // 测试线程历史管理
    printf("Testing thread history management...\n");
    ThreadAccessHistory* history = race_detector_find_thread_history(&detector, 123);
    if (!history) {
        history = race_detector_create_thread_history(&detector, 123);
        printf("Created thread history for TID 123: %s\n", history ? "Success" : "Failed");
    }
    
    if (history && record.valid) {
        race_detector_add_access_to_history(&detector, 123, &record);
        printf("Added access to history: count=%d\n", history->access_count);
    }
    
    // 测试路径距离计算
    if (record.valid) {
        AccessRecord record2 = record;
        record2.sn = 5;  // 不同的序列号
        
        int distance = race_detector_calculate_path_distance(&record2, &record);
        double probability = race_detector_calculate_delay_probability(distance);
        printf("Path distance: %d, Delay probability: %f\n", distance, probability);
    }
    
    // 清理资源
    printf("Cleaning up...\n");
    trace_manager_close(&tm);
    race_detector_cleanup(&detector);
    
    printf("Test completed successfully!\n");
    return 0;
}