#include <stdio.h>
#include <string.h>
#include "types.h"

// 函数声明
AccessRecord access_record_init_from_line(const char* line);
LockRecord parse_lock_line(const char* line);

int main() {
    // 读取完整的日志文件
    FILE* fp = fopen("full_trace.log", "r");
    if (!fp) {
        printf("无法打开日志文件\n");
        return 1;
    }

    char line[2048];
    int access_count = 0;
    int lock_count = 0;
    int line_num = 0;
    int success_access = 0;
    int success_lock = 0;
    
    printf("开始解析完整日志...\n");
    printf("========================================\n");
    
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        
        // 检查是否是 access log
        if (strstr(line, "log access:")) {
            access_count++;
            AccessRecord record = access_record_init_from_line(line);
            if (record.valid) {
                success_access++;
                // 只打印前5条和最后几条成功解析的记录
                if (success_access <= 5 || success_access % 50 == 0) {
                    printf("[Access #%d] tid=%d, type=%c, size=%lu, var_name=%lu, addr=0x%lx\n",
                           success_access, record.tid, record.access_type, record.size,
                           record.var_name, record.address);
                }
            } else {
                printf("[ERROR] 行 %d: Access 解析失败\n", line_num);
            }
        }
        
        // 检查是否是 lock log
        if (strstr(line, "Held Lock:")) {
            lock_count++;
            LockRecord lock = parse_lock_line(line);
            if (lock.valid) {
                success_lock++;
                // 只打印前5条和最后几条成功解析的记录
                if (success_lock <= 5 || success_lock % 50 == 0) {
                    printf("[Lock #%d] name='%s', attr=%d, ptr=0x%lx\n",
                           success_lock, lock.name, lock.attr, lock.ptr);
                }
            } else {
                printf("[ERROR] 行 %d: Lock 解析失败\n", line_num);
            }
        }
    }
    
    fclose(fp);
    
    printf("========================================\n");
    printf("解析统计:\n");
    printf("  总行数: %d\n", line_num);
    printf("  Access 日志总数: %d\n", access_count);
    printf("  Access 解析成功: %d (%.2f%%)\n", success_access, 
           access_count > 0 ? (success_access * 100.0 / access_count) : 0);
    printf("  Lock 日志总数: %d\n", lock_count);
    printf("  Lock 解析成功: %d (%.2f%%)\n", success_lock,
           lock_count > 0 ? (success_lock * 100.0 / lock_count) : 0);
    
    return 0;
}
