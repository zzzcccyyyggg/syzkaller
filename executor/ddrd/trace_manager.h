#ifndef TRACE_MANAGER_H
#define TRACE_MANAGER_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h> // for ssize_t

typedef struct {
    int fd;       // trace文件描述符
    bool valid;   // 是否有效
} TraceManager;

// 初始化/销毁
void trace_manager_init(TraceManager* tm);
void trace_manager_close(TraceManager* tm);

// trace buffer 操作
ssize_t trace_manager_read_buffer(TraceManager* tm, char* buf, size_t size);
void trace_manager_reset(TraceManager* tm);
void trace_manager_clear(TraceManager* tm);

// trace 控制
bool trace_manager_enable();
bool trace_manager_disable();
bool trace_manager_is_enabled();

// buffer 大小设置
bool trace_manager_set_buffer_size_kb(int size_kb);
int  trace_manager_get_buffer_size_kb();

#endif // TRACE_MANAGER_H
