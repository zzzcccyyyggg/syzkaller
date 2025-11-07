#ifndef DDRD_TRACE_MANAGER_H
#define DDRD_TRACE_MANAGER_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

typedef struct {
    int fd;
    bool valid;
} TraceManager;

void trace_manager_init(TraceManager* tm);
void trace_manager_close(TraceManager* tm);
ssize_t trace_manager_read_buffer(TraceManager* tm, char* buf, size_t size);
void trace_manager_reset(TraceManager* tm);
void trace_manager_clear(TraceManager* tm);

bool trace_manager_enable(void);
bool trace_manager_disable(void);
bool trace_manager_is_enabled(void);

bool trace_manager_set_buffer_size_kb(int size_kb);
int trace_manager_get_buffer_size_kb(void);

#endif
