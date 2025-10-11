#include "trace_manager.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 内部调试函数
__attribute__((format(printf, 1, 2)))
static void debug(const char* msg, ...) {
    int err = errno;
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
    fflush(stderr);
    errno = err;
}

void trace_manager_init(TraceManager* tm) {
    if (!tm) return;
    tm->fd = open("/sys/kernel/debug/tracing/trace", O_RDONLY);
    tm->valid = (tm->fd >= 0);
    if (!tm->valid)
        debug("Failed to open trace: %s\n", strerror(errno));
}

void trace_manager_close(TraceManager* tm) {
    if (tm && tm->fd >= 0) {
        close(tm->fd);
        tm->fd = -1;
        tm->valid = false;
    }
}

ssize_t trace_manager_read_buffer(TraceManager* tm, char* buffer, size_t size) {
    if (!tm || !buffer || size == 0)
        return -1;

    if (tm->fd < 0) {
        debug("trace_manager_read_buffer: fd is not initialized\n");
        buffer[0] = '\0';
        return -1;
    }

    size_t total = 0;
    if (lseek(tm->fd, 0, SEEK_SET) == (off_t)-1) {
        // 某些 pseudo 文件不支持 lseek
    }

    for (;;) {
        if (total >= size - 1) break;
        size_t want = size - 1 - total;
        ssize_t n = read(tm->fd, buffer + total, want);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        if (n == 0) break; // EOF
        if (errno == EINTR) continue;
        debug("trace_manager_read_buffer: read error (errno=%d)\n", errno);
        break;
    }

    buffer[total] = '\0';
    return (ssize_t)total;
}

void trace_manager_reset(TraceManager* tm) {
    if (tm && tm->fd >= 0)
        lseek(tm->fd, 0, SEEK_SET);
}

void trace_manager_clear(TraceManager* tm) {
    trace_manager_disable();

    int fd = open("/sys/kernel/debug/tracing/trace", O_WRONLY | O_TRUNC);
    if (fd >= 0) {
        close(fd);
        debug("Trace buffer cleared with O_TRUNC\n");
    } else {
        fd = open("/sys/kernel/debug/tracing/trace", O_WRONLY);
        if (fd >= 0) {
            if (ftruncate(fd, 0) == 0)
                debug("Trace buffer cleared with ftruncate\n");
            else
                debug("Failed to truncate trace buffer: %s\n", strerror(errno));
            close(fd);
        } else {
            debug("Failed to open trace buffer for clearing: %s\n", strerror(errno));
        }
    }

    trace_manager_enable();
}

// --- tracing 控制函数 ---

bool trace_manager_enable() {
    int fd = open("/sys/kernel/debug/tracing/tracing_on", O_WRONLY);
    if (fd < 0) {
        debug("Failed to open tracing_on: %s\n", strerror(errno));
        return false;
    }
    ssize_t written = write(fd, "1", 1);
    close(fd);
    return (written > 0);
}

bool trace_manager_disable() {
    int fd = open("/sys/kernel/debug/tracing/tracing_on", O_WRONLY);
    if (fd < 0) {
        debug("Failed to open tracing_on: %s\n", strerror(errno));
        return false;
    }
    ssize_t written = write(fd, "0", 1);
    close(fd);
    return (written > 0);
}

bool trace_manager_is_enabled() {
    int fd = open("/sys/kernel/debug/tracing/tracing_on", O_RDONLY);
    if (fd < 0) {
        debug("Failed to open tracing_on for reading: %s\n", strerror(errno));
        return false;
    }

    char status;
    ssize_t bytes_read = read(fd, &status, 1);
    close(fd);

    if (bytes_read <= 0) {
        debug("Failed to read tracing status: %s\n", strerror(errno));
        return false;
    }

    return (status == '1');
}

// --- buffer size 管理 ---

bool trace_manager_set_buffer_size_kb(int size_kb) {
    char size_str[32];
    snprintf(size_str, sizeof(size_str), "%d", size_kb);

    int fd = open("/sys/kernel/debug/tracing/buffer_size_kb", O_WRONLY);
    if (fd < 0) {
        debug("Failed to open buffer_size_kb: %s\n", strerror(errno));
        return false;
    }

    ssize_t written = write(fd, size_str, strlen(size_str));
    close(fd);

    if (written < 0) {
        debug("Failed to set buffer size to %d KB: %s\n", size_kb, strerror(errno));
        return false;
    }

    debug("Set trace buffer size to %d KB per CPU\n", size_kb);
    return true;
}

int trace_manager_get_buffer_size_kb() {
    trace_manager_disable();

    int fd = open("/sys/kernel/debug/tracing/buffer_size_kb", O_RDONLY);
    if (fd < 0) {
        debug("Failed to open buffer_size_kb for reading: %s\n", strerror(errno));
        return -1;
    }

    char buffer[32];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);

    if (bytes_read <= 0) {
        debug("Failed to read buffer size: %s\n", strerror(errno));
        return -1;
    }

    buffer[bytes_read] = '\0';
    int size = atoi(buffer);
    debug("Current trace buffer size: %d KB per CPU\n", size);

    trace_manager_enable();
    return size;
}
