#include "trace_manager.h"

#include <cstdlib>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((format(printf, 1, 2)))
static void debug(const char* msg, ...)
{
    int err = errno;
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
    fflush(stderr);
    errno = err;
}

static ssize_t trace_manager_trace_size_bytes(void)
{
    int fd = open("/sys/kernel/debug/tracing/trace", O_RDONLY);
    if (fd < 0) {
        debug("trace_manager_clear: failed to open trace for size check: %s\n", strerror(errno));
        return -1;
    }
    ssize_t size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        size = 0;
        if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
            // ignore reposition failure
        }
        char buf[4096];
        for (;;) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n > 0) {
                size += n;
                continue;
            }
            if (n == 0)
                break;
            if (errno == EINTR)
                continue;
            debug("trace_manager_clear: failed to read trace for size check (errno=%d)\n", errno);
            break;
        }
    }
    close(fd);
    return size;
}

void trace_manager_init(TraceManager* tm)
{
    if (!tm)
        return;
    tm->fd = open("/sys/kernel/debug/tracing/trace", O_RDONLY);
    tm->valid = (tm->fd >= 0);
    if (!tm->valid)
        debug("Failed to open trace: %s\n", strerror(errno));
}

void trace_manager_close(TraceManager* tm)
{
    if (tm && tm->fd >= 0) {
        close(tm->fd);
        tm->fd = -1;
        tm->valid = false;
    }
}

ssize_t trace_manager_read_buffer(TraceManager* tm, char* buffer, size_t size)
{
    if (!tm || !buffer || size == 0)
        return -1;

    if (tm->fd < 0) {
        debug("trace_manager_read_buffer: fd is not initialized\n");
        buffer[0] = '\0';
        return -1;
    }

    size_t total = 0;
    if (lseek(tm->fd, 0, SEEK_SET) == (off_t)-1) {
        // Some pseudo files don't support lseek, ignore.
    }

    for (;;) {
        if (total >= size - 1)
            break;
        size_t want = size - 1 - total;
        ssize_t n = read(tm->fd, buffer + total, want);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        if (n == 0)
            break;
        if (errno == EINTR)
            continue;
        debug("trace_manager_read_buffer: read error (errno=%d)\n", errno);
        break;
    }

    buffer[total] = '\0';
    return (ssize_t)total;
}

void trace_manager_reset(TraceManager* tm)
{
    if (tm && tm->fd >= 0)
        lseek(tm->fd, 0, SEEK_SET);
}

void trace_manager_clear(TraceManager* tm)
{
    ssize_t before_bytes = trace_manager_trace_size_bytes();
    if (before_bytes >= 0)
        debug("trace_manager_clear: size before=%zd bytes\n", before_bytes);
    if (trace_manager_disable())
        debug("trace_manager_clear: failed to disable tracing\n");
    int fd = open("/sys/kernel/debug/tracing/trace", O_WRONLY | O_TRUNC);
    if (fd < 0)
        debug("trace_manager_clear: failed to open trace file: %s\n", strerror(errno));
    else
        close(fd);
    if (trace_manager_enable())
        debug("trace_manager_clear: failed to re-enable tracing\n");
    if (tm)
        trace_manager_reset(tm);
    ssize_t after_bytes = trace_manager_trace_size_bytes();
    if (after_bytes >= 0)
        debug("trace_manager_clear: size after=%zd bytes\n", after_bytes);
}

bool trace_manager_enable(void)
{
    return system("echo 1 > /sys/kernel/debug/tracing/tracing_on");
}

bool trace_manager_disable(void)
{
    return system("echo 0 > /sys/kernel/debug/tracing/tracing_on");
}

bool trace_manager_is_enabled(void)
{
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

    return status == '1';
}

bool trace_manager_set_buffer_size_kb(int size_kb)
{
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

int trace_manager_get_buffer_size_kb(void)
{
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
