#include "trace_manager.h"

#include <cstdlib>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((format(printf, 1, 2)))
static void debug(const char* msg, ...)
{
    static int enabled = -1;
    if (enabled < 0)
        enabled = getenv("SYZ_DDRD_DEBUG") != NULL;
    if (!enabled)
        return;
    int err = errno;
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
    fflush(stderr);
    errno = err;
}

static const char* trace_manager_base_path(void)
{
    static const char* base;

    if (base)
        return base;
    if (access("/sys/kernel/debug/tracing/tracing_on", F_OK) == 0)
        base = "/sys/kernel/debug/tracing";
    else if (access("/sys/kernel/tracing/tracing_on", F_OK) == 0)
        base = "/sys/kernel/tracing";
    else
        base = "/sys/kernel/debug/tracing";
    return base;
}

static void trace_manager_make_path(char* path, size_t path_size, const char* name)
{
    snprintf(path, path_size, "%s/%s", trace_manager_base_path(), name);
}

static bool trace_manager_write_control(const char* name, const char* value)
{
    char path[128];
    trace_manager_make_path(path, sizeof(path), name);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        debug("failed to open %s: %s\n", path, strerror(errno));
        return true;
    }
    ssize_t written = write(fd, value, strlen(value));
    int saved_errno = errno;
    close(fd);
    if (written != (ssize_t)strlen(value)) {
        errno = saved_errno;
        debug("failed to write %s to %s: %s\n", value, path, strerror(errno));
        return true;
    }
    return false;
}

void trace_manager_init(TraceManager* tm)
{
    if (!tm)
        return;
    char path[128];
    trace_manager_make_path(path, sizeof(path), "trace");
    tm->fd = open(path, O_RDONLY);
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
    if (trace_manager_disable())
        debug("trace_manager_clear: failed to disable tracing\n");
    char path[128];
    trace_manager_make_path(path, sizeof(path), "trace");
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0)
        debug("trace_manager_clear: failed to open trace file: %s\n", strerror(errno));
    else
        close(fd);
    if (trace_manager_enable())
        debug("trace_manager_clear: failed to re-enable tracing\n");
    if (tm)
        trace_manager_reset(tm);
}

bool trace_manager_enable(void)
{
    return trace_manager_write_control("tracing_on", "1\n");
}

bool trace_manager_disable(void)
{
    return trace_manager_write_control("tracing_on", "0\n");
}

bool trace_manager_is_enabled(void)
{
    char path[128];
    trace_manager_make_path(path, sizeof(path), "tracing_on");
    int fd = open(path, O_RDONLY);
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

    char path[128];
    trace_manager_make_path(path, sizeof(path), "buffer_size_kb");
    int fd = open(path, O_WRONLY);
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
    char path[128];
    trace_manager_make_path(path, sizeof(path), "buffer_size_kb");
    int fd = open(path, O_RDONLY);
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
    return size;
}
