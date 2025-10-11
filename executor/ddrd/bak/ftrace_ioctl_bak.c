#include "race_detector.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

__attribute__((format(printf, 1, 2))) static void debug(const char* msg, ...)
{
	int err = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fflush(stderr);
	errno = err;
}

bool set_buffer_size_kb(int size_kb)
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


// 开启trace
bool enable_tracing(void)
{
	int fd = open("/sys/kernel/debug/tracing/tracing_on", O_WRONLY);
	if (fd < 0) {
		debug("Failed to open tracing_on: %s\n", strerror(errno));
		return false;
	}
	
	ssize_t written = write(fd, "1", 1);
	close(fd);
	
	if (written < 0) {
		debug("Failed to enable tracing: %s\n", strerror(errno));
		return false;
	}
	
	debug("Tracing enabled\n");
	return true;
}

// 关闭trace
bool disable_tracing(void)
{
	int fd = open("/sys/kernel/debug/tracing/tracing_on", O_WRONLY);
	if (fd < 0) {
		debug("Failed to open tracing_on: %s\n", strerror(errno));
		return false;
	}
	
	ssize_t written = write(fd, "0", 1);
	close(fd);
	
	if (written < 0) {
		debug("Failed to disable tracing: %s\n", strerror(errno));
		return false;
	}
	
	debug("Tracing disabled\n");
	return true;
}

// 获取当前的buffer大小（KB）
int get_buffer_size_kb(void)
{
	disable_tracing();
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
	enable_tracing();
	return size;
}

// 检查tracing状态
bool is_tracing_enabled(void)
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
	
	bool enabled = (status == '1');
	debug("Tracing status: %s\n", enabled ? "enabled" : "disabled");
	return enabled;
}

// 改进的清除trace buffer函数
void clear_trace_buffer(void)
{
	// 使用新的管理函数进行清理
	disable_tracing();
	
	// 清空trace buffer
	int fd = open("/sys/kernel/debug/tracing/trace", O_WRONLY | O_TRUNC);
	if (fd >= 0) {
		close(fd); // O_TRUNC 即可清空
		debug("Trace buffer cleared with O_TRUNC\n");
	} else {
		// 某些内核不支持 O_TRUNC；用覆盖方式兜底
		fd = open("/sys/kernel/debug/tracing/trace", O_WRONLY);
		if (fd >= 0) {
			if (ftruncate(fd, 0) == 0) {
				debug("Trace buffer cleared with ftruncate\n");
			} else {
				debug("Failed to truncate trace buffer: %s\n", strerror(errno));
			}
			close(fd);
		} else {
			debug("Failed to open trace buffer for clearing: %s\n", strerror(errno));
		}
	}
	
	enable_tracing();
}