#ifndef SYZ_UKC_H
#define SYZ_UKC_H

#include <cstdarg>
#include <cstdio>
#include <sys/ioctl.h>  // ioctl、_IO/_IOW（多数平台自带）
#include <fcntl.h>      // open、O_RDWR、O_CLOEXEC
#include <unistd.h>     // close
#include <errno.h>      // errno

inline void ukc_print(const char* msg, ...)
{
    int err = errno;
    va_list args;
    va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fflush(stderr);
	errno = err;
}

constexpr char kUkcDevicePath[] = "/dev/kccwf_ctl_dev";

#ifndef _IO
#define _IO(type, nr) (((type) << 8) | (nr))
#endif
#ifndef _IOW
#define _IOW(type, nr, size) (((type) << 8) | (nr) | (sizeof(size) << 16))
#endif

constexpr unsigned long kUkcTurnOff = _IO('c', 0);
constexpr unsigned long kUkcStartMonitor = _IO('c', 1);
constexpr unsigned long kUkcStartLog = _IO('c', 2);

static inline void ukc_turn_off()
{
	int fd = open(kUkcDevicePath, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		ukc_print("ukc: controller init failed (errno=%d)\n", errno);
		return;
	}
	if (ioctl(fd, kUkcTurnOff) == 0) {
		ukc_print("ukc: switched to TURN OFF mode\n");
	} else {
		ukc_print("ukc: failed to switch to LOG mode (errno=%d)\n", errno);
	}
	close(fd);
}


static inline void ukc_enter_log_mode()
{
	int fd = open(kUkcDevicePath, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		ukc_print("ukc: controller init failed (errno=%d)\n", errno);
		return;
	}
	if (ioctl(fd, kUkcStartLog) == 0) {
		ukc_print("ukc: switched to LOG mode\n");
	} else {
		ukc_print("ukc: failed to switch to LOG mode (errno=%d)\n", errno);
	}
	close(fd);
}

static inline void ukc_enter_monitor_mode()
{
	int fd = open(kUkcDevicePath, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		ukc_print("ukc: controller init failed (errno=%d)\n", errno);
		return;
	}
	if (ioctl(fd, kUkcStartMonitor) == 0)
		ukc_print("ukc: switched to MONITOR mode\n");
	else
		ukc_print("ukc: failed to switch to MONITOR mode (errno=%d)\n", errno);
	close(fd);
}

#endif  // SYZ_UKC_H