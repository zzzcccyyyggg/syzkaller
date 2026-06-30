#ifndef SYZ_UKC_H
#define SYZ_UKC_H

#include <cstdarg>
#include <cstdlib>
#include <cstdio>
#include <errno.h> // errno
#include <fcntl.h> // open、O_RDWR、O_CLOEXEC
#include <sys/ioctl.h> // ioctl、_IO/_IOW/_IOR（多数平台自带）
#include <unistd.h> // close

// 这里假定和内核模块共用同一个头，里面定义了：
// kccwf_testing_tids_t / may_race_pair_list_t / check_phase_info_t /
// nolockreproduce_info_t / onesidedreproduce_info_t / may_uaf_pair_t / MAX_RACE_PAIR_NUM 等
#include "kccwf.h"

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
#ifndef _IOR
#define _IOR(type, nr, size) (((type) << 8) | (nr) | (sizeof(size) << 16))
#endif
#ifndef _IOWR
#define _IOWR(type, nr, size) (((type) << 8) | (nr) | (sizeof(size) << 16))
#endif

// 与内核 ctl_dev.h 中定义一一对应
constexpr unsigned long kUkcTurnOff = _IO('c', 0);
constexpr unsigned long kUkcStartMonitor = _IO('c', 1);
constexpr unsigned long kUkcStartLog = _IO('c', 2);
constexpr unsigned long kUkcStartCheckSyncPhase = _IO('c', 3);
constexpr unsigned long kUkcStartValidatePhase = _IO('c', 4);
constexpr unsigned long kUkcModifyTestingTid = _IOW('c', 5, kccwf_testing_tids_t);
constexpr unsigned long kUkcSetMayRacePairs = _IOW('c', 6, may_race_pair_list_t);
constexpr unsigned long kUkcGetMayRacePairs = _IOR('c', 7, may_race_pair_list_t);
constexpr unsigned long kUkcSetCheckPhaseInfo = _IOW('c', 8, check_phase_info_t);
constexpr unsigned long kUkcStartNoLockReproduce = _IO('c', 9);
constexpr unsigned long kUkcSetNoLockReproduceInfo = _IOW('c', 10, nolockreproduce_info_t);
constexpr unsigned long kUkcStartOneSidedReproduce = _IO('c', 11);
constexpr unsigned long kUkcSetOneSidedReproduceInfo = _IOW('c', 12, onesidedreproduce_info_t);
constexpr unsigned long kUkcSetMayUafPair = _IOW('c', 13, may_uaf_pair_t);
constexpr unsigned long kUkcClearMayUafPair = _IO('c', 14);
constexpr unsigned long kUkcStartFineLogMode = _IO('c', 15);
constexpr unsigned long kUkcStartFineMonitorMode = _IO('c', 16);
constexpr unsigned long kUkcGetTraceRecords = _IOWR('c', 17, kccwf_trace_read_t);
constexpr unsigned long kUkcClearTraceRecords = _IO('c', 18);

// 小工具：打开 /dev，失败时打印日志
static inline int ukc_open_dev()
{
	static int cached_fd = -1;
	static pid_t cached_pid = -1;
	pid_t pid = getpid();

	if (cached_fd >= 0 && cached_pid == pid)
		return cached_fd;
	if (cached_fd >= 0) {
		close(cached_fd);
		cached_fd = -1;
	}

	cached_fd = open(kUkcDevicePath, O_RDWR | O_CLOEXEC);
	cached_pid = pid;
	if (cached_fd < 0) {
		ukc_print("ukc: controller init failed (errno=%d)\n", errno);
	}
	return cached_fd;
}

// ========== 无参数类命令 ==========

static inline void ukc_turn_off()
{
	int fd = ukc_open_dev();
	if (fd < 0)
		return;

	if (ioctl(fd, kUkcTurnOff) != 0)
		ukc_print("ukc: failed to switch to TURN OFF mode (errno=%d)\n", errno);
}

// Enter disable mode - the safe/idle mode for UKC
static inline void ukc_enter_disable_mode()
{
	ukc_turn_off();
}

static inline void ukc_enter_log_mode()
{
	int fd = ukc_open_dev();
	if (fd < 0)
		return;

	if (ioctl(fd, kUkcStartLog) != 0)
		ukc_print("ukc: failed to switch to LOG mode (errno=%d)\n", errno);
}

static inline void ukc_enter_monitor_mode()
{
	int fd = ukc_open_dev();
	if (fd < 0)
		return;

	if (ioctl(fd, kUkcStartMonitor) != 0)
		ukc_print("ukc: failed to switch to MONITOR mode (errno=%d)\n", errno);
}

static inline void ukc_enter_check_sync_phase()
{
	int fd = ukc_open_dev();
	if (fd < 0)
		return;

	if (ioctl(fd, kUkcStartCheckSyncPhase) != 0)
		ukc_print("ukc: failed to switch to CHECK_SYNC phase (errno=%d)\n", errno);
}

static inline void ukc_enter_validate_phase()
{
	int fd = ukc_open_dev();
	if (fd < 0)
		return;

	if (ioctl(fd, kUkcStartValidatePhase) != 0)
		ukc_print("ukc: failed to switch to VALIDATE phase (errno=%d)\n", errno);
}

static inline void ukc_enter_nolockreproduce_mode()
{
	int fd = ukc_open_dev();
	if (fd < 0)
		return;

	if (ioctl(fd, kUkcStartNoLockReproduce) != 0)
		ukc_print("ukc: failed to switch to NOLOCK REPRODUCE mode (errno=%d)\n", errno);
}

static inline void ukc_enter_fine_log_mode()
{
	int fd = ukc_open_dev();
	if (fd < 0)
		return;

	if (ioctl(fd, kUkcStartFineLogMode) != 0)
		ukc_print("ukc: failed to switch to FINE_LOG mode (errno=%d)\n", errno);
}

static inline void ukc_enter_fine_monitor_mode()
{
	int fd = ukc_open_dev();
	if (fd < 0)
		return;

	if (ioctl(fd, kUkcStartFineMonitorMode) != 0)
		ukc_print("ukc: failed to switch to FINE_MONITOR mode (errno=%d)\n", errno);
}

static inline void ukc_enter_onesidedreproduce_mode()
{
	int fd = ukc_open_dev();
	if (fd < 0)
		return;

	if (ioctl(fd, kUkcStartOneSidedReproduce) != 0)
		ukc_print("ukc: failed to switch to ONESIDED REPRODUCE mode (errno=%d)\n", errno);
}

static inline void ukc_clear_may_uaf_pair()
{
	int fd = ukc_open_dev();
	if (fd < 0)
		return;

	if (ioctl(fd, kUkcClearMayUafPair) != 0)
		ukc_print("ukc: failed to CLEAR_MAY_UAF_PAIR (errno=%d)\n", errno);
}

static inline bool ukc_optional_debug_enabled()
{
	return getenv("SYZ_DDRD_DEBUG") != nullptr;
}

static inline int ukc_clear_trace_records()
{
	int fd = ukc_open_dev();
	if (fd < 0)
		return -1;

	int ret = ioctl(fd, kUkcClearTraceRecords);
	int saved_errno = errno;
	if (ret != 0 && ukc_optional_debug_enabled())
		ukc_print("ukc: optional CLEAR_TRACE_RECORDS failed (errno=%d)\n", saved_errno);

	errno = saved_errno;
	return ret;
}

static inline int ukc_get_trace_records(kccwf_trace_read_t* req)
{
	if (!req) {
		ukc_print("ukc: ukc_get_trace_records: req is NULL\n");
		return -1;
	}
	int fd = ukc_open_dev();
	if (fd < 0)
		return -1;

	int ret = ioctl(fd, kUkcGetTraceRecords, req);
	int saved_errno = errno;
	if (ret != 0 && ukc_optional_debug_enabled())
		ukc_print("ukc: optional GET_TRACE_RECORDS failed (errno=%d)\n", saved_errno);

	errno = saved_errno;
	return ret;
}

// ========== 需要传入结构体参数的命令 ==========

// 修改正在测试的 tid 集
static inline int ukc_modify_testing_tid(const kccwf_testing_tids_t* tids)
{
	if (!tids) {
		ukc_print("ukc: ukc_modify_testing_tid: tids is NULL\n");
		return -1;
	}
	int fd = ukc_open_dev();
	if (fd < 0)
		return -1;

	int ret = ioctl(fd, kUkcModifyTestingTid, tids);
	if (ret != 0)
		ukc_print("ukc: MODIFY_TESTING_TID failed (errno=%d)\n", errno);
	return ret;
}

// 设置 may-race pair 列表
// 注意：
//   - 结构体布局必须与内核侧 may_race_pair_list_t 完全一致
//   - list->pairs 指向用户态的 may_race_pair_t 数组，内核会 copy_from_user
static inline int ukc_set_may_race_pairs(const may_race_pair_list_t* list)
{
	if (!list) {
		ukc_print("ukc: ukc_set_may_race_pairs: list is NULL\n");
		return -1;
	}
	int fd = ukc_open_dev();
	if (fd < 0)
		return -1;

	int ret = ioctl(fd, kUkcSetMayRacePairs, list);
	if (ret != 0)
		ukc_print("ukc: SET_MAY_RACE_PAIRS failed (errno=%d)\n", errno);
	return ret;
}

// 获取 may-race pair 列表
// 使用方式：
//   1) 在用户态分配一块连续缓冲区 buf：
//        size >= sizeof(may_race_pair_list_t) + N * sizeof(may_race_pair_t)
//      并把 buf 作为 arg 传入；
//   2) 内核会把一个 may_race_pair_list_t 写在 buf 开头，
//      其中 .num 为实际对数，.pairs 指向 (buf + sizeof(may_race_pair_list_t))；
//   3) 之后可以按如下方式解析：
//        auto* header = (may_race_pair_list_t*)buf;
//        auto* pairs  = (may_race_pair_t*)((char*)buf + sizeof(may_race_pair_list_t));
static inline int ukc_get_may_race_pairs(void* buf)
{
	if (!buf) {
		ukc_print("ukc: ukc_get_may_race_pairs: buf is NULL\n");
		return -1;
	}
	int fd = ukc_open_dev();
	if (fd < 0)
		return -1;

	int ret = ioctl(fd, kUkcGetMayRacePairs, buf);
	if (ret != 0)
		ukc_print("ukc: GET_MAY_RACE_PAIRS failed (errno=%d)\n", errno);
	return ret;
}

// 设置 CHECK 阶段信息
static inline int ukc_set_check_phase_info(const check_phase_info_t* info)
{
	if (!info) {
		ukc_print("ukc: ukc_set_check_phase_info: info is NULL\n");
		return -1;
	}
	int fd = ukc_open_dev();
	if (fd < 0)
		return -1;

	int ret = ioctl(fd, kUkcSetCheckPhaseInfo, info);
	if (ret != 0)
		ukc_print("ukc: SET_CHECK_PHASE_INFO failed (errno=%d)\n", errno);
	return ret;
}

// 设置 NOLOCK reproduce 信息
static inline int ukc_set_nolockreproduce_info(const nolockreproduce_info_t* info)
{
	if (!info) {
		ukc_print("ukc: ukc_set_nolockreproduce_info: info is NULL\n");
		return -1;
	}
	int fd = ukc_open_dev();
	if (fd < 0)
		return -1;

	int ret = ioctl(fd, kUkcSetNoLockReproduceInfo, info);
	if (ret != 0)
		ukc_print("ukc: SET_NOLOCKREPRODUCE_INFO failed (errno=%d)\n", errno);
	return ret;
}

// 设置 ONESIDED reproduce 信息
static inline int ukc_set_onesidedreproduce_info(const onesidedreproduce_info_t* info)
{
	if (!info) {
		ukc_print("ukc: ukc_set_onesidedreproduce_info: info is NULL\n");
		return -1;
	}
	int fd = ukc_open_dev();
	if (fd < 0)
		return -1;

	int ret = ioctl(fd, kUkcSetOneSidedReproduceInfo, info);
	if (ret != 0)
		ukc_print("ukc: SET_ONESIDEDREPRODUCE_INFO failed (errno=%d)\n", errno);
	return ret;
}

// 设置 may-UAF 对
static inline int ukc_set_may_uaf_pair(const may_uaf_pair_t* pair)
{
	if (!pair) {
		ukc_print("ukc: ukc_set_may_uaf_pair: pair is NULL\n");
		return -1;
	}
	int fd = ukc_open_dev();
	if (fd < 0)
		return -1;

	int ret = ioctl(fd, kUkcSetMayUafPair, pair);
	if (ret != 0)
		ukc_print("ukc: SET_MAY_UAF_PAIR failed (errno=%d)\n", errno);
	return ret;
}

#endif // SYZ_UKC_H
