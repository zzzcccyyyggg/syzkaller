#ifndef UKC_CTL_H
#define UKC_CTL_H

#include "ukc.h"
#include "ukc_ctl_dev.h"
#include <stdlib.h>

#if !GOOS_windows
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// C-style interface for UKC control
typedef struct {
    int fd_;
} ukc_ctl_t;

// Initialize UKC controller
static inline ukc_ctl_t* ukc_ctl_init(const char* dev_path)
{
    ukc_ctl_t* ctl = (ukc_ctl_t*)malloc(sizeof(ukc_ctl_t));
    if (!ctl)
        return NULL;
    
    ctl->fd_ = open(dev_path, O_RDWR);
    if (ctl->fd_ < 0) {
        free(ctl);
        return NULL;
    }
    return ctl;
}

// Cleanup UKC controller
static inline void ukc_ctl_cleanup(ukc_ctl_t* ctl)
{
    if (ctl) {
        if (ctl->fd_ >= 0)
            close(ctl->fd_);
        free(ctl);
    }
}

// Helper function for ioctl without arguments
static inline int ukc_ctl_ioctl_noarg(ukc_ctl_t* ctl, unsigned long req)
{
    if (!ctl)
        return -1;
    return ioctl(ctl->fd_, req);
}

// Control functions
static inline int ukc_ctl_turn_off(ukc_ctl_t* ctl)
{
    return ukc_ctl_ioctl_noarg(ctl, TURN_OFF_UKC);
}

static inline int ukc_ctl_start_monitor(ukc_ctl_t* ctl)
{
    return ukc_ctl_ioctl_noarg(ctl, START_MONITOR);
}

static inline int ukc_ctl_start_log_phase(ukc_ctl_t* ctl)
{
    return ukc_ctl_ioctl_noarg(ctl, START_LOG_PHASE);
}

static inline int ukc_ctl_start_check_sync(ukc_ctl_t* ctl)
{
    return ukc_ctl_ioctl_noarg(ctl, START_CHECK_SYNC_PHASE);
}

static inline int ukc_ctl_start_validate(ukc_ctl_t* ctl)
{
    return ukc_ctl_ioctl_noarg(ctl, START_VALIDATE_PHASE);
}

static inline int ukc_ctl_start_nolockreproduce(ukc_ctl_t* ctl)
{
    return ukc_ctl_ioctl_noarg(ctl, START_NOLOCKREPRODUCE_MODE);
}

static inline int ukc_ctl_start_onesidedreproduce(ukc_ctl_t* ctl)
{
    return ukc_ctl_ioctl_noarg(ctl, START_ONESIDEDREPRODUCE_MODE);
}

static inline int ukc_ctl_set_testing_tids(ukc_ctl_t* ctl, tid_t* tids, int num_tids)
{
    if (!ctl || !tids)
        return -1;
    
    ukc_testing_tids_t arg = {};
    arg.num = num_tids > UKC_MAX_TESTING_TID_NUM ? UKC_MAX_TESTING_TID_NUM : num_tids;
    for (int i = 0; i < arg.num; ++i) {
        arg.tids[i] = tids[i];
    }
    return ioctl(ctl->fd_, MODIFY_TESTING_TID, &arg);
}

static inline int ukc_ctl_set_check_info(ukc_ctl_t* ctl, uint64_t varname, uint32_t testing_tid)
{
    if (!ctl)
        return -1;
    
    check_phase_info_t info;
    info.var_name = varname;
    info.testing_tid = testing_tid;
    return ioctl(ctl->fd_, SET_CHECK_PHASE_INFO, &info);
}

static inline int ukc_ctl_set_nolockrepro_info(ukc_ctl_t* ctl, nolockreproduce_info_t info)
{
    if (!ctl)
        return -1;
    return ioctl(ctl->fd_, SET_NOLOCKREPRODUCE_INFO, &info);
}

static inline int ukc_ctl_set_onesidedrepro_info(ukc_ctl_t* ctl, onesidedreproduce_info_t info)
{
    if (!ctl)
        return -1;
    return ioctl(ctl->fd_, SET_ONESIDEDREPRODUCE_INFO, &info);
}

#ifdef __cplusplus
}
#endif

#endif // UKC_CTL_H
