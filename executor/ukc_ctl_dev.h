#ifndef UKC_CTL_DEV_H
#define UKC_CTL_DEV_H

#include "ukc.h"

#if GOOS_linux
#include <linux/ioctl.h>
#else
#define _IO(type,nr) (((type) << 8) | (nr))
#define _IOW(type,nr,size) (((type) << 8) | (nr) | (sizeof(size) << 16))
#endif

#define DEV_MAGIC 'c'
#define TURN_OFF_UKC _IO(DEV_MAGIC, 0)
#define START_MONITOR _IO(DEV_MAGIC, 1)
#define START_LOG_PHASE _IO(DEV_MAGIC, 2)
#define START_CHECK_SYNC_PHASE _IO(DEV_MAGIC, 3)
#define START_VALIDATE_PHASE _IO(DEV_MAGIC, 4)
#define MODIFY_TESTING_TID _IOW(DEV_MAGIC, 5, ukc_testing_tids_t)
#define SET_MAY_RACE_PAIRS _IOW(DEV_MAGIC, 6, may_race_pair_list_t)
#define SET_CHECK_PHASE_INFO _IOW(DEV_MAGIC, 8, check_phase_info_t)
#define START_NOLOCKREPRODUCE_MODE _IO(DEV_MAGIC, 9)
#define SET_NOLOCKREPRODUCE_INFO _IOW(DEV_MAGIC, 10, nolockreproduce_info_t)
#define START_ONESIDEDREPRODUCE_MODE _IO(DEV_MAGIC, 11)
#define SET_ONESIDEDREPRODUCE_INFO _IOW(DEV_MAGIC, 12, onesidedreproduce_info_t)

#define DEVICE_NAME "kccwf_ctl_dev"
#define CLASS_NAME "checker_class"

#endif // UKC_CTL_DEV_H
