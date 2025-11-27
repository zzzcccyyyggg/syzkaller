// Shared constants for barrier start delay handling between executor and runner.
#pragma once

#include <stdint.h>

#ifdef __cplusplus
constexpr uint32_t kMaxBarrierDelays = 32;
#else
static const uint32_t kMaxBarrierDelays = 32;
#endif
