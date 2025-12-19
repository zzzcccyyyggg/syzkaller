#ifndef DDRD_UTILS_H
#define DDRD_UTILS_H

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t hash_string(const char* str);
char* my_strdup(const char* s);
uint64_t hash_race_signal(const char* var1, const char* stack1,
                          const char* var2, const char* stack2);
uint64_t hash_uaf_signal(const char* var1, const char* stack1,
                          const char* var2, const char* stack2);
// New: hash signals from uint64_t values directly (not strings)
uint64_t hash_uaf_signal_u64(uint64_t var1, uint64_t stack1,
                              uint64_t var2, uint64_t stack2);
uint64_t hash_race_signal_u64(uint64_t var1, uint64_t stack1,
                               uint64_t var2, uint64_t stack2);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
