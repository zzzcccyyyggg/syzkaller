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
uint64_t hash_uaf_signal(const char* var_name, const char* free_stack, const char* use_stack);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
