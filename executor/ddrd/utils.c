#include "utils.h"
#include <stdlib.h>
#include <string.h>

uint64_t hash_string(const char* str) {
    uint64_t h = 1469598103934665603ULL;
    while (*str) {
        h ^= (unsigned char)(*str++);
        h *= 1099511628211ULL;
    }
    return h;
}

char* my_strdup(const char* s) {
    size_t len = strlen(s) + 1;
    char* p = malloc(len);
    if (p) memcpy(p, s, len);
    return p;
}

uint64_t hash_race_signal(const char* var1, const char* stack1,
				 const char* var2, const char* stack2)
{
	uint64_t h1 = hash_string(var1 ? var1 : "");
	uint64_t h2 = hash_string(stack1 ? stack1 : "");
	uint64_t h3 = hash_string(var2 ? var2 : "");
	uint64_t h4 = hash_string(stack2 ? stack2 : "");

	// 将 (var, stack) 两对先分别合成
	uint64_t pair1 = h1 ^ (h2 << 1);
	uint64_t pair2 = h3 ^ (h4 << 1);

	// 顺序无关组合：用加法或 commutative 异或
	// 为减少碰撞，可以用 pair1 < pair2 排序后再组合
	if (pair1 > pair2) {
		uint64_t tmp = pair1;
		pair1 = pair2;
		pair2 = tmp;
	}

	return pair1 * 1315423911u ^ pair2;
}

uint64_t hash_uaf_signal(const char* var_name, const char* free_stack, const char* use_stack)
{
	uint64_t h1 = hash_string(var_name ? var_name : "");
	uint64_t h2 = hash_string(free_stack ? free_stack : "");
	uint64_t h3 = hash_string(use_stack ? use_stack : "");
	
	// 组合三个哈希值
	return h1 ^ (h2 << 1) ^ (h3 << 2);
}