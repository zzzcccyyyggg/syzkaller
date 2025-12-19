#include "utils.h"

uint64_t hash_string(const char* str)
{
    uint64_t h = 1469598103934665603ULL;
    while (*str) {
        h ^= (unsigned char)(*str++);
        h *= 1099511628211ULL;
    }
    return h;
}

char* my_strdup(const char* s)
{
    size_t len = strlen(s) + 1;
    char* p = (char*)malloc(len);
    if (p)
        memcpy(p, s, len);
    return p;
}

uint64_t hash_race_signal(const char* var1, const char* stack1,
                          const char* var2, const char* stack2)
{
    uint64_t h1 = hash_string(var1 ? var1 : "");
    uint64_t h2 = hash_string(stack1 ? stack1 : "");
    uint64_t h3 = hash_string(var2 ? var2 : "");
    uint64_t h4 = hash_string(stack2 ? stack2 : "");

    uint64_t pair1 = h1 ^ (h2 << 1);
    uint64_t pair2 = h3 ^ (h4 << 1);

    if (pair1 > pair2) {
        uint64_t tmp = pair1;
        pair1 = pair2;
        pair2 = tmp;
    }

    return pair1 * 1315423911u ^ pair2;
}

uint64_t hash_uaf_signal(const char* var1, const char* stack1,
                          const char* var2, const char* stack2)
{
    uint64_t h1 = hash_string(var1 ? var1 : "");
    uint64_t h2 = hash_string(stack1 ? stack1 : "");
    uint64_t h3 = hash_string(var2 ? var2 : "");
    uint64_t h4 = hash_string(stack2 ? stack2 : "");

    uint64_t pair1 = h1 ^ (h2 << 1);
    uint64_t pair2 = h3 ^ (h4 << 1);

    if (pair1 > pair2) {
        uint64_t tmp = pair1;
        pair1 = pair2;
        pair2 = tmp;
    }

    return pair1 * 1315423911u ^ pair2;
}

// Hash UAF signal from uint64_t values directly (not strings)
// This is the correct version to use when var_name and call_stack_hash are uint64_t
uint64_t hash_uaf_signal_u64(uint64_t var1, uint64_t stack1,
                              uint64_t var2, uint64_t stack2)
{
    // Use the uint64_t values directly, no string hashing needed
    // Apply FNV-1a-like mixing to ensure good distribution
    const uint64_t fnv_prime = 1099511628211ULL;
    const uint64_t fnv_offset = 1469598103934665603ULL;

    uint64_t h1 = fnv_offset;
    h1 ^= var1;
    h1 *= fnv_prime;

    uint64_t h2 = fnv_offset;
    h2 ^= stack1;
    h2 *= fnv_prime;

    uint64_t h3 = fnv_offset;
    h3 ^= var2;
    h3 *= fnv_prime;

    uint64_t h4 = fnv_offset;
    h4 ^= stack2;
    h4 *= fnv_prime;

    uint64_t pair1 = h1 ^ (h2 << 1);
    uint64_t pair2 = h3 ^ (h4 << 1);

    if (pair1 > pair2) {
        uint64_t tmp = pair1;
        pair1 = pair2;
        pair2 = tmp;
    }

    return pair1 * 1315423911u ^ pair2;
}

// Hash race signal from uint64_t values directly (not strings)
// This is the correct version to use when var_name and call_stack_hash are uint64_t
uint64_t hash_race_signal_u64(uint64_t var, uint64_t stack)
{
    // Use the uint64_t values directly, no string hashing needed
    // Apply FNV-1a-like mixing to ensure good distribution
    const uint64_t fnv_prime = 1099511628211ULL;
    const uint64_t fnv_offset = 1469598103934665603ULL;

    uint64_t h1 = fnv_offset;
    h1 ^= var;
    h1 *= fnv_prime;

    uint64_t h2 = fnv_offset;
    h2 ^= stack;
    h2 *= fnv_prime;

    return h1 ^ (h2 << 1);
}
