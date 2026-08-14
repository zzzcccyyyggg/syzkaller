#include "types.h"
#include "utils.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    RACE_PAIR_CANDIDATE_SCAN_MULTIPLIER = 4,
};

static void debug(const char* fmt, ...);
static int compare_access_record_time(const void* lhs, const void* rhs);
static uint64_t rotate_left64_value(uint64_t value, unsigned int shift);
static uint64_t race_pair_id_from_records(const AccessRecord* first_access, const AccessRecord* second_access);
static size_t next_power_of_two_size(size_t value);
static bool prepare_seen_pair_scratch(AccessContext* record_ctx, size_t table_size);
static bool seen_pair_id_contains(const uint64_t* table, const bool* occupied, size_t table_size, uint64_t id);
static bool insert_seen_pair_id(uint64_t* table, bool* occupied, size_t table_size, uint64_t id);

int parse_access_records_to_set(AccessContext* record_ctx, const char* buffer, int max_records, int max_frees)
{
    if (!buffer || !record_ctx || max_records <= 0 || max_frees <= 0)
        return 0;

    int record_count = 0;
    int free_count = 0;
    bool records_sorted = true;
    bool frees_sorted = true;
    uint64_t last_record_time = 0;
    uint64_t last_free_time = 0;

    record_ctx->thread_count = 0;
    if (record_ctx->enable_history && record_ctx->thread_histories) {
        for (int i = 0; i < MAX_THREADS; i++) {
            record_ctx->thread_histories[i].tid = -1;
            record_ctx->thread_histories[i].access_count = 0;
            record_ctx->thread_histories[i].access_index = 0;
            record_ctx->thread_histories[i].buffer_full = false;
        }
    }

    char* buffer_copy = my_strdup(buffer);
    if (!buffer_copy)
        return 0;

    char* line = strtok(buffer_copy, "\n");
    AccessRecord current_record = {0};
    bool has_current = false;

    while (line) {
        AccessRecord access = access_record_init_from_line(line);
        if (access.valid) {
            if (has_current) {
                if (record_ctx->enable_history) {
                    ThreadAccessHistory* thread_history = access_context_find_thread(record_ctx, current_record.tid);
                    if (!thread_history)
                        thread_history = access_context_create_thread_history(record_ctx, current_record.tid);
                    if (thread_history)
                        add_access_to_history(thread_history, &current_record);
                }

                if (current_record.access_type == 'F' && free_count < max_frees) {
                    AccessRecord* free_rec = &record_ctx->free_records[free_count];
                    free_rec->address = current_record.address;
                    free_rec->size = current_record.size;
                    free_rec->access_time = current_record.access_time;
                    free_rec->tid = current_record.tid;
                    free_rec->var_name = current_record.var_name;
                    free_rec->call_stack_hash = current_record.call_stack_hash;
                    free_rec->lock_count = current_record.lock_count;
                    for (int k = 0; k < current_record.lock_count && k < 8; k++)
                        free_rec->held_locks[k] = current_record.held_locks[k];
                    if (free_count > 0 && free_rec->access_time < last_free_time)
                        frees_sorted = false;
                    last_free_time = free_rec->access_time;
                    free_count++;
                } else if (current_record.access_type != 'F' && record_count < max_records) {
                    if (record_count > 0 && current_record.access_time < last_record_time)
                        records_sorted = false;
                    last_record_time = current_record.access_time;
                    record_ctx->records[record_count++] = current_record;
                }
            }

            current_record = access;
            current_record.lock_count = 0;
            has_current = true;
        } else {
            LockRecord lock = parse_lock_line(line);
            if (lock.valid && has_current && current_record.lock_count < 8)
                current_record.held_locks[current_record.lock_count++] = lock;
        }
        line = strtok(NULL, "\n");
    }

    if (has_current) {
        if (record_ctx->enable_history) {
            ThreadAccessHistory* thread_history = access_context_find_thread(record_ctx, current_record.tid);
            if (!thread_history)
                thread_history = access_context_create_thread_history(record_ctx, current_record.tid);
            if (thread_history)
                add_access_to_history(thread_history, &current_record);
        }

        if (current_record.access_type == 'F' && free_count < max_frees) {
            AccessRecord* free_rec = &record_ctx->free_records[free_count];
            free_rec->address = current_record.address;
            free_rec->size = current_record.size;
            free_rec->access_time = current_record.access_time;
            free_rec->tid = current_record.tid;
            free_rec->var_name = current_record.var_name;
            free_rec->call_stack_hash = current_record.call_stack_hash;
            free_rec->lock_count = current_record.lock_count;
            for (int k = 0; k < current_record.lock_count && k < 8; k++)
                free_rec->held_locks[k] = current_record.held_locks[k];
            if (free_count > 0 && free_rec->access_time < last_free_time)
                frees_sorted = false;
            last_free_time = free_rec->access_time;
            free_count++;
        } else if (current_record.access_type != 'F' && record_count < max_records) {
            if (record_count > 0 && current_record.access_time < last_record_time)
                records_sorted = false;
            last_record_time = current_record.access_time;
            record_ctx->records[record_count++] = current_record;
        }
    }

    if (record_count > 1 && !records_sorted)
        qsort(record_ctx->records, record_count, sizeof(AccessRecord), compare_access_record_time);
    if (free_count > 1 && !frees_sorted)
        qsort(record_ctx->free_records, free_count, sizeof(AccessRecord), compare_access_record_time);

    record_ctx->record_count = record_count;
    record_ctx->free_count = free_count;

    free(buffer_copy);
    return record_count;
}

// Default threshold in nanoseconds (10ms, unified with collector)
#define DEFAULT_TIME_THRESHOLD_NS 10000000

static int compare_access_record_time(const void* lhs, const void* rhs)
{
    const AccessRecord* a = (const AccessRecord*)lhs;
    const AccessRecord* b = (const AccessRecord*)rhs;
    if (a->access_time < b->access_time)
        return -1;
    if (a->access_time > b->access_time)
        return 1;
    return 0;
}

static uint64_t rotate_left64_value(uint64_t value, unsigned int shift)
{
    return (value << shift) | (value >> (64 - shift));
}

static uint64_t race_pair_id_from_records(const AccessRecord* first_access, const AccessRecord* second_access)
{
    // Keep this in sync with pkg/ddrd.MayUAFPair.UAFPairID().
    // The race pipeline currently maps first_access to Use* and second_access
    // to Free* fields in may_uaf_pair_t.
    const uint64_t mix_const = 1315423911ULL;
    uint64_t var_pair_id = second_access->var_name ^ rotate_left64_value(first_access->var_name, 32);
    uint64_t stack_pair_id = second_access->call_stack_hash ^ rotate_left64_value(first_access->call_stack_hash, 32);

    return var_pair_id ^ rotate_left64_value(stack_pair_id, 17) ^ (stack_pair_id * mix_const);
}

static size_t next_power_of_two_size(size_t value)
{
    size_t result = 1;
    while (result < value)
        result <<= 1;
    return result;
}

static bool insert_seen_pair_id(uint64_t* table, bool* occupied, size_t table_size, uint64_t id)
{
    if (!table || !occupied || table_size == 0)
        return false;

    size_t idx = (size_t)(id * 11400714819323198485ULL) & (table_size - 1);
    for (size_t probe = 0; probe < table_size; probe++) {
        uint64_t* slot = &table[(idx + probe) & (table_size - 1)];
        bool* used = &occupied[(idx + probe) & (table_size - 1)];
        if (*used && *slot == id)
            return false;
        if (!*used) {
            *slot = id;
            *used = true;
            return true;
        }
    }
    return true;
}

static bool prepare_seen_pair_scratch(AccessContext* record_ctx, size_t table_size)
{
    if (!record_ctx || table_size == 0)
        return false;
    if (record_ctx->seen_pair_ids && record_ctx->seen_pair_occupied &&
        record_ctx->seen_pair_capacity >= table_size) {
        memset(record_ctx->seen_pair_occupied, 0,
               record_ctx->seen_pair_capacity * sizeof(*record_ctx->seen_pair_occupied));
        return true;
    }
    if (table_size > SIZE_MAX / sizeof(*record_ctx->seen_pair_ids) ||
        table_size > SIZE_MAX / sizeof(*record_ctx->seen_pair_occupied))
        return false;

    uint64_t* ids = (uint64_t*)malloc(table_size * sizeof(*ids));
    bool* occupied = (bool*)malloc(table_size * sizeof(*occupied));
    if (!ids || !occupied) {
        free(ids);
        free(occupied);
        return false;
    }

    free(record_ctx->seen_pair_ids);
    free(record_ctx->seen_pair_occupied);
    record_ctx->seen_pair_ids = ids;
    record_ctx->seen_pair_occupied = occupied;
    record_ctx->seen_pair_capacity = table_size;
    memset(record_ctx->seen_pair_occupied, 0,
           table_size * sizeof(*record_ctx->seen_pair_occupied));
    return true;
}

static bool seen_pair_id_contains(const uint64_t* table, const bool* occupied, size_t table_size, uint64_t id)
{
    if (!table || !occupied || table_size == 0)
        return false;

    size_t idx = (size_t)(id * 11400714819323198485ULL) & (table_size - 1);
    for (size_t probe = 0; probe < table_size; probe++) {
        size_t slot_idx = (idx + probe) & (table_size - 1);
        if (!occupied[slot_idx])
            return false;
        if (table[slot_idx] == id)
            return true;
    }
    return false;
}

int access_context_analyze_race_pairs_with_threshold(AccessContext* record_ctx, RacePair* pairs, int max_pairs, uint64_t threshold_us)
{
    if (!record_ctx || !pairs || max_pairs <= 0)
        return 0;

    // Convert threshold from microseconds to nanoseconds
    // If threshold_us is 0, use the default 10ms threshold
    const uint64_t TIME_THRESHOLD = (threshold_us > 0) ? (threshold_us * 1000) : DEFAULT_TIME_THRESHOLD_NS;
    const uint64_t FAST_THRESHOLD = TIME_THRESHOLD; // Use same threshold for W-W pairs
    const uint64_t MAX_THRESHOLD = TIME_THRESHOLD > FAST_THRESHOLD ? TIME_THRESHOLD : FAST_THRESHOLD;
    int pair_count = 0;
    int candidate_count = 0;
    int max_candidates = max_pairs;
    uint64_t* seen_pair_ids = NULL;
    bool* seen_pair_occupied = NULL;
    size_t seen_pair_capacity = 0;

    debug("[RACE-ANALYZE] Using threshold: %llu ns (%llu us)\n", 
          (unsigned long long)TIME_THRESHOLD, (unsigned long long)(TIME_THRESHOLD / 1000));

    if (max_pairs <= 0x1fffffff)
        max_candidates = max_pairs * RACE_PAIR_CANDIDATE_SCAN_MULTIPLIER;
    seen_pair_capacity = next_power_of_two_size((size_t)max_pairs * 4);
    if (prepare_seen_pair_scratch(record_ctx, seen_pair_capacity)) {
        seen_pair_ids = record_ctx->seen_pair_ids;
        seen_pair_occupied = record_ctx->seen_pair_occupied;
        seen_pair_capacity = record_ctx->seen_pair_capacity;
    }

    for (int i = 0; i < record_ctx->record_count &&
         pair_count < max_pairs && candidate_count < max_candidates; i++) {
        for (int j = i + 1; j < record_ctx->record_count &&
             pair_count < max_pairs && candidate_count < max_candidates; j++) {
            AccessRecord* a = &record_ctx->records[i];
            AccessRecord* b = &record_ctx->records[j];

            if (b->access_time >= a->access_time &&
                b->access_time - a->access_time > MAX_THRESHOLD)
                break;

            if (a->tid == b->tid)
                continue;
            if (!(a->access_type == 'W' || b->access_type == 'W'))
                continue;
            if (!access_record_addresses_overlap(a, b))
                continue;

            uint64_t time_diff = (a->access_time > b->access_time) ?
                (a->access_time - b->access_time) : (b->access_time - a->access_time);

            uint64_t threshold = TIME_THRESHOLD;
            if (a->access_type == 'W' && b->access_type == 'W')
                threshold = FAST_THRESHOLD;
            if (time_diff > threshold)
                continue;

            const AccessRecord* first_access = a;
            const AccessRecord* second_access = b;
            if (a->access_time > b->access_time) {
                first_access = b;
                second_access = a;
            }
            uint64_t pair_id = race_pair_id_from_records(first_access, second_access);
            if (seen_pair_ids &&
                seen_pair_id_contains(seen_pair_ids, seen_pair_occupied, seen_pair_capacity, pair_id))
                continue;

            LockStatus lock_status = determine_lock_status(a, b);
            if (lock_status == LOCK_SYNC_WITH_COMMON_LOCK)
                continue;

            if (!access_context_check_data_race_validity(record_ctx, a, b))
                continue;

            candidate_count++;

            RacePair* pair = &pairs[pair_count];
            pair->first = *first_access;
            pair->second = *second_access;
            if (seen_pair_ids &&
                !insert_seen_pair_id(seen_pair_ids, seen_pair_occupied, seen_pair_capacity, pair_id))
                continue;

            pair->access_time_diff = time_diff;
            pair->trigger_counts = 1;
            pair->lock_status = lock_status;

            // Debug: log the tid and access_time from parsed RacePair
            debug("[RACE-ANALYZE] pair[%d] first.tid=%d second.tid=%d first.time=%llu second.time=%llu\n",
                pair_count, pair->first.tid, pair->second.tid,
                (unsigned long long)pair->first.access_time, (unsigned long long)pair->second.access_time);

            pair->thread1_history = NULL;
            pair->thread2_history = NULL;
            pair->first_access_index = -1;
            pair->second_access_index = -1;

            if (record_ctx->enable_history)
                pair->thread1_history = access_context_find_thread(record_ctx, pair->first.tid);
            if (pair->thread1_history) {
                int total_accesses1 = pair->thread1_history->buffer_full ?
                    SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : pair->thread1_history->access_count;
                for (int k = 0; k < total_accesses1; k++) {
                    int actual_index = pair->thread1_history->buffer_full ?
                        (pair->thread1_history->access_index + k) % SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : k;
                    if (pair->thread1_history->accesses[actual_index].access_time == pair->first.access_time &&
                        pair->thread1_history->accesses[actual_index].address == pair->first.address) {
                        pair->first_access_index = actual_index;
                        break;
                    }
                }
            }

            if (record_ctx->enable_history)
                pair->thread2_history = access_context_find_thread(record_ctx, pair->second.tid);
            if (pair->thread2_history) {
                int total_accesses2 = pair->thread2_history->buffer_full ?
                    SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : pair->thread2_history->access_count;
                for (int k = 0; k < total_accesses2; k++) {
                    int actual_index = pair->thread2_history->buffer_full ?
                        (pair->thread2_history->access_index + k) % SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : k;
                    if (pair->thread2_history->accesses[actual_index].access_time == pair->second.access_time &&
                        pair->thread2_history->accesses[actual_index].address == pair->second.address) {
                        pair->second_access_index = actual_index;
                        break;
                    }
                }
            }

            pair_count++;
        }
    }

    return pair_count;
}

// Backward-compatible wrapper: uses the default 10ms threshold
int access_context_analyze_race_pairs(AccessContext* record_ctx, RacePair* pairs, int max_pairs)
{
    return access_context_analyze_race_pairs_with_threshold(record_ctx, pairs, max_pairs, 0);
}

int access_context_analyze_uaf_pairs(AccessContext* record_ctx, UAFPair* uaf_pairs, int max_pairs)
{
    const uint64_t TIME_THRESHOLD = 10000000000ULL;
    int pair_count = 0;

    for (int i = 0; i < record_ctx->record_count && pair_count < max_pairs; i++) {
        AccessRecord* use_access = &record_ctx->records[i];
        AccessRecord* closest_free = NULL;
        uint64_t closest_time_diff = UINT64_MAX;

        for (int j = 0; j < record_ctx->free_count; j++) {
            AccessRecord* free_op = &record_ctx->free_records[j];

            if (use_access->tid == free_op->tid)
                continue;

            uint64_t use_end = use_access->address + use_access->size;
            uint64_t free_end = free_op->address + free_op->size;
            if (!((use_access->address < free_end) && (free_op->address < use_end)))
                continue;

            uint64_t time_diff = free_op->access_time - use_access->access_time;
            if (time_diff > TIME_THRESHOLD)
                continue;

            if (time_diff < closest_time_diff) {
                closest_free = free_op;
                closest_time_diff = time_diff;
            }
        }

        if (closest_free) {
            if (!access_context_check_uaf_validity(record_ctx, use_access, closest_free))
                continue;

            LockStatus lock_status = determine_lock_status(use_access, closest_free);
            if (lock_status == LOCK_SYNC_WITH_COMMON_LOCK)
                continue;
            UAFPair* uaf_pair = &uaf_pairs[pair_count];
            uaf_pair->use_access = *use_access;
            uaf_pair->free_access = *closest_free;
            uaf_pair->time_diff = closest_time_diff;
            uaf_pair->lock_status = lock_status;
            uaf_pair->trigger_count = 1;

            uaf_pair->use_thread_history = access_context_find_thread(record_ctx, use_access->tid);
            uaf_pair->free_thread_history = access_context_find_thread(record_ctx, closest_free->tid);
            uaf_pair->use_access_index = -1;
            uaf_pair->free_access_index = -1;

            if (uaf_pair->use_thread_history) {
                int total_accesses = uaf_pair->use_thread_history->buffer_full ?
                    SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : uaf_pair->use_thread_history->access_count;
                for (int k = 0; k < total_accesses; k++) {
                    int actual_index = uaf_pair->use_thread_history->buffer_full ?
                        (uaf_pair->use_thread_history->access_index + k) % SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : k;
                    if (uaf_pair->use_thread_history->accesses[actual_index].access_time == use_access->access_time &&
                        uaf_pair->use_thread_history->accesses[actual_index].address == use_access->address) {
                        uaf_pair->use_access_index = actual_index;
                        break;
                    }
                }
            }

            if (uaf_pair->free_thread_history) {
                int total_accesses = uaf_pair->free_thread_history->buffer_full ?
                    SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : uaf_pair->free_thread_history->access_count;
                for (int k = 0; k < total_accesses; k++) {
                    int actual_index = uaf_pair->free_thread_history->buffer_full ?
                        (uaf_pair->free_thread_history->access_index + k) % SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM : k;
                    if (uaf_pair->free_thread_history->accesses[actual_index].access_time == closest_free->access_time &&
                        uaf_pair->free_thread_history->accesses[actual_index].address == closest_free->address &&
                        uaf_pair->free_thread_history->accesses[actual_index].access_type == 'F') {
                        uaf_pair->free_access_index = actual_index;
                        break;
                    }
                }
            }

            pair_count++;
        }
    }

    return pair_count;
}

bool access_context_check_data_race_validity(AccessContext* record_ctx, const AccessRecord* a, const AccessRecord* b)
{
    uint64_t min_time = (a->access_time <= b->access_time) ? a->access_time : b->access_time;
    uint64_t max_time = (a->access_time > b->access_time) ? a->access_time : b->access_time;

    for (int i = 0; i < record_ctx->free_count; i++) {
        const AccessRecord* free_rec = &record_ctx->free_records[i];
        if (free_rec->access_time <= min_time)
            continue;
        if (free_rec->access_time >= max_time)
            break;
        if (access_record_addresses_overlap(a, free_rec) || access_record_addresses_overlap(b, free_rec))
            return false;
    }

    return true;
}

bool access_context_check_uaf_validity(AccessContext* record_ctx, const AccessRecord* use_access, const AccessRecord* free_op)
{
    uint64_t use_time = use_access->access_time;
    uint64_t free_time = free_op->access_time;

    for (int i = 0; i < record_ctx->free_count; i++) {
        const AccessRecord* other_free = &record_ctx->free_records[i];
        if (other_free->access_time <= free_time)
            continue;
        if (other_free->access_time >= use_time)
            break;
        if (other_free->access_time == free_time &&
            other_free->address == free_op->address &&
            other_free->tid == free_op->tid)
            continue;

        if (access_record_addresses_overlap(other_free, use_access))
            return false;
    }
    return true;
}

ThreadAccessHistory* access_context_find_thread(AccessContext* record_set, int tid)
{
    for (int i = 0; i < record_set->thread_count; i++) {
        if (record_set->thread_histories[i].tid == tid)
            return &record_set->thread_histories[i];
    }
    return NULL;
}

ThreadAccessHistory* access_context_create_thread_history(AccessContext* record_set, int tid)
{
    if (record_set->thread_count >= MAX_THREADS) {
        debug("Warning: Maximum thread count reached, cannot create history for TID %d\n", tid);
        return NULL;
    }

    ThreadAccessHistory* history = &record_set->thread_histories[record_set->thread_count];
    history->tid = tid;
    history->access_count = 0;
    history->access_index = 0;
    history->buffer_full = false;
    record_set->thread_count++;
    return history;
}

static void debug(const char* fmt, ...)
{
    static int enabled = -1;
    if (enabled < 0)
        enabled = getenv("SYZ_DDRD_DEBUG") != NULL;
    if (!enabled)
        return;
    int err = errno;
    fprintf(stderr, "[access_context]: ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
    errno = err;
}

int access_context_init_from_records(AccessContext* record_ctx, const AccessRecord* records, int input_count, int max_records, int max_frees)
{
    if (!record_ctx || !records || input_count <= 0 || max_records <= 0 || max_frees <= 0)
        return 0;

    int record_count = 0;
    int free_count = 0;
    bool records_sorted = true;
    bool frees_sorted = true;
    uint64_t last_record_time = 0;
    uint64_t last_free_time = 0;

    record_ctx->thread_count = 0;
    if (record_ctx->enable_history && record_ctx->thread_histories) {
        for (int i = 0; i < MAX_THREADS; i++) {
            record_ctx->thread_histories[i].tid = -1;
            record_ctx->thread_histories[i].access_count = 0;
            record_ctx->thread_histories[i].access_index = 0;
            record_ctx->thread_histories[i].buffer_full = false;
        }
    }

    for (int i = 0; i < input_count; i++) {
        const AccessRecord* current = &records[i];
        if (!current->valid)
            continue;

        if (record_ctx->enable_history) {
            ThreadAccessHistory* thread_history = access_context_find_thread(record_ctx, current->tid);
            if (!thread_history)
                thread_history = access_context_create_thread_history(record_ctx, current->tid);
            if (thread_history)
                add_access_to_history(thread_history, current);
        }

        if (current->access_type == 'F' && free_count < max_frees) {
            if (free_count > 0 && current->access_time < last_free_time)
                frees_sorted = false;
            last_free_time = current->access_time;
            record_ctx->free_records[free_count++] = *current;
        } else if (current->access_type != 'F' && record_count < max_records) {
            if (record_count > 0 && current->access_time < last_record_time)
                records_sorted = false;
            last_record_time = current->access_time;
            record_ctx->records[record_count++] = *current;
        }
    }

    if (record_count > 1 && !records_sorted)
        qsort(record_ctx->records, record_count, sizeof(AccessRecord), compare_access_record_time);
    if (free_count > 1 && !frees_sorted)
        qsort(record_ctx->free_records, free_count, sizeof(AccessRecord), compare_access_record_time);

    record_ctx->record_count = record_count;
    record_ctx->free_count = free_count;
    return record_count;
}

int access_context_init_from_buffer(AccessContext* record_ctx, const char* buffer, int max_records, int max_frees)
{
    return parse_access_records_to_set(record_ctx, buffer, max_records, max_frees);
}
