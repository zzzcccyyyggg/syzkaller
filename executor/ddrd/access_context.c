#include "types.h"
#include "utils.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void debug(const char* fmt, ...);

int parse_access_records_to_set(AccessContext* record_ctx, const char* buffer, int max_records, int max_frees)
{
    if (!buffer || !record_ctx || max_records <= 0 || max_frees <= 0)
        return 0;

    int record_count = 0;
    int free_count = 0;

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

                if (current_record.access_type == 'F') {
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
                    free_count++;
                } else {
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
            free_count++;
        } else if (current_record.access_type != 'F' && record_count < max_records) {
            record_ctx->records[record_count++] = current_record;
        }
    }

    record_ctx->record_count = record_count;
    record_ctx->free_count = free_count;

    free(buffer_copy);
    return record_count;
}

int access_context_analyze_race_pairs(AccessContext* record_ctx, RacePair* pairs, int max_pairs)
{
    const uint64_t TIME_THRESHOLD = 1000000;
    const uint64_t FAST_THRESHOLD = 100000;
    int pair_count = 0;

    for (int i = 0; i < record_ctx->record_count && pair_count < max_pairs; i++) {
        for (int j = i + 1; j < record_ctx->record_count && pair_count < max_pairs; j++) {
            AccessRecord* a = &record_ctx->records[i];
            AccessRecord* b = &record_ctx->records[j];

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

            if (!access_context_check_data_race_validity(record_ctx, a, b))
                continue;

            LockStatus lock_status = determine_lock_status(a, b);
            RacePair* pair = &pairs[pair_count];
            if (a->access_time <= b->access_time) {
                pair->first = *a;
                pair->second = *b;
            } else {
                pair->first = *b;
                pair->second = *a;
            }
            pair->access_time_diff = time_diff;
            pair->trigger_counts = 1;
            pair->lock_status = lock_status;

            pair->thread1_history = access_context_find_thread(record_ctx, pair->first.tid);
            pair->thread2_history = access_context_find_thread(record_ctx, pair->second.tid);
            pair->first_access_index = -1;
            pair->second_access_index = -1;

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
        if (free_rec->access_time > min_time && free_rec->access_time < max_time) {
            if (access_record_addresses_overlap(a, free_rec) || access_record_addresses_overlap(b, free_rec))
                return false;
        }
    }

    return true;
}

bool access_context_check_uaf_validity(AccessContext* record_ctx, const AccessRecord* use_access, const AccessRecord* free_op)
{
    uint64_t use_time = use_access->access_time;
    uint64_t free_time = free_op->access_time;

    for (int i = 0; i < record_ctx->free_count; i++) {
        const AccessRecord* other_free = &record_ctx->free_records[i];
        if (other_free->access_time == free_time &&
            other_free->address == free_op->address &&
            other_free->tid == free_op->tid)
            continue;

        if (other_free->access_time > free_time && other_free->access_time < use_time) {
            if (access_record_addresses_overlap(other_free, use_access))
                return false;
        }
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
    int err = errno;
    fprintf(stderr, "[access_context]: ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
    errno = err;
}

int access_context_init_from_buffer(AccessContext* record_ctx, const char* buffer, int max_records, int max_frees)
{
    return parse_access_records_to_set(record_ctx, buffer, max_records, max_frees);
}
