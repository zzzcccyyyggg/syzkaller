#include "types.h"

void add_access_to_history(ThreadAccessHistory* history, const AccessRecord* access)
{
    if (!history || !access)
        return;

    history->accesses[history->access_index] = *access;
    history->access_index = (history->access_index + 1) % SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM;

    if (history->access_count < SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM) {
        history->access_count++;
    } else {
        history->buffer_full = true;
    }
}
