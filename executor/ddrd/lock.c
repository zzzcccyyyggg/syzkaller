#include "types.h"

#include <stdlib.h>
#include <string.h>

LockRecord parse_lock_line(const char* line)
{
    LockRecord lock;
    memset(&lock, 0, sizeof(lock));
    if (!line)
        return lock;

    const char* marker = "Held Lock:";
    const char* content = strstr(line, marker);
    if (!content)
        return lock;

    content += strlen(marker);

    const char* name_start = strstr(content, "name='");
    if (name_start) {
        name_start += 6;
        const char* name_end = strchr(name_start, '\'');
        if (name_end) {
            int name_len = name_end - name_start;
            if (name_len >= (int)sizeof(lock.name))
                name_len = sizeof(lock.name) - 1;
            memcpy(lock.name, name_start, name_len);
            lock.name[name_len] = '\0';
        }
    }

    const char* ptr_pos = strstr(content, "ptr=");
    if (ptr_pos) {
        const char* ptr_value = ptr_pos + 4;
        if (strncmp(ptr_value, "0x", 2) == 0 || strncmp(ptr_value, "0X", 2) == 0)
            lock.ptr = strtoull(ptr_value, NULL, 0);
        else
            lock.ptr = strtoull(ptr_value, NULL, 16);
    }

    const char* attr_pos = strstr(content, "attr=");
    if (attr_pos)
        lock.attr = atoi(attr_pos + 5);

    if (lock.name[0] != '\0' || lock.ptr > 0)
        lock.valid = true;

    return lock;
}

static bool has_lock(const AccessRecord* rec)
{
    return rec && rec->lock_count > 0;
}

static bool share_common_lock(const AccessRecord* a, const AccessRecord* b)
{
    for (int i = 0; i < a->lock_count; i++) {
        for (int j = 0; j < b->lock_count; j++) {
            if (a->held_locks[i].ptr == b->held_locks[j].ptr)
                return true;
        }
    }
    return false;
}

LockStatus determine_lock_status(const AccessRecord* a, const AccessRecord* b)
{
    if (!has_lock(a) && !has_lock(b))
        return LOCK_NO_LOCKS;

    if (has_lock(a) && has_lock(b))
        return share_common_lock(a, b) ? LOCK_SYNC_WITH_COMMON_LOCK : LOCK_UNSYNC_LOCKS;

    if (has_lock(a))
        return LOCK_FIRST_HAS_LOCKS;

    return LOCK_SECOND_HAS_LOCKS;
}
