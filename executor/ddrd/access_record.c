#include "types.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

AccessRecord access_record_init_from_line(const char* line)
{
    AccessRecord record = {0};
    if (!line || strlen(line) < 20)
        return record;

    const char* marker = "[KCCWF] log access:";
    const char* content = strstr(line, marker);
    if (!content)
        return record;

    content += strlen(marker);

    const char* pos = content;
    char key[32];
    char value[64];

    while (*pos) {
        while (*pos == ' ' || *pos == ',')
            pos++;
        if (*pos == '\0')
            break;

        const char* eq = strchr(pos, '=');
        if (!eq)
            break;

        int key_len = eq - pos;
        if (key_len >= (int)sizeof(key))
            key_len = sizeof(key) - 1;
        memcpy(key, pos, key_len);
        key[key_len] = '\0';

        pos = eq + 1;

        const char* value_end = pos;
        while (*value_end && *value_end != ',' && *value_end != ' ')
            value_end++;

        int value_len = value_end - pos;
        if (value_len >= (int)sizeof(value))
            value_len = sizeof(value) - 1;
        memcpy(value, pos, value_len);
        value[value_len] = '\0';

        if (strcmp(key, "tid") == 0) {
            record.tid = atoi(value);
        } else if (strcmp(key, "var_name") == 0) {
            record.var_name = strtoull(value, NULL, 10);
        } else if (strcmp(key, "var_addr") == 0) {
            if (strncmp(value, "0x", 2) == 0 || strncmp(value, "0X", 2) == 0)
                record.address = strtoull(value, NULL, 0);
            else
                record.address = strtoull(value, NULL, 16);
        } else if (strcmp(key, "type") == 0) {
            int type_val = atoi(value);
            record.access_type = (type_val == 1) ? 'W' : (type_val == 2) ? 'F' : 'R';
        } else if (strcmp(key, "size") == 0) {
            record.size = strtoull(value, NULL, 10);
        } else if (strcmp(key, "call_stack_hash") == 0) {
            record.call_stack_hash = strtoull(value, NULL, 10);
        } else if (strcmp(key, "access_time") == 0) {
            record.access_time = strtoull(value, NULL, 10);
        } else if (strcmp(key, "sn") == 0) {
            record.sn = atoi(value);
        }

        pos = value_end;
    }

    if (record.tid >= 0 && record.var_name > 0) {
        record.valid = true;
        record.lock_count = 0;
    }

    return record;
}

bool access_record_addresses_overlap(const AccessRecord* a, const AccessRecord* b)
{
    return (a->address < b->address + b->size) && (b->address < a->address + a->size);
}
