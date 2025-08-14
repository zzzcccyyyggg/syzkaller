// ===============DDRD====================
// Simple test to debug the log parsing issue
// ===============DDRD====================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>

#include "race_detector.h"

void debug(const char* msg, ...) {
    va_list args;
    va_start(args, msg);
    printf("[DEBUG] ");
    vprintf(msg, args);
    va_end(args);
}

// Simplified test with one line to debug parsing
const char* simple_test = "[KCCWF] log access: type=0, file_line=196609, tid=485, size=8, delay_time=0, is_skip=0, var_name=6731188247591027786, var_addr=0000000083023f94, call_stack_hash=6759527560005010778, access_time=19786074608, sn=1\n";

int main() {
    printf("=== Debug Log Parsing ===\n");
    printf("Input: %s\n", simple_test);
    
    AccessRecord records[10];
    int count = parse_access_records_from_buffer(simple_test, records, 10);
    
    printf("Parsed %d records\n", count);
    
    if (count > 0) {
        const AccessRecord* r = &records[0];
        printf("Parsed record:\n");
        printf("  TID: %d\n", r->tid);
        printf("  Type: %c\n", r->access_type);
        printf("  Address: 0x%016lx\n", (unsigned long)r->address);
        printf("  Size: %lu\n", (unsigned long)r->size);
        printf("  VarName: %lu\n", (unsigned long)r->var_name);
        printf("  Time: %lu\n", (unsigned long)r->access_time);
        printf("  Valid: %s\n", r->valid ? "true" : "false");
    }
    
    return 0;
}
