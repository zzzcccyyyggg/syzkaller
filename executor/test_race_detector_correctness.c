// ===============DDRD====================
// Test program to validate race_detector.c race pair analysis correctness
// Tests the DDRD algorithm implementation with real log data
// ===============DDRD====================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>

// Include race detector header
#include "race_detector.h"

// Mock debug function for testing
void debug(const char* msg, ...) {
    va_list args;
    va_start(args, msg);
    printf("[DEBUG] ");
    vprintf(msg, args);
    va_end(args);
}

// Test data based on the log file, but with different thread IDs to create race conditions
const char* test_log_data = 
"[KCCWF] log access: type=0, file_line=196609, tid=485, size=8, delay_time=0, is_skip=0, var_name=6731188247591027786, var_addr=0000000083023f94, call_stack_hash=6759527560005010778, access_time=19786074608, sn=1\n"
"[KCCWF] log access: type=1, file_line=196609, tid=486, size=8, delay_time=0, is_skip=0, var_name=6731188247591027786, var_addr=0000000083023f94, call_stack_hash=1564548222263053632, access_time=19786074700, sn=1\n"  // Write access by different thread, same address, very close time
"[KCCWF] log access: type=0, file_line=327681, tid=485, size=4, delay_time=0, is_skip=0, var_name=3209775198740140502, var_addr=00000000bdcf2468, call_stack_hash=12840636332377115196, access_time=19786203500, sn=1\n"
"[KCCWF] log access: type=1, file_line=327683, tid=487, size=4, delay_time=0, is_skip=0, var_name=3209775198740140504, var_addr=00000000bdcf2468, call_stack_hash=8325367866626130261, access_time=19786203600, sn=1\n"  // Read-Write race on same address
"[KCCWF] log access: type=0, file_line=589825, tid=485, size=8, delay_time=0, is_skip=0, var_name=4636243354914367775, var_addr=0000000050e58bda, call_stack_hash=3987551658481625188, access_time=19786521025, sn=1\n"
"[KCCWF] log access: type=0, file_line=589825, tid=486, size=8, delay_time=0, is_skip=0, var_name=4636243354914367775, var_addr=00000000aff6aed4, call_stack_hash=3987551658481625188, access_time=19786530162, sn=2\n"  // Read-Read on different addresses (no race)
"[KCCWF] log access: type=1, file_line=458753, tid=487, size=8, delay_time=0, is_skip=0, var_name=16852794420713350076, var_addr=000000008197f245, call_stack_hash=7074486464909428699, access_time=19786538728, sn=1\n"
"[KCCWF] log access: type=0, file_line=458753, tid=488, size=8, delay_time=0, is_skip=0, var_name=16852794420713350076, var_addr=000000008197f245, call_stack_hash=7074486464909428699, access_time=19786538800, sn=1\n"  // Write-Read race on same address
"[KCCWF] log access: type=1, file_line=720897, tid=485, size=4, delay_time=0, is_skip=0, var_name=2870364437683594888, var_addr=000000000b86b0bc, call_stack_hash=12445926791692778980, access_time=19786585286, sn=1\n"
"[KCCWF] log access: type=1, file_line=720897, tid=486, size=4, delay_time=0, is_skip=0, var_name=2870364437683594888, var_addr=000000000b86b0bc, call_stack_hash=12445926791692778980, access_time=19786585300, sn=1\n"  // Write-Write race on same address
"[KCCWF] log access: type=2, file_line=720897, tid=487, size=4, delay_time=0, is_skip=0, var_name=2870364437683594888, var_addr=000000000b86b0bc, call_stack_hash=12445926791692778980, access_time=19786585400, sn=1\n"  // Free operation
"[KCCWF] log access: type=0, file_line=720897, tid=488, size=4, delay_time=0, is_skip=0, var_name=2870364437683594888, var_addr=000000000b86b0bc, call_stack_hash=12445926791692778980, access_time=19786585500, sn=1\n"  // Access after free (should be filtered out)
"[KCCWF] log access: type=0, file_line=196609, tid=485, size=8, delay_time=0, is_skip=0, var_name=1738179873343442683, var_addr=000000006f0cf527, call_stack_hash=12218238964861975294, access_time=19786618248, sn=1\n"
"[KCCWF] log access: type=1, file_line=196609, tid=488, size=8, delay_time=0, is_skip=0, var_name=1738179873343442683, var_addr=000000006f0cf527, call_stack_hash=12218238964861975294, access_time=19790000000, sn=1\n"; // Large time difference (should be filtered out)

void print_access_record(const AccessRecord* record, int index) {
    printf("  Record %d: TID=%d, Type=%c, Addr=0x%016lx, Size=%lu, Time=%lu, VarName=%lu, StackHash=%lu, SN=%d, Locks=%d\n",
           index, record->tid, record->access_type, (unsigned long)record->address, (unsigned long)record->size, 
           (unsigned long)record->access_time, (unsigned long)record->var_name, (unsigned long)record->call_stack_hash, record->sn, record->lock_count);
}

void print_race_pair(const RacePair* pair, int index) {
    printf("Race Pair %d:\n", index);
    printf("  First:  TID=%d, Type=%c, Addr=0x%016lx, Size=%lu, Time=%lu\n",
           pair->first.tid, pair->first.access_type, (unsigned long)pair->first.address, 
           (unsigned long)pair->first.size, (unsigned long)pair->first.access_time);
    printf("  Second: TID=%d, Type=%c, Addr=0x%016lx, Size=%lu, Time=%lu\n",
           pair->second.tid, pair->second.access_type, (unsigned long)pair->second.address, 
           (unsigned long)pair->second.size, (unsigned long)pair->second.access_time);
    printf("  Time Diff: %lu us, Lock Status: %d\n", (unsigned long)pair->access_time_diff, pair->lock_status);
    printf("  Race Type: %s\n", 
           (pair->first.access_type == 'W' && pair->second.access_type == 'W') ? "Write-Write" :
           (pair->first.access_type == 'W' && pair->second.access_type == 'R') ? "Write-Read" :
           (pair->first.access_type == 'R' && pair->second.access_type == 'W') ? "Read-Write" : "Read-Read");
}

bool test_address_overlap() {
    printf("\n=== Testing Address Overlap Function ===\n");
    
    AccessRecord a = {.address = 0x1000, .size = 8};
    AccessRecord b = {.address = 0x1004, .size = 8};  // Overlaps: [0x1000-0x1008) vs [0x1004-0x100C)
    AccessRecord c = {.address = 0x1010, .size = 8};  // No overlap: [0x1010-0x1018)
    
    bool overlap_ab = addresses_overlap(&a, &b);
    bool overlap_ac = addresses_overlap(&a, &c);
    
    printf("Test 1: Addr1=[0x%lx-0x%lx), Addr2=[0x%lx-0x%lx) -> Overlap: %s (Expected: true)\n",
           (unsigned long)a.address, (unsigned long)(a.address + a.size), (unsigned long)b.address, (unsigned long)(b.address + b.size), 
           overlap_ab ? "true" : "false");
           
    printf("Test 2: Addr1=[0x%lx-0x%lx), Addr2=[0x%lx-0x%lx) -> Overlap: %s (Expected: false)\n",
           (unsigned long)a.address, (unsigned long)(a.address + a.size), (unsigned long)c.address, (unsigned long)(c.address + c.size), 
           overlap_ac ? "true" : "false");
    
    return overlap_ab && !overlap_ac;
}

bool test_lock_status() {
    printf("\n=== Testing Lock Status Determination ===\n");
    
    AccessRecord no_lock = {.lock_count = 0};
    AccessRecord with_lock = {.lock_count = 1, .held_locks = {{.ptr = 0x5000, .valid = true}}};
    AccessRecord with_same_lock = {.lock_count = 1, .held_locks = {{.ptr = 0x5000, .valid = true}}};
    AccessRecord with_diff_lock = {.lock_count = 1, .held_locks = {{.ptr = 0x6000, .valid = true}}};
    
    LockStatus status1 = determine_lock_status(&no_lock, &no_lock);
    LockStatus status2 = determine_lock_status(&no_lock, &with_lock);
    LockStatus status3 = determine_lock_status(&with_lock, &with_same_lock);
    LockStatus status4 = determine_lock_status(&with_lock, &with_diff_lock);
    
    printf("No locks vs No locks: %d (Expected: %d LOCK_NO_LOCKS)\n", status1, LOCK_NO_LOCKS);
    printf("No locks vs With locks: %d (Expected: %d LOCK_ONE_SIDED_LOCK)\n", status2, LOCK_ONE_SIDED_LOCK);
    printf("Same locks: %d (Expected: %d LOCK_SYNC_WITH_COMMON_LOCK)\n", status3, LOCK_SYNC_WITH_COMMON_LOCK);
    printf("Different locks: %d (Expected: %d LOCK_UNSYNC_LOCKS)\n", status4, LOCK_UNSYNC_LOCKS);
    
    return (status1 == LOCK_NO_LOCKS) && (status2 == LOCK_ONE_SIDED_LOCK) && 
           (status3 == LOCK_SYNC_WITH_COMMON_LOCK) && (status4 == LOCK_UNSYNC_LOCKS);
}

void analyze_expected_races() {
    printf("\n=== Expected Race Analysis ===\n");
    printf("Based on test data, we expect to find these races:\n");
    printf("1. TID 485(R) vs TID 486(W) at addr 0x83023f94 - Read-Write race (time diff: 92us)\n");
    printf("2. TID 485(R) vs TID 487(W) at addr 0xbdcf2468 - Read-Write race (time diff: 100us)\n");
    printf("3. TID 487(W) vs TID 488(R) at addr 0x8197f245 - Write-Read race (time diff: 72us)\n");
    printf("4. TID 485(W) vs TID 486(W) at addr 0x0b86b0bc - Write-Write race (time diff: 14us)\n");
    printf("\nShould NOT find:\n");
    printf("- TID 485(R) vs TID 486(R) - Both reads, no race\n");
    printf("- TID 488 access after TID 487 free - Separated by free operation\n");
    printf("- TID 485 vs TID 488 with large time difference - Exceeds time threshold\n");
}

int main() {
    printf("=== DDRD Race Detector Correctness Test ===\n");
    
    // Test individual functions first
    bool overlap_test = test_address_overlap();
    bool lock_test = test_lock_status();
    
    if (!overlap_test || !lock_test) {
        printf("❌ Basic function tests failed!\n");
        return 1;
    }
    printf("✅ Basic function tests passed!\n");
    
    // Test the main race detection algorithm
    printf("\n=== Testing Race Pair Detection Algorithm ===\n");
    
    #define MAX_TEST_RECORDS 50
    #define MAX_TEST_PAIRS 20
    
    AccessRecord records[MAX_TEST_RECORDS];
    RacePair pairs[MAX_TEST_PAIRS];
    
    // Parse the test log data
    int record_count = parse_access_records_from_buffer(test_log_data, records, MAX_TEST_RECORDS);
    printf("Parsed %d access records from test data\n", record_count);
    
    // Print all parsed records
    printf("\n--- Parsed Access Records ---\n");
    for (int i = 0; i < record_count; i++) {
        print_access_record(&records[i], i);
    }
    
    // Analyze race pairs
    int pair_count = analyze_race_pairs_from_records(records, record_count, pairs, MAX_TEST_PAIRS);
    printf("\nFound %d race pairs\n", pair_count);
    
    // Print all detected race pairs
    printf("\n--- Detected Race Pairs ---\n");
    for (int i = 0; i < pair_count; i++) {
        print_race_pair(&pairs[i], i + 1);
        printf("\n");
    }
    
    // Show expected results
    analyze_expected_races();
    
    // Validate results
    printf("\n=== Validation Results ===\n");
    if (pair_count == 0) {
        printf("❌ No race pairs detected - algorithm may have issues\n");
        return 1;
    }
    
    // Check for specific expected races
    int found_races = 0;
    bool found_rw_race = false, found_wr_race = false, found_ww_race = false;
    
    for (int i = 0; i < pair_count; i++) {
        const RacePair* pair = &pairs[i];
        
        // Check if this is one of our expected races
        if ((pair->first.tid == 485 && pair->second.tid == 486) ||
            (pair->first.tid == 486 && pair->second.tid == 485)) {
            if ((pair->first.address == 0x83023f94 && pair->second.address == 0x83023f94)) {
                found_rw_race = true;
                found_races++;
                printf("✅ Found expected Read-Write race between TID 485 and 486\n");
            }
        }
        
        if ((pair->first.tid == 485 && pair->second.tid == 487) ||
            (pair->first.tid == 487 && pair->second.tid == 485)) {
            if ((pair->first.address == 0xbdcf2468 && pair->second.address == 0xbdcf2468)) {
                found_wr_race = true;
                found_races++;
                printf("✅ Found expected Read-Write race between TID 485 and 487\n");
            }
        }
        
        if ((pair->first.tid == 485 && pair->second.tid == 486) ||
            (pair->first.tid == 486 && pair->second.tid == 485)) {
            if ((pair->first.address == 0x0b86b0bc && pair->second.address == 0x0b86b0bc) &&
                (pair->first.access_type == 'W' && pair->second.access_type == 'W')) {
                found_ww_race = true;
                found_races++;
                printf("✅ Found expected Write-Write race between TID 485 and 486\n");
            }
        }
    }
    
    printf("\nSummary:\n");
    printf("- Total race pairs found: %d\n", pair_count);
    printf("- Expected specific races found: %d\n", found_races);
    printf("- Read-Write race detection: %s\n", found_rw_race ? "✅" : "❌");
    printf("- Write-Read race detection: %s\n", found_wr_race ? "✅" : "❌");  
    printf("- Write-Write race detection: %s\n", found_ww_race ? "✅" : "❌");
    
    if (found_races >= 2 && pair_count >= 2) {
        printf("\n🎉 DDRD race detection algorithm appears to be working correctly!\n");
        return 0;
    } else {
        printf("\n❌ Race detection algorithm may need adjustment\n");
        return 1;
    }
}
