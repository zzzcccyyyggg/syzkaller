#ifndef KCCWF_TRACE_UAPI_H
#define KCCWF_TRACE_UAPI_H

#include <stdint.h>

#define KCCWF_TRACE_RECORD_VERSION 1
#define KCCWF_TRACE_MAX_LOCKS 8
#define KCCWF_TRACE_ACCESS_READ 0
#define KCCWF_TRACE_ACCESS_WRITE 1
#define KCCWF_TRACE_ACCESS_FREE 2

typedef struct {
	uint64_t ptr;
	int32_t attr;
	int32_t reserved;
} kccwf_trace_lock_record_t;

typedef struct {
	uint32_t version;
	uint8_t access_type;
	uint8_t lock_count;
	uint16_t size;
	int32_t tid;
	int32_t sn;
	int32_t file_line;
	uint64_t var_name;
	uint64_t var_addr;
	uint64_t call_stack_hash;
	uint64_t access_time;
	kccwf_trace_lock_record_t locks[KCCWF_TRACE_MAX_LOCKS];
} kccwf_trace_record_t;

typedef struct {
	uint32_t version;
	uint32_t capacity;
	uint32_t count;
	uint32_t dropped;
	uint32_t record_size;
	uint32_t flags;
	uint64_t write_seq;
	uint64_t records;
} kccwf_trace_read_t;

#endif /* KCCWF_TRACE_UAPI_H */
