#include "types.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

AccessRecord access_record_init_from_line(const char* line)
{
	AccessRecord record = {0};
	// debug("%s\n", line);
	if (!line || strlen(line) < 20) {
		return record;
	}

	// 查找 "[KCCWF] log access:" 标记
	// 注意：实际日志中可能有 "handle_log_mode: [KCCWF] log access:" 格式
	const char* marker = "[KCCWF] log access:";
	const char* content = strstr(line, marker);
	if (!content) {
		return record;
	}

	content += strlen(marker);

	// 解析各个字段
	const char* pos = content;
	char key[32], value[64];

	while (*pos) {
		// 跳过空格和逗号
		while (*pos == ' ' || *pos == ',')
			pos++;
		if (*pos == '\0')
			break;

		// 解析 key=value 对
		const char* eq = strchr(pos, '=');
		if (!eq)
			break;

		int key_len = eq - pos;
		if (key_len >= sizeof(key))
			key_len = sizeof(key) - 1;
		strncpy(key, pos, key_len);
		key[key_len] = '\0';

		pos = eq + 1;

		// 提取value
		const char* value_end = pos;
		while (*value_end && *value_end != ',' && *value_end != ' ')
			value_end++;

		int value_len = value_end - pos;
		if (value_len >= sizeof(value))
			value_len = sizeof(value) - 1;
		strncpy(value, pos, value_len);
		value[value_len] = '\0';

		// 根据key设置对应字段
		if (strcmp(key, "tid") == 0) {
			record.tid = atoi(value);
		} else if (strcmp(key, "var_name") == 0) {
			record.var_name = strtoull(value, NULL, 10);
		} else if (strcmp(key, "var_addr") == 0) {
			// 地址值通常是十六进制格式（可能有或没有0x前缀）
			if (strncmp(value, "0x", 2) == 0 || strncmp(value, "0X", 2) == 0) {
				record.address = strtoull(value, NULL, 0); // 有0x前缀，自动检测
			} else {
				record.address = strtoull(value, NULL, 16); // 没有0x前缀，强制十六进制
			}
		} else if (strcmp(key, "type") == 0) {
			int type_val = atoi(value);
			record.access_type = (type_val == 1) ? 'W' : (type_val == 2) ? 'F'
										     : 'R';
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

	// 检查是否解析到有效数据
	// 注意：tid 可以是 0（主线程或特殊线程），所以用 >= 0 检查
	if (record.tid >= 0 && record.var_name > 0) {
		record.valid = true;
		record.lock_count = 0; // 初始化锁计数
		// 添加调试输出
		// debug("Parsed access record: tid=%d, var_name=%llu, address=0x%llx, type='%c', size=%llu, time=%llu, sn=%d\n",
		//       record.tid, (unsigned long long)record.var_name, (unsigned long long)record.address, 
		//       record.access_type, (unsigned long long)record.size, (unsigned long long)record.access_time, record.sn);
	}

	return record;
}

bool access_record_addresses_overlap(const AccessRecord* a, const AccessRecord* b)
{
	return (a->address < b->address + b->size) && (b->address < a->address + a->size);
}
