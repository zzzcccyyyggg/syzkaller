#include "types.h"
#include "utils.h"

LockRecord parse_lock_line(const char* line)
{
	LockRecord lock = {0};

	if (!line) {
		return lock;
	}

	// 查找 "Held Lock:" 标记
	const char* marker = "Held Lock:";
	const char* content = strstr(line, marker);
	if (!content) {
		return lock;
	}

	content += strlen(marker);

	// 解析name='...'
	const char* name_start = strstr(content, "name='");
	if (name_start) {
		name_start += 6; // 跳过 "name='"
		const char* name_end = strchr(name_start, '\'');
		if (name_end) {
			int name_len = name_end - name_start;
			if (name_len >= sizeof(lock.name))
				name_len = sizeof(lock.name) - 1;
			strncpy(lock.name, name_start, name_len);
			lock.name[name_len] = '\0';
		}
	}

	// 解析ptr=0x...
	const char* ptr_pos = strstr(content, "ptr=");
	if (ptr_pos) {
		lock.ptr = strtoull(ptr_pos + 4, NULL, 0);
	}

	// 解析attr=...
	const char* attr_pos = strstr(content, "attr=");
	if (attr_pos) {
		lock.attr = atoi(attr_pos + 5);
	}

	if (strlen(lock.name) > 0 || lock.ptr > 0) {
		lock.valid = true;
	}

	return lock;
}

LockStatus determine_lock_status(const AccessRecord* a, const AccessRecord* b)
{
	if (a->lock_count == 0 && b->lock_count == 0) {
		return LOCK_NO_LOCKS;
	}

	if (a->lock_count == 0 || b->lock_count == 0) {
		return LOCK_ONE_SIDED_LOCK;
	}

	// 检查是否有公共锁
	for (int i = 0; i < a->lock_count; i++) {
		for (int j = 0; j < b->lock_count; j++) {
			if (a->held_locks[i].ptr == b->held_locks[j].ptr) {
				return LOCK_SYNC_WITH_COMMON_LOCK;
			}
		}
	}

	return LOCK_UNSYNC_LOCKS;
}