#include "types.h"

// 添加访问记录到线程历史（环形缓冲区）
void add_access_to_history(ThreadAccessHistory* history, const AccessRecord* access)
{
	if (!history || !access) {
		return;
	}
	
	// 复制访问记录到历史缓冲区
	history->accesses[history->access_index] = *access;
	
	// 更新索引（环形缓冲区）
	history->access_index = (history->access_index + 1) % SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM;
	
	// 更新计数
	if (history->access_count < SINGLE_THREAD_MAX_ACCESS_HISTORY_NUM) {
		history->access_count++;
	} else {
		history->buffer_full = true;
		// debug("Thread history buffer full for TID %d, overwriting oldest records\n", history->tid);
	}
	
	// debug("Added access to history for TID %d: count=%d, index=%d, type='%c'\n", 
	//       history->tid, history->access_count, history->access_index, access->access_type);
}
