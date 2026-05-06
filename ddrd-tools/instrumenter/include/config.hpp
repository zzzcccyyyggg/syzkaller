#ifndef CCWF_CONFIG_HPP
#define CCWF_CONFIG_HPP

#include <map>
#include <string>

#define INSERT_INFO_PATH "/home/zzzccc/BASS/DDRD-syzkaller/ddrd-tools/instrumenter/insert_info.txt"

// 默认插桩函数名称，可以通过配置修改
#ifndef INSTRUMENTATION_FUNC_NAME
#define INSTRUMENTATION_FUNC_NAME "kccwf_rec_mem_access"
#endif

#ifndef FUNC_ENTER_NAME
#define FUNC_ENTER_NAME "kccwf_rec_func_enter"
#endif

#ifndef FUNC_EXIT_NAME
#define FUNC_EXIT_NAME "kccwf_rec_func_exit"
#endif

#ifndef BASIC_BLOCK_NAME
#define BASIC_BLOCK_NAME "kccwf_rec_bbs"
#endif

#ifndef LOCK_FUNC_NAME
#define LOCK_FUNC_NAME "rec_lock"
#endif

#ifndef MEMORY_FREE_FUNC_NAME
#define MEMORY_FREE_FUNC_NAME "kccwf_rec_memory_free"
#endif

#ifndef MEMORY_FREE_AFTER_FUNC_NAME
#define MEMORY_FREE_AFTER_FUNC_NAME "kccwf_rec_memory_free_after"
#endif

// 是否启用内存释放函数的模糊匹配（匹配所有包含"free"的函数）
#ifndef ENABLE_FUZZY_FREE_MATCH
#define ENABLE_FUZZY_FREE_MATCH true
#endif

#define IR_INSTRUCTIONS 0
#define FUNCTION_CALL 1


struct InsertInfo {
    int target_kind;         // 插桩目标类型：FUNCTION_CALL 或 IR_INSTRUCTIONS_TYPE
    int access_type;         // 访问类型：READ / WRITE
    int operand_index;       // 被插桩函数或指令中待记录的参数索引
    int insertion_offset;    // 插入点相对位置：从匹配指令向后偏移几条指令后插入
};

extern std::map<std::string, InsertInfo> insert_info_local_map;

// 可配置的插桩函数名
extern std::string instrumentation_func_name;
extern std::string func_enter_name;
extern std::string func_exit_name;
extern std::string basic_block_name;
extern std::string lock_func_name;
extern std::string memory_free_func_name;

#endif
