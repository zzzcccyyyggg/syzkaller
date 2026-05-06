#ifndef INSTRUMENTATION_OPTIONS_HPP
#define INSTRUMENTATION_OPTIONS_HPP
#pragma once

#include <string>

struct InstrumentationOptions {
    bool instrument_functions = false;      // 函数进入退出插桩
    bool instrument_variables = false;      // 共享变量访问插桩
    bool instrument_basic_blocks = false;   // 基本块插桩
    bool instrument_locks = false;          // 锁操作插桩
    bool instrument_free_funcs = false; // Free函数插桩
    bool datarace_only = false;             // datarace-only模式：变量+可选锁，默认禁用函数/BB/free
    std::string lock_file = "";            // 锁配置文件
    std::string trylock_file = "";         // try锁配置文件
    std::string instrumentation_func_name = ""; // 自定义插桩函数名
    std::string func_enter_name = "";      // 自定义函数进入函数名
    std::string func_exit_name = "";       // 自定义函数退出函数名
    std::string basic_block_name = "";     // 自定义基本块函数名
    std::string lock_func_name = "";       // 自定义锁函数名
    std::string free_func_name = "";       // 自定义Free函数名
    
    InstrumentationOptions() = default;
    
    // 检查是否启用了任何插桩
    bool hasAnyInstrumentation() const {
        return instrument_functions || instrument_variables || 
               instrument_basic_blocks || instrument_locks || instrument_free_funcs;
    }
};

// 解析命令行参数
InstrumentationOptions parseCommandLineOptions(int argc, char** argv);

// 打印帮助信息
void printUsage(const char* program_name);

#endif // INSTRUMENTATION_OPTIONS_HPP
