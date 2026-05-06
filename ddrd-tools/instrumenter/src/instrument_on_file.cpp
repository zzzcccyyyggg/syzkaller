#include "instrument_on_file.hpp"
#include "record_bbs.hpp"
#include "record_lock_func.hpp"
#include "record_shared_variable.hpp"
#include "memory_free_instrument.hpp"
#include <iostream>

// 新的函数实现，接受选项结构
void InstrumentOnFile(llvm::Module *mod, const InstrumentationOptions& options) {
    std::cout << "Starting instrumentation with selected options...\n";
    if (options.datarace_only) {
        std::cout << "- Datarace-only mode: function/basic-block/free hooks disabled by default\n";
    }
    
    // 设置自定义函数名（如果指定了的话）
    if (!options.instrumentation_func_name.empty()) {
        std::cout << "- Setting custom memory access function name: " 
                  << options.instrumentation_func_name << "\n";
        SetInstrumentationFuncName(options.instrumentation_func_name);
    }
    
    if (!options.func_enter_name.empty()) {
        std::cout << "- Setting custom function enter name: " 
                  << options.func_enter_name << "\n";
        SetFuncEnterName(options.func_enter_name);
    }
    
    if (!options.func_exit_name.empty()) {
        std::cout << "- Setting custom function exit name: " 
                  << options.func_exit_name << "\n";
        SetFuncExitName(options.func_exit_name);
    }
    
    if (!options.basic_block_name.empty()) {
        std::cout << "- Setting custom basic block function name: " 
                  << options.basic_block_name << "\n";
        SetBasicBlockName(options.basic_block_name);
    }
    
    if (!options.lock_func_name.empty()) {
        std::cout << "- Setting custom lock function name: " 
                  << options.lock_func_name << "\n";
        SetLockFuncName(options.lock_func_name);
    }
    
    if (options.instrument_functions) {
        std::cout << "- Instrumenting function enter/exit...\n";
        RecordFunctionEnterExit(mod);
    }
    
    if (options.instrument_variables) {
        std::cout << "- Instrumenting shared variable access...\n";
        RecordSharedVariableAccess(mod, options.datarace_only);
    }
    
    if (options.instrument_basic_blocks) {
        std::cout << "- Instrumenting basic blocks...\n";
        RecordBBs(mod);
    }
    
    if (options.instrument_locks) {
        std::cout << "- Instrumenting lock operations...\n";
        if (!options.lock_file.empty()) {
            RecordLockPrimitive(mod, const_cast<char*>(options.lock_file.c_str()));
        } else {
            std::cout << "Warning: Lock instrumentation requested but no lock file provided\n";
        }
    }
    
    if (options.instrument_free_funcs) {
        std::cout << "- Instrumenting memory free functions (kfree, kvfree, kmem_cache_free)...\n";
        RecordMemoryFreeFunctions(mod);
    }
    
    std::cout << "Instrumentation completed.\n";
}

// 保留旧的函数实现以向后兼容
void InstrumentOnFile(llvm::Module *mod, std::string lockfile, std::string trylockfile) {
    RecordFunctionEnterExit(mod);
    RecordSharedVariableAccess(mod);
    RecordBBs(mod);
    RecordLockPrimitive(mod, const_cast<char*>(lockfile.c_str()));
}
