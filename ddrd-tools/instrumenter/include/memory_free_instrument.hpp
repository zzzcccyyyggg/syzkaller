#ifndef MEMORY_FREE_INSTRUMENT_HPP
#define MEMORY_FREE_INSTRUMENT_HPP
#pragma once

#include <llvm/IR/Module.h>
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DebugInfo.h"
#include <set>
#include <string>

#include "auxiliary.hpp"

// 内存释放函数名称集合
extern std::set<std::string> memory_free_functions;

// 插桩函数名称
#ifndef MEMORY_FREE_FUNC_NAME
#define MEMORY_FREE_FUNC_NAME "kccwf_rec_free"
#endif

extern std::string memory_free_func_name;
extern std::string memory_free_after_func_name;
extern bool enable_fuzzy_free_match;

// 声明内存释放插桩函数
llvm::Function* DeclareMemoryFreeFunc(llvm::Module *mod);
llvm::Function* DeclareMemoryFreeAfterFunc(llvm::Module *mod);

// 检查函数调用是否为内存释放函数
bool IsMemoryFreeFunction(llvm::CallInst *CI);

// 为内存释放函数插入插桩代码
void InstrumentMemoryFreeCall(llvm::CallInst *CI, llvm::Function *free_func, llvm::Function *free_after_func);

// 遍历模块并插桩所有内存释放函数调用
void InstrumentMemoryFreeFunctions(llvm::Module *mod);

/* -------- Extern Interface --------*/
void RecordMemoryFreeFunctions(llvm::Module *mod);

#endif // MEMORY_FREE_INSTRUMENT_HPP
