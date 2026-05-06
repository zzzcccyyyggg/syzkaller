#ifndef RECORD_SHARED_VARIABLE_HPP
#define RECORD_SHARED_VARIABLE_HPP
#pragma once
#define TAINT_ANALYSIS 1

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Type.h"

#include "auxiliary.hpp"
#include "config.hpp"
#include "taint_analysis.hpp"

#include <vector>
#include <string>
#include <map>

/* -------- Extern Interface --------*/
void RecordSharedVariableAccess(llvm::Module *mod, bool access_first = false);

// 设置插桩函数名称
void SetInstrumentationFuncName(const std::string& func_name);
void SetFuncEnterName(const std::string& func_name);
void SetFuncExitName(const std::string& func_name);
void SetBasicBlockName(const std::string& func_name);
void SetLockFuncName(const std::string& func_name);

#endif // RECORD_SHARED_VARIABLE_HPP
