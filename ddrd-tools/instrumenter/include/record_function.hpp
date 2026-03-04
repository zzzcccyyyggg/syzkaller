#ifndef RECORD_FUNCTION_HPP
#define RECORD_FUNCTION_HPP
#pragma once

#include <llvm/IR/Module.h>
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DebugInfo.h"

#include "auxiliary.hpp"

llvm::Function* DeclareEnterFunc(llvm::Module *mod);
llvm::Function* DeclareExitFunc(llvm::Module *mod);
void InsertEnterExit(llvm::Function *func_enter, llvm::Function* func_exit, llvm::Module *mod);

/* -------- Extern Interface --------*/
void RecordFunctionEnterExit(llvm::Module *mod);

#endif // RECORD_FUNCTION_HPP