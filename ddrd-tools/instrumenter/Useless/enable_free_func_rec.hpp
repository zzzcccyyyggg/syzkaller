#ifndef RECORD_ENABLE_FREE_FUNC_HPP
#define RECORD_ENABLE_FREE_FUNC_HPP
#pragma once
#define FREE_FUNC_INFO_PATH "/home/zzzccc/CCWF/instrumenter/free_func_info.txt"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Type.h"

#include "auxiliary.hpp"
#include "race.h"
#include "taint_analysis.hpp"
llvm::Function* DeclareEnableKccwfFreeRec(llvm::Module *mod);
llvm::Function* DeclareDisableKccwfFreeRec(llvm::Module *mod);
void InsertEnableFuncOnfree(llvm::Module* mod,llvm::Function *enable_kccwf_free_rec,llvm::Function *disable_kccwf_free_rec);
void InsertEnableFuncOnfree(llvm::Module* mod);
#endif // RECORD_SHARED_VARIABLE_HPP