#ifndef RECORD_BLOCKS_HPP
#define RECORD_BLOCKS_HPP
#pragma once

#include <llvm/IR/Module.h>
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DebugInfo.h"

#include "auxiliary.hpp"

void RecordBBs(llvm::Module *mod);

#endif // RECORD_FUNCTION_HPP