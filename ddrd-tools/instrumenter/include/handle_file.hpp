#ifndef HANDLE_FILE_HPP
#define HANDLE_FILE_HPP
#pragma once

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"

#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"

#include "llvm/Support/Error.h"

#include <string>
#include <iostream>
#include "instrument_on_file.hpp"
#include "instrumentation_options.hpp"

// 新的函数接口，接受选项结构
void HandleFile(const std::string& filein, const InstrumentationOptions& options);

// 保留旧的接口以向后兼容
void HandleFile(std::string filein, std::string lockfile, std::string trylockfile);

void WriteModuleToFile(llvm::Module *mod, std::string file_out);

#endif // HANDLE_FILE_HPP