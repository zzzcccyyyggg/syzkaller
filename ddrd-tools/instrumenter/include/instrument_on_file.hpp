#ifndef INSTRUMENT_ON_FILE_HPP
#define INSTRUMENT_ON_FILE_HPP
#pragma once

#include <llvm/IR/Module.h>

#include "record_function.hpp"
#include "record_shared_variable.hpp"
#include "instrumentation_options.hpp"


/* -------- Extern Interface --------*/
// 新的接口，接受选项结构
void InstrumentOnFile(llvm::Module *mod, const InstrumentationOptions& options);

// 保留旧的接口以向后兼容
void InstrumentOnFile(llvm::Module *mod, std::string lockfile, std::string trylockfile);

#endif // INSTRUMENT_ON_FILE_HPP