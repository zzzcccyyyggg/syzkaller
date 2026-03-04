#include "record_bbs.hpp"
#include "config.hpp"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"



uint64_t computeBlockHash(const std::string& funcName, int block_serial) {
    std::string key = funcName + ":" + std::to_string(block_serial);
    return BKDRHash(key.c_str(), 0);
}

/// 声明外部函数 void kccwf_rec_bbs(uint64_t hash)
llvm::Function* DeclareRecordBBsFunc(llvm::Module* mod) {
    llvm::LLVMContext& Context = mod->getContext();
    llvm::Type* Int64Ty = llvm::Type::getInt64Ty(Context);
    llvm::FunctionType* FuncTy = llvm::FunctionType::get(
        llvm::Type::getVoidTy(Context), { Int64Ty }, false);

    llvm::Function* Func = mod->getFunction(basic_block_name);
    if (!Func) {
        Func = llvm::Function::Create(FuncTy, llvm::Function::ExternalLinkage,
                                      basic_block_name, mod);
        Func->setCallingConv(llvm::CallingConv::C);
    }
    return Func;
}

void InsertRecBBsFunc(llvm::Function* kccwf_rec_bbs, llvm::Module* mod) {
    for (auto& F : *mod) {
        std::string funcName = F.getName().str();

        // 跳过特殊函数
        if (funcName.find("asan") != std::string::npos ||
            funcName.find("llvm") != std::string::npos ||
            funcName.find("kccwf") != std::string::npos) {
            continue;
        }

        llvm::IRBuilder<> builder(F.getContext());
        int local_bbs_index = 0;

        for (auto& BB : F) {
            llvm::Instruction* insertPt = &*BB.getFirstInsertionPt();
            builder.SetInsertPoint(insertPt);

            int index = local_bbs_index++;
            uint64_t bbHash = computeBlockHash(funcName, index);

            llvm::LLVMContext& context = builder.getContext();
            llvm::Value* bb_hash_val = llvm::ConstantInt::get(
                llvm::Type::getInt64Ty(context), bbHash);

            builder.CreateCall(kccwf_rec_bbs, { bb_hash_val});
        }
    }
}

void RecordBBs(llvm::Module* mod) {
    llvm::Function* kccwf_rec_bbs = DeclareRecordBBsFunc(mod);
    InsertRecBBsFunc(kccwf_rec_bbs, mod);
}
