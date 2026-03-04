#include "enable_free_func_rec.hpp"
#include "llvm/IR/Function.h"
#include <set>
#include <string>
std::set<std::string> free_funcs_info;
static void read_free_funcs_info(string path)
{
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) {
        cout << "*** [ERROR] Fail to open free func file ***" << endl;
        return;
    }
    char name[100];
    while (fscanf(fp, "%s", name) != EOF) {
        free_funcs_info.insert(name);
    }
    fclose(fp);
}
llvm::Function* DeclareEnableKccwfFreeRec(llvm::Module *mod) {
    llvm::LLVMContext &Context = mod->getContext();
    llvm::FunctionType *FuncTy = llvm::FunctionType::get(llvm::Type::getVoidTy(Context), {}, false);
    llvm::Function *Func = mod->getFunction("enable_kccwf_free_rec");
    if (!Func) {
        llvm::Function *Func = llvm::Function::Create(FuncTy, llvm::Function::ExternalLinkage, "enable_kccwf_free_rec", mod);
        Func->setCallingConv(llvm::CallingConv::C);
        return Func;
    }
    return Func;
}
llvm::Function* DeclareDisableKccwfFreeRec(llvm::Module *mod) {
    llvm::LLVMContext &Context = mod->getContext();
    llvm::FunctionType *FuncTy = llvm::FunctionType::get(llvm::Type::getVoidTy(Context), {}, false);
    llvm::Function *Func = mod->getFunction("disable_kccwf_free_rec");
    if (!Func) {
        llvm::Function *Func = llvm::Function::Create(FuncTy, llvm::Function::ExternalLinkage, "disable_kccwf_free_rec", mod);
        Func->setCallingConv(llvm::CallingConv::C);
        return Func;
    }
    return Func;
}

void InsertEnableFuncOnfree(llvm::Module* mod,llvm::Function *enable_kccwf_free_rec,llvm::Function *disable_kccwf_free_rec)
{
    for (auto& F : *mod) {
        if (F.getName().str().find("asan") != std::string::npos || F.getName().str().find("llvm") != std::string::npos || F.getName().str().find("kcsan") != std::string::npos) {
            continue;
        }
        for (auto& BB : F) {
            for (auto& I : BB) {
                if (auto* inst = llvm::dyn_cast<llvm::Instruction>(&I)) {
                    if (llvm::CallInst* callInst = llvm::dyn_cast<llvm::CallInst>(inst)) {
                        std::string func_name_str = F.getName().str();
                        llvm::Function* calledFunction = callInst->getCalledFunction();
                        if (!calledFunction) {
                            continue;
                        }
                        std::string calle_funcName = calledFunction->getName().str();
                        if (free_funcs_info.find(calle_funcName) != free_funcs_info.end()) {
                            llvm::IRBuilder<> builder(callInst);
                            llvm::Instruction* next_inst = (llvm::Instruction*)callInst->getNextNode();
                            if (enable_kccwf_free_rec && disable_kccwf_free_rec) {
                                builder.CreateCall(enable_kccwf_free_rec, {});
                                builder.SetInsertPoint(next_inst);
                                builder.CreateCall(disable_kccwf_free_rec, {});
                            }
                        }
                    }
                }
            }
        }
    }
}

void InsertEnableFuncOnfree(llvm::Module* mod)
{
    read_free_funcs_info(FREE_FUNC_INFO_PATH);
    llvm::Function *enable_kccwf_free_rec = DeclareEnableKccwfFreeRec(mod);
    llvm::Function *disable_kccwf_free_rec = DeclareDisableKccwfFreeRec(mod);
    InsertEnableFuncOnfree(mod, enable_kccwf_free_rec, disable_kccwf_free_rec);
}