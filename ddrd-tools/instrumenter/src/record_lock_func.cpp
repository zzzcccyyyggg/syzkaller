
#include "record_lock_func.hpp"
#include "config.hpp"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Type.h"
#include <fstream>
#include <iostream>
using namespace std;
using namespace llvm;

#ifndef LOCK_REQUIRE
#define LOCK_REQUIRE 1
#endif
#ifndef LOCK_RELEASE
#define LOCK_RELEASE 2
#endif

std::vector<LockPair> mylockpair;
unsigned int HashStr(const std::string &str) { // BKDR Hash Function
    const int seed = 131;
    unsigned int hash = 0;
    for (char c : str) {
        hash = hash * seed + static_cast<unsigned char>(c);
    }
    return hash;
}

// Create words to parameter
Constant *CreateWords(Module *mod, const std::string &str) {
    std::string mystr = "$$$" + std::to_string(HashStr(str));
    GlobalValue *my_name = mod->getNamedValue(mystr);
    ArrayType *ArrayTy = ArrayType::get(IntegerType::get(mod->getContext(), 8), str.length() + 1);
    ConstantInt *const_int = ConstantInt::get(mod->getContext(), APInt(32, 0));
    std::vector<Constant *> const_ptr_indices = {const_int, const_int};
    if (my_name) {
        auto *my_global = cast<GlobalVariable>(my_name);
        return ConstantExpr::getGetElementPtr(ArrayTy, my_global, const_ptr_indices);
    }
    auto *global_name = new GlobalVariable(*mod, ArrayTy, true, GlobalValue::PrivateLinkage, nullptr, mystr);
    global_name->setAlignment(llvm::MaybeAlign(1));
    Constant *const_array = ConstantDataArray::getString(mod->getContext(), str, true);
    global_name->setInitializer(const_array);
    return ConstantExpr::getGetElementPtr(ArrayTy, global_name, const_ptr_indices);
}

// Read pair function from the file
bool ReadLockPairFile(const char *file) {
    std::ifstream in(file);
    if (!in.is_open()) {
        std::cerr << "SDILP: Fail to open lock pair file!" << std::endl;
        return false;
    }
    std::string require, release;
    int attribute;
    while (in >> require >> release >> attribute) {
        mylockpair.emplace_back(require, release, attribute);
    }
    return true;
}
// Declare the extern function:  void rec_lock(char*, int, int, void*);
Function *LockPairInfo(Module *mod) {
    PointerType *PointerChar = PointerType::get(IntegerType::get(mod->getContext(), 8), 0);
    IntegerType *IntTy32 = IntegerType::get(mod->getContext(), 32);
    std::vector<Type *> FuncTy_args = {PointerChar, IntTy32, IntTy32, PointerChar};
    FunctionType *FuncTy = FunctionType::get(Type::getVoidTy(mod->getContext()), FuncTy_args, false);
    Function *func = mod->getFunction(lock_func_name);
    if (!func) {
        func = Function::Create(FuncTy, GlobalValue::ExternalLinkage, lock_func_name, mod);
        func->setCallingConv(CallingConv::C);
    }
    func->setAttributes(AttributeList());
    return func;
}


void RecordLockPrimitive(Module *mod, const char *lockfile) {
    if (!ReadLockPairFile(lockfile))
        return;
    Function *func_lock = LockPairInfo(mod); // 声明插桩函数
    PointerType *PointerVoid = PointerType::get(IntegerType::get(mod->getContext(), 8), 0);
    for (auto &f : *mod) {
        for (auto &bb : f) {
            for (auto it = bb.begin(); it != bb.end(); ++it) {
                Instruction &inst = *it;
                if (!isa<CallInst>(inst)) continue;
                Function *called = cast<CallInst>(inst).getCalledFunction();
                if (!called) continue;
                std::string name = called->getName().str();
                Instruction *MyIn = nullptr;
                int flag = 0, attribute = 0;
                for (const auto &p : mylockpair) {
                    if (name == p.require_func) {
                        flag = LOCK_REQUIRE;
                        MyIn = &inst;
                        attribute = p.lock_attribute;
                        break;
                    } else if (name == p.release_func) {
                        flag = LOCK_RELEASE;
                        MyIn = inst.getNextNode(); // 插桩点放在unlock之后
                        attribute = p.lock_attribute;
                        break;
                    }
                }
                if (!flag || !MyIn) continue;
                Constant *func_name = CreateWords(mod, name);
                Value *func_flag = ConstantInt::get(mod->getContext(), APInt(32, flag));
                Value *func_attribute = ConstantInt::get(mod->getContext(), APInt(32, attribute));
                std::vector<Value *> para = {func_name, func_flag, func_attribute};
                int ops = cast<CallInst>(inst).getNumOperands();
                if (ops != 0) {
                    Value *myvalue = cast<CallInst>(inst).getOperand(0);
                    if (myvalue->getType()->isPointerTy()) {
                        para.push_back(new BitCastInst(myvalue, PointerVoid, "", MyIn));
                    }
                }
                if (para.size() != 4) {
                    para.push_back(Constant::getNullValue(PointerVoid));
                }
                auto *pair_call = CallInst::Create(func_lock, para, "", MyIn);
                pair_call->setCallingConv(CallingConv::C);
                pair_call->setTailCall(false);
            }
        }
    }
}