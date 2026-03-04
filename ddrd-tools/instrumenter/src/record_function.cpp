#include "record_function.hpp"
#include "config.hpp"

// 声明 void rec_func_enter(char* func_name, int32 func_line);
llvm::Function* DeclareEnterFunc(llvm::Module* mod)
{
    // 函数参数和函数声明
    llvm::LLVMContext& Context = mod->getContext();
    // llvm::Type *CharPtrTy = llvm::Type::getInt8PtrTy(Context);
    llvm::Type* Int64Ty = llvm::Type::getInt64Ty(Context);
    llvm::Type* Int32Ty = llvm::Type::getInt32Ty(Context);
    llvm::FunctionType* FuncTy = llvm::FunctionType::get(llvm::Type::getVoidTy(Context), { Int64Ty, Int32Ty }, false);
    // 查找声明，不存在则创建
    llvm::Function* Func = mod->getFunction(func_enter_name);
    if (!Func) {
        llvm::Function* Func = llvm::Function::Create(FuncTy, llvm::Function::ExternalLinkage, func_enter_name, mod);
        Func->setCallingConv(llvm::CallingConv::C);
        // 注意作用域
        return Func;
    }
    return Func;
}

// 声明 void rec_func_exit(char* func_name, int32 func_line);
llvm::Function* DeclareExitFunc(llvm::Module* mod)
{
    // 函数参数和函数声明
    llvm::LLVMContext& Context = mod->getContext();
    // llvm::Type *CharPtrTy = llvm::Type::getInt8PtrTy(Context);
    llvm::Type* Int64Ty = llvm::Type::getInt64Ty(Context);
    llvm::Type* Int32Ty = llvm::Type::getInt32Ty(Context);
    llvm::FunctionType* FuncTy = llvm::FunctionType::get(llvm::Type::getVoidTy(Context), { Int64Ty, Int32Ty }, false);
    // 查找声明，不存在则创建
    llvm::Function* Func = mod->getFunction(func_exit_name);
    if (!Func) {
        llvm::Function* Func = llvm::Function::Create(FuncTy, llvm::Function::ExternalLinkage, func_exit_name, mod);
        Func->setCallingConv(llvm::CallingConv::C);
        // 注意作用域
        return Func;
    }
    return Func;
}

void InsertEnterExit(llvm::Function* func_enter, llvm::Function* func_exit, llvm::Module* mod)
{
    bool isFirstBB = true;
    for (auto& F : *mod) {
        for (auto& BB : F) { // 遍历函数中的所有基本块
            for (auto& I : BB) { // 遍历基本块中的所有指令
                if (auto* CI = llvm::dyn_cast<llvm::CallInst>(&I)) {
                    if (CI->isMustTailCall()) {
                        // 如果这是一个 musttail 调用，就移除这个属性。
                        CI->setTailCallKind(llvm::CallInst::TCK_Tail);
                    }
                }
            }
        }
        isFirstBB = true;
        if (F.getName().str().find("asan") != std::string::npos || F.getName().str().find("llvm") != std::string::npos) {
            // std::cout << "===Function name is asan or llvm==" << std::endl;
            continue;
        }
        for (auto& BB : F) {
            for (auto& I : BB) {
                if (auto* inst = llvm::dyn_cast<llvm::Instruction>(&I)) {
                    if (inst == &BB.front() && isFirstBB) {
                        // 插入函数入口记录
                        llvm::IRBuilder<> builder(&BB, BB.getFirstInsertionPt());
                        std::string func_name_str = F.getName().str();
                        if (func_name_str.empty()) {
                            std::cout << "Function name is empty" << std::endl;
                            continue;
                        }
                        unsigned long func_name = BKDRHash(func_name_str.c_str(), 0);
                        llvm::LLVMContext& context = builder.getContext(); // 获取当前的LLVM上下文
                        llvm::Type* int64Type = llvm::Type::getInt64Ty(context); // 获取64位整数类型
                        llvm::Value* func_name_val = llvm::ConstantInt::get(int64Type, func_name, false);
                        // llvm::Value *func_name_val = builder.getInt64(func_name);
                        // writeToFile("/home/s1eepy/Desktop/HDD/concurrency/QemuKernel/images_6.11-rc2/btrfs/record.txt", func_name_str, func_name);
                        // Something wrong here
                        if (F.hasMetadata()) {
                            llvm::MDNode* md = F.getMetadata("dbg");
                            if (md) {
                                llvm::DISubprogram* loc = llvm::dyn_cast<llvm::DISubprogram>(md);
                                llvm::Value* func_line_val = builder.getInt32(loc->getLine());
                                builder.CreateCall(func_enter, { func_name_val, func_line_val });
                            }
                        } else {
                            llvm::Value* func_line_val = builder.getInt32(0);
                            builder.CreateCall(func_enter, { func_name_val, func_line_val });
                        }
                        isFirstBB = false;
                    }
                }
                if (auto* ret = llvm::dyn_cast<llvm::ReturnInst>(&I)) {
                    // 插入函数出口记录
                    llvm::IRBuilder<> builder(ret);
                    std::string func_name_str = F.getName().str();
                    if (func_name_str.empty()) {
                        std::cout << "Function name is empty" << std::endl;
                        continue;
                    }
                    unsigned long func_name = BKDRHash(func_name_str.c_str(), 0);
                    llvm::Value* func_name_val = builder.getInt64(func_name);
                    if (F.hasMetadata()) {
                        llvm::MDNode* md = F.getMetadata("dbg");
                        if (md) {
                            llvm::DISubprogram* loc = llvm::dyn_cast<llvm::DISubprogram>(md);
                            llvm::Value* func_line_val = builder.getInt32(loc->getLine());
                            builder.CreateCall(func_exit, { func_name_val, func_line_val });
                        }
                    } else {
                        llvm::Value* func_line_val = builder.getInt32(0);
                        builder.CreateCall(func_enter, { func_name_val, func_line_val });
                    }
                }
            }
        }
    }
}

void RecordFunctionEnterExit(llvm::Module* mod)
{
    llvm::Function* func_enter = DeclareEnterFunc(mod);
    llvm::Function* func_exit = DeclareExitFunc(mod);

    InsertEnterExit(func_enter, func_exit, mod);
}