#include "memory_free_instrument.hpp"
#include "config.hpp"
#include <cstdint>

// 内存释放函数名称集合（精确匹配列表）
std::set<std::string> memory_free_functions = {
    "kfree",
    "kvfree", 
    "kmem_cache_free"
};

// 插桩函数名称
std::string memory_free_func_name = MEMORY_FREE_FUNC_NAME;
std::string memory_free_after_func_name = MEMORY_FREE_AFTER_FUNC_NAME;

// 是否启用模糊匹配（匹配所有包含"free"的函数）
bool enable_fuzzy_free_match = ENABLE_FUZZY_FREE_MATCH;

// 声明插桩函数 void kccwf_rec_memory_free(uint64_t identifier);
llvm::Function* DeclareMemoryFreeFunc(llvm::Module* mod)
{
    llvm::LLVMContext& Context = mod->getContext();
    llvm::Type* Int64Ty = llvm::Type::getInt64Ty(Context);
    llvm::FunctionType* FuncTy = llvm::FunctionType::get(
        llvm::Type::getVoidTy(Context), 
        { Int64Ty }, 
        false
    );
    
    // 查找声明，不存在则创建
    llvm::Function* Func = mod->getFunction(memory_free_func_name);
    if (!Func) {
        Func = llvm::Function::Create(
            FuncTy, 
            llvm::Function::ExternalLinkage, 
            memory_free_func_name, 
            mod
        );
        Func->setCallingConv(llvm::CallingConv::C);
    }
    return Func;
}

// 声明插桩函数 void kccwf_rec_memory_free_after(uint64_t identifier);
llvm::Function* DeclareMemoryFreeAfterFunc(llvm::Module* mod)
{
    llvm::LLVMContext& Context = mod->getContext();
    llvm::Type* Int64Ty = llvm::Type::getInt64Ty(Context);
    llvm::FunctionType* FuncTy = llvm::FunctionType::get(
        llvm::Type::getVoidTy(Context), 
        { Int64Ty }, 
        false
    );
    
    // 查找声明，不存在则创建
    llvm::Function* Func = mod->getFunction(memory_free_after_func_name);
    if (!Func) {
        Func = llvm::Function::Create(
            FuncTy, 
            llvm::Function::ExternalLinkage, 
            memory_free_after_func_name, 
            mod
        );
        Func->setCallingConv(llvm::CallingConv::C);
    }
    return Func;
}

// 检查函数调用是否为内存释放函数
bool IsMemoryFreeFunction(llvm::CallInst *CI)
{
    if (!CI) return false;
    
    llvm::Function* calledFunc = CI->getCalledFunction();
    if (!calledFunc) return false;
    
    std::string funcName = calledFunc->getName().str();
    
    // 过滤掉我们自己插入的插桩函数，防止死循环
    if (funcName == memory_free_func_name || funcName == memory_free_after_func_name) {
        return false;
    }
    
    // 先检查精确匹配
    if (memory_free_functions.find(funcName) != memory_free_functions.end()) {
        return true;
    }
    
    // 如果启用了模糊匹配，检查是否包含 "free" 关键字
    if (enable_fuzzy_free_match) {
        return funcName.find("free") != std::string::npos;
    }
    
    return false;
}

// 为内存释放函数插入插桩代码
void InstrumentMemoryFreeCall(llvm::CallInst *CI, llvm::Function *free_func, llvm::Function *free_after_func)
{
    if (!CI || !free_func || !free_after_func) return;
    
    // 生成唯一标识符 (基于函数名和指令位置的哈希)
    std::string func_name = CI->getFunction()->getName().str();
    std::string call_info = func_name + "_" + CI->getCalledFunction()->getName().str();
    
    // 获取调试信息中的行号（如果有）
    unsigned line_number = 0;
    if (auto* debug_loc = CI->getDebugLoc().get()) {
        line_number = debug_loc->getLine();
        call_info += "_line_" + std::to_string(line_number);
    }
    
    // 计算哈希值作为唯一标识符
    uint64_t identifier = BKDRHash(call_info.c_str(), 0);
    
    llvm::LLVMContext& context = CI->getContext();
    llvm::Type* uint64Type = llvm::Type::getInt64Ty(context);
    llvm::Value* identifier_val = llvm::ConstantInt::get(uint64Type, identifier, false);
    
    // 在调用指令前插入插桩代码
    llvm::IRBuilder<> builder_before(CI);
    builder_before.CreateCall(free_func, { identifier_val });
    
    // 在调用指令后插入插桩代码
    llvm::IRBuilder<> builder_after(CI);
    builder_after.SetInsertPoint(CI->getNextNode());
    builder_after.CreateCall(free_after_func, { identifier_val });
}

// 遍历模块并插桩所有内存释放函数调用
void InstrumentMemoryFreeFunctions(llvm::Module *mod)
{
    if (!mod) return;
    
    // 声明插桩函数
    llvm::Function* free_func = DeclareMemoryFreeFunc(mod);
    llvm::Function* free_after_func = DeclareMemoryFreeAfterFunc(mod);
    
    // 遍历所有函数
    for (auto& F : *mod) {
        // 跳过 asan 和 llvm 内部函数
        if (F.getName().str().find("asan") != std::string::npos || 
            F.getName().str().find("llvm") != std::string::npos) {
            continue;
        }
        
        // 遍历所有基本块
        for (auto& BB : F) {
            // 遍历所有指令
            for (auto& I : BB) {
                if (auto* CI = llvm::dyn_cast<llvm::CallInst>(&I)) {
                    // 检查是否为内存释放函数调用
                    if (IsMemoryFreeFunction(CI)) {
                        InstrumentMemoryFreeCall(CI, free_func, free_after_func);
                    }
                }
            }
        }
    }
}

// 外部接口函数
void RecordMemoryFreeFunctions(llvm::Module *mod)
{
    InstrumentMemoryFreeFunctions(mod);
}
