#include "record_shared_variable.hpp"
#include "auxiliary.hpp"
#include "config.hpp"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/raw_ostream.h"
#include <iostream>
#include <string>
#include <map>
#include <set>

// ==================== 全局变量 ====================

// 序列号生成相关变量
static int block_serial_number = 0;
static int instruction_serial_number = 0;

// 统计插桩次数
static int record_count = 0;

// 插桩配置信息映射表
std::map<std::string, InsertInfo> insert_info_local_map;

// 可配置的插桩函数名，默认为对应的宏定义值
std::string instrumentation_func_name = INSTRUMENTATION_FUNC_NAME;
std::string func_enter_name = FUNC_ENTER_NAME;
std::string func_exit_name = FUNC_EXIT_NAME;
std::string basic_block_name = BASIC_BLOCK_NAME;
std::string lock_func_name = LOCK_FUNC_NAME;

// ==================== 工具函数 ====================

/**
 * @brief 生成IR指令在函数中的唯一序列号
 * @param block_serial_number 基本块序号
 * @param instruction_serial_number 指令序号
 * @return 唯一序列号（高16位为基本块序号，低16位为指令序号）
 */
static unsigned int get_serial_number_in_ir(int block_serial_number, int instruction_serial_number)
{
    return ((block_serial_number & 0xffff) << 16) | (instruction_serial_number & 0xffff);
}

/**
 * @brief 计算函数和指令位置的哈希值
 * @param funcName 函数名
 * @param ir_serial IR序列号
 * @return 哈希值
 */
uint64_t computeFuncHash(const std::string& funcName, int ir_serial)
{
    std::string line_str = std::to_string(ir_serial);
    return BKDRHash((funcName + ":" + line_str).c_str(), 0);
}

/**
 * @brief 获取指令类型的字符串表示
 * @param I LLVM指令指针
 * @return 指令类型字符串
 */
std::string getInstructionTypeAsString(llvm::Instruction* I)
{
    if (llvm::isa<llvm::StoreInst>(I)) {
        return "StoreInst";
    } else if (llvm::isa<llvm::LoadInst>(I)) {
        return "LoadInst";
    } else if (llvm::isa<llvm::CallInst>(I)) {
        return "CallInst";
    } else if (llvm::isa<llvm::AllocaInst>(I)) {
        return "AllocaInst";
    } else {
        return "UnknownType";
    }
}

// ==================== LLVM相关函数 ====================

/**
 * @brief 声明内存访问记录函数
 * @param mod LLVM模块
 * @return 声明的函数指针
 */
static llvm::Function* DeclareMemRec(llvm::Module* mod)
{
    llvm::LLVMContext& context = mod->getContext();
    llvm::Type* VoidPtrTy = llvm::PointerType::get(context, 0); // void* 类型 (opaque pointer)
    llvm::Type* Int32Ty = llvm::Type::getInt32Ty(context);      // int 类型
    llvm::Type* Int64Ty = llvm::Type::getInt64Ty(context);      // int64 类型

    // 创建函数类型：void rec_mem_access(void*, int64, int, int, int)
    llvm::FunctionType* FuncTy = llvm::FunctionType::get(
        llvm::Type::getVoidTy(context), 
        { VoidPtrTy, Int64Ty, Int32Ty, Int32Ty, Int32Ty }, 
        false
    );
    
    std::string func_name = instrumentation_func_name;
    llvm::Function* Func = mod->getFunction(func_name);
    if (!Func) {
        Func = llvm::Function::Create(FuncTy, llvm::Function::ExternalLinkage, func_name, mod);
        Func->setCallingConv(llvm::CallingConv::C);
    }
    
    return Func;
}

/**
 * @brief 生成插桩调用
 * @param builder IR构建器
 * @param recFunc 记录函数
 * @param ptr 内存指针
 * @param func_hash 函数哈希值
 * @param is_write 是否为写操作
 * @param line 行号
 * @param size_bytes 访问大小（字节）
 */
void emitInstrumentationCall(
    llvm::IRBuilder<>& builder,
    llvm::Function* recFunc,
    llvm::Value* ptr,
    uint64_t func_hash,
    int is_write,
    int line,
    int size_bytes)
{
    llvm::LLVMContext& ctx = builder.getContext();
    
    // 在LLVM-18中，所有指针都是opaque pointers，不需要bitcast
    llvm::Value* ptr_cast = ptr;
    llvm::Value* hash_val = llvm::ConstantInt::get(llvm::Type::getInt64Ty(ctx), func_hash);
    llvm::Value* type_val = llvm::ConstantInt::get(llvm::Type::getInt32Ty(ctx), is_write);
    llvm::Value* line_val = llvm::ConstantInt::get(llvm::Type::getInt32Ty(ctx), line);
    llvm::Value* size_val = llvm::ConstantInt::get(llvm::Type::getInt32Ty(ctx), size_bytes);
    
    builder.CreateCall(recFunc, { ptr_cast, hash_val, type_val, line_val, size_val });
}






// ==================== 辅助函数 ====================

/**
 * @brief 检查函数是否应该被跳过
 * @param funcName 函数名
 * @return 是否跳过
 */
static bool shouldSkipFunction(const std::string& funcName)
{
    return funcName.find("asan") != std::string::npos ||
           funcName.find("llvm") != std::string::npos ||
           funcName.find("kcsan") != std::string::npos;
}

/**
 * @brief 处理函数调用指令的插桩
 * @param callInst 调用指令
 * @param recFunc 记录函数
 * @param funcName 当前函数名
 * @return 是否成功插桩
 */
static bool processCallInstruction(
    llvm::CallInst* callInst,
    llvm::Function* recFunc,
    const std::string& funcName)
{
    auto* callee = callInst->getCalledFunction();
    if (!callee) return false;
    
    auto it = insert_info_local_map.find(callee->getName().str());
    if (it == insert_info_local_map.end() || it->second.target_kind != FUNCTION_CALL) {
        return false;
    }
    
    llvm::Value* ptr = callInst->getArgOperand(it->second.operand_index);
    if (!ptr) return false;
    
    llvm::Instruction* next_inst = callInst;
    for (int i = 0; i < it->second.insertion_offset; i++) {
        next_inst = next_inst->getNextNonDebugInstruction();
    }
    
    llvm::IRBuilder<> builder(next_inst);
    uint64_t func_hash = computeFuncHash(funcName, get_serial_number_in_ir(block_serial_number, instruction_serial_number));
    emitInstrumentationCall(builder, recFunc, ptr, func_hash, it->second.access_type, 
                          get_serial_number_in_ir(block_serial_number, instruction_serial_number), 1);
    
    record_count++;
    return true;
}

/**
 * @brief 处理一般IR指令的插桩
 * @param inst 指令
 * @param recFunc 记录函数
 * @param funcName 当前函数名
 * @param DL 数据布局
 * @param accessSet 访问集合
 * @return 是否成功插桩
 */
static bool processIRInstruction(
    llvm::Instruction* inst,
    llvm::Function* recFunc,
    const std::string& funcName,
    const llvm::DataLayout& DL,
    const std::set<llvm::Instruction*>& accessSet)
{
    std::string instruction_type = getInstructionTypeAsString(inst);
    auto it = insert_info_local_map.find(instruction_type);
    
    if (it == insert_info_local_map.end() || it->second.target_kind != IR_INSTRUCTIONS) {
        return false;
    }
    
    // 跳过原子操作的Load和Store指令
    if (auto* LI = llvm::dyn_cast<llvm::LoadInst>(inst)) {
        if (LI->isAtomic()) {
            return false;
        }
    } else if (auto* SI = llvm::dyn_cast<llvm::StoreInst>(inst)) {
        if (SI->isAtomic()) {
            return false;
        }
    }
    
    if (TAINT_ANALYSIS && !accessSet.count(inst)) {
        return false;
    }
    
    llvm::Instruction* next_inst = inst;
    for (int i = 0; i < insert_info_local_map[instruction_type].insertion_offset; i++) {
        next_inst = next_inst->getNextNonDebugInstruction();
    }
    
    llvm::IRBuilder<> builder(next_inst);
    llvm::Value* ptr = inst->getOperand(it->second.operand_index);
    llvm::Type* orig_ty = getLoadStoreType(inst);
    auto typeSize = DL.getTypeStoreSizeInBits(orig_ty);
    int size = typeSize.getKnownMinValue() / 8;
    
    uint64_t func_hash = computeFuncHash(funcName, get_serial_number_in_ir(block_serial_number, instruction_serial_number));
    emitInstrumentationCall(builder, recFunc, ptr, func_hash, it->second.access_type, 
                          get_serial_number_in_ir(block_serial_number, instruction_serial_number), size);
    
    record_count++;
    return true;
}

// ==================== 主要插桩函数 ====================

/**
 * @brief 在模块中插入内存访问记录函数调用
 * @param recFunc 记录函数
 * @param mod LLVM模块
 */
static void InsertFunc(llvm::Function* recFunc, llvm::Module* mod)
{
    const llvm::DataLayout& DL = mod->getDataLayout();
    
    for (auto& F : *mod) {
        // 跳过特定函数
        if (shouldSkipFunction(F.getName().str())) {
            continue;
        }
        
        block_serial_number = 0;
        
        // 进行污点分析
        TaintAnalysis analyzer;
        analyzer.analyzeFunctionFlowSensitive(F);
        const std::set<llvm::Instruction*>& accessSet = analyzer.getAccessSet();
        
        for (auto& BB : F) {
            instruction_serial_number = 0;
            block_serial_number++;
            
            for (auto& I : BB) {
                instruction_serial_number++;
                auto* inst = llvm::dyn_cast<llvm::Instruction>(&I);
                if (!inst) continue;
                
                // 处理函数调用指令
                if (auto* callInst = llvm::dyn_cast<llvm::CallInst>(inst)) {
                    if (processCallInstruction(callInst, recFunc, F.getName().str())) {
                        continue;
                    }
                }
                
                // 处理一般IR指令
                processIRInstruction(inst, recFunc, F.getName().str(), DL, accessSet);
            }
        }
    }
    
    std::cout << "Total instrumentation count: " << record_count << std::endl;
}

// ==================== 配置文件读取 ====================

/**
 * @brief 读取插桩配置信息
 * @param path 配置文件路径
 */
static void read_insert_info(const std::string& path)
{
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) {
        std::cout << "*** [ERROR] Failed to open insert info file: " << path << " ***" << std::endl;
        return;
    }
    
    char name[100];
    int arg_pos = 0;
    int insert_pos = 0;
    int type = 0;
    int inserted_type = 0;
    
    while (fscanf(fp, "%s%d%d%d%d", name, &type, &inserted_type, &arg_pos, &insert_pos) != EOF) {
        InsertInfo new_insert_info{
            .target_kind = type,
            .access_type = inserted_type,
            .operand_index = arg_pos,
            .insertion_offset = insert_pos
        };
        insert_info_local_map[name] = new_insert_info;
        std::cout << "Read insert info: " << name 
                  << ", type: " << type 
                  << ", inserted_type: " << inserted_type 
                  << ", operand_index: " << arg_pos 
                  << ", insertion_offset: " << insert_pos << "\n" << std::endl;
    }
    PrintInfo("Read insert info from " + path + " successfully.\n");
    fclose(fp);
    std::cout << "Loaded " << insert_info_local_map.size() << " insert info entries" << std::endl;
}

// ==================== 公共接口函数 ====================

/**
 * @brief 设置插桩函数名
 * @param func_name 函数名
 */
void SetInstrumentationFuncName(const std::string& func_name)
{
    instrumentation_func_name = func_name;
    std::cout << "Set instrumentation function name to: " << instrumentation_func_name << std::endl;
}

/**
 * @brief 设置函数进入记录函数名
 * @param func_name 函数名
 */
void SetFuncEnterName(const std::string& func_name)
{
    func_enter_name = func_name;
    std::cout << "Set function enter name to: " << func_enter_name << std::endl;
}

/**
 * @brief 设置函数退出记录函数名
 * @param func_name 函数名
 */
void SetFuncExitName(const std::string& func_name)
{
    func_exit_name = func_name;
    std::cout << "Set function exit name to: " << func_exit_name << std::endl;
}

/**
 * @brief 设置基本块记录函数名
 * @param func_name 函数名
 */
void SetBasicBlockName(const std::string& func_name)
{
    basic_block_name = func_name;
    std::cout << "Set basic block function name to: " << basic_block_name << std::endl;
}

/**
 * @brief 设置锁函数名
 * @param func_name 函数名
 */
void SetLockFuncName(const std::string& func_name)
{
    lock_func_name = func_name;
    std::cout << "Set lock function name to: " << lock_func_name << std::endl;
}

/**
 * @brief 主入口函数：对模块进行共享变量访问记录插桩
 * @param mod LLVM模块
 */
void RecordSharedVariableAccess(llvm::Module* mod)
{
    std::cout << "Starting shared variable access instrumentation..." << std::endl;
    
    // 读取插桩配置信息
    read_insert_info(INSERT_INFO_PATH);
    
    // 声明内存记录函数
    llvm::Function* func_mem = DeclareMemRec(mod);
    
    // 执行插桩
    InsertFunc(func_mem, mod);
    
    std::cout << "Shared variable access instrumentation completed." << std::endl;
}