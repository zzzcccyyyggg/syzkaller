#include "record_shared_variable.hpp"
#include "auxiliary.hpp"
#include "config.hpp"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <climits>
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

enum class AccessEventKind {
    PlainRead,
    PlainWrite,
    AtomicRead,
    AtomicWrite,
    AtomicRMW,
    MemIntrinsicRead,
    MemIntrinsicWrite,
    ConfiguredRead,
    ConfiguredWrite,
};

static const char* accessKindName(AccessEventKind kind)
{
    switch (kind) {
    case AccessEventKind::PlainRead:
        return "plain-read";
    case AccessEventKind::PlainWrite:
        return "plain-write";
    case AccessEventKind::AtomicRead:
        return "atomic-read";
    case AccessEventKind::AtomicWrite:
        return "atomic-write";
    case AccessEventKind::AtomicRMW:
        return "atomic-rmw";
    case AccessEventKind::MemIntrinsicRead:
        return "memintrinsic-read";
    case AccessEventKind::MemIntrinsicWrite:
        return "memintrinsic-write";
    case AccessEventKind::ConfiguredRead:
        return "configured-read";
    case AccessEventKind::ConfiguredWrite:
        return "configured-write";
    }
    return "unknown";
}

static int legacyAccessType(AccessEventKind kind)
{
    switch (kind) {
    case AccessEventKind::PlainWrite:
    case AccessEventKind::AtomicWrite:
    case AccessEventKind::AtomicRMW:
    case AccessEventKind::MemIntrinsicWrite:
    case AccessEventKind::ConfiguredWrite:
        return 1;
    default:
        return 0;
    }
}

static int lineOrFallback(llvm::Instruction* inst, int fallback)
{
    if (auto debug_loc = inst->getDebugLoc()) {
        unsigned line = debug_loc.getLine();
        if (line != 0)
            return static_cast<int>(std::min<unsigned>(line, INT_MAX));
    }
    return fallback;
}

static void appendDebugLocation(std::string& key, const llvm::DILocation* loc)
{
    for (const llvm::DILocation* cur = loc; cur; cur = cur->getInlinedAt()) {
        if (!key.empty())
            key += "<-";
        if (!cur->getDirectory().empty()) {
            key += cur->getDirectory().str();
            key += "/";
        }
        key += cur->getFilename().str();
        key += ":";
        key += std::to_string(cur->getLine());
        key += ":";
        key += std::to_string(cur->getColumn());
        key += ":";
        key += std::to_string(cur->getDiscriminator());
    }
}

static uint64_t computeStableSiteHash(llvm::Instruction* inst,
                                      const std::string& funcName,
                                      int ir_serial,
                                      AccessEventKind kind)
{
    std::string key;
    if (auto debug_loc = inst->getDebugLoc())
        appendDebugLocation(key, debug_loc.get());

    if (key.empty()) {
        key = funcName;
        key += ":";
        key += std::to_string(ir_serial);
    }

    key += ":";
    key += accessKindName(kind);
    return BKDRHash(key.c_str(), 0);
}

static bool isIgnorableIntrinsic(const llvm::IntrinsicInst* intrinsic)
{
    switch (intrinsic->getIntrinsicID()) {
    case llvm::Intrinsic::dbg_declare:
    case llvm::Intrinsic::dbg_value:
    case llvm::Intrinsic::dbg_label:
    case llvm::Intrinsic::lifetime_start:
    case llvm::Intrinsic::lifetime_end:
        return true;
    default:
        return false;
    }
}

static bool allocaUseEscapes(const llvm::Value* value,
                             const llvm::AllocaInst* alloca,
                             std::set<const llvm::Value*>& seen)
{
    if (!seen.insert(value).second)
        return false;

    for (const llvm::Use& use : value->uses()) {
        const llvm::User* user = use.getUser();

        if (llvm::isa<llvm::BitCastInst>(user) ||
            llvm::isa<llvm::AddrSpaceCastInst>(user) ||
            llvm::isa<llvm::GetElementPtrInst>(user) ||
            llvm::isa<llvm::GEPOperator>(user) ||
            llvm::isa<llvm::PHINode>(user) ||
            llvm::isa<llvm::SelectInst>(user)) {
            if (allocaUseEscapes(user, alloca, seen))
                return true;
            continue;
        }

        if (auto* load = llvm::dyn_cast<llvm::LoadInst>(user)) {
            if (load->getPointerOperand() == value)
                continue;
            return true;
        }

        if (auto* store = llvm::dyn_cast<llvm::StoreInst>(user)) {
            if (store->getPointerOperand() == value)
                continue;
            return true;
        }

        if (auto* rmw = llvm::dyn_cast<llvm::AtomicRMWInst>(user)) {
            if (rmw->getPointerOperand() == value)
                continue;
            return true;
        }

        if (auto* cmpxchg = llvm::dyn_cast<llvm::AtomicCmpXchgInst>(user)) {
            if (cmpxchg->getPointerOperand() == value)
                continue;
            return true;
        }

        if (auto* mem = llvm::dyn_cast<llvm::AnyMemIntrinsic>(user)) {
            if (mem->getRawDest() == value)
                continue;
            if (auto* transfer = llvm::dyn_cast<llvm::AnyMemTransferInst>(mem)) {
                if (transfer->getRawSource() == value)
                    continue;
            }
            return true;
        }

        if (auto* intrinsic = llvm::dyn_cast<llvm::IntrinsicInst>(user)) {
            if (isIgnorableIntrinsic(intrinsic))
                continue;
            return true;
        }

        (void)alloca;
        return true;
    }

    return false;
}

static bool allocaEscapes(const llvm::AllocaInst* alloca,
                          std::map<const llvm::AllocaInst*, bool>& cache)
{
    auto it = cache.find(alloca);
    if (it != cache.end())
        return it->second;

    std::set<const llvm::Value*> seen;
    bool escapes = allocaUseEscapes(alloca, alloca, seen);
    cache[alloca] = escapes;
    return escapes;
}

static void collectAddressRoots(llvm::Value* value,
                                std::set<const llvm::Value*>& roots,
                                std::set<const llvm::Value*>& seen)
{
    if (!value)
        return;

    value = value->stripPointerCasts();
    if (!seen.insert(value).second)
        return;

    if (auto* gep = llvm::dyn_cast<llvm::GEPOperator>(value)) {
        collectAddressRoots(gep->getPointerOperand(), roots, seen);
        return;
    }

    if (auto* phi = llvm::dyn_cast<llvm::PHINode>(value)) {
        for (llvm::Value* incoming : phi->incoming_values())
            collectAddressRoots(incoming, roots, seen);
        return;
    }

    if (auto* select = llvm::dyn_cast<llvm::SelectInst>(value)) {
        collectAddressRoots(select->getTrueValue(), roots, seen);
        collectAddressRoots(select->getFalseValue(), roots, seen);
        return;
    }

    roots.insert(value);
}

static bool isDefinitelyLocalAddress(llvm::Value* ptr,
                                     std::map<const llvm::AllocaInst*, bool>& allocaEscapeCache)
{
    std::set<const llvm::Value*> roots;
    std::set<const llvm::Value*> seen;
    collectAddressRoots(ptr, roots, seen);

    if (roots.empty())
        return false;

    for (const llvm::Value* root : roots) {
        auto* alloca = llvm::dyn_cast<llvm::AllocaInst>(root);
        if (!alloca)
            return false;
        if (allocaEscapes(alloca, allocaEscapeCache))
            return false;
    }

    return true;
}

static llvm::Value* constInt32(llvm::IRBuilder<>& builder, uint64_t value)
{
    uint64_t capped = std::min<uint64_t>(value, static_cast<uint64_t>(INT_MAX));
    return llvm::ConstantInt::get(llvm::Type::getInt32Ty(builder.getContext()), capped);
}

static llvm::Value* accessSizeFromType(llvm::IRBuilder<>& builder,
                                       const llvm::DataLayout& DL,
                                       llvm::Type* type)
{
    if (!type)
        return nullptr;
    uint64_t bytes = DL.getTypeStoreSize(type).getKnownMinValue();
    if (bytes == 0)
        bytes = 1;
    return constInt32(builder, bytes);
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
    llvm::Value* size_value);

void emitInstrumentationCall(
    llvm::IRBuilder<>& builder,
    llvm::Function* recFunc,
    llvm::Value* ptr,
    uint64_t func_hash,
    int is_write,
    int line,
    int size_bytes)
{
    emitInstrumentationCall(builder, recFunc, ptr, func_hash, is_write,
                            line, constInt32(builder, size_bytes));
}

void emitInstrumentationCall(
    llvm::IRBuilder<>& builder,
    llvm::Function* recFunc,
    llvm::Value* ptr,
    uint64_t func_hash,
    int is_write,
    int line,
    llvm::Value* size_value)
{
    llvm::LLVMContext& ctx = builder.getContext();
    
    // 在LLVM-18中，所有指针都是opaque pointers，不需要bitcast
    llvm::Value* ptr_cast = ptr;
    llvm::Value* hash_val = llvm::ConstantInt::get(llvm::Type::getInt64Ty(ctx), func_hash);
    llvm::Value* type_val = llvm::ConstantInt::get(llvm::Type::getInt32Ty(ctx), is_write);
    llvm::Value* line_val = llvm::ConstantInt::get(llvm::Type::getInt32Ty(ctx), line);
    llvm::Value* size_val = size_value ? size_value : llvm::ConstantInt::get(llvm::Type::getInt32Ty(ctx), 1);
    if (!size_val->getType()->isIntegerTy(32)) {
        size_val = builder.CreateZExtOrTrunc(size_val, llvm::Type::getInt32Ty(ctx));
    }
    
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
           funcName.find("kcsan") != std::string::npos ||
           funcName.find("kccwf") != std::string::npos;
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
    const std::string& funcName,
    std::map<const llvm::AllocaInst*, bool>& allocaEscapeCache)
{
    auto* callee = callInst->getCalledFunction();
    if (!callee) return false;
    
    auto it = insert_info_local_map.find(callee->getName().str());
    if (it == insert_info_local_map.end() || it->second.target_kind != FUNCTION_CALL) {
        return false;
    }
    
    llvm::Value* ptr = callInst->getArgOperand(it->second.operand_index);
    if (!ptr) return false;
    if (isDefinitelyLocalAddress(ptr, allocaEscapeCache))
        return false;
    
    llvm::Instruction* next_inst = callInst;
    for (int i = 0; i < it->second.insertion_offset; i++) {
        next_inst = next_inst->getNextNonDebugInstruction();
    }
    
    llvm::IRBuilder<> builder(next_inst);
    int ir_serial = get_serial_number_in_ir(block_serial_number, instruction_serial_number);
    AccessEventKind kind = it->second.access_type == 1 ?
        AccessEventKind::ConfiguredWrite : AccessEventKind::ConfiguredRead;
    uint64_t func_hash = computeStableSiteHash(callInst, funcName, ir_serial, kind);
    emitInstrumentationCall(builder, recFunc, ptr, func_hash, legacyAccessType(kind),
                          lineOrFallback(callInst, ir_serial), 1);
    
    record_count++;
    return true;
}

static bool emitAccess(llvm::Instruction* insertBefore,
                       llvm::Function* recFunc,
                       llvm::Value* ptr,
                       llvm::Value* sizeValue,
                       const std::string& funcName,
                       AccessEventKind kind)
{
    llvm::IRBuilder<> builder(insertBefore);
    int ir_serial = get_serial_number_in_ir(block_serial_number, instruction_serial_number);
    uint64_t site_hash = computeStableSiteHash(insertBefore, funcName, ir_serial, kind);
    emitInstrumentationCall(builder, recFunc, ptr, site_hash, legacyAccessType(kind),
                            lineOrFallback(insertBefore, ir_serial), sizeValue);
    record_count++;
    return true;
}

static bool isBlockedByTaintGate(const std::set<llvm::Instruction*>* accessSet,
                                 llvm::Instruction* inst)
{
    return accessSet && !accessSet->count(inst);
}

static bool processMemoryInstruction(
    llvm::Instruction* inst,
    llvm::Function* recFunc,
    const std::string& funcName,
    const llvm::DataLayout& DL,
    std::map<const llvm::AllocaInst*, bool>& allocaEscapeCache,
    const std::set<llvm::Instruction*>* accessSet)
{
    if (auto* load = llvm::dyn_cast<llvm::LoadInst>(inst)) {
        if (!load->isAtomic() && isBlockedByTaintGate(accessSet, inst))
            return false;
        llvm::Value* ptr = load->getPointerOperand();
        if (isDefinitelyLocalAddress(ptr, allocaEscapeCache))
            return false;
        llvm::IRBuilder<> builder(inst);
        AccessEventKind kind = load->isAtomic() ?
            AccessEventKind::AtomicRead : AccessEventKind::PlainRead;
        return emitAccess(inst, recFunc, ptr, accessSizeFromType(builder, DL, load->getType()),
                          funcName, kind);
    }

    if (auto* store = llvm::dyn_cast<llvm::StoreInst>(inst)) {
        if (!store->isAtomic() && isBlockedByTaintGate(accessSet, inst))
            return false;
        llvm::Value* ptr = store->getPointerOperand();
        if (isDefinitelyLocalAddress(ptr, allocaEscapeCache))
            return false;
        llvm::IRBuilder<> builder(inst);
        AccessEventKind kind = store->isAtomic() ?
            AccessEventKind::AtomicWrite : AccessEventKind::PlainWrite;
        return emitAccess(inst, recFunc, ptr,
                          accessSizeFromType(builder, DL, store->getValueOperand()->getType()),
                          funcName, kind);
    }

    if (auto* rmw = llvm::dyn_cast<llvm::AtomicRMWInst>(inst)) {
        llvm::Value* ptr = rmw->getPointerOperand();
        if (isDefinitelyLocalAddress(ptr, allocaEscapeCache))
            return false;
        llvm::IRBuilder<> builder(inst);
        return emitAccess(inst, recFunc, ptr,
                          accessSizeFromType(builder, DL, rmw->getValOperand()->getType()),
                          funcName, AccessEventKind::AtomicRMW);
    }

    if (auto* cmpxchg = llvm::dyn_cast<llvm::AtomicCmpXchgInst>(inst)) {
        llvm::Value* ptr = cmpxchg->getPointerOperand();
        if (isDefinitelyLocalAddress(ptr, allocaEscapeCache))
            return false;
        llvm::IRBuilder<> builder(inst);
        return emitAccess(inst, recFunc, ptr,
                          accessSizeFromType(builder, DL, cmpxchg->getCompareOperand()->getType()),
                          funcName, AccessEventKind::AtomicRMW);
    }

    if (auto* transfer = llvm::dyn_cast<llvm::AnyMemTransferInst>(inst)) {
        bool inserted = false;
        llvm::Value* len = transfer->getLength();
        llvm::Value* dst = transfer->getRawDest();
        llvm::Value* src = transfer->getRawSource();

        if (!isDefinitelyLocalAddress(src, allocaEscapeCache)) {
            inserted |= emitAccess(inst, recFunc, src, len, funcName,
                                   AccessEventKind::MemIntrinsicRead);
        }
        if (!isDefinitelyLocalAddress(dst, allocaEscapeCache)) {
            inserted |= emitAccess(inst, recFunc, dst, len, funcName,
                                   AccessEventKind::MemIntrinsicWrite);
        }
        return inserted;
    }

    if (auto* memset = llvm::dyn_cast<llvm::AnyMemSetInst>(inst)) {
        llvm::Value* dst = memset->getRawDest();
        if (isDefinitelyLocalAddress(dst, allocaEscapeCache))
            return false;
        return emitAccess(inst, recFunc, dst, memset->getLength(), funcName,
                          AccessEventKind::MemIntrinsicWrite);
    }

    return false;
}

// ==================== 主要插桩函数 ====================

/**
 * @brief 在模块中插入内存访问记录函数调用
 * @param recFunc 记录函数
 * @param mod LLVM模块
 */
static void InsertFunc(llvm::Function* recFunc, llvm::Module* mod, bool access_first)
{
    const llvm::DataLayout& DL = mod->getDataLayout();
    
    for (auto& F : *mod) {
        // 跳过特定函数
        if (shouldSkipFunction(F.getName().str())) {
            continue;
        }
        
        block_serial_number = 0;
        
        std::map<const llvm::AllocaInst*, bool> allocaEscapeCache;
        const std::set<llvm::Instruction*>* accessSet = nullptr;
        TaintAnalysis analyzer;
        if (!access_first) {
            analyzer.analyzeFunctionFlowSensitive(F);
            accessSet = &analyzer.getAccessSet();
        }
        
        for (auto& BB : F) {
            instruction_serial_number = 0;
            block_serial_number++;
            
            for (auto& I : BB) {
                instruction_serial_number++;
                auto* inst = llvm::dyn_cast<llvm::Instruction>(&I);
                if (!inst) continue;
                
                // 处理函数调用指令
                if (auto* callInst = llvm::dyn_cast<llvm::CallInst>(inst)) {
                    if (processCallInstruction(callInst, recFunc, F.getName().str(), allocaEscapeCache)) {
                        continue;
                    }
                }
                
                // Datarace-only uses access-first. Legacy variable mode keeps the
                // taint gate for plain load/store to avoid exploding overhead.
                processMemoryInstruction(inst, recFunc, F.getName().str(), DL,
                                         allocaEscapeCache, accessSet);
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
void RecordSharedVariableAccess(llvm::Module* mod, bool access_first)
{
    std::cout << "Starting shared variable access instrumentation..." << std::endl;
    std::cout << "Variable instrumentation mode: "
              << (access_first ? "access-first" : "taint-gated") << std::endl;
    
    // 读取插桩配置信息
    read_insert_info(INSERT_INFO_PATH);
    
    // 声明内存记录函数
    llvm::Function* func_mem = DeclareMemRec(mod);
    
    // 执行插桩
    InsertFunc(func_mem, mod, access_first);
    
    std::cout << "Shared variable access instrumentation completed." << std::endl;
}
