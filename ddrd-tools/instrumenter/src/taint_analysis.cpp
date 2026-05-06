#include "taint_analysis.hpp"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Operator.h"
#include <deque>

namespace {

struct TaintState {
    std::set<Value *> pointer_values;
    std::set<const Value *> pointer_memory;
};

static const Value *stripCastsForKey(const Value *value)
{
    if (!value)
        return nullptr;

    const Value *stripped = value->stripPointerCasts();
    if (auto *gep = dyn_cast<GEPOperator>(stripped))
        return stripCastsForKey(gep->getPointerOperand());
    return stripped;
}

static bool isGlobalDerivedPointer(Value *value);
static bool isGlobalDerivedPointer(Value *value, std::set<const Function *> &function_seen,
                                   std::set<const Value *> &value_seen);
static bool functionMayReturnGlobalPointer(Function *func, std::set<const Function *> &function_seen,
                                           std::set<const Value *> &value_seen);

static bool isGlobalDerivedPointer(Value *value)
{
    std::set<const Function *> function_seen;
    std::set<const Value *> value_seen;
    return isGlobalDerivedPointer(value, function_seen, value_seen);
}

static bool isGlobalDerivedPointer(Value *value, std::set<const Function *> &function_seen,
                                   std::set<const Value *> &value_seen)
{
    if (!value)
        return false;

    value = value->stripPointerCasts();
    if (!value_seen.insert(value).second)
        return false;

    if (isa<GlobalVariable>(value))
        return true;

    if (auto *gep = dyn_cast<GEPOperator>(value))
        return isGlobalDerivedPointer(gep->getPointerOperand(), function_seen, value_seen);

    if (auto *phi = dyn_cast<PHINode>(value)) {
        for (Value *incoming : phi->incoming_values()) {
            if (isGlobalDerivedPointer(incoming, function_seen, value_seen))
                return true;
        }
        return false;
    }

    if (auto *select = dyn_cast<SelectInst>(value))
        return isGlobalDerivedPointer(select->getTrueValue(), function_seen, value_seen) ||
               isGlobalDerivedPointer(select->getFalseValue(), function_seen, value_seen);

    if (auto *call = dyn_cast<CallBase>(value))
        return functionMayReturnGlobalPointer(call->getCalledFunction(), function_seen, value_seen);

    return false;
}

static bool functionMayReturnGlobalPointer(Function *func, std::set<const Function *> &function_seen,
                                           std::set<const Value *> &value_seen)
{
    if (!func || !func->getReturnType()->isPointerTy())
        return false;
    if (!function_seen.insert(func).second)
        return false;

    for (BasicBlock &bb : *func) {
        if (auto *ret = dyn_cast<ReturnInst>(bb.getTerminator())) {
            if (isGlobalDerivedPointer(ret->getReturnValue(), function_seen, value_seen))
                return true;
        }
    }
    return false;
}

static bool isPointerValueTainted(Value *value, const TaintState &state,
                                  std::set<Value *> &seen)
{
    if (!value || !value->getType()->isPointerTy())
        return false;

    value = value->stripPointerCasts();
    if (!seen.insert(value).second)
        return false;

    if (state.pointer_values.count(value))
        return true;

    if (isGlobalDerivedPointer(value))
        return true;

    if (auto *gep = dyn_cast<GEPOperator>(value))
        return isPointerValueTainted(gep->getPointerOperand(), state, seen);

    if (auto *phi = dyn_cast<PHINode>(value)) {
        for (Value *incoming : phi->incoming_values()) {
            if (isPointerValueTainted(incoming, state, seen))
                return true;
        }
        return false;
    }

    if (auto *select = dyn_cast<SelectInst>(value)) {
        return isPointerValueTainted(select->getTrueValue(), state, seen) ||
               isPointerValueTainted(select->getFalseValue(), state, seen);
    }

    return false;
}

static bool isPointerValueTainted(Value *value, const TaintState &state)
{
    std::set<Value *> seen;
    return isPointerValueTainted(value, state, seen);
}

static bool hasTaintedPointerOperand(Instruction &inst, const TaintState &state)
{
    for (Use &use : inst.operands()) {
        Value *operand = use.get();
        if (operand && operand->getType()->isPointerTy() &&
            isPointerValueTainted(operand, state))
            return true;
    }
    return false;
}

static bool taintPointerValue(Value *value, TaintState &state)
{
    if (!value || !value->getType()->isPointerTy())
        return false;

    Value *stripped = value->stripPointerCasts();
    return state.pointer_values.insert(stripped).second;
}

static bool taintPointerMemory(Value *ptr, TaintState &state)
{
    const Value *key = stripCastsForKey(ptr);
    if (!key)
        return false;
    return state.pointer_memory.insert(key).second;
}

static bool pointerMemoryIsTainted(Value *ptr, const TaintState &state)
{
    const Value *key = stripCastsForKey(ptr);
    return key && state.pointer_memory.count(key);
}

static bool mergeInto(TaintState &dst, const TaintState &src)
{
    bool changed = false;
    for (Value *value : src.pointer_values)
        changed |= dst.pointer_values.insert(value).second;
    for (const Value *value : src.pointer_memory)
        changed |= dst.pointer_memory.insert(value).second;
    return changed;
}

static void seedInitialState(Function &func, TaintState &state)
{
    for (Argument &arg : func.args()) {
        if (arg.getType()->isPointerTy())
            taintPointerValue(&arg, state);
    }

    Module *mod = func.getParent();
    if (!mod)
        return;

    for (GlobalVariable &global : mod->globals())
        taintPointerValue(&global, state);
}

static void transferInstruction(Instruction &inst, TaintState &state,
                                std::set<Instruction *> &accessSet)
{
    if (auto *load = dyn_cast<LoadInst>(&inst)) {
        Value *ptr = load->getPointerOperand();
        bool address_tainted = isPointerValueTainted(ptr, state);
        if (address_tainted)
            accessSet.insert(&inst);

        if (load->getType()->isPointerTy() &&
            (address_tainted || pointerMemoryIsTainted(ptr, state)))
            taintPointerValue(load, state);
        return;
    }

    if (auto *store = dyn_cast<StoreInst>(&inst)) {
        Value *ptr = store->getPointerOperand();
        if (isPointerValueTainted(ptr, state))
            accessSet.insert(&inst);

        Value *value = store->getValueOperand();
        if (value->getType()->isPointerTy() && isPointerValueTainted(value, state))
            taintPointerMemory(ptr, state);
        return;
    }

    if (auto *call = dyn_cast<CallBase>(&inst)) {
        if (call->getType()->isPointerTy()) {
            std::set<const Function *> function_seen;
            std::set<const Value *> value_seen;
            if (functionMayReturnGlobalPointer(call->getCalledFunction(), function_seen, value_seen) ||
                hasTaintedPointerOperand(inst, state))
                taintPointerValue(call, state);
        }
        return;
    }

    if (inst.getType()->isPointerTy() && hasTaintedPointerOperand(inst, state))
        taintPointerValue(&inst, state);
}

} // namespace

std::size_t TaintAnalysis::hashSet(const std::set<Value *> &var_set) {
    std::size_t hashValue = 0;

    for (const auto &val : var_set) {
        hashValue ^= reinterpret_cast<std::size_t>(val); // 将指针值转为整数后异或
    }

    return hashValue;
}

void TaintAnalysis::traversePath(BasicBlock *BB, std::set<Value *> &var_set)
{
    if (!BB || visitedBlocks.count(BB)){
        // llvm::outs() << "has found \n";
        return;
    }
    if (bb_2_var_set_hash[BB].count(hashSet(var_set))){
        return;
    }
    bb_2_var_set_hash[BB].insert(hashSet(var_set));
    visitedBlocks.insert(BB);
    currentPath.push_back(BB);

    // 使用局部变量跟踪当前基本块添加的 taint 值
    // 修复：原来使用类成员 var_set_each_path 会被子树的 clear() 误删
    std::set<Value *> local_added;

    for (auto &I : *BB)
    {
        Value *resVal = nullptr;
        std::set<Value *> opValSet;

        // 获取结果值和操作数
        if (auto *op = dyn_cast<Instruction>(&I))
        {
            resVal = &I;
            for (unsigned i = 0; i < op->getNumOperands(); ++i)
            {
                auto *operand = op->getOperand(i);
                if (operand)
                    opValSet.insert(operand);
            }
        }

        // 检查操作数集合是否与 var_set 存在交集
        bool hasIntersection = false;
        for (auto *opVal : opValSet)
        {
            if (var_set.count(opVal))
            {
                hasIntersection = true;
                break;
            }
        }

        // 如果结果值是指针类型，将其加入 var_set
        if (hasIntersection && resVal && resVal->getType()->isPointerTy())
        {
            if (!var_set.count(resVal)){
                var_set.insert(resVal);
                local_added.insert(resVal);
            }
        }

        // 如果是共享变量访问的 LOAD 或 STORE 指令，加入 accessSet
        if (hasIntersection && (isa<LoadInst>(&I) || isa<StoreInst>(&I)))
        {
            accessSet.insert(&I);
        }
    }

    // 遍历当前基本块的后继节点
    for (auto *Succ : successors(BB))
    {
        traversePath(Succ, var_set);
    }

    // 仅清理当前基本块添加的 taint 值，不影响其他层级
    for (auto Val : local_added){
        var_set.erase(Val);
    }
    currentPath.pop_back();
    // visitedBlocks.erase(BB);
} 
// 分析函数实现
void TaintAnalysis::analyzeFunctionFlowSensitive(Function &F)
{
    var_set.clear();
    accessSet.clear();
    bb_2_var_set_hash.clear();
    currentPath.clear();
    visitedBlocks.clear();
    if (F.empty())
        return; // 确保函数非空

    std::map<BasicBlock *, TaintState> in_states;
    std::map<BasicBlock *, TaintState> out_states;
    std::deque<BasicBlock *> worklist;
    std::set<BasicBlock *> queued;

    BasicBlock *entryBB = &F.getEntryBlock();
    seedInitialState(F, in_states[entryBB]);
    worklist.push_back(entryBB);
    queued.insert(entryBB);

    while (!worklist.empty()) {
        BasicBlock *bb = worklist.front();
        worklist.pop_front();
        queued.erase(bb);

        TaintState state = in_states[bb];
        for (Instruction &inst : *bb)
            transferInstruction(inst, state, accessSet);

        TaintState &old_out = out_states[bb];
        bool out_changed = old_out.pointer_values != state.pointer_values ||
                           old_out.pointer_memory != state.pointer_memory;
        if (!out_changed)
            continue;

        old_out = state;
        for (BasicBlock *succ : successors(bb)) {
            if (mergeInto(in_states[succ], state) && !queued.count(succ)) {
                worklist.push_back(succ);
                queued.insert(succ);
            }
        }
    }
}

void TaintAnalysis::analyzeFunction(Function &F)
{
    // 清空集合
    var_set.clear();
    accessSet.clear();

    // Step 1: 收集函数参数
    for (auto &arg : F.args())
    {
        var_set.insert(&arg);
    }

    // Step 2: 收集全局变量
    Module *M = F.getParent();
    for (auto &global : M->globals())
    {
        var_set.insert(&global);
    }

    // Step 3: 遍历每个基本块和指令
    for (auto &BB : F)
    {
        for (auto &I : BB)
        {
            Value *resVal = nullptr;
            std::set<Value *> opValSet;

            // 获取操作数集合
            if (auto *op = dyn_cast<Instruction>(&I))
            {
                resVal = &I;
                for (unsigned i = 0; i < op->getNumOperands(); ++i)
                {
                    opValSet.insert(op->getOperand(i));
                }
            }

            // 检查是否与全局变量或参数集有交集
            bool hasIntersection = false;
            for (auto *opVal : opValSet)
            {
                if (var_set.count(opVal))
                {
                    hasIntersection = true;
                    break;
                }
            }

            if (hasIntersection && resVal && resVal->getType()->isPointerTy())
            {
                var_set.insert(resVal);
            }

            // 如果是共享变量访问的 LOAD 或 STORE 指令，加入 accessSet
            if (hasIntersection && (isa<LoadInst>(&I) || isa<StoreInst>(&I)))
            {
                // I.print(llvm::outs());
                accessSet.insert(&I);
            }
        }
    }
}
// 获取访问集合
const std::set<Instruction *> &TaintAnalysis::getAccessSet() const
{
    return accessSet;
}

// 打印访问集合
void TaintAnalysis::printAccessSet() const
{
    for (auto *I : accessSet)
    {
        errs() << "Accessed Instruction: " << *I << "\n";
    }
}
