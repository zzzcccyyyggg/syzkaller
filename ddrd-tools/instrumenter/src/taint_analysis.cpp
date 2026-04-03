#include "taint_analysis.hpp"

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
    if (F.empty())
        return; // 确保函数非空

    // Step 1: 收集函数参数
    for (auto &arg : F.args())
    {
        var_set.insert(&arg);
    }

    // Step 2: 收集全局变量
    Module *M = F.getParent();
    if (!M)
        return; // 确保模块非空
    for (auto &global : M->globals())
    {
        var_set.insert(&global);
    }

    // 获取入口基本块
    BasicBlock *entryBB = &F.getEntryBlock();
    if (!entryBB)
        return; // 确保入口基本块非空

    traversePath(entryBB, var_set);
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
