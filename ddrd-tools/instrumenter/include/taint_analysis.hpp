#ifndef TAINT_ANALYSIS_HPP
#define TAINT_ANALYSIS_HPP

#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/CFG.h"
#include "llvm/Support/raw_ostream.h"
#include <set>
#include <vector>
#include <stack>
#include <map>
using namespace llvm;
using namespace std;
class TaintAnalysis
{
private:
    std::set<Value *> var_set_each_path;
    std::set<Value *> var_set;
    Value *var_set_end = nullptr;
    std::map<BasicBlock *, std::set<std::size_t>> bb_2_var_set_hash;
    // 共享变量访问的指令集合
    std::set<Instruction *> accessSet;

    // 当前路径上的基本块序列
    std::vector<BasicBlock *> currentPath;

    // 记录已访问的基本块，防止无限循环
    std::set<BasicBlock *> visitedBlocks;

    void traversePath(BasicBlock *BB, std::set<Value *> &var_set);

    std::size_t hashSet(const std::set<Value *> &var_set);
public:
    // 构造函数
    TaintAnalysis() = default;

    // 析构函数
    ~TaintAnalysis() = default;

    // 分析函数中的污点
    void analyzeFunction(Function &F);

    void analyzeFunctionFlowSensitive(Function &F);

    // 获取共享变量访问指令集合
    const std::set<Instruction *> &getAccessSet() const;

    // 打印共享变量访问指令集合
    void printAccessSet() const;
};

#endif // TAINT_ANALYSIS_HPP
