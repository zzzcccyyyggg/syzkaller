
#pragma once
#include <string>
#include <vector>
#include "llvm/IR/Module.h"
#include "llvm/IR/Constants.h"

struct LockPair {
    std::string require_func;
    std::string release_func;
    int lock_attribute; // 0: normal lock, 1: read lock, 2: write lock
    LockPair(std::string require, std::string release, int attribute)
        : require_func(require), release_func(release), lock_attribute(attribute) {}
};

struct TryLock {
    std::string func_name;
    int success_ret;
    int lock_attribute;
    TryLock(std::string name, int ret, int attribute)
        : func_name(name), success_ret(ret), lock_attribute(attribute) {}
};


extern std::vector<LockPair> mylockpair;
extern bool ReadLockPairFile(char *lockfile);
extern llvm::Constant* CreateWords(llvm::Module *mod, const std::string &str);
llvm::Function *LockPairInfo(llvm::Module *mod);
void RecordLockPrimitive(llvm::Module *mod, const char *lockfile);

// 标志常量
#define LOCK_REQUIRE 1
#define LOCK_RELEASE 2
