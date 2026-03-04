#ifndef _RACE_H_
#define _RACE_H_

#include <set>
#include <map>
#include <vector>
#include <string>
#include <sys/file.h>

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

#include "steensgaard.h"

struct RacePair {
	llvm::Function *entry1;
	llvm::Value *val1;
	llvm::Function *entry2;
	llvm::Value *val2;
};

class RaceInfo {
private:
	llvm::Function *func;
	llvm::Instruction *inst;
	llvm::Value *val;
public:
	RaceInfo(llvm::Function *func, llvm::Instruction *inst, llvm::Value *val);
	llvm::Function *getRaceFunc();
	llvm::Instruction *getRaceInst();
	llvm::Value *getRaceValue();
};

class LockSet {
public:
	enum AccessType {Read, Write};
private:
	Steensgaard *steen;
	llvm::Function *entry_func;
	CG *cg;
	std::map<llvm::Value *, std::set<SteensgaardNode *> > access_map;
	std::map<llvm::Value *, AccessType> access_type_map;
	std::map<llvm::BasicBlock *, std::set<SteensgaardNode *> > block_map;
	std::set<llvm::BasicBlock *> analyzed_block;
	std::map<std::string, int> lock_arg_local_map;
	std::map<std::string, int> unlock_arg_local_map;

	void handleCall(llvm::CallInst *call, std::set<SteensgaardNode *> &lock_set);
	void handleFunc(llvm::Function *func);
	void handleBlock(llvm::BasicBlock *block);
public:
	LockSet(llvm::Function *entry_func, Steensgaard *steen, CG *cg);
	std::set<SteensgaardNode *> getIntersection(
				std::vector<std::set<SteensgaardNode *> > &lock_set_vec);
	SteensgaardNode *getLockNode(llvm::CallInst *call);
	SteensgaardNode *getUnlockNode(llvm::CallInst *call);
	void readLockInfo(std::string path);
	void analyze();
	std::map<llvm::Value *, std::set<SteensgaardNode *> > &getAllAccesses();
	std::map<llvm::Value *, LockSet::AccessType> &getAllAccessTypes();
};

class Race {
private:
	std::vector<llvm::Module *> mod_vec;
	std::vector<RaceInfo *> race_vec;
	CG *cg;
	Steensgaard *steen;
	std::set<llvm::Function *> entry_func_set;
	std::vector<LockSet *> lock_set_vec;
	std::map<LockSet *, llvm::Function *> lock_set_entry_map;

	std::set<llvm::Value *> race_result;
	std::vector<RacePair> race_pair_vec;

	bool getInstInfoInSource(llvm::Instruction *inst, int &line, std::string &file);
	std::string getInstInfo(llvm::Instruction *inst);
	void check(LockSet *lock_set1, LockSet *lock_set2);
public:
	Race(llvm::Module *mod);
	Race(std::vector<llvm::Module *> &mod_vec);
	~Race();
	void detect();
	std::set<llvm::Value *> &getRaceValue();
	std::vector<RacePair> &getRacePairs();
	void showRaces();
};

#endif
