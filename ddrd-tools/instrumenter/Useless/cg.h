#ifndef _CG_H_
#define _CG_H_

#include <vector>
#include <map>

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

class CG {
private:
	std::vector<llvm::Module *> mod_vec;
	std::map<llvm::Instruction *, std::vector<llvm::Function *> > called_funcs;
	std::set<llvm::Function *> entry_funcs;
private:
	void build();
public:
	CG(std::vector<llvm::Module *> &mod_vec);
	std::vector<llvm::Function *> &getCalledFuncs(llvm::Instruction *call);
	std::set<llvm::Function *> &getEntryFuncs();
};

#endif
