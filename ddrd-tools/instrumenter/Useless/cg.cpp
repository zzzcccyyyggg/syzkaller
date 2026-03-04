#include "cg.h"

using namespace std;
using namespace llvm;

/**************** Implementation of CG ****************/
CG::CG(vector<Module *> &mod_vec) {
	this->mod_vec = mod_vec;
	build();
}

void CG::build() {
	for (size_t i = 0; i < mod_vec.size(); i++) {
		Module *mod = mod_vec[i];
		Module::iterator m_it, m_end;
		m_it = mod->begin();
		m_end = mod->end();
		for (; m_it != m_end; m_it++) {
			Function *func = &(*m_it);
			if (!func->isDeclaration()) {
				entry_funcs.insert(func);
			}
		}
	}
	for (size_t i = 0; i < mod_vec.size(); i++) {
		Module *mod = mod_vec[i];
		Module::iterator m_it, m_end;
		m_it = mod->begin();
		m_end = mod->end();
		for (; m_it != m_end; m_it++) {
			Function *func = &(*m_it);
			Function::iterator f_it, f_end;
			f_it = func->begin();
			f_end = func->end();
			for (; f_it != f_end; f_it++) {
				BasicBlock *block = &(*f_it);
				BasicBlock::iterator b_it, b_end;
				b_it = block->begin();
				b_end = block->end();
				for (; b_it != b_end; b_it++) {
					Instruction *inst = &(*b_it);
					if (CallInst *call = dyn_cast<CallInst>(inst)) {
						Function *func = call->getCalledFunction();
						if (func && !func->isDeclaration()) {
							called_funcs[call].push_back(func);
							entry_funcs.erase(func);
						}
					}
				}
			}
		}
	}
}

vector<Function *> &CG::getCalledFuncs(Instruction *call) {
	return called_funcs[call];
}

set<Function *> &CG::getEntryFuncs() {
	return entry_funcs;
}
