#include "race.h"
#include <algorithm>
#include <iostream>

#include "llvm/IR/DebugInfoMetadata.h"

using namespace std;
using namespace llvm;

/**************** Implementation of RaceInfo ****************/
RaceInfo::RaceInfo(Function *func, Instruction *inst, Value *val) {
	this->func = func;
	this->inst = inst;
	this->val = val;
}

Function *RaceInfo::getRaceFunc() {
	return func;
}

Instruction *RaceInfo::getRaceInst() {
	return inst;
}

Value *RaceInfo::getRaceValue() {
	return val;
}

/**************** Implementation of LockSet ****************/
LockSet::LockSet(Function *entry_func, Steensgaard *steen, CG *cg) {
	readLockInfo("/home/zzzccc/CCWF/instrumenter/lockset.txt");
	this->entry_func = entry_func;
	this->steen = steen;
	this->cg = cg;
	analyze();
}

set<SteensgaardNode *> LockSet::getIntersection(
					vector<set<SteensgaardNode *> > &lock_set_vec) {
	set<SteensgaardNode *> result;
	if (lock_set_vec.empty()) {
		return result;
	}
	result = lock_set_vec[0];
	for (size_t i = 1; i < lock_set_vec.size(); i++) {
		set<SteensgaardNode *> lock_set = lock_set_vec[i];
		set<SteensgaardNode *> tmp_set;
		set_intersection(result.begin(), result.end(), 
						lock_set.begin(), lock_set.end(),
						inserter(tmp_set, tmp_set.begin()));
		result = tmp_set;
	}
	return result;
}

SteensgaardNode *LockSet::getLockNode(CallInst *call) {
	Function *func = call->getCalledFunction();
	if (func == NULL) {
		return NULL;
	}
	string func_name = func->getName().str();
	if (lock_arg_local_map.find(func_name) == lock_arg_local_map.end()) {
		return NULL;
	}
	int lock_arg_local = lock_arg_local_map[func_name];
	if (lock_arg_local >= call->arg_size()) {
		return NULL;
	}
	Value *arg = call->getArgOperand(lock_arg_local);
	return steen->getSteensgaardNode(arg);
}

SteensgaardNode *LockSet::getUnlockNode(CallInst *call) {
	Function *func = call->getCalledFunction();
	if (func == NULL) {
		return NULL;
	}
	string func_name = func->getName().str();
	if (unlock_arg_local_map.find(func_name) == unlock_arg_local_map.end()) {
		return NULL;
	}
	int unlock_arg_local = unlock_arg_local_map[func_name];
	if (unlock_arg_local >= call->arg_size()) {
		return NULL;
	}
	Value *arg = call->getArgOperand(unlock_arg_local);
	return steen->getSteensgaardNode(arg);
}

void LockSet::handleCall(CallInst *call, set<SteensgaardNode *> &lock_set) {
	SteensgaardNode *lock_node = getLockNode(call);
	if (lock_node) {
		lock_set.insert(lock_node);
		return;
	}
	SteensgaardNode *unlock_node = getUnlockNode(call);
	if (unlock_node) {
		lock_set.erase(unlock_node);
		return;
	}
	
	vector<Function *> &called_funcs = cg->getCalledFuncs(call);
	for (size_t i = 0; i < called_funcs.size(); i++) {
		Function *func = called_funcs[i];
		handleFunc(func);
	}
}

void LockSet::handleBlock(BasicBlock *block) {
	if (block_map.find(block) != block_map.end()) {
		return;
	}
	vector<set<SteensgaardNode *> > lock_set_vec;
	block_map[block].clear();
	pred_iterator pi = pred_begin(block);
	pred_iterator pi_end = pred_end(block);
	for (; pi != pi_end; pi++) {
		BasicBlock *pre_block = *pi;
		if (block_map.find(pre_block) == block_map.end()) {
			handleBlock(pre_block);
		}
		if (analyzed_block.find(pre_block) != analyzed_block.end()) {
			lock_set_vec.push_back(block_map[pre_block]);
		}
	} 
	set<SteensgaardNode *> lock_set = getIntersection(lock_set_vec);
	BasicBlock::iterator b_it, b_end;
	b_it = block->begin();
	b_end = block->end();
	for (; b_it != b_end; b_it++) {
		Instruction *inst = &(*b_it);
		if (isa<LoadInst>(inst)) {
			Value *access_val = inst->getOperand(0);
			if (steen->isArgValue(access_val)) {
				access_map[access_val] = lock_set;
				access_type_map[access_val] = LockSet::Read;
			}
		} else if (isa<StoreInst>(inst)) {
			Value *access_val = inst->getOperand(1);
			if (steen->isArgValue(access_val)) {
				access_map[access_val] = lock_set;
				access_type_map[access_val] = LockSet::Write;
			}
		} else if(CallInst *call = dyn_cast<CallInst>(inst)) {
			handleCall(call, lock_set);
		}
	}
	analyzed_block.insert(block);
}

void LockSet::handleFunc(Function *func) {
	Function::iterator f_it, f_end;
	f_it = func->begin();
	f_end = func->end();
	for (; f_it != f_end; f_it++) {
		BasicBlock *block = &(*f_it);
		handleBlock(block);
	}
}

void LockSet::readLockInfo(string path) {
	FILE *fp = fopen(path.c_str(), "r");
	if (!fp) {
		cout << "*** [ERROR] Fail to open lock func file *** " << path << endl;
		return;
	}
	char lock_func[200], unlock_func[200];
	int lock_arg_pos, unlock_arg_pos;
	int ret_state;
	while (fscanf(fp, "%s%d%s%d%d", lock_func, &lock_arg_pos, 
							unlock_func, &unlock_arg_pos,
							&ret_state) != EOF) {
		lock_arg_local_map[lock_func] = lock_arg_pos;
		unlock_arg_local_map[unlock_func] = unlock_arg_pos;
	}
	fclose(fp);
}

void LockSet::analyze() {
	handleFunc(entry_func);
}

map<Value *, set<SteensgaardNode *> > &LockSet::getAllAccesses() {
	return access_map;
}

map<Value *, LockSet::AccessType> &LockSet::getAllAccessTypes() {
	return access_type_map;
}

/**************** Implementation of Race ****************/
Race::Race(llvm::Module *mod) {
	mod_vec.clear();
	mod_vec.push_back(mod);
	cg = new CG(mod_vec);
	steen = new Steensgaard();
	entry_func_set = cg->getEntryFuncs();
	set<Function *>::iterator entry_it, entry_end;
	entry_it = entry_func_set.begin();
	entry_end = entry_func_set.end();
	for (; entry_it != entry_end; entry_it++) {
		Function *entry_func = *entry_it;
		Steensgaard *single_steen = new Steensgaard(entry_func, cg);
		steen->bind(single_steen);
		delete single_steen;
	}
	steen->compress();
	entry_it = entry_func_set.begin();
	entry_end = entry_func_set.end();
	for (; entry_it != entry_end; entry_it++) {
		steen->setArgNode(*entry_it);
	}
	detect();

}

Race::Race(vector<Module *> &mod_vec) {
	this->mod_vec = mod_vec;
	cg = new CG(mod_vec);
	steen = new Steensgaard();
	entry_func_set = cg->getEntryFuncs();
	set<Function *>::iterator entry_it, entry_end;
	entry_it = entry_func_set.begin();
	entry_end = entry_func_set.end();
	for (; entry_it != entry_end; entry_it++) {
		Function *entry_func = *entry_it;
		Steensgaard *single_steen = new Steensgaard(entry_func, cg);
		steen->bind(single_steen);
		delete single_steen;
	}
	steen->compress();
	entry_it = entry_func_set.begin();
	entry_end = entry_func_set.end();
	for (; entry_it != entry_end; entry_it++) {
		steen->setArgNode(*entry_it);
	}
	detect();
}

Race::~Race() {
	for (size_t i = 0; i < race_vec.size(); i++) {
		delete race_vec[i];
	}
	for (size_t i = 0; i < lock_set_vec.size(); i++) {
		delete lock_set_vec[i];
	}
	delete cg;
	delete steen;
}

void Race::check(LockSet *lock_set1, LockSet *lock_set2) {
	Function *entry1 = lock_set_entry_map[lock_set1];
	Function *entry2 = lock_set_entry_map[lock_set2];

	string func_name1 = entry1->getName().str();
	string func_name2 = entry2->getName().str();
	if (func_name1.find("init") != string::npos ||
				func_name2.find("init") != string::npos) {
		return;
	}

	map<Value *, set<SteensgaardNode *> > &access_map1 = lock_set1->getAllAccesses();
	map<Value *, set<SteensgaardNode *> > &access_map2 = lock_set2->getAllAccesses();
	map<Value *, LockSet::AccessType> &access_type_map1 = lock_set1->getAllAccessTypes();
	map<Value *, LockSet::AccessType> &access_type_map2 = lock_set2->getAllAccessTypes();
	map<Value *, set<SteensgaardNode *> >::iterator access_it, access_end;
	access_it = access_map1.begin();
	access_end = access_map1.end();
	for (; access_it != access_end; access_it++) {
		Value *val1 = access_it->first;
		SteensgaardNode *node = steen->getSteensgaardNode(val1);
		set<Value *> &val_set = node->getAllValues();
		set<Value *>::iterator v_it, v_end;
		v_it = val_set.begin();
		v_end = val_set.end();
		for (; v_it != v_end; v_it++) {
			Value *val2 = *v_it;
			if (val1 == val2) {
				continue;
			}
			set<SteensgaardNode *> &lock_set_value1 = access_it->second;
			if (access_map2.find(val2) != access_map2.end()) {
				set<SteensgaardNode *> &lock_set_value2 = access_map2[val2];
				set<SteensgaardNode *> inter_lock_set_value;
				set_intersection(lock_set_value1.begin(), lock_set_value1.end(), 
					lock_set_value2.begin(), lock_set_value2.end(), 
					inserter(inter_lock_set_value, inter_lock_set_value.begin()));
				if (inter_lock_set_value.empty() && 
						(access_type_map1[val1] == LockSet::Write || 
						access_type_map2[val2] == LockSet::Write)) {
					bool is_exist = false;
					for (size_t i = 0; i < race_pair_vec.size(); i++) {
						RacePair &race_pair = race_pair_vec[i];
						if ((val1 == race_pair.val1 && val2 == race_pair.val2) ||
								(val2 == race_pair.val1 && val1 == race_pair.val2)) {
							is_exist = true;
							break;
						}
					}
					if (!is_exist) {
						RacePair race_pair{entry1, val1, entry2, val2};
						race_pair_vec.push_back(race_pair);
					}
				}
			}
		}
	}
}

void Race::detect() {
	set<Function *>::iterator entry_it, entry_end;
	entry_it = entry_func_set.begin();
	entry_end = entry_func_set.end();
	int i = 0;
	for (; entry_it != entry_end; entry_it++, i++) {
		Function *entry_func = *entry_it;
		LockSet *lock_set = new LockSet(entry_func, steen, cg);
		lock_set_vec.push_back(lock_set);
		lock_set_entry_map[lock_set] = entry_func;
	}
	for (size_t i = 0; i < lock_set_vec.size(); i++) {
		for (size_t j = i + 1; j < lock_set_vec.size(); j++) {
			LockSet *lock_set1 = lock_set_vec[i];
			LockSet *lock_set2 = lock_set_vec[j];
			check(lock_set1, lock_set2);
		}
	}
}

set<Value *> &Race::getRaceValue() {
	return race_result;
}

vector<RacePair> &Race::getRacePairs() {
	return race_pair_vec;
}

bool Race::getInstInfoInSource(Instruction *inst, int &line, string &file) {
	file = "";
	line = 0;
	DILocation *loc = inst->getDebugLoc();
	if (loc) {
		line = (int)(loc->getLine());
		string local_file = loc->getFilename().str();
		string local_dir = loc->getDirectory().str();
		file = local_dir + "/" + local_file;
		return true;
	}
	return false;
}


string Race::getInstInfo(Instruction *inst) {
	string ret_str = "";
	int line;
	string src_file;
	if (!getInstInfoInSource(inst, line, src_file))
		return ret_str;
	char str_last[2000];
	sprintf(str_last, "%s at %d", src_file.c_str(), line);
	ret_str = str_last;
	return ret_str;
}

void Race::showRaces() {
	for (size_t i = 0; i < race_pair_vec.size(); i++) {
		RacePair &race_pair = race_pair_vec[i];
		Value *val1 = race_pair.val1;
		Value *val2 = race_pair.val2;
		Instruction *inst1 = dyn_cast<Instruction>(val1);
		Instruction *inst2 = dyn_cast<Instruction>(val2);
		if (inst1 && inst2) {
			string inst_info1 = getInstInfo(inst1);
			string inst_info2 = getInstInfo(inst2);
			if (inst_info1 != "" && inst_info2 != "") {
				string race_info = "[RACE " + to_string(i) + "]\n" ;
				race_info = race_info + "      Entry1:  " + 
										race_pair.entry1->getName().str() + "\n";
				race_info = race_info + "      Access1: " + 
										inst_info1 + "\n";
				race_info = race_info + "      Entry2:  " + 
										race_pair.entry2->getName().str() + "\n";
				race_info = race_info + "      Access2: " + 
										inst_info2 + "\n";
				cout << race_info << endl;
			}
		}
	}
}

