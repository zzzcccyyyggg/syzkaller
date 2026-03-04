#include "steensgaard.h"

#include <stack>

#include "llvm/IR/Constants.h"

using namespace std;
using namespace llvm;


/**************** Implementation of UFS ****************/
void UFS::UFSUnion(SteensgaardNode *node1, SteensgaardNode *node2) {
	SteensgaardNode *ancestor1 = UFSFind(node1);
	SteensgaardNode *ancestor2 = UFSFind(node2);
	if (ancestor1 != ancestor2) {
		ancestor_map[ancestor1] = ancestor2;
	}
}

SteensgaardNode *UFS::UFSFind(SteensgaardNode *node) {
	if (ancestor_map.find(node) == ancestor_map.end()) {
		ancestor_map[node] = node;
		return node;
	}
	while (ancestor_map[node] != node) {
		node = ancestor_map[node];
	}
	return node;
}

/**************** Implementation of SteensgaardNode ****************/
SteensgaardNode::SteensgaardNode() {
	is_arg_node = false;
}

SteensgaardNode::SteensgaardNode(Value *val) {
	val_set.insert(val);
	is_arg_node = false;
}

SteensgaardNode::~SteensgaardNode() {
	for (size_t i = 0; i < edge_vec.size(); i++) {
		delete edge_vec[i];
	}
}

SteensgaardNode *SteensgaardNode::getRefNode() {
	for (size_t i = 0; i < edge_vec.size(); i++) {
		SteensgaardEdge *edge = edge_vec[i];
		if (edge->getType() == SteensgaardEdge::Ref) {
			return edge->getDst();
		}
	}
	return NULL;
}

SteensgaardNode *SteensgaardNode::getGepNode() {
	for (size_t i = 0; i < edge_vec.size(); i++) {
		SteensgaardEdge *edge = edge_vec[i];
		if (edge->getType() == SteensgaardEdge::Gep) {
			return edge->getDst();
		}
	}
	return NULL;
}

SteensgaardNode *SteensgaardNode::getOffsetNode(int offset) {
	for (size_t i = 0; i < edge_vec.size(); i++) {
		SteensgaardEdge *edge = edge_vec[i];
		if (edge->getType() == SteensgaardEdge::Offset) {
			if (edge->getOffset() == offset) {
				return edge->getDst();
			}
		}
	}
	return NULL;
}

SteensgaardNode *SteensgaardNode::getDstNode(SteensgaardEdge *edge) {
	switch (edge->getType()) {
		case SteensgaardEdge::Ref:
			return getRefNode();
			break;
		case SteensgaardEdge::Gep:
			return getGepNode();
			break;
		case SteensgaardEdge::Offset:
			return getOffsetNode(edge->getOffset());
			break;
		default:
			return NULL;
	}
	return NULL;
}

void SteensgaardNode::insertEdge(SteensgaardEdge *edge) {
	edge_vec.push_back(edge);
}

vector<SteensgaardEdge *> &SteensgaardNode::getAllEdges() {
	return edge_vec;
}

void SteensgaardNode::insertValue(Value *val) {
	val_set.insert(val);
}

set<Value *> &SteensgaardNode::getAllValues() {
	return val_set;
}

void SteensgaardNode::setArgNode(bool is_arg_node) {
	this->is_arg_node = is_arg_node;
}

bool SteensgaardNode::isArgNode() {
	return is_arg_node;
}

string SteensgaardNode::getTypeName() {
	if (val_set.empty()) {
		return "";
	}
	Value *val = *(val_set.begin());
	PointerType *ptr_type = dyn_cast<PointerType>(val->getType());
	if (!ptr_type) {
		return "";
	}
	StructType *type = dyn_cast<StructType>(ptr_type->getPointerElementType());
	if (!type) {
		return "";
	}
	if (!type->hasName()) {
		return "";
	}
	return type->getStructName().str();
}

SteensgaardNode *SteensgaardNode::copy() {
	SteensgaardNode *node = new SteensgaardNode();
	set<Value *>::iterator v_it, v_end;
	v_it = val_set.begin();
	v_end = val_set.end();
	for (; v_it != v_end; v_it++) {
		Value *val = *v_it;
		node->insertValue(val);
	}
	node->setArgNode(is_arg_node);
	return node;
}



/**************** Implementation of SteensgaardEdge ****************/
SteensgaardEdge::SteensgaardEdge(SteensgaardNode *src, SteensgaardNode *dst,
							SteensgaardEdge::EdgeType edge_type, int offset) {
	this->edge_type = edge_type;
	this->offset = offset;
	this->src = src;
	this->dst = dst;
}

SteensgaardEdge::EdgeType SteensgaardEdge::getType() {
	return edge_type;
}

int SteensgaardEdge::getOffset() {
	return offset;
}

SteensgaardNode *SteensgaardEdge::getSrc() {
	return src;
}

SteensgaardNode *SteensgaardEdge::getDst() {
	return dst;
}

/**************** Implementation of Steensgaard ****************/
Steensgaard::Steensgaard() {
	entry_func = NULL;
	cg = NULL;
	ufs = new UFS();
	node_set.clear();
	entry_node_set.clear();
	val_node_map.clear();
	func_record.clear();
}

Steensgaard::Steensgaard(Function *entry_func, CG *cg) {
	this->entry_func = entry_func;
	this->cg = cg;
	this->ufs = new UFS();
	analyze();
	compress();
}

Steensgaard::~Steensgaard() {
	set<SteensgaardNode *>::iterator node_it, node_end;
	node_it = node_set.begin();
	node_end = node_set.end();
	for (; node_it != node_end; node_it++) {
		delete *node_it;
	}
	delete ufs;
}

SteensgaardNode *Steensgaard::findOrCreateSteensgaardNode(Value *val) {
	if (val_node_map.find(val) != val_node_map.end()) {
		return val_node_map[val];
	}
	SteensgaardNode *node = new SteensgaardNode(val);
	val_node_map[val] = node;
	node_set.insert(node);
	return node;
}

void Steensgaard::mergeNode(SteensgaardNode *node1, SteensgaardNode *node2) {
	set<SteensgaardNode *> node_record;
	stack<SteensgaardNode *> node_stk1;
	stack<SteensgaardNode *> node_stk2;
	node_stk1.push(node1);
	node_stk2.push(node2);
	while (!node_stk1.empty()) {
		SteensgaardNode *node1 = node_stk1.top();
		SteensgaardNode *node2 = node_stk2.top();
		node_stk1.pop();
		node_stk2.pop();
		if (node_record.find(node1) != node_record.end()) {
			continue;
		}
		node_record.insert(node1);
		ufs->UFSUnion(node1, node2);
		vector<SteensgaardEdge *> &edge_vec = node1->getAllEdges();
		for (size_t i = 0; i < edge_vec.size(); i++) {
			SteensgaardEdge *edge = edge_vec[i];
			SteensgaardNode *succ_node1 = edge->getDst();
			SteensgaardNode *succ_node2 = node2->getDstNode(edge);
			if (succ_node2 != NULL) {
				node_stk1.push(succ_node1);
				node_stk2.push(succ_node2);
			}
		}
	}
}

void Steensgaard::handleAlloc(Instruction *inst) {
	findOrCreateSteensgaardNode(inst);
}

void Steensgaard::handleLoad(Instruction *inst) {
	Value *val = inst;
	Value *pointer = inst->getOperand(0);

	SteensgaardNode *val_node = findOrCreateSteensgaardNode(val);
	SteensgaardNode *src = findOrCreateSteensgaardNode(pointer);
	SteensgaardNode *dst = src->getRefNode();
	if (dst == NULL) {
		SteensgaardEdge *edge = new SteensgaardEdge(src, val_node,
									SteensgaardEdge::Ref, 0);
		src->insertEdge(edge);
	} else {
		mergeNode(val_node, dst);
	}
}

void Steensgaard::handleStore(Instruction *inst) {
	Value *val = inst->getOperand(0);
	Value *pointer = inst->getOperand(1);
	
	SteensgaardNode *val_node = findOrCreateSteensgaardNode(val);
	SteensgaardNode *src = findOrCreateSteensgaardNode(pointer);
	SteensgaardNode *dst = src->getRefNode();
	if (dst == NULL) {
		SteensgaardEdge *edge = new SteensgaardEdge(src, val_node,
									SteensgaardEdge::Ref, 0);
		src->insertEdge(edge);
	} else {
		mergeNode(val_node, dst);
	}
}

void Steensgaard::handleGep(Instruction *inst) {
	Value *val = inst;
	Value *pointer = inst->getOperand(0);
	Value *offset_val = inst->getOperand(inst->getNumOperands() - 1);

	SteensgaardNode *val_node = findOrCreateSteensgaardNode(val);
	SteensgaardNode *src = findOrCreateSteensgaardNode(pointer);

	if (ConstantInt *const_int = dyn_cast<ConstantInt>(offset_val)) {
		if (const_int->getBitWidth() <= 64) {
			int offset = const_int->getSExtValue();
			SteensgaardNode *dst = src->getOffsetNode(offset);
			if (dst == NULL) {
				SteensgaardEdge *edge = new SteensgaardEdge(
					src, val_node, SteensgaardEdge::Offset, offset);
				src->insertEdge(edge);
			} else {
				mergeNode(val_node, dst);
			}
			return;
		}
	}
	SteensgaardNode *dst = src->getGepNode();
	if (dst == NULL) {
		SteensgaardEdge *edge = new SteensgaardEdge(src, val_node,
									SteensgaardEdge::Gep, 0);
		src->insertEdge(edge);
	} else {
		mergeNode(val_node, dst);
	}
}

void Steensgaard::handleCast(Instruction *inst) {
	Value *val1 = inst;
	Value *val2 = inst->getOperand(0);
	SteensgaardNode *node1 = findOrCreateSteensgaardNode(val1);
	SteensgaardNode *node2 = findOrCreateSteensgaardNode(val2);
	mergeNode(node1, node2);
}

void Steensgaard::handleCall(Instruction *inst) {
	CallInst *call_inst = dyn_cast<CallInst>(inst);
	vector<Function *> &func_vec = cg->getCalledFuncs(inst);
	for (size_t i = 0; i < func_vec.size(); i++) {
		Function *func = func_vec[i];
		if (func_record.find(func) != func_record.end()) {
			continue;
		}
		func_record.insert(func);
		if (func->isVarArg()) {
			continue;
		}
		int arg_num = call_inst->arg_size();
		Function::arg_iterator arg_it, arg_end;
		arg_it = func->arg_begin();
		arg_end = func->arg_end();
		for (int i = 0; i < arg_num && arg_it != arg_end; i++, arg_it++) {
			Value *formal_arg = &(*arg_it);
			Value *actual_arg = call_inst->getArgOperand(i);
			SteensgaardNode *formal_node = 
							findOrCreateSteensgaardNode(formal_arg);
			SteensgaardNode *actual_node =
							findOrCreateSteensgaardNode(actual_arg);
			mergeNode(formal_node, actual_node);
		}
		handleFunc(func);
	}
}

void Steensgaard::handleFunc(Function *func) {
	Function::iterator func_it, func_end;
	func_it = func->begin();
	func_end = func->end();
	for (; func_it != func_end; func_it++) {
		BasicBlock *block = &(*func_it);
		BasicBlock::iterator b_it, b_end;
		b_it = block->begin();
		b_end = block->end();
		for (; b_it != b_end; b_it++) {
			Instruction *inst = &(*b_it);
			switch (inst->getOpcode()) {
				case Instruction::Alloca:
					handleAlloc(inst);
					break;
				case Instruction::Load:
					handleLoad(inst);
					break;
				case Instruction::Store:
					handleStore(inst);
					break;
				case Instruction::GetElementPtr:
					handleGep(inst);
					break;
				case Instruction::Trunc:
				case Instruction::ZExt:
				case Instruction::SExt:
				case Instruction::FPToUI:
				case Instruction::UIToFP:
				case Instruction::SIToFP:
				case Instruction::FPTrunc:
				case Instruction::FPExt:
				case Instruction::PtrToInt:
				case Instruction::IntToPtr:
				case Instruction::BitCast:
					handleCast(inst);
					break;
				case Instruction::Call:
					handleCall(inst);
					break;
				default:
					break;
			}
		}
	}
}

void Steensgaard::analyze() {
	Function::arg_iterator arg_it, arg_end;
	arg_it = entry_func->arg_begin();
	arg_end = entry_func->arg_end();
	for (; arg_it != arg_end; arg_it++) {
		Value *arg = &(*arg_it);
		SteensgaardNode *node = findOrCreateSteensgaardNode(arg);
		entry_node_set.insert(node);
	}
	handleFunc(entry_func);
}

set<SteensgaardNode *> &Steensgaard::getAllNodes() {
	return node_set;
}

set<SteensgaardNode *> &Steensgaard::getEntryNodes() {
	return entry_node_set;
}

void Steensgaard::bind(Steensgaard *steen) {
	set<SteensgaardNode *> &node_set = steen->getAllNodes();
	map<SteensgaardNode *, SteensgaardNode *> bind_node_map;
	set<SteensgaardNode *>::iterator n_it, n_end;
	n_it = node_set.begin();
	n_end = node_set.end();
	for (; n_it != n_end; n_it++) {
		SteensgaardNode *node = *n_it;
		SteensgaardNode *new_node = node->copy();
		bind_node_map[node] = new_node;
		this->node_set.insert(new_node);
	}
	n_it = node_set.begin();
	n_end = node_set.end();
	for (; n_it != n_end; n_it++) {
		SteensgaardNode *node = *n_it;
		SteensgaardNode *new_node = bind_node_map[node];
		vector<SteensgaardEdge *> &edge_vec = node->getAllEdges();
		for (size_t i = 0; i < edge_vec.size(); i++) {
			SteensgaardEdge *edge = edge_vec[i];
			SteensgaardEdge::EdgeType edge_type = edge->getType();
			int offset = edge->getOffset();
			SteensgaardNode *dst = edge->getDst();
			SteensgaardEdge *new_edge = new SteensgaardEdge(
					new_node, bind_node_map[dst], edge_type, offset);
			new_node->insertEdge(new_edge);
		}
	}
	map<SteensgaardNode *, SteensgaardNode *>::iterator bindn_it, bindn_end;
	bindn_it = bind_node_map.begin();
	bindn_end = bind_node_map.end();
	for (; bindn_it != bindn_end; bindn_it++) {
		SteensgaardNode *node = bindn_it->first;
		SteensgaardNode *new_node = bindn_it->second;
		set<Value *> &val_set = node->getAllValues();
		set<Value *>::iterator v_it, v_end;
		v_it = val_set.begin();
		v_end = val_set.end();
		for (; v_it != v_end; v_it++) {
			Value *val = *v_it;
			if (val_node_map.find(val) != val_node_map.end()) {
				ufs->UFSUnion(new_node, val_node_map[val]);
			}
			val_node_map[val] = new_node;
		}
	}
	set<SteensgaardNode *> &entry_node_set = 
							steen->getEntryNodes();
	set<SteensgaardNode *>::iterator en1_it, en1_end, en2_it, en2_end;
	en1_it = entry_node_set.begin();
	en1_end = entry_node_set.end();
	en2_it = this->entry_node_set.begin();
	en2_end = this->entry_node_set.end();
	for (; en1_it != en1_end; en1_it++) {
		for (; en2_it != en2_end; en2_it++) {
			SteensgaardNode *node1 = *en1_it;
			SteensgaardNode *node2 = *en2_it;
			stack<SteensgaardNode *> node_stk1;
			stack<SteensgaardNode *> node_stk2;
			set<SteensgaardNode *> node_record1;
			set<SteensgaardNode *> node_record2;
			node_stk1.push(node1);
			node_stk2.push(node2);
			while (!node_stk1.empty()) {
				SteensgaardNode *node1 = node_stk1.top();
				node_stk1.pop();
				if (node_record1.find(node1) != node_record1.end()) {
					continue;
				}
				node_record1.insert(node1);
				if (node1->getTypeName() != "" && 
						node1->getTypeName() == node2->getTypeName()) {
					mergeNode(node1, node2);
					break;
				}
				vector<SteensgaardEdge *> &edge_vec =
										node1->getAllEdges();
				for (size_t i = 0; i < edge_vec.size(); i++) {
					SteensgaardEdge *edge = edge_vec[i];
					node_stk1.push(edge->getDst());
				}
			}			
			while (!node_stk2.empty()) {
				SteensgaardNode *node2 = node_stk2.top();
				node_stk2.pop();
				if (node_record2.find(node2) != node_record2.end()) {
					continue;
				}
				node_record2.insert(node2);
				if (node2->getTypeName() != "" && 
						node2->getTypeName() == node1->getTypeName()) {
					mergeNode(node2, node1);
					break;
				}
				vector<SteensgaardEdge *> &edge_vec =
										node2->getAllEdges();
				for (size_t i = 0; i < edge_vec.size(); i++) {
					SteensgaardEdge *edge = edge_vec[i];
					node_stk2.push(edge->getDst());
				}
			}
		}
	}
}

void Steensgaard::setArgNode(Function *func) {
	set<Value *> arg_val_set;
	Module *mod = func->getParent();
	Module::global_iterator g_it, g_end;
	g_it = mod->global_begin();
	g_end = mod->global_end();
	for (; g_it != g_end; g_it++) {
		GlobalValue *gval = &(*g_it);
		arg_val_set.insert(gval);
	}
	Function::arg_iterator arg_it, arg_end;
	arg_it = func->arg_begin();
	arg_end = func->arg_end();
	for (; arg_it != arg_end; arg_it++) {
		Value *value = &(*arg_it);
		arg_val_set.insert(value);
	}
	set<Value *>::iterator v_it, v_end;
	v_it = arg_val_set.begin();
	v_end = arg_val_set.end();
	for (; v_it != v_end; v_it++) {
		Value *val = *v_it;
		SteensgaardNode *arg_node = findOrCreateSteensgaardNode(val);
		arg_node_set.insert(arg_node);
		stack<SteensgaardNode *> node_stk;
		set<SteensgaardNode *> node_record;
		node_stk.push(arg_node);
		while (!node_stk.empty()) {
			SteensgaardNode *node = node_stk.top();;
			node_stk.pop();
			node->setArgNode(true);
			if (node_record.find(node) != node_record.end()) {
				continue;
			}
			node_record.insert(node);
			vector<SteensgaardEdge *> &edge_vec = node->getAllEdges();
			for (size_t i = 0; i < edge_vec.size(); i++) {
				SteensgaardEdge *edge = edge_vec[i];
				SteensgaardNode *node = edge->getDst();
				node_stk.push(node);
			}
		}
	}
}

bool Steensgaard::isArgValue(Value *val) {
	if (val_node_map.find(val) != val_node_map.end()) {
		return val_node_map[val]->isArgNode();
	} else {
		return false;
	}
}

void Steensgaard::compress() {
	set<SteensgaardNode *> new_node_set;
	map<Value *, SteensgaardNode *> new_val_node_map;
	map<SteensgaardNode *, SteensgaardNode *> new_node_map;
	set<SteensgaardNode *>::iterator node_it, node_end;
	node_it = node_set.begin();
	node_end = node_set.end();
	for (; node_it != node_end; node_it++) {
		SteensgaardNode *node = *node_it;
		SteensgaardNode *ancestor = ufs->UFSFind(node);
		if (new_node_map.find(ancestor) == new_node_map.end()) {
			SteensgaardNode *new_node = new SteensgaardNode(); 
			new_node_set.insert(new_node);
			new_node_map[node] = new_node;
			new_node_map[ancestor] = new_node;
		} else {
			new_node_map[node] = new_node_map[ancestor];
		}
	}
	node_it = node_set.begin();
	node_end = node_set.end();
	for (; node_it != node_end; node_it++) {
		SteensgaardNode *old_node = *node_it;
		SteensgaardNode *new_node = new_node_map[old_node];
		vector<SteensgaardEdge *> &edge_vec = old_node->getAllEdges();
		for (size_t i = 0; i < edge_vec.size(); i++) {
			SteensgaardEdge *edge = edge_vec[i];
			SteensgaardEdge::EdgeType edge_type = edge->getType();
			int offset = edge->getOffset();
			SteensgaardNode *dst = edge->getDst();
			SteensgaardEdge *new_edge = new SteensgaardEdge(
						new_node, new_node_map[dst], edge_type, offset);
			new_node->insertEdge(new_edge);
		}
	}
	map<Value *, SteensgaardNode *>::iterator val_node_it, val_node_end;
	val_node_it = val_node_map.begin();
	val_node_end = val_node_map.end();
	for (; val_node_it != val_node_end; val_node_it++) {
		Value *val = val_node_it->first;
		SteensgaardNode *node = val_node_it->second;
		SteensgaardNode *new_node = new_node_map[node];
		new_node->insertValue(val);
		new_val_node_map[val] = new_node;
	}
	node_it = node_set.begin();
	node_end = node_set.end();
	for (; node_it != node_end; node_it++) {
		delete *node_it;
	}
	node_set = new_node_set;
	val_node_map = new_val_node_map;
}

SteensgaardNode *Steensgaard::getSteensgaardNode(Value *val) {
	if (val_node_map.find(val) != val_node_map.end()) {
		return val_node_map[val];
	} else {
		return NULL;
	}
}
