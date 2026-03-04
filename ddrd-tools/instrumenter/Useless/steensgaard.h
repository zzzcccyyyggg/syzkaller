#ifndef _STEENSGAARD_H_
#define _STEENSGAARD_H_

#include <set>
#include <map>
#include <vector>

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

#include "cg.h"

class SteensgaardNode;
class SteensgaardEdge;

class UFS {
private:
	std::map<SteensgaardNode *, SteensgaardNode *> ancestor_map;
public:
	void UFSUnion(SteensgaardNode * node1, SteensgaardNode *node2);
	SteensgaardNode *UFSFind(SteensgaardNode *node);
};

class SteensgaardNode {
private:
	std::set<llvm::Value *> val_set;
	std::vector<SteensgaardEdge *> edge_vec;
	bool is_arg_node;
public:
	SteensgaardNode();
	SteensgaardNode(llvm::Value *val);
	~SteensgaardNode();
	SteensgaardNode *getRefNode();
	SteensgaardNode *getGepNode();
	SteensgaardNode *getOffsetNode(int offset);
	SteensgaardNode *getDstNode(SteensgaardEdge *edge);
	void insertEdge(SteensgaardEdge *edge);
	std::vector<SteensgaardEdge *> &getAllEdges();

	void insertValue(llvm::Value *val);
	std::set<llvm::Value *> &getAllValues();
	void setArgNode(bool is_arg_node);
	bool isArgNode();
	std::string getTypeName();
	SteensgaardNode *copy();
};

class SteensgaardEdge {
public:
	enum EdgeType {Ref, Offset, Gep};
private:
	EdgeType edge_type;
	int offset;
	SteensgaardNode *src;
	SteensgaardNode *dst;
public:
	SteensgaardEdge(SteensgaardNode *src, SteensgaardNode *dst,
							EdgeType edge_type, int offset);
	SteensgaardEdge::EdgeType getType();
	int getOffset();
	SteensgaardNode *getSrc();
	SteensgaardNode *getDst();
};

class Steensgaard {
private:
	llvm::Function *entry_func;
	CG *cg;
	UFS *ufs;
	std::set<SteensgaardNode *>  node_set;
	std::set<SteensgaardNode *> entry_node_set;
	std::set<SteensgaardNode *> arg_node_set;
	std::map<llvm::Value *, SteensgaardNode *> val_node_map;
	std::set<llvm::Function *> func_record;
	
private:
	SteensgaardNode *findOrCreateSteensgaardNode(llvm::Value *val);
	void mergeNode(SteensgaardNode *node1, SteensgaardNode *node2);
	void handleAlloc(llvm::Instruction *inst);
	void handleLoad(llvm::Instruction *inst);
	void handleStore(llvm::Instruction *inst);
	void handleGep(llvm::Instruction *inst);
	void handleCast(llvm::Instruction *inst);
	void handleCall(llvm::Instruction *inst);
	void handleFunc(llvm::Function *func);

	void analyze();
public:
	Steensgaard();
	Steensgaard(llvm::Function *entry_func, CG *cg);
	~Steensgaard();

	std::set<SteensgaardNode *> &getAllNodes();
	std::set<SteensgaardNode *> &getEntryNodes();
	void bind(Steensgaard *steen);
	void setArgNode(llvm::Function *func);
	void compress();

	bool isArgValue(llvm::Value *val);                                                                                                     
	SteensgaardNode *getSteensgaardNode(llvm::Value *val);
};

#endif
