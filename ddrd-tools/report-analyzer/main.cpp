#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SourceMgr.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;
using namespace llvm;

namespace {

struct HashMatch {
	fs::path irPath;
	std::string parentFunction;
	std::string calledFunction;
	uint64_t hash = 0;
	std::string accessKind;
	uint64_t instrumentFileLine = 0;
	std::string instruction;
	std::vector<std::string> debugChain;
};

bool isHashString(const std::string &value)
{
	if (value.empty())
		return false;
	if (value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0) {
		if (value.size() <= 2)
			return false;
		return std::all_of(value.begin() + 2, value.end(), [](unsigned char ch) {
			return std::isxdigit(ch) != 0;
		});
	}
	return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
		return std::isdigit(ch) != 0;
	});
}

std::optional<uint64_t> parseHash(const std::string &value)
{
	try {
		size_t consumed = 0;
		uint64_t hash = 0;
		if (value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0)
			hash = std::stoull(value, &consumed, 16);
		else
			hash = std::stoull(value, &consumed, 10);
		if (consumed != value.size())
			return std::nullopt;
		return hash;
	} catch (...) {
		return std::nullopt;
	}
}

std::vector<fs::path> collectIRFiles(const fs::path &input)
{
	std::vector<fs::path> instrumented;
	std::vector<fs::path> plain;

	if (!fs::exists(input))
		return {};

	if (fs::is_regular_file(input)) {
		if (input.extension() == ".ll")
			return {input};
		return {};
	}

	for (const auto &entry : fs::recursive_directory_iterator(input)) {
		if (!entry.is_regular_file())
			continue;
		const auto &path = entry.path();
		if (path.extension() != ".ll")
			continue;
		if (path.filename().string().find("instrumented.ll") != std::string::npos)
			instrumented.push_back(path);
		else
			plain.push_back(path);
	}

	auto sorter = [](const fs::path &left, const fs::path &right) {
		return left.string() < right.string();
	};
	std::sort(instrumented.begin(), instrumented.end(), sorter);
	std::sort(plain.begin(), plain.end(), sorter);

	return !instrumented.empty() ? instrumented : plain;
}

std::string formatScope(const DILocation *loc)
{
	if (!loc)
		return "<unknown>";
	if (const auto *scope = loc->getScope()) {
		if (const auto *subprogram = scope->getSubprogram())
			return subprogram->getName().str();
	}
	return "<unknown>";
}

void printDebugChain(const DILocation *loc, int indent = 0)
{
	if (!loc)
		return;
	std::string prefix(static_cast<size_t>(indent), ' ');
	std::cout << prefix << "- " << loc->getFilename().str() << ":" << loc->getLine()
		  << ":" << loc->getColumn() << " in " << formatScope(loc) << "\n";
	if (const DILocation *inlinedAt = loc->getInlinedAt()) {
		std::cout << prefix << "  inlined at\n";
		printDebugChain(inlinedAt, indent + 4);
	}
}

std::vector<std::string> collectDebugChain(const DILocation *loc)
{
	std::vector<std::string> chain;
	while (loc) {
		std::string entry = loc->getFilename().str() + ":" +
			std::to_string(loc->getLine()) + ":" +
			std::to_string(loc->getColumn()) + " in " + formatScope(loc);
		chain.push_back(entry);
		loc = loc->getInlinedAt();
	}
	return chain;
}

std::string accessKindForCall(const CallInst &call, const std::string &callee)
{
	if (callee == "kccwf_rec_free")
		return "free";
	if (callee != "kccwf_rec_mem_access")
		return "unknown";
	if (call.arg_size() < 3)
		return "unknown";
	if (const auto *typeArg = dyn_cast<ConstantInt>(call.getArgOperand(2)))
		return typeArg->getZExtValue() ? "write" : "read";
	return "unknown";
}

uint64_t fileLineForCall(const CallInst &call, const std::string &callee)
{
	if (callee != "kccwf_rec_mem_access")
		return 0;
	if (call.arg_size() < 4)
		return 0;
	if (const auto *lineArg = dyn_cast<ConstantInt>(call.getArgOperand(3)))
		return lineArg->getZExtValue();
	return 0;
}

std::vector<HashMatch> findHashesInIR(const fs::path &irPath,
				      const std::set<uint64_t> &targets)
{
	std::vector<HashMatch> matches;
	LLVMContext context;
	SMDiagnostic error;
	std::unique_ptr<Module> module = parseIRFile(irPath.string(), error, context);

	if (!module) {
		std::cerr << "failed to parse IR: " << irPath << "\n";
		std::cerr << "  message: " << error.getMessage().str() << "\n";
		return matches;
	}

	for (Function &function : *module) {
		for (BasicBlock &block : function) {
			for (Instruction &inst : block) {
				auto *call = dyn_cast<CallInst>(&inst);
				if (!call)
					continue;

				Function *callee = call->getCalledFunction();
				if (!callee)
					continue;

				std::string calleeName = callee->getName().str();
				int hashArgIndex = -1;
				if (calleeName == "kccwf_rec_mem_access")
					hashArgIndex = 1;
				else if (calleeName == "kccwf_rec_free")
					hashArgIndex = 0;
				else
					continue;

				if (call->arg_size() <= static_cast<unsigned>(hashArgIndex))
					continue;

				auto *hashArg = dyn_cast<ConstantInt>(call->getArgOperand(hashArgIndex));
				if (!hashArg)
					continue;

				uint64_t hash = hashArg->getZExtValue();
				if (!targets.count(hash))
					continue;

				std::string instruction;
				raw_string_ostream stream(instruction);
				stream << inst;
				stream.flush();

				HashMatch match;
				match.irPath = irPath;
				match.parentFunction = function.getName().str();
				match.calledFunction = calleeName;
				match.hash = hash;
				match.accessKind = accessKindForCall(*call, calleeName);
				match.instrumentFileLine = fileLineForCall(*call, calleeName);
				match.instruction = instruction;
				match.debugChain = collectDebugChain(call->getDebugLoc().get());
				matches.push_back(std::move(match));
			}
		}
	}

	return matches;
}

void printHashMatch(const HashMatch &match)
{
	std::cout << "\n=== match ===\n";
	std::cout << "IR file       : " << match.irPath << "\n";
	std::cout << "Parent func   : " << match.parentFunction << "\n";
	std::cout << "Call target   : " << match.calledFunction << "\n";
	std::cout << "VarName/hash  : " << match.hash << " (0x" << std::hex << match.hash
		  << std::dec << ")\n";
	std::cout << "Access kind   : " << match.accessKind << "\n";
	if (match.instrumentFileLine)
		std::cout << "Instrument arg: file_line=" << match.instrumentFileLine << "\n";
	std::cout << "Instruction   : " << match.instruction << "\n";
	if (!match.debugChain.empty()) {
		std::cout << "Debug chain   :\n";
		for (size_t index = 0; index < match.debugChain.size(); ++index) {
			std::cout << "  - " << match.debugChain[index] << "\n";
			if (index + 1 != match.debugChain.size())
				std::cout << "    inlined at\n";
		}
	} else {
		std::cout << "Debug chain   : <missing>\n";
	}
}

void printDebugInfo(const fs::path &irPath, const std::string &funcName,
			 int blockLineNumber, int irLineNumber)
{
	LLVMContext context;
	SMDiagnostic error;
	std::unique_ptr<Module> module = parseIRFile(irPath.string(), error, context);
	if (!module) {
		std::cerr << "failed to parse IR: " << irPath << "\n";
		std::cerr << "  message: " << error.getMessage().str() << "\n";
		return;
	}

	for (Function &function : *module) {
		if (function.getName() != funcName)
			continue;

		int blockNumber = 0;
		for (BasicBlock &block : function) {
			++blockNumber;
			int instNumber = 0;
			for (Instruction &inst : block) {
				++instNumber;
				if (blockNumber != blockLineNumber || instNumber != irLineNumber)
					continue;
				std::cout << "IR file     : " << irPath << "\n";
				std::cout << "Function    : " << funcName << "\n";
				std::cout << "Block/Inst  : " << blockLineNumber << "/" << irLineNumber << "\n";
				std::string instruction;
				raw_string_ostream stream(instruction);
				stream << inst;
				stream.flush();
				std::cout << "Instruction : " << instruction << "\n";
				if (const DILocation *loc = inst.getDebugLoc().get()) {
					std::cout << "Debug chain :\n";
					printDebugChain(loc, 2);
				} else {
					std::cout << "Debug chain : <missing>\n";
				}
				return;
			}
		}
	}

	std::cout << "no matching debug info in " << irPath << "\n";
}

void usage(const char *argv0)
{
	std::cerr << "Usage:\n";
	std::cerr << "  " << argv0 << " <ir-file-or-dir> <hash> [hash ...]\n";
	std::cerr << "  " << argv0 << " <ir-file-or-dir> <function> <block-no> <ir-no>\n\n";
	std::cerr << "Examples:\n";
	std::cerr << "  " << argv0 << " kernels/builds/x86/net/bluetooth 7350912627818033108\n";
	std::cerr << "  " << argv0 << " kernels/builds/x86/net/bluetooth/sco.instrumented.ll sco_sock_connect 50 1\n";
}

} // namespace

int main(int argc, char **argv)
{
	if (argc < 3) {
		usage(argv[0]);
		return 1;
	}

	fs::path input = argv[1];
	std::vector<fs::path> irFiles = collectIRFiles(input);
	if (irFiles.empty()) {
		std::cerr << "no .ll files found under " << input << "\n";
		return 1;
	}

	if (argc == 5 && !isHashString(argv[2])) {
		const std::string funcName = argv[2];
		const int blockLineNumber = std::stoi(argv[3]);
		const int irLineNumber = std::stoi(argv[4]);
		for (const auto &irPath : irFiles)
			printDebugInfo(irPath, funcName, blockLineNumber, irLineNumber);
		return 0;
	}

	std::set<uint64_t> targets;
	for (int index = 2; index < argc; ++index) {
		auto hash = parseHash(argv[index]);
		if (!hash) {
			std::cerr << "invalid hash: " << argv[index] << "\n";
			return 1;
		}
		targets.insert(*hash);
	}

	std::unordered_map<uint64_t, std::vector<HashMatch>> allMatches;
	for (const auto &irPath : irFiles) {
		for (const auto &match : findHashesInIR(irPath, targets))
			allMatches[match.hash].push_back(match);
	}

	for (uint64_t hash : targets) {
		std::cout << "\n========================================\n";
		std::cout << "VarName/hash: " << hash << " (0x" << std::hex << hash << std::dec << ")\n";
		std::cout << "========================================\n";
		auto it = allMatches.find(hash);
		if (it == allMatches.end()) {
			std::cout << "not found in current IR inputs\n";
			continue;
		}
		for (const auto &match : it->second)
			printHashMatch(match);
	}

	return 0;
}