#include "handle_file.hpp"
#include "auxiliary.hpp"

void WriteModuleToFile(llvm::Module *mod, std::string file_out) {
        std::error_code ec;
        llvm::raw_fd_ostream out(file_out, ec);
        mod->print(out, nullptr);
        out.close();
}

// 新的函数实现，接受选项结构
void HandleFile(const std::string& filein, const InstrumentationOptions& options) {
    if (filein.empty()) {
        std::cout << "Filename is required" << std::endl;
        exit(1);
    }

    llvm::LLVMContext Context;
    llvm::SMDiagnostic Err;
    std::unique_ptr<llvm::Module> M = llvm::parseIRFile(filein, Err, Context);
    if (!M) {
        Err.print(filein.c_str(), llvm::errs());
        exit(1);
    }

    // 使用选项结构进行插桩
    InstrumentOnFile(M.get(), options);

    if (verifyModule(*M, &llvm::errs())) {
        llvm::errs() << "Error: Module failed verification\n";
        exit(1);
    }

    llvm::StringRef in_file_name = filein;
    std::string fileout;
    fileout = (in_file_name.ends_with(".ll") ? in_file_name.drop_back(3) : in_file_name).str();
    fileout += ".instrumented.ll";

    WriteModuleToFile(M.get(), fileout);
    PrintSuccess("Successfully instrument " + fileout );
}

// 保留旧的函数实现以向后兼容
void HandleFile(std::string filein, std::string lockfile, std::string trylockfile) {
    InstrumentationOptions options;
    options.instrument_functions = true;
    options.instrument_variables = true;
    options.instrument_basic_blocks = true;
    options.instrument_locks = !lockfile.empty();
    options.lock_file = lockfile;
    options.trylock_file = trylockfile;
    
    HandleFile(filein, options);
}