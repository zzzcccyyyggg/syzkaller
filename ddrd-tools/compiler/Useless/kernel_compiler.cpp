#include "kernel_compiler.hpp"

void RemoveAssemblyOptions(int argc, char **argv) {
    std::string last_arg = argv[argc - 1];
    if (last_arg.rfind(".s") == last_arg.length() - 2 || 
        last_arg.rfind(".S") == last_arg.length() - 2) {
        
        auto ori_argv = new char*[argc + 5];
        ori_argv[0] = CLANG;
        int i;
		for (i = 1; i < argc; i++) {
			ori_argv[i] = argv[i];
		}
        ori_argv[i] = NULL;

        execvp(ori_argv[0], ori_argv);
		std::cout << "failed to execute " << ori_argv[0] << std::endl;
		exit(-1);
    }
}

void RemoveOtherOptions(int argc, char **argv) {
    if (object_file == "" || 
        object_file.rfind("xfs_bmap") == object_file.length() - 8 || 
        object_file.rfind("xfs_inode_fork") == object_file.length() - 14) {
		auto ori_argv = new char*[argc + 128];
		
		ori_argv[0] = CLANG;
		int i;
		int new_i = 1;
		for (i = 1; i < argc; i++) {
			ori_argv[new_i++] = argv[i];
		}
		ori_argv[new_i++] = NULL;

		execvp(ori_argv[0], ori_argv);
		std::cout << "failed to execute " << ori_argv[0] << std::endl;
		exit(-1);
    }
}

void EditParams(int argc, char **argv) {
    for(int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if(arg == "-c") {
            no_link = true;
        } else if(arg == "-o") {
            link_all = true;
            object_file = argv[i + 1];
        } else if(arg.rfind(".c") == arg.length() - 2) {
            source_files.push_back(arg);
        } else {
            std::cout << "Unknown flag[" << other_args.size() << "]: " << arg << std::endl;
            other_args.push_back(arg);
        }
    }
    if(no_link) {
        for (std::string source_file : source_files) {
            std::string target_file = source_file.substr(0, source_file.length() - 2) + ".o";
            target_file = target_file.substr(target_file.find_last_of("/") + 1);
            target_files.push_back(target_file);
        }
        return;
    }
    if(link_all) {
        if(object_file.rfind(".o") == object_file.length() -2  && !(object_file.rfind(".mod.o") == object_file.length() - 6)) {
            target_files.push_back(object_file);
        }
        return;
    }
    return;
}

void CompileToLL() {
    std::string clang_command = CLANG;
    clang_command += " -S -emit-llvm -g";
    for (std::string source_file : source_files) {
        clang_command += " " + source_file;
    }
    system(clang_command.c_str());
    return;
}

void Instrument() {
    for (std::string source_file : source_files) {
        std::string instrumenter_command = INSTRUMENTER;
        std::string lock_file = LOCK_FILE;
        std::string trylock_file = TRYLOCK_FILE;
        instrumenter_command += " " + lock_file + " " + trylock_file;
        std::string ll_file = source_file.substr(0, source_file.length() - 2) + ".ll";
        instrumenter_command += " " + ll_file;
        system(instrumenter_command.c_str());
        instrumenter_command.clear();
    }
    return;
}

void CompileToO() {
    std::string clang_command = CLANG;
    for (std::string arg : other_args) {
        clang_command += " " + arg;
    }
    for (std::string source_file : source_files) {
        std::string ll_file = source_file.substr(0, source_file.length() - 2) + ".instrument.ll";
        clang_command += " " + ll_file;
    }
    system(clang_command.c_str());
    return;
}

int main(int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        std::cout << "argv[" << i << "] = " << argv[i] << std::endl;
    }
    RemoveAssemblyOptions(argc, argv);
    EditParams(argc, argv);
    RemoveOtherOptions(argc, argv);
    CompileToLL();
    Instrument();
    CompileToO();
    return 0;
}