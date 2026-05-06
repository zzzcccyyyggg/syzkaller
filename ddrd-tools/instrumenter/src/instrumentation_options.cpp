#include "instrumentation_options.hpp"
#include <iostream>
#include <cstring>
#include <string>
#include <cstdlib>

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <input_file> [options]\n"
              << "Options:\n"
              << "  -f, --functions     Enable function enter/exit instrumentation\n"
              << "  -v, --variables     Enable shared variable access instrumentation\n"
              << "  -b, --basic-blocks  Enable basic block instrumentation\n"
              << "  -l, --locks <file>  Enable lock instrumentation with lock config file\n"
              << "  -t, --trylock <file> Specify trylock config file\n"
              << "  --datarace-only     Enable datarace-only mode (memory accesses + optional locks)\n"
              << "  --free              Enable memory free function instrumentation\n"
              << "  --enter-name <name> Set custom function enter function name\n"
              << "                      (default: kccwf_rec_func_enter)\n"
              << "  --exit-name <name>  Set custom function exit function name\n"
              << "                      (default: kccwf_rec_func_exit)\n"
              << "  --bb-name <name>    Set custom basic block function name\n"
              << "                      (default: kccwf_rec_bbs)\n"
              << "  --lock-name <name>  Set custom lock function name\n"
              << "                      (default: rec_lock)\n"
              << "  --free-name <name>  Set custom free function name\n"
              << "                      (default: kccwf_rec_free)\n"
              << "  -a, --all           Enable all instrumentations (requires lock file)\n"
              << "  -h, --help          Show this help message\n"
              << "\nExamples:\n"
              << "  " << program_name << " input.ll -f -v\n"
              << "  " << program_name << " input.ll -l locks.txt -t trylocks.txt\n"
              << "  " << program_name << " input.ll --datarace-only -l locks.txt\n"
              << "  " << program_name << " input.ll --free\n"
              << "  " << program_name << " input.ll -v --func-name __ddrace_rec_mem_access\n"
              << "  " << program_name << " input.ll -f --enter-name my_func_enter --exit-name my_func_exit\n"
              << "  " << program_name << " input.ll -a -l locks.txt\n";
}

InstrumentationOptions parseCommandLineOptions(int argc, char** argv) {
    InstrumentationOptions options;
    
    if (argc < 2) {
        printUsage(argv[0]);
        exit(1);
    }
    
    // 首先检查是否有帮助选项
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            exit(0);
        }
    }
    
    // 第一个参数是输入文件
    // 从第2个参数开始解析选项
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-f" || arg == "--functions") {
            options.instrument_functions = true;
        }
        else if (arg == "-v" || arg == "--variables") {
            options.instrument_variables = true;
        }
        else if (arg == "-b" || arg == "--basic-blocks") {
            options.instrument_basic_blocks = true;
        }
        else if (arg == "-l" || arg == "--locks") {
            if (i + 1 < argc) {
                options.instrument_locks = true;
                options.lock_file = argv[++i];
            } else {
                std::cerr << "Error: Lock option requires a file argument\n";
                exit(1);
            }
        }
        else if (arg == "-t" || arg == "--trylock") {
            if (i + 1 < argc) {
                options.trylock_file = argv[++i];
            } else {
                std::cerr << "Error: Trylock option requires a file argument\n";
                exit(1);
            }
        }
        else if (arg == "--datarace-only") {
            options.datarace_only = true;
            options.instrument_variables = true;
            options.instrument_functions = false;
            options.instrument_basic_blocks = false;
            options.instrument_free_funcs = false;
        }
        else if (arg == "--free") {
            options.instrument_free_funcs = true;
        }
        else if (arg == "--all") {
            options.instrument_functions = true;
            options.instrument_variables = true;
            options.instrument_basic_blocks = true;
            options.instrument_locks = true;
            options.instrument_free_funcs = true;
        }
        else if (arg == "--func-name") {
            if (i + 1 < argc) {
                options.instrumentation_func_name = argv[++i];
            } else {
                std::cerr << "Error: --func-name option requires a function name argument\n";
                exit(1);
            }
        }
        else if (arg == "--enter-name") {
            if (i + 1 < argc) {
                options.func_enter_name = argv[++i];
            } else {
                std::cerr << "Error: --enter-name option requires a function name argument\n";
                exit(1);
            }
        }
        else if (arg == "--exit-name") {
            if (i + 1 < argc) {
                options.func_exit_name = argv[++i];
            } else {
                std::cerr << "Error: --exit-name option requires a function name argument\n";
                exit(1);
            }
        }
        else if (arg == "--bb-name") {
            if (i + 1 < argc) {
                options.basic_block_name = argv[++i];
            } else {
                std::cerr << "Error: --bb-name option requires a function name argument\n";
                exit(1);
            }
        }
        else if (arg == "--lock-name") {
            if (i + 1 < argc) {
                options.lock_func_name = argv[++i];
            } else {
                std::cerr << "Error: --lock-name option requires a function name argument\n";
                exit(1);
            }
        }
        else if (arg == "--free-name") {
            if (i + 1 < argc) {
                options.free_func_name = argv[++i];
            } else {
                std::cerr << "Error: --free-name option requires a function name argument\n";
                exit(1);
            }
        }
        else if (arg == "-a" || arg == "--all") {
            options.instrument_functions = true;
            options.instrument_variables = true;
            options.instrument_basic_blocks = true;
            options.instrument_locks = true;
        }
        else {
            std::cerr << "Error: Unknown option " << arg << "\n";
            printUsage(argv[0]);
            exit(1);
        }
    }
    
    // 如果启用了锁插桩但没有提供锁文件，给出警告
    if (options.instrument_locks && options.lock_file.empty()) {
        std::cerr << "Warning: Lock instrumentation enabled but no lock file specified\n";
        options.instrument_locks = false;
    }

    if (options.datarace_only) {
        options.instrument_variables = true;
        options.instrument_functions = false;
        options.instrument_basic_blocks = false;
        options.instrument_free_funcs = false;
    }
    
    // 如果没有启用任何插桩，默认启用所有（为了向后兼容）
    if (!options.hasAnyInstrumentation()) {
        std::cout << "No specific instrumentation options provided. Use -h for help.\n";
        exit(1);
    }
    
    return options;
}
