#include <string>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <sys/types.h>
#include <sys/wait.h>
#include <cstring>

using namespace std;

// 配置常量
constexpr auto CLANG_PATH = "clang-18";

// 通过环境变量获取路径, 允许灵活配置
string get_instrumenter_path() {
    const char* env = getenv("DDRD_INSTRUMENTER");
    if (env && env[0]) return string(env);
    // 回退: 相对于 compiler 目录的 ../build/bin/instrumenter
    const char* toolchain = getenv("DDRD_TOOLCHAIN");
    if (toolchain && toolchain[0]) return string(toolchain) + "/build/bin/instrumenter";
    return "/home/zzzccc/BASS/DDRD-syzkaller/ddrd-tools/build/bin/instrumenter";
}

string get_lock_file() {
    const char* toolchain = getenv("DDRD_TOOLCHAIN");
    if (toolchain && toolchain[0]) return string(toolchain) + "/instrumenter/LockFunc.txt";
    return "/home/zzzccc/BASS/DDRD-syzkaller/ddrd-tools/instrumenter/LockFunc.txt";
}

string get_trylock_file() {
    const char* toolchain = getenv("DDRD_TOOLCHAIN");
    if (toolchain && toolchain[0]) return string(toolchain) + "/instrumenter/race_case/TryLock.txt";
    return "/home/zzzccc/BASS/DDRD-syzkaller/ddrd-tools/instrumenter/race_case/TryLock.txt";
}

// 编译目标信息
struct BuildTarget {
    string output;      // -o 指定的输出文件
    string source;      // 源文件路径
    string base_name;   // 基础文件名（无扩展名）
    string ll_file;     // LLVM IR 文件
    string instrumented_file; // 插桩后的文件
};

// 执行命令的封装函数
void execute_command(const vector<const char*>& args) {
    pid_t pid = fork();
    if (pid == 0) {
        // 转换为 execvp 需要的格式
        vector<char*> exec_args;
        for (const auto& arg : args) {
            exec_args.push_back(const_cast<char*>(arg));
        }
        exec_args.push_back(nullptr);

        execvp(exec_args[0], exec_args.data());
        cerr << "Failed to execute: " << exec_args[0] << endl;
        exit(EXIT_FAILURE);
    }
    waitpid(pid, nullptr, 0);
}

// The first stage emits LLVM IR for DDRD's own instrumenter. Keep frontend
// sanitizer flags so the IR still carries attributes such as sanitize_address,
// but skip sanitizer pass-tuning options because LLVM passes are disabled here.
bool should_skip_ir_sanitizer_pass_arg(const string& arg, int argc, char** argv, int& i) {
    if (arg == "-mllvm" && i + 1 < argc) {
        const string next = argv[i + 1];
        if (next.rfind("-asan", 0) == 0 ||
            next.rfind("-sancov", 0) == 0 ||
            next.rfind("-sanitizer", 0) == 0) {
            ++i;
            return true;
        }
    }

    if (arg.rfind("-mllvm=", 0) == 0) {
        const string opt = arg.substr(strlen("-mllvm="));
        if (opt.rfind("-asan", 0) == 0 ||
            opt.rfind("-sancov", 0) == 0 ||
            opt.rfind("-sanitizer", 0) == 0) {
            return true;
        }
    }

    return false;
}

// 处理汇编文件快速返回
bool handle_assembly_file(int argc, char** argv) {
    string fn(argv[argc-1]);
    if (fn.size() < 2) return false;
    
    const string ext = fn.substr(fn.size()-2);
    if (ext != ".s" && ext != ".S") return false;

    vector<const char*> args = {CLANG_PATH, "-Og","-g"};  // 添加-Og选项
    for (int i=1; i < argc; i++) {
        // 跳过其他优化选项
        if (strcmp(argv[i], "-O0") == 0 || 
            strcmp(argv[i], "-O1") == 0 ||
            strcmp(argv[i], "-O2") == 0 ||
            strcmp(argv[i], "-O3") == 0 ||
            strcmp(argv[i], "-Os") == 0 ||
            strcmp(argv[i], "-Oz") == 0 ||
            strcmp(argv[i], "-Ofast") == 0) {
            continue;
        }
        args.push_back(argv[i]);
    }
    execute_command(args);
    return true;
}

// 解析编译目标信息
BuildTarget parse_build_target(int argc, char** argv) {
    BuildTarget target;
    bool next_is_output = false;
    bool has_c_option = false;

    for (int i = 0; i < argc; i++) {
        const string arg = argv[i];
        
        if (next_is_output) {
            target.output = arg;
            next_is_output = false;
            std::cout << "Parsed output file: " << target.output << std::endl;
            continue;
        }

        if (arg == "-o") {
            next_is_output = true;
            continue;
        }

        if (arg == "-c") {
            has_c_option = true;
            continue;
        }

        if (arg.size() > 2 && arg.substr(arg.size() - 2) == ".c") {
            target.source = arg;
            std::cout << "Parsed source file: " << target.source << std::endl;
        }
    }

    if (target.output.empty() && has_c_option && !target.source.empty()) {
        size_t dot_pos = target.source.rfind('.');
        size_t slash_pos = target.source.rfind('/');
        target.output = target.source.substr(slash_pos + 1, dot_pos - slash_pos - 1) + ".o";
        std::cout << "Auto-generated output file: " << target.output << std::endl;
    }

    if (!target.output.empty() && 
        target.output.size() > 2 && 
        target.output.substr(target.output.size() - 2) == ".o" &&
        target.output.find(".mod.o") == string::npos) 
    {
        size_t dot_pos = target.output.rfind('.');
        target.base_name = target.output.substr(0, dot_pos);
        target.ll_file = target.base_name + ".ll";
        target.instrumented_file = target.base_name + ".instrumented.ll";
        std::cout << "Derived base name: " << target.base_name << std::endl;
        std::cout << "LLVM IR file: " << target.ll_file << std::endl;
        std::cout << "Instrumented LLVM file: " << target.instrumented_file << std::endl;
    }

    return target;
}

// 生成LLVM IR
void generate_llvm_ir(int argc, char** argv, const BuildTarget& target) {
    std::cout << "Generating LLVM IR for: " << target.source << endl;
    vector<const char*> args = {
        CLANG_PATH,
        "-Og",  // 使用-Og替代其他优化选项
        "-S", "-emit-llvm",
        "-Xclang", "-disable-llvm-passes",
        "-g",
        "-Qunused-arguments",
        "-Wno-unused-command-line-argument"
    };

    for (int i=1; i<argc; i++) {
        const string arg = argv[i];
        
        // 跳过优化选项和其他不需要的参数
        if (arg == "-Werror,-Wunused-command-line-argument" ||
            arg == "-O0" || arg == "-O1" || arg == "-O2" || 
            arg == "-O3" || arg == "-Os" || arg == "-Oz" ||
            arg == "-Ofast") {
            continue;
        }
        if (should_skip_ir_sanitizer_pass_arg(arg, argc, argv, i)) {
            continue;
        }
        if (arg == target.output) {
            args.push_back(target.ll_file.c_str());
            continue;
        }
        args.push_back(argv[i]);
    }

    execute_command(args);
}

// 运行插桩工具
void run_instrumenter(const BuildTarget& target) {
    string instrumenter = get_instrumenter_path();
    string lockfile = get_lock_file();
    string trylockfile = get_trylock_file();
    execute_command({
        instrumenter.c_str(),
        target.ll_file.c_str(),
        "-f",
        "-v",
        "-l",
        lockfile.c_str(),
        "-t",
        trylockfile.c_str(),
        "--free"
    });
}

// 编译插桩后的代码
void compile_instrumented_code(int argc, char** argv, const BuildTarget& target) {
    vector<const char*> args = {CLANG_PATH, "-Og"};  // 添加-Og选项

    args.insert(args.end(), {
        "-Qunused-arguments",
        "-Wno-unused-command-line-argument"
    });

    for (int i=1; i<argc; i++) {
        const string arg = argv[i];
        
        // 跳过优化选项和其他不需要的参数
        if (arg == "-Werror,-Wunused-command-line-argument" ||
            arg == "-O0" || arg == "-O1" || arg == "-O2" || 
            arg == "-O3" || arg == "-Os" || arg == "-Oz" ||
            arg == "-Ofast") {
            continue;
        }
        // 跳过预处理器依赖相关参数:
        // 输入是 .instrumented.ll (LLVM IR), 不经过 C 预处理器,
        // 这些参数会导致 .d 文件不生成或被清空.
        // .d 文件已在 generate_llvm_ir 步骤中正确生成.
        if (arg.find("-Wp,") == 0) {
            continue;
        }
        if (arg == "-MD" || arg == "-MMD") {
            continue;
        }
        if (arg == "-MF" || arg == "-MT" || arg == "-MQ") {
            // 这些选项后面跟一个路径参数, 一起跳过
            if (i + 1 < argc) i++;
            continue;
        }
        if (arg == target.source) {
            args.push_back(target.instrumented_file.c_str());
            continue;
        }
        args.push_back(argv[i]);
    }

    execute_command(args);
}

int main(int argc, char** argv) {
    if (handle_assembly_file(argc, argv)) {
        return 0;
    }

    BuildTarget target = parse_build_target(argc, argv);

    if (target.base_name.empty()) 
    {
        vector<const char*> args = {CLANG_PATH, "-Og"};  // 添加-Og选项
        for (int i=1; i < argc; i++) {
            if (strcmp(argv[i], "-O0") == 0 || 
                strcmp(argv[i], "-O1") == 0 ||
                strcmp(argv[i], "-O2") == 0 ||
                strcmp(argv[i], "-O3") == 0 ||
                strcmp(argv[i], "-Os") == 0 ||
                strcmp(argv[i], "-Oz") == 0 ||
                strcmp(argv[i], "-Ofast") == 0) {
                continue;
            }
            args.push_back(argv[i]);
        }
        execute_command(args);
        return 0;
    }

    generate_llvm_ir(argc, argv, target);
    run_instrumenter(target);
    compile_instrumented_code(argc, argv, target);

    return 0;
}
