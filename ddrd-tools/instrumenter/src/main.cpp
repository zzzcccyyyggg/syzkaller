#include "handle_file.hpp"
#include "instrumentation_options.hpp"

int main(int argc, char **argv) {
    // 解析命令行选项
    InstrumentationOptions options = parseCommandLineOptions(argc, argv);
    
    // 输入文件是第一个参数
    std::string input_file = argv[1];
    
    // 调用处理函数
    HandleFile(input_file, options);
    return 0;
}