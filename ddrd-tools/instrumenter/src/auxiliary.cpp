#include "auxiliary.hpp"

void PrintError(std::string error) {
    std::cout << RED << "Error: " << error << RESET << std::endl;
}

void PrintWarning(std::string warning) {
    std::cout << YELLOW << "Warning: " << warning << RESET << std::endl;
}

void PrintInfo(std::string info) {
    std::cout << BLUE << "Info: " << info << RESET << std::endl;
}

void PrintSuccess(std::string success) {
    std::cout << GREEN << "Success: " << success << RESET << std::endl;
}

unsigned long BKDRHash(const char *str, unsigned long hash) 
{
	unsigned long seed = 131;
    while (*str) {
        hash = hash * seed + (*str++);
    }
	return hash;
}


void writeToFile(const std::string& filename, const std::string& str, unsigned long num) {
    // 打开文件进行写入（以追加模式打开文件，防止覆盖现有内容）
    std::ofstream outFile;
    outFile.open(filename, std::ios::out | std::ios::app);

    // 检查文件是否成功打开
    if (!outFile) {
        std::cerr << "Error: Could not open the file: " <<  filename << std::endl;
        return;
    }

    // 将字符串和 unsigned long 类型的数值写入文件
    outFile << "String: " << str << ", Number: " << num << std::endl;

    // 关闭文件
    outFile.close();
    
}