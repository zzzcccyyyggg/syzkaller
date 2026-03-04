#ifndef KERNEL_COMPILER_HPP
#define KERNEL_COMPILER_HPP
#pragma once

#define CLANG "clang-12"
#define INSTRUMENTER "/home/s1eepy/Desktop/HDD/concurrency/conzzer-kernel/instrumenter/build/bin/instrumenter"
#define LOCK_FILE "/home/s1eepy/Desktop/HDD/concurrency/conzzer-kernel/instrumenter/race_case/LockFunc.txt"
#define TRYLOCK_FILE "/home/s1eepy/Desktop/HDD/concurrency/conzzer-kernel/instrumenter/race_case/TryLock.txt"

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>

std::vector<std::string> source_files;
std::vector<std::string> target_files;
std::vector<std::string> other_args;
std::string object_file;

bool no_link = false; // -c flag
bool link_all = false; // -o flag

void RemoveAssemblyOptions(int argc, char **argv);

void RemoveOtherOptions(int argc, char **argv);

void EditParams(int argc, char **argv);

void CompileToLL();

void Instrument();

void CompileToO();

#endif // KERNEL_COMPILER_HPP