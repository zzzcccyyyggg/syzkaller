#ifndef AUXILIARY_HPP
#define AUXILIARY_HPP
#pragma once

/* Define Some Color For Output*/
#define RESET   "\x1B[0m"
#define RED     "\x1B[31m"
#define GREEN   "\x1B[32m"
#define YELLOW  "\x1B[33m"
#define BLUE    "\x1B[34m"

#include <iostream>
#include <string>
#include <fstream>

void PrintError(std::string error);

void PrintWarning(std::string warning);

void PrintInfo(std::string info);

void PrintSuccess(std::string success);

unsigned long BKDRHash(const char *str, unsigned long hash);

void writeToFile(const std::string& filename, const std::string& str, unsigned long num);

#endif // AUXILIARY_HPP