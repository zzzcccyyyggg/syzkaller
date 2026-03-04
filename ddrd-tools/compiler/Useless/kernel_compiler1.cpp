#include <string>
#include <unistd.h>
#include <iostream>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fstream>

using namespace std;

#define CLANG "clang-15"
#define INSTRUMENTER "/home/s1eepy/Desktop/HDD/concurrency/CCWF/instrumenter/build/bin/instrumenter"
// #define INSTRUMENTER "/home/s1eepy/Desktop/HDD/concurrency/conzzer-kernel/checker_instrumenter/build/bin/instrumenter"
#define LOCK_FILE "/home/s1eepy/Desktop/HDD/concurrency/CCWF/instrumenter/LockFunc.txt"
#define TRYLOCK_FILE "/home/s1eepy/Desktop/HDD/concurrency/CCWF/instrumenter/TryLock.txt"
string TARGET_O = "";
string TARGET_N = "";
string TARGET_C = "";

int main(int argc, char **argv)
{
	bool target_flag = false;
	bool target_flag_total = false;
	bool cflag = false;

	// assembly file is not handled by clang
	string last_arg = argv[argc - 1];
	if (last_arg.rfind(".s") == last_arg.length() - 2 ||
		last_arg.rfind(".S") == last_arg.length() - 2)
	{

		auto ori_argv = new char *[argc + 5];
		ori_argv[0] = CLANG;
		int i;
		for (i = 1; i < argc; i++)
		{
			ori_argv[i] = argv[i];
		}
		ori_argv[i] = NULL;

		execvp(ori_argv[0], ori_argv);
		cout << "failed to execute " << ori_argv[0] << endl;
		exit(-1);
	}

	// find -o option and target file
	for (int i = 0; i < argc; i++)
	{
		if (target_flag == true)
			TARGET_O = argv[i];

		if (!strcmp(argv[i], "-o"))
		{
			target_flag = true;
			target_flag_total = true;
		}
		else
		{
			target_flag = false;
		}
	}

	cflag = false;
	// check if there is "-c"
	for (int i = 0; i < argc; i++)
	{
		string str_argv = argv[i];
		if (str_argv == "-c")
			cflag = true;
	}

	// if there is "-c", find the .c file
	if (cflag == true)
	{
		for (int i = 0; i < argc; i++)
		{
			string str_argv = argv[i];
			if (str_argv.rfind(".c") == str_argv.length() - 2)
			{
                if (TARGET_C.find("fs/") == string::npos) // if not in fs directory, skip
                    continue;
				// if donot have the -o, use .c file to infer .o file
				if (target_flag_total == false)
				{
					auto len = str_argv.size() - 2;
					TARGET_O = str_argv.substr(0, len);
					TARGET_O = TARGET_O + ".o";

					auto off = str_argv.rfind("/");
					TARGET_O = TARGET_O.substr(off + 1);
					cout << "\033[33mDont have -o, default output is: " << TARGET_O << "\033[0m" << endl;
				}

				// get .c file
				TARGET_C = str_argv;
			}
		}
	}

	// if the TARGET_O is a .o file, TARGET_N will be assigned
	if (TARGET_O.rfind(".o") == TARGET_O.length() - 2 &&
		(TARGET_O.length() < 6 || TARGET_O.rfind(".mod.o") != TARGET_O.length() - 6))
	{
		auto off = TARGET_O.rfind(".");
		TARGET_N = TARGET_O.substr(0, off);
	}

	// if the TARGET_O isn't a .o file
	if (TARGET_N == "" ||
		TARGET_N.rfind("xfs_bmap") == TARGET_N.length() - 8 ||
		TARGET_N.rfind("xfs_inode_fork") == TARGET_N.length() - 14)
	{
		auto ori_argv = new char *[argc + 128];

		ori_argv[0] = CLANG;
		int i;
		int new_i = 1;
		for (i = 1; i < argc; i++)
		{
			ori_argv[new_i++] = argv[i];
		}
		ori_argv[new_i++] = NULL;

		execvp(ori_argv[0], ori_argv);
		cout << "failed to execute " << ori_argv[0] << endl;
		exit(-1);
	}

	// -----------------------------------------------
	// compile the source file .c to .ll
	auto new_argv = new char *[argc + 128];
	int new_argv_count = 0;
	new_argv[new_argv_count++] = CLANG;
	new_argv[new_argv_count++] = "-S";
	new_argv[new_argv_count++] = "-emit-llvm";
	new_argv[new_argv_count++] = "-g";
	new_argv[new_argv_count++] = "-Qunused-arguments";
	new_argv[new_argv_count++] = "-Wno-unused-command-line-argument";
	// new_argv[new_argv_count++] = "-O0";
	// copy the argv to new_argv

	
	for (int i = 1; i < argc; i++)
	{

		// 如果当前参数是 -Werror,-Wunused-command-line-argument，跳过此参数
		if (strcmp(argv[i], "-Werror,-Wunused-command-line-argument") == 0)
		{
			continue; // 跳过这个参数，相当于删除
		}
		if (!strcmp(argv[i], TARGET_O.c_str()))
		{
			new_argv[new_argv_count] = new char[(TARGET_N + ".ll").length() + 4];
			strcpy(new_argv[new_argv_count], (TARGET_N + ".ll").c_str());
			new_argv_count++;

			continue;
		}
		new_argv[new_argv_count++] = argv[i];
	}
	// new_argv[new_argv_count++] = "-O1";
	// new_argv[new_argv_count++] = "-fno-inline";
	// new_argv[new_argv_count++] = "-Dalways_inline=cold";
	new_argv[new_argv_count++] = NULL;

	auto child_pid = fork();
	if (child_pid == 0)
	{
		execvp(new_argv[0], new_argv);
		cout << "failed to execute " << new_argv[0] << endl;
		exit(-1);
	}
	wait(NULL);

	// --------------------------------------------------
	// execute INSTRUMENTER ${TARGET_N}.ll LOCK_FILE TRYLOCK_FILE
	cout << "run checker inst start" << endl;
	auto argv_dr = new char *[5];
	argv_dr[0] = INSTRUMENTER;
	argv_dr[1] = new char[(TARGET_N + ".ll").length() + 4];
	strcpy(argv_dr[1], (TARGET_N + ".ll").c_str());
	argv_dr[2] = LOCK_FILE;
	argv_dr[3] = TRYLOCK_FILE;
	argv_dr[4] = NULL;

	child_pid = fork();
	if (child_pid == 0)
	{
		execvp(argv_dr[0], argv_dr);
		cout << "failed to execute " << argv_dr[0] << endl;
		exit(-1);
	}
	wait(NULL);
	cout << "run checker inst finish" << endl;

	// ----------------------------------------------------
	// execute CLANG -c "${TARGET_N}.ll" -o "${TARGET_O}" -fPIC -O0 -g
	auto argv_c = new char *[256];
	argv_c[0] = CLANG;

	// copy the argv to argv_c
	int argv_c_num = 1;
	// argv_c[argv_c_num++] = "-O0";
	argv_c[argv_c_num++] = "-Qunused-arguments";
	argv_c[argv_c_num++] = "-Wno-unused-command-line-argument";
	for (int i = 1; i < argc; i++)
	{
		// 如果当前参数是 -Werror,-Wunused-command-line-argument，跳过此参数
		if (strcmp(argv[i], "-Werror,-Wunused-command-line-argument") == 0)
		{
			continue; // 跳过这个参数，相当于删除
		}
		// if (!strcmp(argv[i], "-O1"))
		// 	continue;
		// if (!strcmp(argv[i], "-O2"))
		// 	continue;
		// if (!strcmp(argv[i], "-O3"))
		// 	continue;
		// if (!strcmp(argv[i], "-Os"))
		// 	continue;
		// if (!strcmp(argv[i], "-Oz"))
		// 	continue;
		// if (!strcmp(argv[i], "-Ofast"))
		// 	continue;
		// if (!strcmp(argv[i], "-Og"))
		// 	continue;
		if (!strcmp(argv[i], TARGET_C.c_str()))
		{
			argv_c[argv_c_num] = new char[(TARGET_N + ".instrumented.ll").length() + 4];
			strcpy(argv_c[argv_c_num], (TARGET_N + ".instrumented.ll").c_str());
			argv_c_num++;

			continue;
		}
		argv_c[argv_c_num++] = argv[i];
	}

	argv_c[argv_c_num++] = NULL;

	child_pid = fork();
	if (child_pid == 0)
	{
		execvp(argv_c[0], argv_c);
		cout << "failed to execute " << argv_c[0] << endl;
		exit(-1);
	}
	wait(NULL);
}