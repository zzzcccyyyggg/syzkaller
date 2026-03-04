# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++14 -Wall -Wextra -O2 -g

# Source file
SOURCE = userspace-compiler.cpp

# Target executables
TARGET_C = ddrace-cc
TARGET_CXX = ddrace-cxx

# Phony targets for commands that don't produce files
.PHONY: all clean install test

# Default target: build both compiler wrappers
all: $(TARGET_C) $(TARGET_CXX)

# Rule to build the C compiler wrapper (ddrace-cc)
# This is the default build without any special flags.
$(TARGET_C): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $@ $<

# Rule to build the C++ compiler wrapper (ddrace-cxx)
# This build defines the DDRACE_CXX macro.
$(TARGET_CXX): $(SOURCE)
	$(CXX) $(CXXFLAGS) -DDDRACE_CXX -o $@ $<

# Clean up both executables and any generated files
clean:
	rm -f $(TARGET_C) $(TARGET_CXX) *.o *.ll test test.c test.cpp test_*

# Install both compiler wrappers to /usr/local/bin
install: all
	cp $(TARGET_C) /usr/local/bin/
	cp $(TARGET_CXX) /usr/local/bin/
	chmod +x /usr/local/bin/$(TARGET_C)
	chmod +x /usr/local/bin/$(TARGET_CXX)
	@echo "Installed $(TARGET_C) and $(TARGET_CXX) to /usr/local/bin"

# Test target to verify both compilers
test: all
	@echo "--- Testing C Compiler ($(TARGET_C)) ---"
	@echo "--> Testing help option..."
	./$(TARGET_C) --ddrace-help
	@echo "\n--> Testing compilation without instrumentation..."
	echo 'int main(){return 0;}' > test.c
	./$(TARGET_C) -o test_c_regular test.c
	@echo "\n--> Testing with instrumentation..."
	./$(TARGET_C) --ddrace-all -o test_c_instrumented test.c

	@echo "\n--- Testing C++ Compiler ($(TARGET_CXX)) ---"
	@echo "--> Testing help option..."
	./$(TARGET_CXX) --ddrace-help
	@echo "\n--> Testing compilation without instrumentation..."
	echo '#include <iostream>\nint main(){std::cout << "Hello" << std::endl;return 0;}' > test.cpp
	./$(TARGET_CXX) -o test_cpp_regular test.cpp
	@echo "\n--> Testing with instrumentation..."
	./$(TARGET_CXX) --ddrace-all -o test_cpp_instrumented test.cpp

	@echo "\n--- Test complete. Cleaning up... ---"
	rm -f test.c test.cpp test_* *.ll *.o

