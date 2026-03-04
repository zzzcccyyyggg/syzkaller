cmake_minimum_required(VERSION 3.5)
project(instrumenter)

# llvm相关引入
# set(LLVM_DIR "/home/zzzccc/llvm-15/llvm-project/build/lib/cmake/llvm")
# set(LLVM_DIR "/home/zzzccc/llvm-15/llvm-project/build/lib/cmake/llvm")
find_package(LLVM 18.1.3 REQUIRED CONFIG)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-fno-rtti -g)

include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
add_definitions(${LLVM_DEFINITIONS})

set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )

llvm_map_components_to_libnames(llvm_libs 
    support
    core
    irreader
    bitwriter
    target
    transformutils
    analysis
)

# 设置目录名
set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# 设置源文件
set(SOURCES
    ${SOURCE_DIR}/main.cpp
    ${SOURCE_DIR}/auxiliary.cpp
    ${SOURCE_DIR}/handle_file.cpp
    ${SOURCE_DIR}/instrument_on_file.cpp
    ${SOURCE_DIR}/record_function.cpp
    ${SOURCE_DIR}/record_shared_variable.cpp
    ${SOURCE_DIR}/taint_analysis.cpp
    ${SOURCE_DIR}/record_bbs.cc
    ${SOURCE_DIR}/record_lock_func.cpp
    ${SOURCE_DIR}/instrumentation_options.cpp
    ${SOURCE_DIR}/memory_free_instrument.cpp
)

# 引入头文件
include_directories(${INCLUDE_DIR})

add_executable(instrumenter ${SOURCES})
target_link_libraries(instrumenter ${llvm_libs})

# target_link_libraries(instrumenter PRIVATE ${llvm_libs} -fsanitize=address)
# target_compile_options(instrumenter PRIVATE -fsanitize=address -fno-omit-frame-pointer)