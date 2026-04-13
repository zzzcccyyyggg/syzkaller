cmake_minimum_required(VERSION 3.5)
project(report_analyzer)

find_package(LLVM REQUIRED CONFIG)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
add_definitions(${LLVM_DEFINITIONS})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

llvm_map_components_to_libnames(llvm_libs
    support
    core
    irreader
    bitreader
)

add_executable(report-analyzer main.cpp)
target_link_libraries(report-analyzer ${llvm_libs})
