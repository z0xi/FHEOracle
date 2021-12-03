### simplified copy of the CMakeLists.txt file of the HElib examples
cmake_minimum_required(VERSION 3.10.2 FATAL_ERROR)
## Use -std=c++17 as default.
set(CMAKE_CXX_STANDARD 17)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)
project(HELibDemo VERSION 1.0)

# 开启调试信息
set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")


add_executable(test1 test1.cpp FHsha256.cpp SHA256.cpp holder.cpp)
find_package(helib ${HELIB_VERSION} REQUIRED)
target_link_libraries(test1 helib)
