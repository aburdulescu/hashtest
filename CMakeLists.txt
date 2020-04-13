cmake_minimum_required(VERSION 3.10)

project(hashtest)

add_executable(hashtest main.cc MurmurHash3.cpp xxhash.c)
target_link_libraries(hashtest PRIVATE crypto)
