cmake_minimum_required(VERSION 3.10)

project(hashtest)

add_executable(hashtest main.cc MurmurHash3.cpp)
