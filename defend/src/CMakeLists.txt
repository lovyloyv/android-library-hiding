cmake_minimum_required(VERSION 3.22)
project(remap_defend_native LANGUAGES CXX)

if(NOT ANDROID)
    message(FATAL_ERROR "Use defend/build.sh to build with the Android NDK.")
endif()

add_library(defend SHARED main.cpp anti.cpp)
target_compile_features(defend PRIVATE cxx_std_17)
target_compile_options(defend PRIVATE -Wall -Wextra -Wpedantic)
target_link_options(defend PRIVATE "-Wl")
target_link_libraries(defend PRIVATE log)
set_target_properties(defend PROPERTIES CXX_VISIBILITY_PRESET hidden)
