cmake_minimum_required(VERSION 3.22)
project(remap_attack LANGUAGES CXX)

if(NOT ANDROID)
    message(FATAL_ERROR "Use attack/build.sh to build with the Android NDK.")
endif()

add_library(injector SHARED injector/main.cpp shared/remap.cpp shared/manmap.cpp)
add_library(remap SHARED payload_remap/main.cpp shared/remap.cpp)
add_library(manmap SHARED payload_manmap/main.cpp shared/remap.cpp)

foreach(target injector remap manmap)
    target_compile_features(${target} PRIVATE cxx_std_20)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wreturn-type -Wpedantic)
    target_link_options(${target} PRIVATE "-Wl")
    target_link_libraries(${target} PRIVATE log)
    set_target_properties(${target} PROPERTIES CXX_VISIBILITY_PRESET hidden)
endforeach()
