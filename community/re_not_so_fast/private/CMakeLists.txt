cmake_minimum_required(VERSION 3.14)

message("CTF_PLATFORM=${CTF_PLATFORM}")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "-O0 -fno-exceptions -fno-elide-constructors -fdce -fdata-sections -ffunction-sections -Wl,--gc-sections -D${CTF_PLATFORM}")
set(CMAKE_CXX_FLAGS_DEBUG "-ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG")

add_link_options("-Wl,--gc-sections")

project(not-so-fast)

add_subdirectory(src)
add_subdirectory(test)
