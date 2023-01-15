cmake_minimum_required(VERSION 3.20.0)

project(fast-replace)

set(CMAKE_EXPORT_COMPILE_COMMANDS YES)
find_package(PkgConfig)

pkg_check_modules(PCRE2_8 REQUIRED IMPORTED_TARGET libpcre2-8)

add_library(fastreplace SHARED fast_replace.c)
target_link_libraries(fastreplace PUBLIC PkgConfig::PCRE2_8)
add_executable(demo testing/demo.c)
target_link_libraries(demo PUBLIC PkgConfig::PCRE2_8)

add_executable(demo2 testing/demo2.c)
target_link_libraries(demo2 PUBLIC PkgConfig::PCRE2_8)
