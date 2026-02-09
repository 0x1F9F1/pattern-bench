cmake_minimum_required(VERSION 3.4...4.2)

set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

project(pattern-bench CXX)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_compile_options(/MP /EHa /arch:AVX2)
else()
    add_compile_options(-mavx2)
endif()

add_executable(${PROJECT_NAME}
    src/main.cpp
    src/pattern_entry.cpp
    include/pattern_entry.h

    patterns/baseline.cpp
    patterns/brick.cpp
    patterns/cfx.cpp
    patterns/forza.cpp
    patterns/mrexodia.cpp
    patterns/darth_ton.cpp
    patterns/lightning_scanner.cpp
    patterns/tbs.cpp
    patterns/sig.cpp
    patterns/libhat.cpp
    patterns/peribunt.cpp
    patterns/x64dbg.cpp
    patterns/x64dbg_bmh.cpp
    patterns/std_regex.cpp
    patterns/pattern16.cpp
)

add_subdirectory(vendor EXCLUDE_FROM_ALL)

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})

target_include_directories(${PROJECT_NAME} PRIVATE
    include
    vendor/pattern16/include)

set_source_files_properties(patterns/pattern16.cpp PROPERTIES
    COMPILE_OPTIONS "$<$<CXX_COMPILER_ID:MSVC>:/std:c++20>;$<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-std=c++20>")

target_link_libraries(${PROJECT_NAME}
    mem fmt)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 11
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    CXX_STANDARD_REQUIRED ON)
