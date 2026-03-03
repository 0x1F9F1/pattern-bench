cmake_minimum_required(VERSION 3.25...4.2)

set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
set(CMAKE_OPTIMIZE_DEPENDENCIES ON)
set(CMAKE_CONFIGURATION_TYPES Debug;Release)
option(BUILD_SHARED_LIBS "Build Shared Libraries" OFF)

project(pattern-bench CXX)

set(output_directory "${CMAKE_BINARY_DIR}/out/$<CONFIG>/")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${output_directory}/lib/")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${output_directory}/bin/")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${output_directory}/bin/")
set(CMAKE_PDB_OUTPUT_DIRECTORY "${output_directory}/dbg/")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT Embedded)

if (MSVC)
    add_compile_options(/MP /EHa /arch:AVX2)
    add_link_options(/DEBUG /INCREMENTAL:NO /OPT:REF)
elseif(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i[3-7]86")
    # Non-x86: use SIMDE via shim so <immintrin.h> resolves transparently
    add_compile_options(-mcpu=native)
    add_compile_definitions(SIMDE_ENABLE_NATIVE_ALIASES)
    # Tell mem's simd_scanner to use the SIMD path (it checks these macros)
    add_compile_definitions(MEM_SIMD_AVX2 MEM_SIMD_AVX MEM_SIMD_SSSE3 MEM_SIMD_SSE3 MEM_SIMD_SSE2 MEM_SIMD_SSE)
    include_directories(BEFORE SYSTEM compat/simde-shim vendor/simde)
else()
    add_compile_options(-mavx2 -mbmi)
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
    patterns/can.cpp
    patterns/tbs.cpp
    patterns/sig.cpp
    patterns/libhat.cpp
    patterns/peribunt.cpp
    patterns/x64dbg.cpp
    patterns/x64dbg_bmh.cpp
    patterns/std_regex.cpp
    patterns/pattern16.cpp
    patterns/legacy_extras.cpp
    patterns/qis.cpp
)

add_subdirectory(vendor EXCLUDE_FROM_ALL)

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})

target_include_directories(${PROJECT_NAME} PRIVATE
    include
    vendor/pattern16/include)

target_link_libraries(${PROJECT_NAME}
    mem fmt)