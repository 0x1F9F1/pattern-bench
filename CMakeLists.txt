cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(pattern-bench CXX)

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
)

add_subdirectory(vendor EXCLUDE_FROM_ALL)

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})

target_include_directories(${PROJECT_NAME} PRIVATE
    include)

target_link_libraries(${PROJECT_NAME}
    mem fmt)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
)
