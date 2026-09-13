cmake_minimum_required(VERSION 3.20)

project(android C)

if(NOT TARGET redasm::redasm)
    find_package(redasm REQUIRED)
endif()

add_library(${PROJECT_NAME} SHARED)

target_sources(${PROJECT_NAME} 
    PRIVATE
        dalvik/dalvik.c
        dalvik/formats.c
        dalvik/opcodes.c
        dex/classes.c
        dex/dex.c
        dex/format.c
        dex/map.c
        dex/mutf8.c
        dex/sections.c
        dex/strings.c
        plugin.c
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(${PROJECT_NAME} PRIVATE redasm::redasm)

