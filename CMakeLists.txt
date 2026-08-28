cmake_minimum_required(VERSION 4.2)

# Force ld.lld for the IPO test. ld.lld has LTO built in, so no
# LLVMgold.so plugin is needed — and none is available anyway, since
# the only LLVMgold.so on disk is from apt's LLVM 21, which can't
# consume LTO bytecode produced by pixi's clang 22.
# Must be set BEFORE project() so check_ipo_supported picks it up.
set(CMAKE_CXX_USE_LINKER LLD)
set(CMAKE_C_USE_LINKER LLD)

set(FASTAPI_PROJECT_NAME FastAPI)

# Resolve CMAKE_C/CXX_COMPILER to absolute paths BEFORE project().
# When invoked outside the pixi shell, `clang`/`clang++` are not on
# PATH (they live in `.pixi/envs/default/bin/`). The preset's
# CMAKE_C_COMPILER=clang lands in the cache as a relative name; without
# intervention, `project()` resolves it relative to CMAKE_SOURCE_DIR and
# the configure fails with "not a full path to an existing compiler".
# Looking up clang/clang++ in the pixi bin and forcing absolute paths
# into the cache makes the configure cache-stable.
#
# `FORCE` is required: without it, `set(... CACHE ...)` is a no-op when
# the variable already exists in the cache (which the preset guarantees).
find_program(_FASTAPI_CXX_PATH
        NAMES clang++
        PATHS "${CMAKE_SOURCE_DIR}/.pixi/envs/default/bin"
        NO_DEFAULT_PATH)
find_program(_FASTAPI_CC_PATH
        NAMES clang
        PATHS "${CMAKE_SOURCE_DIR}/.pixi/envs/default/bin"
        NO_DEFAULT_PATH)
if(_FASTAPI_CXX_PATH)
    set(CMAKE_CXX_COMPILER "${_FASTAPI_CXX_PATH}" CACHE FILEPATH "C++ compiler" FORCE)
endif()
if(_FASTAPI_CC_PATH)
    set(CMAKE_C_COMPILER "${_FASTAPI_CC_PATH}" CACHE FILEPATH "C compiler" FORCE)
endif()

project(${FASTAPI_PROJECT_NAME})

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_EXE_LINKER_FLAGS_INIT "-fuse-ld=lld")
    set(CMAKE_SHARED_LINKER_FLAGS_INIT "-fuse-ld=lld")
    set(CMAKE_MODULE_LINKER_FLAGS_INIT "-fuse-ld=lld")
endif()

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(FASTAPI_APP_TARGET ${PROJECT_NAME})
set(FASTAPI_CONFIG_TARGET ${PROJECT_NAME}_config)
set(FASTAPI_CONFIG_ALIAS ${PROJECT_NAME}::config)
set(FASTAPI_SPI_TARGET ${PROJECT_NAME}_spi)
set(FASTAPI_SPI_ALIAS ${PROJECT_NAME}::spi)
set(FASTAPI_DPI_TARGET ${PROJECT_NAME}_dpi)
set(FASTAPI_DPI_ALIAS ${PROJECT_NAME}::dpi)
set(FASTAPI_DPDK_TARGET ${PROJECT_NAME}_dpdk)
set(FASTAPI_DPDK_ALIAS ${PROJECT_NAME}::dpdk)
set(FASTAPI_PCAP_TARGET ${PROJECT_NAME}_pcap)
set(FASTAPI_PCAP_ALIAS ${PROJECT_NAME}::pcap)

find_package(PkgConfig REQUIRED)
include(CheckIPOSupported)

check_ipo_supported(RESULT FASTAPI_IPO_SUPPORTED OUTPUT FASTAPI_IPO_ERROR)
if(FASTAPI_IPO_SUPPORTED)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
else()
    message(WARNING "IPO/LTO disabled: ${FASTAPI_IPO_ERROR}")
endif()

set(FASTAPI_RELEASE_OPTIONS
        $<$<CONFIG:Release>:-fno-plt>)

# pixi clang bundles sysroot_linux-64 (glibc 2.28 headers), but its
# libstdc++ is gcc-15 (built against modern glibc). The two don't agree
# on macro names like __PTHREAD_SPINS, which breaks <atomic>/<mutex>.
# Point both C and CXX at the host sysroot so system glibc headers win,
# and pin the gcc toolchain to the pixi env so the C++ standard library
# still resolves to the pixi libstdc++.
get_filename_component(_FASTAPI_GCC_DIR "${_FASTAPI_CXX_PATH}" DIRECTORY)
get_filename_component(_FASTAPI_GCC_DIR "${_FASTAPI_GCC_DIR}" DIRECTORY)
set(_FASTAPI_INIT_FLAGS
        --sysroot=/
        "SHELL:--gcc-toolchain=${_FASTAPI_GCC_DIR}")
# Same flags must reach the linker so ld.lld resolves Scrt1.o / libc_nonshared.a
# from the host sysroot instead of the bundled pixi one (glibc 2.28, missing
# __libc_csu_init).
add_link_options(
        "SHELL:--sysroot=/"
        "SHELL:--gcc-toolchain=${_FASTAPI_GCC_DIR}")

# DPDK headers include <bsd/string.h>. libbsd's bsd/sys/cdefs.h defaults
# to `#include <sys/cdefs.h>`, which finds itself recursively when
# /usr/include/x86_64-linux-gnu/bsd is in the include path. Defining
# LIBBSD_OVERLAY switches it to `#include_next` instead.
add_compile_definitions(LIBBSD_OVERLAY)

# DPDK headers require native ISA features (e.g. -mssse3) in all configs.
add_compile_options(-march=native -mtune=native)

# Shared compile options and include directories for all project targets.
add_library(fastapi_common INTERFACE)
target_compile_options(fastapi_common INTERFACE
        -fno-exceptions
        ${_FASTAPI_INIT_FLAGS}
        ${FASTAPI_RELEASE_OPTIONS}
        -Wall -Wextra -Wpedantic -Werror)
target_include_directories(fastapi_common INTERFACE
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)

pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)
get_target_property(FASTAPI_DPDK_COMPILE_OPTIONS
        PkgConfig::DPDK
        INTERFACE_COMPILE_OPTIONS)
if(FASTAPI_DPDK_COMPILE_OPTIONS)
    list(FILTER FASTAPI_DPDK_COMPILE_OPTIONS EXCLUDE REGEX "^-march=.*")
    set_target_properties(PkgConfig::DPDK PROPERTIES
            INTERFACE_COMPILE_OPTIONS "${FASTAPI_DPDK_COMPILE_OPTIONS}")
endif()
# libdpdk.pc adds /usr/include/x86_64-linux-gnu. We need its `bsd/`
# subdir (libbsd's <bsd/string.h>) but its bare glibc <bits/...> cross-
# mixes with the pixi conda sysroot <pthread.h> and breaks
# __PTHREAD_SPINS visibility. Narrow the include to just the bsd/
# subdir — DPDK keeps its libbsd headers, the system glibc tree stays
# out of pixi compiles.
get_target_property(FASTAPI_DPDK_INCLUDE_DIRS
        PkgConfig::DPDK
        INTERFACE_INCLUDE_DIRECTORIES)
list(REMOVE_ITEM FASTAPI_DPDK_INCLUDE_DIRS "/usr/include/x86_64-linux-gnu")
list(APPEND FASTAPI_DPDK_INCLUDE_DIRS "/usr/include/x86_64-linux-gnu/bsd")
set_target_properties(PkgConfig::DPDK PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${FASTAPI_DPDK_INCLUDE_DIRS}")

pkg_check_modules(HYPERSCAN IMPORTED_TARGET libhs)
if(NOT HYPERSCAN_FOUND)
    pkg_check_modules(HYPERSCAN IMPORTED_TARGET hyperscan)
endif()
if(NOT HYPERSCAN_FOUND)
    find_path(HYPERSCAN_INCLUDE_DIR hs/hs.h PATHS "${CMAKE_SOURCE_DIR}/.pixi/envs/default/include" "/usr/include")
    find_library(HYPERSCAN_LIBRARY NAMES hs vectorscan PATHS "${CMAKE_SOURCE_DIR}/.pixi/envs/default/lib" "/usr/lib" "/usr/lib64" "/usr/lib/x86_64-linux-gnu")
    if(HYPERSCAN_INCLUDE_DIR AND HYPERSCAN_LIBRARY)
        add_library(PkgConfig::HYPERSCAN UNKNOWN IMPORTED)
        set_target_properties(PkgConfig::HYPERSCAN PROPERTIES
            IMPORTED_LOCATION "${HYPERSCAN_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${HYPERSCAN_INCLUDE_DIR}")
        set(HYPERSCAN_FOUND TRUE)
    endif()
endif()

include(FetchContent)

if(NOT HYPERSCAN_FOUND)
    message(STATUS "Hyperscan/Vectorscan not found in system or pixi. Fetching vectorscan via FetchContent...")
    FetchContent_Declare(
        vectorscan
        GIT_REPOSITORY https://github.com/VectorCamp/vectorscan.git
        GIT_TAG vectorscan/5.4.11
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(vectorscan)
    add_library(PkgConfig::HYPERSCAN ALIAS hs)
endif()


FetchContent_Declare(
        glaze
        GIT_REPOSITORY https://github.com/stephenberry/glaze.git
        GIT_TAG main
        GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(glaze)

add_subdirectory(include)
add_subdirectory(test/dpi)

add_executable(${FASTAPI_APP_TARGET} main.cpp)
target_link_libraries(${FASTAPI_APP_TARGET} PRIVATE
        fastapi_common
        -Wl,--start-group
        ${FASTAPI_CONFIG_ALIAS}
        ${FASTAPI_SPI_ALIAS}
        ${FASTAPI_DPI_ALIAS}
        ${FASTAPI_DPDK_ALIAS}
        ${FASTAPI_PCAP_ALIAS}
        -Wl,--end-group)
target_compile_definitions(${FASTAPI_APP_TARGET} PRIVATE CONFIG_PATH="./config.yaml")

# Binary BEVE Stream converter tool
add_executable(yaml2beve tools/yaml2beve.cpp)
target_link_libraries(yaml2beve PRIVATE
        fastapi_common
        ${FASTAPI_CONFIG_ALIAS})

# Copy config.yaml to build dir so it sits next to the executable
configure_file(${CMAKE_SOURCE_DIR}/config.yaml ${CMAKE_CURRENT_BINARY_DIR}/config.yaml COPYONLY)

