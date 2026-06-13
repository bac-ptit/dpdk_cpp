cmake_minimum_required(VERSION 4.2)
project(untitled)

set(CMAKE_CXX_STANDARD 26)


find_package(PkgConfig REQUIRED)

# pkg-config để tìm DPDK (tên gói trên Fedora/Ubuntu là 'libdpdk')
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)
include(FetchContent)

FetchContent_Declare(
        glaze
        GIT_REPOSITORY https://github.com/stephenberry/glaze.git
        GIT_TAG main
        GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(glaze)


add_executable(untitled main.cpp
        include/dpdk_config_loader.cpp
        include/dpdk_environment.cpp
        include/spi_packet_parser.cpp
        include/spi_pipeline.cpp
        include/spi_rule_engine.cpp)

target_compile_options(untitled PRIVATE -fno-exceptions)
target_link_libraries(untitled PRIVATE PkgConfig::DPDK glaze::glaze)
target_include_directories(untitled PRIVATE include)
target_compile_options(untitled PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(untitled PRIVATE CONFIG_PATH="${CMAKE_CURRENT_BINARY_DIR}/config.yaml")

# Copy config.yaml to build dir so it sits next to the executable
configure_file(${CMAKE_SOURCE_DIR}/config.yaml ${CMAKE_CURRENT_BINARY_DIR}/config.yaml COPYONLY)

