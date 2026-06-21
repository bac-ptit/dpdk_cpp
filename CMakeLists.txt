cmake_minimum_required(VERSION 4.2)

set(FASTAPI_PROJECT_NAME FastAPI)
project(${FASTAPI_PROJECT_NAME})

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(FASTAPI_APP_TARGET ${PROJECT_NAME})
set(FASTAPI_DPDK_TARGET ${PROJECT_NAME}_dpdk)
set(FASTAPI_DPDK_ALIAS ${PROJECT_NAME}::dpdk)

find_package(PkgConfig REQUIRED)
include(CheckIPOSupported)

check_ipo_supported(RESULT FASTAPI_IPO_SUPPORTED OUTPUT FASTAPI_IPO_ERROR)
if(FASTAPI_IPO_SUPPORTED)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
else()
    message(WARNING "IPO/LTO disabled: ${FASTAPI_IPO_ERROR}")
endif()

set(FASTAPI_RELEASE_OPTIONS
        $<$<CONFIG:Release>:-march=native>
        $<$<CONFIG:Release>:-mtune=native>
        $<$<CONFIG:Release>:-fno-plt>)

# pkg-config để tìm DPDK (tên gói trên Fedora/Ubuntu là 'libdpdk')
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)
get_target_property(FASTAPI_DPDK_COMPILE_OPTIONS
        PkgConfig::DPDK
        INTERFACE_COMPILE_OPTIONS)
if(FASTAPI_DPDK_COMPILE_OPTIONS)
    list(FILTER FASTAPI_DPDK_COMPILE_OPTIONS EXCLUDE REGEX "^-march=.*")
    set_target_properties(PkgConfig::DPDK PROPERTIES
            INTERFACE_COMPILE_OPTIONS "${FASTAPI_DPDK_COMPILE_OPTIONS}")
endif()
include(FetchContent)

FetchContent_Declare(
        glaze
        GIT_REPOSITORY https://github.com/stephenberry/glaze.git
        GIT_TAG main
        GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(glaze)

add_subdirectory(include)

add_executable(${FASTAPI_APP_TARGET} main.cpp)
target_compile_options(${FASTAPI_APP_TARGET} PRIVATE
        -fno-exceptions
        ${FASTAPI_RELEASE_OPTIONS})
target_link_libraries(${FASTAPI_APP_TARGET} PRIVATE ${FASTAPI_DPDK_ALIAS})
target_compile_options(${FASTAPI_APP_TARGET} PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(${FASTAPI_APP_TARGET} PRIVATE CONFIG_PATH="${CMAKE_CURRENT_BINARY_DIR}/config.yaml")

# Copy config.yaml to build dir so it sits next to the executable
configure_file(${CMAKE_SOURCE_DIR}/config.yaml ${CMAKE_CURRENT_BINARY_DIR}/config.yaml COPYONLY)
