add_library(${FASTAPI_DPDK_TARGET} STATIC
        app_signal.cpp
        dpdk_config_loader.cpp
        dpdk_environment.cpp
        spi_ip_address.cpp
        spi_packet_parser.cpp
        spi_pipeline.cpp
        spi_rule_engine.cpp)

add_library(${FASTAPI_DPDK_ALIAS} ALIAS ${FASTAPI_DPDK_TARGET})

target_include_directories(${FASTAPI_DPDK_TARGET}
        PUBLIC
        ${PROJECT_SOURCE_DIR}/include)

target_compile_options(${FASTAPI_DPDK_TARGET}
        PRIVATE
        -fno-exceptions
        ${FASTAPI_RELEASE_OPTIONS}
        -Wall
        -Wextra
        -Wpedantic
        -Werror)

target_link_libraries(${FASTAPI_DPDK_TARGET}
        PUBLIC
        PkgConfig::DPDK
        PRIVATE
        glaze::glaze)
