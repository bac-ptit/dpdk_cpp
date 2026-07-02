add_subdirectory(config)
add_subdirectory(spi)
add_subdirectory(dpi)

add_library(${FASTAPI_DPDK_TARGET} STATIC
        app_signal.cpp
        dpdk_environment.cpp)

add_library(${FASTAPI_DPDK_ALIAS} ALIAS ${FASTAPI_DPDK_TARGET})

target_link_libraries(${FASTAPI_DPDK_TARGET}
        PUBLIC
        fastapi_common
        ${FASTAPI_CONFIG_ALIAS}
        PkgConfig::DPDK
        PRIVATE
        glaze::glaze)
