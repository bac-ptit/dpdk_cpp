add_library(${FASTAPI_CONFIG_TARGET} STATIC
        dpdk_config_loader.cpp)

add_library(${FASTAPI_CONFIG_ALIAS} ALIAS ${FASTAPI_CONFIG_TARGET})

target_link_libraries(${FASTAPI_CONFIG_TARGET}
        PUBLIC
        fastapi_common
        ${FASTAPI_SPI_ALIAS}
        PkgConfig::DPDK
        PRIVATE
        glaze::glaze)
