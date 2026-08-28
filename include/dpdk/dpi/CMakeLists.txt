add_library(${FASTAPI_DPI_TARGET} STATIC
        dpi_rule_engine.cpp
        hostname_cache.cpp)

add_library(${FASTAPI_DPI_ALIAS} ALIAS ${FASTAPI_DPI_TARGET})

target_link_libraries(${FASTAPI_DPI_TARGET}
        PUBLIC
        fastapi_common
        ${FASTAPI_CONFIG_ALIAS}
        PkgConfig::DPDK
        PkgConfig::HYPERSCAN)

