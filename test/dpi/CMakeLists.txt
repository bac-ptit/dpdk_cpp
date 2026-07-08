add_executable(dpi_cache_bench dpi_cache_bench.cpp)
target_link_libraries(dpi_cache_bench PRIVATE
        fastapi_common
        -Wl,--start-group
        ${FASTAPI_CONFIG_ALIAS}
        ${FASTAPI_SPI_ALIAS}
        ${FASTAPI_DPI_ALIAS}
        ${FASTAPI_DPDK_ALIAS}
        -Wl,--end-group)
