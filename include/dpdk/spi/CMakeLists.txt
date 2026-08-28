add_library(${FASTAPI_SPI_TARGET} STATIC
        spi_flow_table.cpp
        spi_ip_address.cpp
        spi_packet_parser.cpp
        spi_pipeline.cpp
        spi_tcp_reassembly.cpp
        spi_rule_engine.cpp)

add_library(${FASTAPI_SPI_ALIAS} ALIAS ${FASTAPI_SPI_TARGET})

target_link_libraries(${FASTAPI_SPI_TARGET}
        PUBLIC
        fastapi_common
        ${FASTAPI_CONFIG_ALIAS}
        PkgConfig::DPDK)
