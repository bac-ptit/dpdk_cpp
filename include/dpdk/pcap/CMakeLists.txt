find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)

add_library(${FASTAPI_PCAP_TARGET} STATIC
        pcap_replay.cpp)

add_library(${FASTAPI_PCAP_ALIAS} ALIAS ${FASTAPI_PCAP_TARGET})

target_link_libraries(${FASTAPI_PCAP_TARGET}
        PUBLIC
        fastapi_common
        PkgConfig::DPDK
        PRIVATE
        PkgConfig::PCAP
        glaze::glaze)
