// Translation unit for dpdk::dpi::HostnameCache — currently header-only
// but reserved for future non-inline implementation.

#include "dpdk/dpi/hostname_cache.hpp"

namespace dpdk::dpi {
// All methods are inline in the header. This TU exists so the CMake
// target always compiles at least one source file (avoids "no source"
// warnings on some generators).
}  // namespace dpdk::dpi
