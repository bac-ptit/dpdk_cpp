// Standalone DPI hostname-cache benchmark.
//
// Reads a pcap file directly from disk, constructs rte_mbuf objects with
// the full packet bytes preserved (bypassing the net_pcap PMD's payload
// truncation bug), and exercises the same ParsePacket → ExtractTlsSni /
// ExtractHttpHost → DpiRuleTable::Match code path the production pipeline
// uses on flow-cache misses. This lets us measure DPI hostname-cache hit
// rate and throughput without needing a real NIC.
//
// Usage:
//   dpi_cache_bench <pcap_path> <cycles>
// where `cycles` is how many times to replay the pcap. With cycles >= 2,
// the hostnames seen in cycle 1 should populate the cache; cycles 2+
// should produce 100% DPI cache hits.
//
// Build: linked through the project CMake — see test/dpi/CMakeLists.txt.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <expected>
#include <fstream>
#include <print>
#include <string>
#include <vector>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "dpdk/dpi/dpi_rule_engine.hpp"
#include "dpdk/dpi/hostname_cache.hpp"
#include "dpdk/spi/spi_packet_parser.hpp"
#include "helpers/format_helpers.hpp"

namespace {

/// One packet read from a pcap.
struct PcapPacket {
  std::vector<std::uint8_t> bytes;
};

/// Read a pcap file and return raw packet bytes.
/// Format: 24-byte global header then N records of (16-byte pkt header + payload).
[[nodiscard]] std::expected<std::vector<PcapPacket>, std::string> LoadPcap(
    const std::string& path) noexcept {
  std::ifstream file{path, std::ios::binary};
  if (!file) {
    return std::unexpected(std::format("Cannot open pcap: {}", path));
  }

  std::uint8_t global_hdr[24]{};
  if (!file.read(reinterpret_cast<char*>(global_hdr), 24) || file.gcount() != 24) {
    return std::unexpected("pcap: short global header");
  }
  constexpr std::uint32_t kPcapMagic{0xa1b2c3d4};
  std::uint32_t magic;
  std::memcpy(&magic, global_hdr, 4);
  if (magic != kPcapMagic) {
    return std::unexpected(std::format("pcap: bad magic 0x{:x}", magic));
  }

  std::vector<PcapPacket> out;
  while (true) {
    std::uint8_t pkt_hdr[16]{};
    if (!file.read(reinterpret_cast<char*>(pkt_hdr), 16)) break;
    if (file.gcount() != 16) break;
    std::uint32_t caplen;
    std::memcpy(&caplen, pkt_hdr + 8, 4);
    if (caplen == 0 || caplen > 65535) break;
    PcapPacket p;
    p.bytes.resize(caplen);
    if (!file.read(reinterpret_cast<char*>(p.bytes.data()), caplen)) break;
    if (static_cast<std::uint32_t>(file.gcount()) != caplen) break;
    out.push_back(std::move(p));
  }
  return out;
}

/// Initialize EAL with a minimal config suitable for a self-contained test.
/// Single lcore, no PCI, no vdev, legacy-mem — just enough for
/// rte_pktmbuf_pool_create. We use real hugepages (not --no-huge) so the
/// mempool allocations don't compete with process address space.
[[nodiscard]] std::expected<void, std::string> InitEal() noexcept {
  std::vector<std::string> args = {
      "dpi_cache_bench",
      "-l", "0",
      "--no-pci",
      "--legacy-mem",
      "--file-prefix", "dpi_cache_bench",
      "--log-level", "8",
  };
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (auto& a : args) argv.push_back(a.data());

  if (rte_eal_init(static_cast<int>(argv.size()), argv.data()) < 0) {
    return std::unexpected(std::format("rte_eal_init failed (rte_errno={})", rte_errno));
  }
  return {};
}

/// Create a small mempool for mbuf storage. 16K mbufs × 2 KB buffers.
/// ~32 MB total — fits in any reasonable lab environment. Restricting to
/// 16K means the bench can hold ~10K pre-allocated packets at a time;
/// callers should sample from the pcap accordingly.
[[nodiscard]] std::expected<rte_mempool*, std::string> CreateMempool() noexcept {
  constexpr std::uint32_t kNumMbufs{16385};
  constexpr std::uint16_t kCacheSize{256};
  constexpr std::uint16_t kDataRoomSize{2048};

  rte_mempool* pool{rte_pktmbuf_pool_create("dpi_test_pool", kNumMbufs, kCacheSize,
                                            0, kDataRoomSize, rte_socket_id())};
  if (pool == nullptr) {
    return std::unexpected(std::format("rte_pktmbuf_pool_create failed (rte_errno={}: {})",
                                       rte_errno, rte_strerror(rte_errno)));
  }
  return pool;
}

/// Copy a pcap packet into a freshly allocated mbuf. Sets data_len and pkt_len
/// to the actual packet length so subsequent rte_pktmbuf_read sees full bytes.
[[nodiscard]] std::expected<rte_mbuf*, std::string> PacketToMbuf(rte_mempool* pool,
                                                                  const PcapPacket& p) noexcept {
  rte_mbuf* m{rte_pktmbuf_alloc(pool)};
  if (m == nullptr) {
    return std::unexpected("rte_pktmbuf_alloc failed");
  }
  // A freshly-allocated mbuf has data_off = RTE_PKTMBUF_HEADROOM and 0 bytes
  // appended. rte_pktmbuf_append returns a pointer to the writable tail and
  // grows data_len by the requested size.
  void* tail{rte_pktmbuf_append(m, p.bytes.size())};
  if (tail == nullptr) {
    rte_pktmbuf_free(m);
    return std::unexpected(std::format("rte_pktmbuf_append({}) failed", p.bytes.size()));
  }
  std::memcpy(tail, p.bytes.data(), p.bytes.size());
  return m;
}

/// Minimal DPI filter config matching the production config's
/// `*.facebook.com`, `*.google.com`, `*.youtube.com`, etc. rules.
/// Patterns mirror `CompileDpiRuleTable` conventions: `*.<domain>` → suffix
/// match, plain `<host>` → exact match, single `*` → catch-all.
[[nodiscard]] std::vector<dpdk::dpi::CompiledDpiFilter> MakeSampleFilters() noexcept {
  using dpdk::dpi::CompiledDpiFilter;
  std::vector<CompiledDpiFilter> out;
  auto add_suffix = [&](const char* domain, const char* group, std::uint32_t prio,
                         const char* label) {
    CompiledDpiFilter f{};
    std::strncpy(f.hostname_pattern, domain, sizeof(f.hostname_pattern) - 1);
    f.hostname_pattern_length = static_cast<std::uint16_t>(std::strlen(domain));
    f.is_suffix_match = true;
    f.filter_group = group;
    f.priority = prio;
    f.label = label;
    out.push_back(f);
  };
  auto add_exact = [&](const char* domain, const char* group, std::uint32_t prio,
                       const char* label) {
    CompiledDpiFilter f{};
    std::strncpy(f.hostname_pattern, domain, sizeof(f.hostname_pattern) - 1);
    f.hostname_pattern_length = static_cast<std::uint16_t>(std::strlen(domain));
    f.filter_group = group;
    f.priority = prio;
    f.label = label;
    out.push_back(f);
  };
  auto add_catch_all = [&](const char* group, std::uint32_t prio, const char* label) {
    CompiledDpiFilter f{};
    f.hostname_pattern[0] = '*';
    f.hostname_pattern_length = 1;
    f.is_catch_all = true;
    f.filter_group = group;
    f.priority = prio;
    f.label = label;
    out.push_back(f);
  };
  add_suffix("*.facebook.com", "fg_l7_facebook", 10, "facebook");
  add_suffix("*.fbcdn.net", "fg_l7_facebook", 10, "facebook_cdn");
  add_suffix("*.messenger.com", "fg_l7_facebook", 10, "messenger");
  add_suffix("*.instagram.com", "fg_l7_facebook", 10, "instagram");
  add_suffix("*.whatsapp.net", "fg_l7_facebook", 10, "whatsapp");
  add_suffix("*.google.com", "fg_l7_google", 30, "google");
  add_suffix("*.googleapis.com", "fg_l7_google", 30, "googleapis");
  add_suffix("*.gstatic.com", "fg_l7_google", 30, "gstatic");
  add_suffix("*.googleusercontent.com", "fg_l7_google", 30, "googleusercontent");
  add_suffix("*.youtube.com", "fg_l7_youtube", 20, "youtube");
  add_suffix("*.ytimg.com", "fg_l7_youtube", 20, "ytimg");
  add_suffix("*.spotify.com", "fg_l7_music", 120, "spotify");
  add_suffix("*.soundcloud.com", "fg_l7_music", 120, "soundcloud");
  add_exact("dns.google", "fg_l7_doh", 140, "doh_google");
  add_exact("cloudflare-dns.com", "fg_l7_doh", 140, "doh_cloudflare");
  add_catch_all("fg_l7_default", 999, "default");
  return out;
}

struct CycleCounters {
  std::uint64_t parsed{};
  std::uint64_t dns_noport{};  // IPv4/non-TCP packets
  std::uint64_t dpi_attempts{};
  std::uint64_t dpi_cache_hits{};
  std::uint64_t dpi_cache_misses{};
  std::uint64_t dpi_match_after_miss{};
  std::chrono::nanoseconds extract_ns{};
  std::chrono::nanoseconds match_ns{};
};

/// Walk all packets in one cycle through the DPI cache. Caller pre-allocates
/// all mbufs (so we don't time allocation in the hot path); this function
/// only frees them at the end.
void RunDpiCycle(const std::vector<rte_mbuf*>& mbufs, dpdk::dpi::DpiRuleTable& rules,
                 dpdk::dpi::HostnameCache& cache, CycleCounters& c) noexcept {
  for (rte_mbuf* m : mbufs) {
    const rte_mbuf& pkt{*m};
    // Parse L2/L3/L4 metadata (the same ParsePacket the pipeline calls).
    auto parsed{dpdk::spi::ParsePacket(pkt)};
    if (!parsed) {
      continue;
    }
    ++c.parsed;
    const auto& md{*parsed};
    // Only run DPI on TCP/443 or TCP/80 — same gate as production.
    constexpr std::uint16_t kTlsPort{443};
    constexpr std::uint16_t kHttpPort{80};
    if (md.protocol != dpdk::spi::Protocol::kTcp) {
      ++c.dns_noport;
      continue;
    }
    if (md.destination_port != kTlsPort && md.destination_port != kHttpPort) {
      ++c.dns_noport;
      continue;
    }

    // L4 offset = sizeof(ether) + ip_header_len. Only the start of TCP header
    // is needed; tcp data_offset is computed by ExtractHostname (not exposed),
    // so we re-derive here from the same offset the pipeline uses.
    const auto ip_hdr{static_cast<const rte_ipv4_hdr*>(
        rte_pktmbuf_mtod_offset(&pkt, void*, sizeof(rte_ether_hdr)))};
    const auto l4_off{sizeof(rte_ether_hdr) + rte_ipv4_hdr_len(ip_hdr)};
    rte_tcp_hdr tcp_hdr{};
    // rte_pktmbuf_read returns either `&tcp_hdr` (when it copied) or a
    // pointer into the mbuf (when data is contiguous). We need the bytes
    // regardless — copy from the returned pointer if it points into the mbuf.
    const void* tcp_data{rte_pktmbuf_read(&pkt, l4_off, sizeof(tcp_hdr), &tcp_hdr)};
    if (tcp_data == nullptr) {
      continue;
    }
    if (tcp_data != &tcp_hdr) {
      std::memcpy(&tcp_hdr, tcp_data, sizeof(tcp_hdr));
    }
    const auto tcp_hdr_len{static_cast<std::uint32_t>(tcp_hdr.data_off >> 4U) * 4U};
    if (tcp_hdr_len < sizeof(rte_tcp_hdr)) {
      continue;
    }
    const auto payload_off{l4_off + tcp_hdr_len};

    ++c.dpi_attempts;

    // Try the hostname cache first.
    std::string_view hostname;
    std::optional<std::pair<const char*, std::uint16_t>> host_result;
    {
      const auto start{std::chrono::steady_clock::now()};
      host_result = (md.destination_port == kTlsPort)
                        ? dpdk::spi::ExtractTlsSni(pkt, payload_off)
                        : dpdk::spi::ExtractHttpHost(pkt, payload_off);
      const auto end{std::chrono::steady_clock::now()};
      c.extract_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    }
    if (!host_result) {
      continue;
    }
    hostname = {host_result->first, host_result->second};

    const auto cached_idx{cache.Lookup(hostname, /*current_generation=*/0U)};
    if (cached_idx != dpdk::dpi::HostnameCache::kNoMatchIdx) [[likely]] {
      ++c.dpi_cache_hits;
      continue;
    }
    ++c.dpi_cache_misses;
    const auto start{std::chrono::steady_clock::now()};
    const auto matched{rules.Match(hostname)};
    const auto end{std::chrono::steady_clock::now()};
    c.match_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    if (matched.matched) {
      ++c.dpi_match_after_miss;
    }
    cache.Insert(hostname, matched.matched ? 1U : dpdk::dpi::HostnameCache::kNoMatchIdx,
                 /*current_generation=*/0U);
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::println(stderr, "Usage: {} <pcap_path> [cycles]", argv[0]);
    return 1;
  }
  const std::string pcap_path{argv[1]};
  const int cycles = (argc >= 3) ? std::atoi(argv[2]) : 2;

  auto packets{LoadPcap(pcap_path)};
  if (!packets) {
    std::println(stderr, "{}", packets.error());
    return 1;
  }
  std::println("Loaded {} packets from {}", packets->size(), pcap_path);

  if (auto eal{InitEal()}; !eal) {
    std::println(stderr, "EAL: {}", eal.error());
    return 1;
  }
  rte_mempool* pool{nullptr};
  if (auto mp{CreateMempool()}; !mp) {
    std::println(stderr, "Mempool: {}", mp.error());
    return 1;
  } else {
    pool = *mp;
  }

  // Build DPI rule table once.
  auto rules{dpdk::dpi::DpiRuleTable{MakeSampleFilters()}};
  if (!rules.IsEnabled()) {
    std::println(stderr, "No DPI filters compiled");
    return 1;
  }

  // Pre-allocate mbufs so the per-cycle timer measures only DPI work,
  // not allocation. Reuse the same buffer slot across cycles (the data
  // pointer still points into the same payload).
  std::vector<rte_mbuf*> mbufs;
  mbufs.reserve(packets->size());
  for (const auto& p : *packets) {
    auto m{PacketToMbuf(pool, p)};
    if (!m) {
      std::println(stderr, "{}", m.error());
      return 1;
    }
    mbufs.push_back(*m);
  }

  // Run cycles with a fresh cache per measurement point. Cycle 1 fills
  // the cache; cycles 2+ should hit on most packets.
  std::println("\n{:<7} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}", "cycle",
               "parsed", "noport", "dpi_att", "cache_hit", "cache_miss", "match", "Mpps");
  for (int cycle = 1; cycle <= cycles; ++cycle) {
    dpdk::dpi::HostnameCache cache{};
    CycleCounters c{};
    const auto wall_start{std::chrono::steady_clock::now()};
    RunDpiCycle(mbufs, rules, cache, c);
    const auto wall_end{std::chrono::steady_clock::now()};
    const auto wall_ns{std::chrono::duration_cast<std::chrono::nanoseconds>(wall_end - wall_start)};
    const auto mpps{static_cast<double>(packets->size()) / static_cast<double>(wall_ns.count()) * 1000.0};
    const auto hit_rate{c.dpi_attempts > 0
                          ? 100.0 * static_cast<double>(c.dpi_cache_hits) /
                                static_cast<double>(c.dpi_attempts)
                          : 0.0};
    std::println("{:<7} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10.2f}", cycle, c.parsed, c.dns_noport,
                 c.dpi_attempts, c.dpi_cache_hits, c.dpi_cache_misses, c.dpi_match_after_miss, mpps);
    if (cycle == cycles) {
      std::println("\nFinal hit rate: {:.2f}%  ({} hits / {} attempts)", hit_rate,
                   c.dpi_cache_hits, c.dpi_attempts);
      if (c.dpi_attempts > 0) {
        const auto avg_extract_ns{c.extract_ns.count() / std::max<std::int64_t>(c.dpi_attempts, 1)};
        const auto avg_match_ns{c.match_ns.count() / std::max<std::int64_t>(c.dpi_match_after_miss, 1)};
        std::println("Avg extract_host: {} ns  Avg rule_match (miss path): {} ns", avg_extract_ns,
                     avg_match_ns);
      }
    }
  }

  for (rte_mbuf* m : mbufs) rte_pktmbuf_free(m);
  rte_eal_cleanup();
  return 0;
}
