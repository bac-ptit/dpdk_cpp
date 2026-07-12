#include <rte_cycles.h>
#include <generic/rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "dpdk/pcap/pcap_replay.hpp"

#include <pcap/pcap.h>
#include <pcap/dlt.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <csignal>
#include <expected>
#include <format>
#include <string>
#include <sys/types.h>
#include <utility>
#include <vector>

namespace dpdk::pcap {

// ---------------------------------------------------------------------------
// Internal helpers (anonymous namespace, not exposed in header)
// ---------------------------------------------------------------------------

namespace {

/// Open a pcap file for offline reading. Returns handle or error string.
[[nodiscard]] auto OpenPcapHandle(const std::string& pcap_file, char* errbuf) noexcept
    -> std::expected<pcap_t*, std::string> {
  auto* handle{pcap_open_offline(pcap_file.c_str(), errbuf)};
  if (handle == nullptr) {
    return std::unexpected{std::format("PcapReader: pcap_open_offline failed: {}", errbuf)};
  }
  return handle;
}

/// Validate that the pcap file is readable and uses Ethernet link type.
[[nodiscard]] auto ValidatePcapFile(pcap_t* handle) noexcept -> std::expected<void, std::string> {
  pcap_pkthdr* header{};
  const u_char* data{};
  if (const int ret{pcap_next_ex(handle, &header, &data)}; ret < 0) {
    auto err_msg{std::format("PcapReader: pcap_next_ex failed: {}", pcap_geterr(handle))};
    return std::unexpected{std::move(err_msg)};
  }

  const auto link_type{pcap_datalink(handle)};
  if (link_type != DLT_EN10MB) {
    auto err_msg{std::format("PcapReader: unsupported link type: {} (expected Ethernet)",
                             link_type)};
    return std::unexpected{std::move(err_msg)};
  }

  return {};
}

/// Scan the entire pcap file to count total packets and bytes.
[[nodiscard]] auto CountPcapPackets(pcap_t* handle) noexcept -> std::pair<std::uint64_t, std::uint64_t> {
  std::uint64_t total_pkts{0};
  std::uint64_t total_bytes{0};
  struct pcap_pkthdr* header{};
  const u_char* data{};
  while (pcap_next_ex(handle, &header, &data) > 0) {
    ++total_pkts;
    total_bytes += header->caplen;
  }
  return {total_pkts, total_bytes};
}

/// Raw packet data read from pcap, before copying into rte_mbuf.
struct RawPacket {
  const pcap_pkthdr* header{};
  const u_char* data{};
};

/// Read the next raw packet from a pcap handle.
/// Returns EOF/timeout as empty RawPacket (data == nullptr).
[[nodiscard]] std::expected<RawPacket, std::string> ReadNextRawPacket(
    pcap_t* handle, bool& eof) noexcept {
  pcap_pkthdr* header{};
  const u_char* data{};
  const int ret{pcap_next_ex(handle, &header, &data)};

  if (ret == 0) {
    return RawPacket{};  // Timeout (shouldn't happen offline).
  }
  if (ret == -2) {
    eof = true;
    return RawPacket{};  // EOF.
  }
  if (ret < 0) {
    return std::unexpected(
        std::format("PcapReader: read error: {}", pcap_geterr(handle)));
  }

  return RawPacket{.header = header, .data = data};
}

/// Copy a raw pcap packet into a newly allocated rte_mbuf.
[[nodiscard]] std::expected<rte_mbuf*, std::string> CopyPacketToMbuf(
    rte_mempool* pool, const pcap_pkthdr* header, const u_char* data) noexcept {
  auto* mbuf{rte_pktmbuf_alloc(pool)};
  if (mbuf == nullptr) {
    return std::unexpected("PcapReader: rte_pktmbuf_alloc failed");
  }

  const auto caplen{header->caplen};
  if (caplen > rte_pktmbuf_tailroom(mbuf)) {
    rte_pktmbuf_free(mbuf);
    return std::unexpected("PcapReader: packet too large for mbuf");
  }

  auto* pkt_data{rte_pktmbuf_append(mbuf, static_cast<std::uint16_t>(caplen))};
  if (pkt_data == nullptr) {
    rte_pktmbuf_free(mbuf);
    return std::unexpected("PcapReader: rte_pktmbuf_append failed");
  }

  std::memcpy(pkt_data, data, caplen);
  rte_pktmbuf_pkt_len(mbuf) = header->len;
  rte_pktmbuf_data_len(mbuf) = static_cast<std::uint16_t>(caplen);

  return mbuf;
}

}  // namespace

// ---------------------------------------------------------------------------
// PcapReader
// ---------------------------------------------------------------------------

PcapReader::PcapReader(void* pcap_handle, rte_mempool* mempool,
                       std::uint64_t total_packets, std::uint64_t total_bytes,
                       std::string filename) noexcept
    : pcap_handle_{pcap_handle},
      mempool_{mempool},
      total_packets_{total_packets},
      total_bytes_{total_bytes},
      filename_{std::move(filename)} {}

PcapReader::~PcapReader() {
  if (pcap_handle_ != nullptr) {
    pcap_close(static_cast<pcap_t*>(pcap_handle_));
    pcap_handle_ = nullptr;
  }
}

PcapReader::PcapReader(PcapReader&& other) noexcept
    : pcap_handle_{other.pcap_handle_},
      mempool_{other.mempool_},
      total_packets_{other.total_packets_},
      total_bytes_{other.total_bytes_},
      eof_{other.eof_},
      filename_{std::move(other.filename_)} {
  other.pcap_handle_ = nullptr;
  other.eof_ = true;
}

PcapReader& PcapReader::operator=(PcapReader&& other) noexcept {
  if (this != &other) {
    if (pcap_handle_ != nullptr) {
      pcap_close(static_cast<pcap_t*>(pcap_handle_));
    }
    pcap_handle_ = other.pcap_handle_;
    mempool_ = other.mempool_;
    total_packets_ = other.total_packets_;
    total_bytes_ = other.total_bytes_;
    eof_ = other.eof_;
    other.pcap_handle_ = nullptr;
    other.eof_ = true;
  }
  return *this;
}

std::expected<PcapReader, std::string> PcapReader::Open(
    const std::string& pcap_file, rte_mempool* mempool) noexcept {
  if (mempool == nullptr) {
    return std::unexpected("PcapReader: null mempool");
  }

  std::array<char, PCAP_ERRBUF_SIZE> errbuf{};

  // 1. Open, validate, then close+reopen (libpcap has no rewind).
  auto handle1{OpenPcapHandle(pcap_file, errbuf.data())};
  if (!handle1) {
    return std::unexpected{handle1.error()};
  }
  if (auto result_ok{ValidatePcapFile(*handle1)}; !result_ok) {
    pcap_close(*handle1);
    return std::unexpected{result_ok.error()};
  }
  pcap_close(*handle1);

  // 2. Reopen to count packets & bytes.
  auto handle2{OpenPcapHandle(pcap_file, errbuf.data())};
  if (!handle2) {
    return std::unexpected{handle2.error()};
  }
  const auto [total_pkts, total_bytes]{CountPcapPackets(*handle2)};
  pcap_close(*handle2);

  // 3. Reopen again for actual reading.
  auto handle3{OpenPcapHandle(pcap_file, errbuf.data())};
  if (!handle3) {
    return std::unexpected{handle3.error()};
  }

  return PcapReader{*handle3, mempool, total_pkts, total_bytes, pcap_file};
}

std::expected<rte_mbuf*, std::string> PcapReader::ReadPacket() noexcept {
  if (eof_ || pcap_handle_ == nullptr) {
    return nullptr;
  }

  auto raw{ReadNextRawPacket(static_cast<pcap_t*>(pcap_handle_), eof_)};
  if (!raw) {
    return std::unexpected{std::move(raw).error()};
  }
  if (raw->data == nullptr) {
    return nullptr;  // EOF or timeout.
  }

  return CopyPacketToMbuf(mempool_, raw->header, raw->data);
}

std::expected<std::vector<rte_mbuf*>, std::string> PcapReader::ReadBurst(
    std::uint16_t burst_size) noexcept {
  std::vector<rte_mbuf*> burst;
  burst.reserve(burst_size);

  for (std::uint16_t i{0}; i < burst_size; ++i) {
    auto result = ReadPacket();
    if (!result) {
      // Free any already-allocated mbufs in this burst.
      for (auto* mbuf_iter : burst) {
        rte_pktmbuf_free(mbuf_iter);
      }
      return std::unexpected(result.error());
    }
    if (*result == nullptr) {
      // EOF.
      break;
    }
    burst.push_back(*result);
  }

  return burst;
}

std::expected<void, std::string> PcapReader::Reset() noexcept {
  if (filename_.empty()) {
    return std::unexpected("PcapReader: Reset requires filename (call Open first)");
  }
  if (pcap_handle_ != nullptr) {
    pcap_close(static_cast<pcap_t*>(pcap_handle_));
    pcap_handle_ = nullptr;
  }

  std::array<char, PCAP_ERRBUF_SIZE> errbuf{};
  auto handle{OpenPcapHandle(filename_, errbuf.data())};
  if (!handle) {
    eof_ = true;
    return std::unexpected{std::move(handle).error()};
  }
  pcap_handle_ = *handle;
  eof_ = false;
  return {};
}

// ---------------------------------------------------------------------------
// Internal helpers for RunPcapReplay
// ---------------------------------------------------------------------------

namespace {

/// Run-time state accumulated during pcap replay.
struct PcapReplayState {
  std::uint64_t packets_read{};
  std::uint64_t packets_injected{};
  std::uint64_t bytes_read{};
  std::uint64_t total_latency{};
  std::uint64_t latency_count{};
  std::uint64_t min_latency{UINT64_MAX};
  std::uint64_t max_latency{};
  std::uint32_t loops_completed{};
};

/// Process a burst of mbufs: track bytes/latency and free each mbuf.
void ProcessBurst(std::vector<rte_mbuf*>& burst, std::uint64_t rx_tsc,
                  PcapReplayState& state) noexcept {
  for (auto* mbuf_ptr : burst) {
    if (mbuf_ptr == nullptr) {
      continue;
    }
    state.bytes_read += rte_pktmbuf_pkt_len(mbuf_ptr);
    ++state.packets_injected;
    const auto classify_tsc{rte_rdtsc()};
    const auto latency{classify_tsc - rx_tsc};
    state.total_latency += latency;
    ++state.latency_count;
    state.min_latency = std::min(latency, state.min_latency);
    state.max_latency = std::max(latency, state.max_latency);
    rte_pktmbuf_free(mbuf_ptr);
  }
}

/// Busy-wait to enforce a packets-per-second rate limit.
void ApplyRateLimit(std::uint64_t packets_injected, std::uint64_t tsc_start,
                    std::uint64_t rate_pps,
                    const volatile std::sig_atomic_t& force_quit) noexcept {
  const auto now{rte_rdtsc()};
  const auto elapsed{now - tsc_start};
  const auto expected_tsc{packets_injected * rte_get_tsc_hz() / rate_pps};
  if (elapsed < expected_tsc) {
    while (rte_rdtsc() < expected_tsc && (force_quit == 0)) {
      // spin
    }
  }
}

/// Run the main replay loop: read bursts, process, rate-limit.
[[nodiscard]] std::expected<void, std::string> RunReplayLoop(
    PcapReader& reader, const PcapReplayConfig& config, PcapReplayState& state,
    const volatile std::sig_atomic_t& force_quit) noexcept {
  const auto max_loops{config.loop_count == 0 ? UINT32_MAX : config.loop_count};
  const auto max_packets{config.max_packets == 0 ? UINT64_MAX : config.max_packets};
  const auto rate_limited{config.packets_per_second > 0};
  const auto tsc_start{rte_rdtsc()};

  constexpr std::uint16_t kBurstSize{64};

  while ((force_quit == 0) && state.loops_completed < max_loops && state.packets_injected < max_packets) {
    auto burst_result{reader.ReadBurst(kBurstSize)};
    if (!burst_result) {
      return std::unexpected{burst_result.error()};
    }

    auto& burst{*burst_result};
    if (burst.empty()) {
      ++state.loops_completed;
      if (state.loops_completed >= max_loops) {
        break;
      }
      if (!reader.Reset()) {
        break;
      }
      continue;
    }

    state.packets_read += burst.size();
    const auto rx_tsc{rte_rdtsc()};
    ProcessBurst(burst, rx_tsc, state);

    if (rate_limited) {
      ApplyRateLimit(state.packets_injected, tsc_start, config.packets_per_second, force_quit);
    }
  }

  return {};
}

/// Convert the run-time state into the final stats struct.
[[nodiscard]] PcapReplayStats ToStats(const PcapReplayState& state) noexcept {
  return PcapReplayStats{
    .packets_read = state.packets_read,
    .packets_injected = state.packets_injected,
    .bytes_read = state.bytes_read,
    .loops_completed = state.loops_completed,
    .total_latency_tsc = state.total_latency,
    .min_latency_tsc = state.latency_count > 0 ? state.min_latency : 0,
    .max_latency_tsc = state.max_latency,
    .latency_samples = state.latency_count,
  };
}

}  // namespace

// ---------------------------------------------------------------------------
// RunPcapReplay
// ---------------------------------------------------------------------------

std::expected<PcapReplayStats, std::string> RunPcapReplay(
    const PcapReplayConfig& config,
    rte_mempool* mempool,
    const volatile std::sig_atomic_t& force_quit) noexcept {
  auto reader{PcapReader::Open(config.pcap_file, mempool)};
  if (!reader) {
    return std::unexpected{reader.error()};
  }

  PcapReplayState state;
  auto result_ok{RunReplayLoop(*reader, config, state, force_quit)};
  if (!result_ok) {
    return std::unexpected{result_ok.error()};
  }

  return ToStats(state);
}

}  // namespace dpdk::pcap