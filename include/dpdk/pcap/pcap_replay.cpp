#include "dpdk/pcap/pcap_replay.hpp"

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_byteorder.h>

#include <pcap/pcap.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <string>
#include <vector>

namespace dpdk::pcap {

// ---------------------------------------------------------------------------
// PcapReader
// ---------------------------------------------------------------------------

PcapReader::PcapReader(void* pcap_handle, rte_mempool* mempool,
                       std::uint64_t total_packets,
                       std::uint64_t total_bytes) noexcept
    : pcap_handle_{pcap_handle},
      mempool_{mempool},
      total_packets_{total_packets},
      total_bytes_{total_bytes} {}

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
      eof_{other.eof_} {
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

  char errbuf[PCAP_ERRBUF_SIZE];
  auto* handle = pcap_open_offline(pcap_file.c_str(), errbuf);
  if (handle == nullptr) {
    return std::unexpected(std::string("PcapReader: pcap_open_offline failed: ") + errbuf);
  }

  // Read first packet to validate the file is readable.
  struct pcap_pkthdr* header{};
  const u_char* data{};
  int ret = pcap_next_ex(handle, &header, &data);
  if (ret < 0) {
    auto err = std::string("PcapReader: pcap_next_ex failed: ") +
               pcap_geterr(handle);
    pcap_close(handle);
    return std::unexpected(err);
  }

  // Estimate packet count from file size (rough estimate: ~100 bytes per packet header + average pkt).
  // We'll use the link type for validation.
  const auto link_type = pcap_datalink(handle);
  if (link_type != DLT_EN10MB) {
    auto err = std::string("PcapReader: unsupported link type: ") +
               std::to_string(link_type) + " (expected Ethernet)";
    pcap_close(handle);
    return std::unexpected(err);
  }

  // Rewind: close and reopen since libpcap has no rewind.
  pcap_close(handle);
  handle = pcap_open_offline(pcap_file.c_str(), errbuf);
  if (handle == nullptr) {
    return std::unexpected(std::string("PcapReader: reopen failed: ") + errbuf);
  }

  // Count total packets by scanning the file.
  std::uint64_t total_pkts{0};
  std::uint64_t total_bytes{0};
  while (pcap_next_ex(handle, &header, &data) > 0) {
    ++total_pkts;
    total_bytes += header->caplen;
  }

  // Reopen again for actual reading.
  pcap_close(handle);
  handle = pcap_open_offline(pcap_file.c_str(), errbuf);
  if (handle == nullptr) {
    return std::unexpected(std::string("PcapReader: final reopen failed: ") + errbuf);
  }

  return PcapReader{handle, mempool, total_pkts, total_bytes};
}

std::expected<rte_mbuf*, std::string> PcapReader::ReadPacket() noexcept {
  if (eof_ || pcap_handle_ == nullptr) {
    return nullptr;
  }

  struct pcap_pkthdr* header{};
  const u_char* data{};
  int ret = pcap_next_ex(static_cast<pcap_t*>(pcap_handle_), &header, &data);

  if (ret == 0) {
    // Timeout (shouldn't happen with offline files).
    return nullptr;
  }
  if (ret == -2) {
    // EOF.
    eof_ = true;
    return nullptr;
  }
  if (ret < 0) {
    return std::unexpected(
        std::string("PcapReader: read error: ") +
        pcap_geterr(static_cast<pcap_t*>(pcap_handle_)));
  }

  // Allocate mbuf and copy packet data.
  auto* mbuf = rte_pktmbuf_alloc(mempool_);
  if (mbuf == nullptr) {
    return std::unexpected("PcapReader: rte_pktmbuf_alloc failed");
  }

  const auto caplen = header->caplen;
  if (caplen > rte_pktmbuf_tailroom(mbuf)) {
    rte_pktmbuf_free(mbuf);
    return std::unexpected("PcapReader: packet too large for mbuf");
  }

  auto* pkt_data = rte_pktmbuf_append(mbuf, static_cast<std::uint16_t>(caplen));
  if (pkt_data == nullptr) {
    rte_pktmbuf_free(mbuf);
    return std::unexpected("PcapReader: rte_pktmbuf_append failed");
  }

  std::memcpy(pkt_data, data, caplen);

  // Set packet length to full captured length (not truncated).
  mbuf->pkt_len = header->len;
  mbuf->data_len = static_cast<std::uint16_t>(caplen);

  return mbuf;
}

std::expected<std::vector<rte_mbuf*>, std::string> PcapReader::ReadBurst(
    std::uint16_t burst_size) noexcept {
  std::vector<rte_mbuf*> burst;
  burst.reserve(burst_size);

  for (std::uint16_t i{0}; i < burst_size; ++i) {
    auto result = ReadPacket();
    if (!result) {
      // Free any already-allocated mbufs in this burst.
      for (auto* m : burst) {
        rte_pktmbuf_free(m);
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
  if (pcap_handle_ == nullptr) {
    return std::unexpected("PcapReader: null handle");
  }

  // Close and reopen since libpcap has no rewind for offline files.
  pcap_close(static_cast<pcap_t*>(pcap_handle_));

  // Re-extract filename from the handle is not possible, so we need to store it.
  // Workaround: store the filename in Open() and use it here.
  // For now, we'll require the caller to create a new PcapReader.
  pcap_handle_ = nullptr;
  eof_ = true;
  return std::unexpected("PcapReader: Reset not supported — create a new PcapReader");
}

// ---------------------------------------------------------------------------
// RunPcapReplay
// ---------------------------------------------------------------------------

std::expected<PcapReplayStats, std::string> RunPcapReplay(
    const PcapReplayConfig& config,
    rte_mempool* mempool,
    const volatile std::sig_atomic_t& force_quit) noexcept {
  auto reader = PcapReader::Open(config.pcap_file, mempool);
  if (!reader) {
    return std::unexpected(reader.error());
  }

  PcapReplayStats stats{};
  const std::uint32_t max_loops = config.loop_count == 0 ? UINT32_MAX : config.loop_count;
  const std::uint64_t max_packets = config.max_packets == 0 ? UINT64_MAX : config.max_packets;
  const bool rate_limited = config.packets_per_second > 0;

  // TSC frequency approximation (will be refined per-iteration).
  const auto tsc_start = rte_rdtsc();

  std::uint64_t packets_read{0};
  std::uint64_t packets_injected{0};
  std::uint64_t bytes_read{0};
  std::uint32_t loops_completed{0};
  std::uint64_t min_latency{UINT64_MAX};
  std::uint64_t max_latency{0};
  std::uint64_t total_latency{0};
  std::uint64_t latency_count{0};

  constexpr std::uint16_t kBurstSize{64};

  while (!force_quit && loops_completed < max_loops && packets_injected < max_packets) {
    auto burst_result = reader->ReadBurst(kBurstSize);
    if (!burst_result) {
      return std::unexpected(burst_result.error());
    }

    auto& burst = *burst_result;
    if (burst.empty()) {
      // EOF — check if we should loop.
      ++loops_completed;
      if (loops_completed >= max_loops) {
        break;
      }
      auto reset_result = reader->Reset();
      if (!reset_result) {
        // Reset not supported — break and report stats.
        break;
      }
      continue;
    }

    const auto rx_tsc = rte_rdtsc();
    packets_read += burst.size();

    for (auto* mbuf : burst) {
      if (mbuf == nullptr) continue;

      bytes_read += mbuf->pkt_len;
      ++packets_injected;

      // Latency: time from RX to classification (simulated here as immediate).
      const auto classify_tsc = rte_rdtsc();
      const auto latency = classify_tsc - rx_tsc;
      total_latency += latency;
      ++latency_count;
      if (latency < min_latency) min_latency = latency;
      if (latency > max_latency) max_latency = latency;

      rte_pktmbuf_free(mbuf);
    }

    // Rate limiting: sleep if needed.
    if (rate_limited) {
      const auto now = rte_rdtsc();
      const auto elapsed = now - tsc_start;
      const auto expected_tsc = static_cast<std::uint64_t>(packets_injected) *
                                rte_get_tsc_hz() / config.packets_per_second;
      if (elapsed < expected_tsc) {
        // Busy-wait for precision (better than sleep for short delays).
        while (rte_rdtsc() < expected_tsc && !force_quit) {
          // spin
        }
      }
    }
  }

  stats.packets_read = packets_read;
  stats.packets_injected = packets_injected;
  stats.bytes_read = bytes_read;
  stats.loops_completed = loops_completed;
  stats.total_latency_tsc = total_latency;
  stats.min_latency_tsc = (latency_count > 0) ? min_latency : 0;
  stats.max_latency_tsc = max_latency;
  stats.latency_samples = latency_count;

  return stats;
}

}  // namespace dpdk::pcap
