#pragma once

#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <csignal>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace dpdk::pcap {

/// Configuration for PCAP replay mode.
struct PcapReplayConfig {
  /// Path to the PCAP file.
  std::string pcap_file;
  /// Number of times to loop through the PCAP file (0 = infinite).
  std::uint32_t loop_count{1};
  /// Packets per second rate limit (0 = unlimited).
  std::uint64_t packets_per_second{0};
  /// Maximum packets to replay (0 = all).
  std::uint64_t max_packets{0};
};

/// Statistics from PCAP replay.
struct PcapReplayStats {
  std::uint64_t packets_read{};
  std::uint64_t packets_injected{};
  std::uint64_t bytes_read{};
  std::uint32_t loops_completed{};
  std::uint64_t total_latency_tsc{};
  std::uint64_t min_latency_tsc{};
  std::uint64_t max_latency_tsc{};
  std::uint64_t latency_samples{};
};

/// PCAP file reader that converts packets to rte_mbuf.
class PcapReader final {
 public:
  /**
   * @brief Open a PCAP file for reading.
   * @param pcap_file  Path to the PCAP file.
   * @param mempool    DPDK mempool for mbuf allocation.
   * @return PcapReader on success, or error string.
   */
  [[nodiscard]] static std::expected<PcapReader, std::string> Open(const std::string& pcap_file,
                                                                    rte_mempool* mempool) noexcept;

  /// Close the PCAP file and release resources.
  ~PcapReader();

  PcapReader(const PcapReader&) = delete;
  PcapReader& operator=(const PcapReader&) = delete;
  PcapReader(PcapReader&& other) noexcept;
  PcapReader& operator=(PcapReader&& other) noexcept;

  /**
   * @brief Read the next packet from the PCAP file.
   * @return Pointer to rte_mbuf on success, nullptr at EOF, or error string.
   */
  [[nodiscard]] std::expected<rte_mbuf*, std::string> ReadPacket() noexcept;

  /**
   * @brief Read a burst of packets from the PCAP file.
   * @param burst_size  Maximum number of packets to read.
   * @return Vector of rte_mbuf pointers (may be smaller than burst_size at EOF).
   */
  [[nodiscard]] std::expected<std::vector<rte_mbuf*>, std::string> ReadBurst(std::uint16_t burst_size) noexcept;

  /**
   * @brief Reset reading to the beginning of the PCAP file.
   * @return Void on success, or error string.
   */
  [[nodiscard]] std::expected<void, std::string> Reset() noexcept;

  /// Get the total number of packets in the PCAP file (from header).
  [[nodiscard]] std::uint64_t GetTotalPackets() const noexcept { return total_packets_; }

  /// Get the total bytes in the PCAP file.
  [[nodiscard]] std::uint64_t GetTotalBytes() const noexcept { return total_bytes_; }

  /// Whether the reader has reached EOF.
  [[nodiscard]] bool IsEof() const noexcept { return eof_; }

 private:
  PcapReader(void* pcap_handle, rte_mempool* mempool, std::uint64_t total_packets, std::uint64_t total_bytes,
             std::string filename) noexcept;

  void* pcap_handle_{nullptr};
  rte_mempool* mempool_{nullptr};
  std::uint64_t total_packets_{};
  std::uint64_t total_bytes_{};
  bool eof_{false};
  /// Stored at Open() so Reset() can rewind by closing+reopening.
  std::string filename_;
};

/**
 * @brief Run PCAP replay pipeline — read packets and inject into worker rings.
 *
 * This function reads packets from a PCAP file and injects them into the
 * DPDK pipeline for processing, measuring throughput and latency.
 *
 * @param config     PCAP replay configuration.
 * @param mempool    DPDK mempool for mbuf allocation.
 * @param force_quit  Signal flag to stop replay.
 * @return Replay statistics on success, or error string.
 */
[[nodiscard]] std::expected<PcapReplayStats, std::string> RunPcapReplay(const PcapReplayConfig& config,
                                                                         rte_mempool* mempool,
                                                                         const volatile std::sig_atomic_t& force_quit) noexcept;

}  // namespace dpdk::pcap
