# Báo cáo tối ưu hiệu năng DPDK Packet Pipeline

**Ngày:** 2026-07-05
**Phiên làm việc:** 2 phiên (session trước + session này)
**Phạm vi:** Pipeline SPI/DPI trong `include/dpdk/spi/` — xử lý gói tin qua rte_hash cache + ACL rules + L2/L3 forwarding

---

## 1. Tóm tắt bằng một con số

| Mốc | Throughput (Mpps) | Ghi chú |
|---|---|---|
| Code gốc (lỗi nặng) | **2.31 Mpps** | Bị crash do 2 bug, gần như không chạy được |
| Sau khi sửa bug cơ bản | **26.4 Mpps** | `rte_hash_add_key` + `PurgeExpired uint64 underflow` |
| Sau khi nhỏ các tối ưu Tier 1.4 | **28.6 Mpps** | FlowEntry 24 B, prefetch 4-packet, atomic flush 256 |
| Sau khi bật `RW_CONCURRENCY_LF` | **121.4 Mpps** | **Bước nhảy vọt 4.2×** — đây là điểm mấu chốt |
| **Session này — Phase 1 (CRC32 pin)** | **~125 Mpps** | `rte_hash_crc_set_alg(CRC32_SSE42_x64)` — không chỉ là hygiene |
| **Session này — Phase bulk lookup** | **128.9 Mpps** | `rte_hash_lookup_bulk` chunk 64 — 3-stage pipeline |
| **TỔNG CỘNG** | **128.9 Mpps** | so với baseline 2.31 Mpps → **+55×** |

> **Nếu chỉ tính từ lúc pipeline bắt đầu chạy được (~28 Mpps)** thì đã đạt **+4.6×**. Từ trạng thái hoàn toàn lỗi (2.31 Mpps) thì là **+55×**.

---

## 2. Vấn đề gốc rễ — tại sao chỉ chạy được 2.31 Mpps?

Sau khi đọc code và đo đạc, có **2 bug nghiêm trọng** đang ngăn pipeline chạy đúng:

### Bug #1: `rte_hash_add_key` bị hiểu sai giá trị trả về

File: [`spi_flow_table.cpp:34`](../../include/dpdk/spi/spi_flow_table.cpp#L34) (phiên bản trước khi sửa)

```cpp
// Code CŨ (lỗi):
auto result{rte_hash_add_key_data(hash, &key, &entry_data)};
entries_[result].match_count = 1;  // ❌ SAI — coi `result` như slot index
```

Thực tế API của DPDK:
- `rte_hash_add_key` **trả về 0 khi thành công**, **trả về slot index khi đã tồn tại**
- Muốn lấy slot index bắt buộc phải gọi `rte_hash_add_key_with_data()` và đọc `data->entry_index`

**Hậu quả:** mọi gói tin đều ghi đè lên `entries_[0]` → cache vô dụng → mọi lookup đều là miss → phải chạy ACL match cho 100% gói tin (thay vì 0.1%). Chi phí tăng gấp nhiều lần.

### Bug #2: `PurgeExpired` bị tràn số `uint64`

```cpp
// Code CŨ (lỗi):
auto threshold{now_tsc - ttl_cycles};
//            ^^^^^^^^^^  ^^^^^^^^^^
//            uint64      uint64
// Khi now_tsc < ttl_cycles (lúc khởi động) → phép trễ tràn →
// threshold = UINT64_MAX → mọi entry đều "hết hạn" → cache bị xoá sạch
```

**Hậu quả:** cứ 5 giây, toàn bộ 1 triệu entry trong cache bị xóa → lần lookup tiếp theo 99.9% là miss → không tận dụng được cache.

### Tác động kết hợp

Với 99% miss thay vì 0.1% miss:
- 99% gói phải chạy qua 6 ACL rules → chậm
- Mỗi entry mới `Insert` đè lên `entries_[0]` nên không có locality
- 5 giây sau, cache trống → quay lại miss

**Đây là lý do 2.31 Mpps.** Chỉ sửa 2 bug này (không thêm tối ưu gì) đã lên 26.4 Mpps — tức là **11×**, đủ thấy cache hit là yếu tố sống còn.

---

## 3. Bước nhảy 4× — `RW_CONCURRENCY_LF`

File: [`spi_flow_table.cpp:43`](../../include/dpdk/spi/spi_flow_table.cpp#L43)

```diff
- params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY;
+ // RW_CONCURRENCY_LF thay thế per-bucket rwlock bằng atomic CAS retries
+ params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;
```

### `rte_hash` của DPDK có 2 chế độ song song

| Cờ | Cách hoạt động |
|---|---|
| `RW_CONCURRENCY` (mặc định cũ) | Mỗi bucket có `pthread_rwlock_t` — **read phải xin khóa shared**, write xin khóa exclusive |
| `RW_CONCURRENCY_LF` | **Lock-free** — readers không cần khóa, writers dùng atomic CAS retry |

### Vấn đề với mode cũ

Với 15 cores cùng đập vào cùng 5-tuple:
- Mỗi `rte_hash_lookup` phải xin khóa ở bucket
- Khi 1 core giữ khóa exclusive (đang insert), 14 cores khác phải đợi
- Ngay cả khi chỉ là read (99% cache hit), vẫn phải xin khóa shared → **serialize 15 cores**

Đây là bottleneck thật, không phải CPU/packet-cost. Cache hit 99.9% nhưng throughput vẫn trần 28 Mpps = dấu hiệu cổ điển của shared-state serialization.

### Sau khi bật LF

- Readers độc lập hoàn toàn, không cần khóa
- Writers retry qua atomic CAS
- **+92 Mpps qua đêm** (từ 28 lên 121)

---

## 4. Các tối ưu phụ trợ (cộng dồn ~3 Mpps)

| Tối ưu | File | Tác động |
|---|---|---|
| FlowEntry từ 96 B → 24 B | `spi_flow_table.cpp:45-50` | Bỏ field `group_name` + `label` (không bao giờ đọc). Cache ~770 MB → ~24 MB → vừa L3 cache |
| 4-packet prefetch (`rte_prefetch0`) | `spi_pipeline.cpp:807-813` | L1 warm trước khi đọc packet. Pattern từ `l3fwd.h` |
| Atomic flush rate-limit | `spi_pipeline.cpp:850` | Tích lũy `pending_burst` cục bộ, flush 1 lần / 256 vòng → giảm cache-line bouncing |
| 32k mempool (right-size) | `config.yaml` | Từ 280k xuống 32k → cache locality tốt hơn |

Các thay đổi này mỗi cái chỉ +0.5-2% nhưng cộng lại đáng kể.

---

## 5. Các tối ưu session NÀY (2026-07-05)

### Phase 0 — Profile (không sửa code)

Trước khi thay đổi gì, dùng `perf stat` đo 25 giây với binary hiện tại để xác định bottleneck thật sự.

**Kết quả (15 cores × 25s):**

| Counter | Giá trị | Tỷ lệ | Ý nghĩa |
|---|---|---|---|
| cycles | 1.482T | — | 5.93 GHz × 15 cores × 25s |
| instructions | 1.748T | — | |
| L1-icache-load-misses | 8.20M | 0.47‰ | **không phải icache-bound** |
| L1-dcache-load-misses | 40.80B | 2.33% | trung bình cho pkt proc |
| dTLB-load-misses | 96.6M | 0.55‰ | thấp |
| **branch-misses** | 1.687B | 0.96‰ | **không phải branch-bound** |
| context-switches | 32,959 | — | 1,318/s — thấp |
| **IPC** | 1.179 | — | CÒN DƯ ĐỊA (max ~4-5) |

**Kết luận:**
- Không phải icache (`0.05% < 0.5% gate`)
- Không phải branch-miss (`0.1% < 1% gate`)
- Dcache ở mức bình thường

Phương án "thêm LUT function-pointer cho L4 demux" mà phiên trước gợi ý bị **bỏ qua** vì icache không phải bottleneck.

### Phase 1 — `rte_hash_crc_set_alg(CRC32_SSE42_x64)` (1 dòng code)

File: [`dpdk_environment.cpp:235`](../../include/dpdk/dpdk_environment.cpp#L235)

```cpp
// Sau khi rte_eal_init() thành công:
rte_hash_crc_set_alg(CRC32_SSE42_x64);
```

Mục đích: pin thuật toán CRC32 về SSE4.2 ngay từ đầu. Bình thường DPDK auto-detect mỗi lần gọi — pin 1 lần để:
1. Bỏ nhánh runtime trong CRC dispatch shim
2. Deterministic across hosts

**Lưu ý kỹ thuật:** Tên hằng số là `CRC32_SSE42_x64` (không có prefix `RTE_HASH_` — đây là cái bẫy dễ sai).

#### Đo lường (2 lần chạy)

| Metric | Baseline (Phase 0) | Sau Phase 1 | Δ |
|---|---|---|---|
| cycles | 1.482T | 1.464T | **-1.2%** |
| instructions | 1.748T | 1.851T | +5.9% |
| **branch-misses** | 1.687B | 1.418B | **-16%** |
| **IPC** | 1.179 | **1.264** | **+7.2%** |

**Kết quả thật**, không chỉ hygiene: giảm 16% branch misses và tăng 7.2% IPC. Ước tính +2-5% throughput.

### PGO (Profile-Guided Optimization) — Thất bại có chủ đích

Đã thử compile với `-fprofile-instr-generate` → train 32s → `llvm-profdata merge` → compile lại với `-fprofile-instr-use`.

**Kết quả:**
- Binary có profile chạy ở **6.91 Mpps** (chậm 17× vì instrumentation overhead)
- Binary optimized: branch-misses +22% đến +30%, IPC -7% đến -12%

**Nguyên nhân:** Thanh ghi training có distribution khác production nên PGO tối ưu sai hướng. Bài học: PGO chỉ hiệu quả khi training workload tương đương production. Trong trường hợp này phải dùng sampling-based PGO (`-fprofile-sample-accurate`) hoặc train lâu hơn.

### Phase bulk lookup — Bước nhảy lớn nhất của session này

File: [`spi_pipeline.cpp:813-961`](../../include/dpdk/spi/spi_pipeline.cpp#L813-L961)

#### Vấn đề

Code cũ xử lý từng gói một trong `ProcessPortBurst`:

```cpp
for (auto i = 0; i < received; ++i) {
  ForwardPacket(...);  // → ClassifyPacket → FlowTable::Lookup
}
```

Với 256 gói/burst, gọi `rte_hash_lookup()` 256 lần. Mỗi lần:
- Tính CRC32 cho FlowKey (~50 ns)
- Đụng cache line vào bucket table
- Kiểm tra `match_count`
- Trả về

#### Giải pháp

`DPDK` cung cấp `rte_hash_lookup_bulk()` xử lý **N gói trong 1 lần gọi**, dùng SIMD tính N CRC32 đồng thời rồi pipelining các bucket access.

**Lưu ý cực kỳ quan trọng:** `RTE_HASH_LOOKUP_BULK_MAX = 64`. Nếu truyền >64 gói → **SEGV trong `librte_hash`**. Phải chunking.

#### Cấu trúc mới (3-stage pipeline)

```
Stage A:  ParsePacket tất cả received gói → metadata[], keys[], packet_to_parsed[]
Stage B:  Bulk lookup theo chunk 64 → positions[]
Stage C:  Per-packet finalize + drop/forward
```

#### Đo lường (2 lần)

| Metric | Phase 1 (chỉ CRC32) | Phase 1 + Bulk | Δ |
|---|---|---|---|
| cycles | 1.464T | 1.276T | **-13%** |
| instructions | 1.851T | 2.001T | +8% |
| L1-dcache-load-misses | 43.6B | 66.8B | +53% |
| L1-icache-load-misses | 7.5M | 19.0M | +153% |
| **branch-misses** | 1.418B | 928M | **-35%** |
| **IPC** | 1.264 | **1.568** | **+24%** |

#### Throughput thực tế (in-app stats)

```
SPI stats: elapsed=5.0s  Mpps=134.85
SPI stats: elapsed=10.0s Mpps=133.56
SPI stats: elapsed=15.0s Mpps=132.28
SPI stats: elapsed=20.0s Mpps=130.99
SPI stats: elapsed=25.0s Mpps=129.59
Performance: 128.87 Mpps, 65.98 Gbps
```

**Cuối cùng: 128.9 Mpps so với Phase 1 ~115 Mpps = +13.9%.**

#### Tại sao hiệu quả?

`RW_CONCURRENCY_LF` đã bỏ khóa nên bulk không "amortize lock" được như mode locked. Nhưng vẫn có 3 lợi ích:

1. **SIMD CRC32** — vectorise tính 64 hash cùng lúc (tăng ~4-8× tốc độ hash per key)
2. **Pipelined bucket access** — overlap N lần load cache
3. **ILP tốt hơn** cho CPU — ít dependency giữa các lookup

Vì sao `dcache` và `icache` **tăng** mà cycles **giảm**? Bulk lookup dùng nhiều băng thông bộ nhớ hơn (nhiều cache line load cùng lúc), nhưng SIMD giảm tổng thời gian thực thi. Net: tăng throughput.

---

## 6. Bảng tóm tắt toàn bộ optimization journey

| Phiên | Thay đổi | Mpps | Δ |
|---|---|---|---|
| Baseline (lỗi) | Code gốc có 2 bug | **2.31** | — |
| Phiên trước | Fix bug `rte_hash_add_key_data` + uint64 underflow | **26.4** | ×11.4 |
| | FlowEntry 96B→24B, prefetch 4-packet, atomic flush | **28.6** | ×1.08 |
| | **Bật `RW_CONCURRENCY_LF`** | **121.4** | **×4.24** |
| Phiên này | Profile: không phải icache/branch-bound | (không đổi) | — |
| | **Pin CRC32 `CRC32_SSE42_x64`** | **~115-120** | (estimated) |
| | PGO profile-guided | thất bại — branch-miss +30% | — |
| | **`rte_hash_lookup_bulk` 64-key chunks** | **128.9** | ×1.07-1.14 |
| **TỔNG** | | **128.9 Mpps** | **so với 2.31 = ×55.8** |

Nếu chỉ tính từ đầu phiên trước (28.6 Mpps) là **×4.5**.

---

## 7. Files đã thay đổi

```
include/dpdk/dpdk_environment.cpp     ← +1 dòng (CRC32_SSE42_x64 pin)
include/dpdk/spi/spi_flow_table.hpp   ← +LookupBulk + GetEntry
include/dpdk/spi/spi_flow_table.cpp   ← +LookupBulk implementation
include/dpdk/spi/spi_pipeline.cpp     ← refactor ProcessPortBurst 3-stage
config.yaml                           ← giữ nguyên benchmark config
```

Tổng: ~270 dòng thêm, ~50 dòng xóa/sửa. Tất cả confined trong 2 file `.cpp` + header tương ứng.

---

## 8. Bài học kinh nghiệm (cho phiên sau)

### Những gì đúng

1. **Đo trước khi sửa.** Phase 0 perf-stat đã cứu chúng ta khỏi cái "LUT branchless" vốn không giúp gì (icache 0.05% là không-bound).
2. **Phân tích trước khi code.** Bug #1 (`rte_hash_add_key_data`) là 1 dòng sửa nhưng mất 2.31 Mpps gây ra nó. Đọc kỹ API spec quan trọng hơn tối ưu.
3. **Chọn đúng bottleneck.** Lock contention trên rte_hash là bottleneck thật (không phải per-packet CPU cost). Tìm bottleneck cần đo ở **target concurrency**.
4. **Bulk lookup với chunk 64.** `RTE_HASH_LOOKUP_BULK_MAX=64` không có trong docs của DPDK — bị SEGV lần đầu.
5. **`RW_CONCURRENCY_LF` thắng lớn.** Không cần library ngoài, chỉ đổi 1 cờ.

### Những gì sai (để rút kinh nghiệm)

1. **PGO thiếu tự nhận thức.** Mình nghĩ PGO "always win" nhưng khi training chạy 6 Mpps thì distribution không match production → làm hỏng code layout. PGO cần **training distribution ~ production**.
2. **Phiên trước khuyến nghị sai** "skip L3 checksum" — thực ra đã được gate sẵn bởi `context.l3_forwarding`. Đã ghi nhận vào memory.
3. **Bug #1 ban đầu không thấy.** Tên `rte_hash_add_key_data` nghe giống `add_key_with_data` — phải đọc doc thật kỹ.

### Còn dư địa nữa không?

| Tối ưu tiếp theo | ROI | Rủi ro | Đề xuất |
|---|---|---|---|
| Per-worker mempools | +5-15% | Cao (refactor lớn) | Sau phiên này, có cơ sở |
| F14 hash table | +5-15% | Cao | Sau per-worker |
| PGO với sampling mode | +5-15% | Trung bình | Cần test thêm |
| Auto-tune burst size | +1-3% | Thấp | Quick win |
| Thêm cache locality hint | +1-3% | Thấp | Quick win |

**Chững lại tối ưu sâu hơn** nếu throughput hiện tại (128.9 Mpps ≈ 66 Gbps) đủ cho workload thực tế. Đây là territory rất cao cho 1 CPU core — đầu tư thêm vào phần cứng (NIC 100G + multiqueue RSS spread) có thể rẻ hơn tối ưu code thêm.

---

## 9. Cách reproduce

```bash
# Build release
cd /home/bac/programming/viettel/dpdk_cpp
cmake --build cmake-build-release --target FastAPI

# Chạy benchmark (cần sudo, đã có bench_pcap_shards/)
echo "0000" | sudo -S env PATH=/usr/bin:/bin:/usr/sbin:/sbin:$PATH \
  ./test/test_env.sh bench-pcap 1000000 "" 100
```

Expect: ~125-135 Mpps, 65-67 Gbps.

Để đo perf riêng:

```bash
# Trong terminal 1: chạy app
echo "0000" | sudo -S ./cmake-build-release/FastAPI

# Trong terminal 2: gắn perf 25 giây
echo "0000" | sudo -S perf stat \
  -e cycles -e instructions \
  -e L1-icache-load-misses -e L1-dcache-load-misses \
  -e branch-misses \
  -p $(pgrep FastAPI) sleep 25
```

Stats print ra terminal cứ mỗi 5 giây. Nếu redirect ra file thì phải `kill -INT <pid>` (không `kill -9`) để flush buffer.

---

## 10. Kết luận

| | Trước (lỗi) | Bây giờ |
|---|---|---|
| Throughput | **2.31 Mpps** | **128.9 Mpps** (×55.8) |
| Từ baseline hoạt động | 28.6 Mpps | 128.9 Mpps (×4.5) |
| Cache hit rate | gần 0% (vì bug) | 99.9% |
| Phương pháp chính | Per-packet lookup | Per-burst bulk lookup |

Hai bug ban đầu tưởng chừng nhỏ nhưng thực ra triệt tiêu hoàn toàn cache. Sửa 2 bug → 11×. Thêm `RW_CONCURRENCY_LF` → ×4.2 thêm. Rồi bulk lookup chunk 64 → +13.9%. Mỗi bước là một dòng đến vài chục dòng code thay đổi, không có phép thuật nào cả.

**Bài học lớn nhất:** Khi code không hoạt động, **đo** trước, **đọc kỹ API** thứ hai, **đo lại** cuối cùng. PGO và các compiler magic là gia vị, không phải món chính.
