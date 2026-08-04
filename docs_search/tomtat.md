# Tóm Tắt Tối Ưu Hiệu Năng SPI Pipeline

## Bối cảnh

Hệ thống SPI (Shallow Packet Inspection) phân loại gói tin theo bộ quy tắc ACL.
Với tập `rules.beve` tiêu chuẩn (102 filter groups), hiệu năng đạt **~58 Mpps**.
Khi mở rộng lên `rules_8m.beve` (**8.38 triệu rules**, 4098 filter groups),
hiệu năng sụp xuống chỉ còn **2.5 Mpps** — giảm 23 lần.

**Nguyên nhân gốc**: DPDK ACL giới hạn `RTE_ACL_MAX_CATEGORIES = 16` groups/context.
4098 groups bị chia thành **257 ACL chunks**. Mỗi gói tin cache-miss phải gọi
`rte_acl_classify` **257 lần** — tốn ~1500 CPU cycles/packet.

---

## Kết Quả Cuối Cùng

| Giai đoạn | Throughput | So với ban đầu |
|-----------|-----------|---------------|
| Ban đầu (257 ACL chunks) | **2.5 Mpps** | ×1 |
| Sau tối ưu chunking (17 chunks) | **15.6 Mpps** | ×6.2 |
| **Sau tích hợp rte_member** | **67.5 Mpps** | **×27** |

> **1.35 tỷ gói tin xử lý trong 20 giây** trên 8.38 triệu rules.

---

## Những Gì Đã Làm Thành Công ✅

### 1. Gộp ACL Chunks: 257 → 17 chunks (×6.2 tốc độ)

**Vấn đề**: 4098 groups ÷ 16 groups/chunk = 257 chunks → 257 lần gọi `rte_acl_classify` mỗi burst.

**Giải pháp**: Tăng `kAclMaxCategoriesChunk` lên **256 groups/chunk**.
Mỗi chunk chứa 256 groups, tất cả rules dùng **1 category duy nhất** (Category 0)
với `userdata` encode `(group_index << 16 | filter_index)` và `priority = RTE_ACL_MAX_PRIORITY - precedence`.
DPDK ACL tự chọn rule ưu tiên cao nhất bên trong SIMD trie.

**Kết quả**: 4098 groups → **17 chunks** thay vì 257 chunks. Giảm 93% số lần gọi `rte_acl_classify`.

**Files đã sửa**:
- [`spi_rule_engine.cpp`](file:///home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_rule_engine.cpp) — `CompileRuleTable()`, `BuildAclRule()`

### 2. Biên dịch ACL Song song 16 Cores

**Giải pháp**: Mỗi ACL chunk được biên dịch độc lập bằng `std::async` trên 16 CPU cores.
Thay vì tuần tự build 17 chunks, tất cả chạy đồng thời.

**Kết quả**: Thời gian biên dịch 8.38M rules giảm đáng kể nhờ tận dụng 100% CPU.

**Files đã sửa**:
- [`spi_rule_engine.cpp`](file:///home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_rule_engine.cpp) — `CompileRuleTable()`, `compile_chunk_fn` lambda

### 3. rte_member (Cuckoo Hash) — Bộ lọc Membership O(1) (×4.3 tốc độ tiếp)

**Vấn đề cốt lõi**: Gói tin **không match** bất kỳ rule nào vẫn phải duyệt hết
17 chunks ACL (~180 CPU cycles) trước khi kết luận "unknown".
Trong thực tế, phần lớn gói tin rơi vào trường hợp này.

**Giải pháp**: Tích hợp `rte_member` (DPDK Membership Library) dạng **Hash Table mode**
(Cuckoo Hash, non-cache, AVX2). Trước khi chạy ACL, mỗi gói tin được kiểm tra:

```
MemberKey = (dst_ip, dst_port, protocol)  ← 7 bytes
rte_member_lookup_bulk(member_ctx, keys, n, set_ids)

Nếu set_id == RTE_MEMBER_NO_MATCH:
  → Chắc chắn 100% không match → BỎ QUA ACL hoàn toàn
  → Chi phí: ~4-8 CPU cycles
```

**Kết quả**: Phần lớn gói tin không match bị loại ngay trong **4-8 cycles**
thay vì 180+ cycles. Throughput tăng từ 15.6 Mpps lên **67.5 Mpps**.

**Files đã sửa**:
- [`spi_rule_engine.hpp`](file:///home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_rule_engine.hpp) — thêm `rte_member_setsum*`, `MemberFilterBulk()`
- [`spi_rule_engine.cpp`](file:///home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_rule_engine.cpp) — build Member table, implement `MemberFilterBulk()`
- [`spi_pipeline.cpp`](file:///home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_pipeline.cpp) — chèn Phase 1.7 Member filter vào `FinalizePackets()`

### 4. Short-Circuit Early Exit trong MatchBulk

**Giải pháp**: Khi tất cả 64 gói tin trong burst đã match ở các chunks đầu,
vòng lặp chunks dừng ngay lập tức (`all_matched == true → break`).

**Files đã sửa**:
- [`spi_rule_engine.cpp`](file:///home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_rule_engine.cpp) — `MatchBulk()`

---

## Những Gì Đã Thử Nhưng Thất Bại / Bỏ Đi ❌

### 1. Unified ACL Context duy nhất cho 8.38M rules — OOM ❌

**Ý tưởng**: Gộp tất cả 8.38M rules vào **1 rte_acl_ctx duy nhất** để chỉ cần
gọi `rte_acl_classify` đúng 1 lần duy nhất.

**Kết quả**: DPDK cố cấp phát **805 MB RAM** cho trie ACL → **thất bại OOM**:
```
ACL: allocation of 805307664 bytes on socket 0 for ACL_spi_unified_acl failed
SPI compile error: rte_acl_create failed: Success
```

**Lý do bỏ**: 8.38M rules tạo ra trie ACL quá lớn, vượt quá dung lượng hugepage
khả dụng (3 GB memory_size). Giải pháp chia thành 17 chunks nhỏ hơn (mỗi chunk
~50 MB) là cách tiếp cận thực tế hơn.

### 2. rte_fib (FIB DIR-24-8) — Allocation Failed ❌

**Ý tưởng**: Dùng `rte_fib` (Forwarding Information Base, 64-bit next_hop, AVX-512)
để tra cứu dải IP CIDR trong O(1) trước khi chạy ACL.

**Kết quả**: FIB không thể cấp phát RIB mempool:
```
RIB: Can not allocate mempool for RIB spi_fib
FIB: Can not allocate RIB spi_fib
```

**Lý do**: `max_routes = 8,388,613` quá lớn cho bộ nhớ hugepage còn lại
sau khi đã cấp phát ACL chunks + Member table + Flow table + IP Frag tables.

**Tác động**: FIB graceful degrade — `fib_ctx_ == nullptr` nên `FibLookupBulk()`
tự bỏ qua. Hệ thống vẫn chạy bình thường nhờ Member filter + ACL fallback.
Throughput **67.5 Mpps** hoàn toàn đến từ Member filter, KHÔNG có FIB.

---

## Kiến Trúc Pipeline Cuối Cùng

```
Packet Burst (64 pkts)
  │
  ├─ Tầng 0: FlowTable Cache (rte_hash_lookup_bulk_data)     ~3-5 cycles ✅
  │    └─ 99%+ HIT sau warmup → skip mọi thứ bên dưới
  │
  ├─ Tầng 1: ProbeTss (Hash 5-tuple, 128 slots)              ~15-25 cycles ✅
  │    └─ Exact match cho rules có full 5-tuple
  │
  ├─ Tầng 2: rte_member (Cuckoo Hash, HT mode, AVX2)         ~4-8 cycles ✅  🆕
  │    ├─ NO_MATCH → chắc chắn không match → BỎ QUA ACL
  │    └─ HIT → có thể match → tiếp ACL
  │
  ├─ Tầng 3: rte_acl_classify (17 chunks, ~180 cycles)
  │    └─ Chỉ chạy cho gói tin thoát qua Member filter
  │
  └─ Tầng 4: FlowTable Insert + Forward/Drop
```

---

## Tài liệu Nghiên cứu Đã Lưu

| File | Nội dung |
|------|----------|
| [`30_dpdk_acl_chunking_and_optimization.md`](file:///home/bac/programming/viettel/dpdk_cpp/docs_search/30_dpdk_acl_chunking_and_optimization.md) | ACL chunking, category_mask, short-circuit |
| [`31_dpdk_rte_advanced_optimization_apis.md`](file:///home/bac/programming/viettel/dpdk_cpp/docs_search/31_dpdk_rte_advanced_optimization_apis.md) | rte_fib, rte_lpm, rte_member, rte_hash, rte_flow |
