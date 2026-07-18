# Luồng Hoạt Động FastSPI/DPDK — Phiên bản tối ưu (SPI gates DPI)

Tài liệu này mô tả luồng xử lý gói tin qua FastSPI/DPDK sau khi áp dụng các cơ chế tối ưu SPI→DPI:

1. **Flow cache** với canonical 5-tuple (req + resp dùng chung 1 entry)
2. **SPI-gates-DPI** — chỉ chạy DPI khi SPI group được đánh dấu `l7_required: true`
3. **Một `rte_acl_ctx` duy nhất** cho mọi SPI group (W2 collapse, O(log n + G))
4. **Response-direction skip** + **METHOD/SNI check** để tránh parse lại response
5. **Hostname cache** per-worker (nDPI pattern: extract 1 lần, dùng cho cả flow)

Kiến trúc tổng thể:

```
[VM1] <--> [virbr1] <--> [FastSPI/DPDK] <--> [virbr2] <--> [VM2]
```

---

## Sơ đồ tổng quan (10 bước)

```
START → INIT DPDK → RX BURST → PARSE L2/L3/L4
     → FLOW CACHE LOOKUP (canonical key)
     ├─ HIT  → dùng action đã cache → DISPATCH
     └─ MISS → SPI MATCH (rte_acl_classify, 1 call)
              → SPI-GATES-DPI DECISION
              ├─ skip DPI (l7_required=false / drop / non-TCP / non-80-443 / response)
              │   → insert flow cache (action cố định) → DISPATCH
              └─ run DPI (l7_required=true)
                  ├─ parse METHOD (HTTP) hoặc SNI (TLS)
                  ├─ lookup hostname cache (per-worker)
                  ├─ DpiRuleTable::Match (priority order)
                  └─ insert flow cache → DISPATCH
     → DISPATCH (LPM L3 hoặc L2 pair)
     → WORKER PROCESS (rewrite MAC, TTL--, checksum, TX)
     → STATISTICS (in định kỳ: dpi_cache_*, dpi_skipped_by_spi, ...)
```

---

## 1. START — Load & compile config

- Đọc `config.yaml`.
- Parse:
  - `eal.*` → truyền cho `rte_eal_init`.
  - `spi.filter_groups[]` — **mỗi group có cờ `l7_required: bool`**:
    - `l7_required: false` (mặc định) → nhóm này match xong là **skip DPI hoàn toàn**.
    - `l7_required: true` → nhóm này match xong vẫn phải chạy DPI (cần L7).
  - `dpi.filters[]` — danh sách hostname pattern + group + priority.
- Biên dịch SPI: `rte_acl_create()` một lần duy nhất cho **tất cả group** (W2 collapse), mỗi group là một `category` trong cùng context.
- Biên dịch DPI: `DpiRuleTable` sắp xếp theo `priority ASC`, tách thành `exact_list_` (≤ 10 rule) + `suffix_list_` (~25 rule) + `catch_all_idx_`.

**Mục đích**: SPI được compile thành một cấu trúc trie O(log n) chia sẻ, không phải G context riêng biệt.

---

## 2. INIT DPDK

Giống phiên bản cũ:
- Khởi tạo EAL (`rte_eal_init`).
- Tạo mempool (`rte_pktmbuf_pool_create`).
- Cấu hình port (`rte_eth_dev_configure`), start port, bật promiscuous.
- Cấu hình queue-to-lcore mapping.
- **Mới**: `rte_hash_create` cho flow table với `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF`, capacity = `spi.max_concurrent_flows`.
- **Mới**: `rte_ring_create` cho dispatch rings (mode `flow_hash`).

---

## 3. RECEIVE PACKET (RX Burst)

Worker đọc một burst từ queue đã được gán:
- `rte_eth_rx_burst(port, queue, mbufs, burst_size)` → trả về `nb_rx`.
- **Mới**: `rte_prefetch0` packet `i + 4` để pipeline I-cache trước khi xử lý packet `i`.

---

## 4. PARSE L2/L3/L4 HEADER

Cho mỗi packet:
- Ethernet: chỉ chấp nhận EtherType `0x0800` (IPv4).
- IPv4: validate header length, đọc `src_addr`, `dst_addr`, `next_proto_id`.
- L4:
  - TCP → đọc `src_port`, `dst_port`.
  - UDP → đọc `src_port`, `dst_port`.
- Trả về `PacketMetadata { protocol, src_ip, dst_ip, src_port, dst_port }`.

Nếu không phải IPv4 / TCP-UDP → malformed, đếm `counters.malformed`, **không đi tiếp**.

---

## 5. FLOW CACHE LOOKUP (canonical 5-tuple) — Bước mới

**Trước SPI**, ta thử tra flow cache trước. Cache hit chiếm ~99% traffic ở workload thực.

### 5.1 Tạo canonical FlowKey

```cpp
FlowKey MakeCanonical(src_ip, dst_ip, src_port, dst_port, proto) {
  // Sắp xếp (ip, port) sao cho request và response hash cùng key
  if (tie(src_ip, src_port) > tie(dst_ip, dst_port)) {
    swap(src_ip, dst_ip);
    swap(src_port, dst_port);
  }
  return FlowKey{...};
}
```

**Tác dụng**:
- Request `192.168.100.130:54321 → 192.168.200.180:80` và
- Response `192.168.200.180:80 → 192.168.100.130:54321`
- → cùng một key → cùng một cache entry.
- Cache hit trên gói response **mà không cần DPI thêm lần nào**.

### 5.2 Tra bảng

```cpp
auto* entry = rte_hash_lookup_bulk(hash, keys, results, nb_rx);
if (entry->match_count > 0) {
  // HIT: dùng action đã cache
  ++counters.flow_cache_hits;
  return entry->action;   // forward hoặc drop
}
// MISS: rơi xuống bước 6
```

**Touch on hit**: `entry->last_seen_tsc = rte_rdtsc()` — giữ flow sống qua TTL, tránh bị purge khi đang dùng.

---

## 6. SPI MATCH — Cache miss path

Chỉ chạy khi flow cache **miss** (khoảng ~1% traffic).

### 6.1 Build input

```cpp
AclInputData input{
  .src_ip_be = htobe32(metadata.source_ip_address),
  .dst_ip_be = htobe32(metadata.destination_ip_address),
  .src_port_be = htobe16(metadata.source_port),
  .dst_port_be = htobe16(metadata.destination_port),
  .protocol = metadata.protocol,
};
```

### 6.2 Một `rte_acl_classify` duy nhất

```cpp
uint32_t results[kMaxCategories];
rte_acl_classify(acl_ctx, &data, results, 1, kMaxCategories);
//            ^^^^^^^   combined ctx cho MỌI group
//                              ^^^^^^^^   results[cat] cho mỗi group
```

- **W2 collapse**: trước đây là G lần `rte_acl_classify` (mỗi group 1 context), giờ là **1 lần duy nhất**.
- Complexity: `O(log n + G)` thay vì `O(G × log n)`.

### 6.3 Walk categories theo precedence

```cpp
for (cat in precedence_order_) {           // precedence ASC
  if (results[cat] != 0) {                 // matched
    return ClassificationResult{
      .action = groups_[cat].action,
      .l7_required = groups_[cat].l7_required,    // <-- KEY FIELD
      .group_name = groups_[cat].name,
      .label = ...,
    };
  }
}
return miss;  // không group nào match
```

**`l7_required`** được copy từ config vào `CompiledFilterGroup` lúc compile, và bubble lên `ClassificationResult`. Đây là tín hiệu mà bước 7 sẽ dùng.

---

## 7. SPI-GATES-DPI DECISION — Bước cốt lõi

Sau khi có `spi_match`, quyết định xem có cần DPI hay không. Code ở `spi_pipeline.cpp::TryDpiClassify`:

```cpp
void TryDpiClassify(spi_match, metadata, key, ...) {
  // (A) DPI disabled → skip hoàn toàn, không tính vào skipped_by_spi
  if (!dpi_rules || !dpi_rules->IsEnabled()) return;

  // (B) SPI matched Drop → skip DPI, packet đã drop rồi
  if (spi_match.matched && spi_match.action == kDrop) {
    ++counters.dpi_skipped_by_spi;
    return;
  }

  // (C) SPI matched Forward + l7_required=false → SPI verdict là cuối cùng
  if (spi_match.matched && spi_match.action == kForward && !spi_match.l7_required) {
    ++counters.dpi_skipped_by_spi;
    return;       // <-- đây là shortcut chính, tránh ~99% DPI work
  }

  // (D) Không phải TCP → DPI chỉ xét TCP/80, TCP/443
  if (metadata.protocol != kTcp) {
    ++counters.dpi_skipped_by_spi;
    return;
  }

  // (E) Không phải port 80 hoặc 443
  if (metadata.dst_port != 80 && metadata.dst_port != 443) {
    ++counters.dpi_skipped_by_spi;
    return;
  }

  // (F) Gói RESPONSE (src_port ∈ {80, 443}, dst_port ≥ 1024):
  //     đã có entry trong flow cache từ request, lookup HIT trả về
  //     action luôn — không cần parse lại response.
  if (src_port ∈ {80, 443} && dst_port >= 1024) {
    ++counters.dpi_skipped_by_spi;
    return;
  }

  // (G) Cuối cùng: chạy DPI
  ExtractHostname(packet, metadata);  // SNI hoặc HTTP Host
  if (MatchDpi(hostname)) {
    flow_table->Insert(key, action);
    ++counters.matched;
  }
}
```

**Hệ quả đo được**:
- Counter `dpi_skipped_by_spi` ≈ `parsed` trên traffic có SPI coarse groups (Facebook IPs, YouTube IPs, DNS, drop).
- `dpi_cache_misses` chỉ tăng khi SPI thật sự yêu cầu L7 (group có `l7_required: true`).

---

## 8. DPI (chỉ khi bước 7 cho phép)

### 8.1 ExtractHostname — phân nhánh theo port

```cpp
if (dst_port == 443)  return ExtractTlsSni(packet, tcp_payload_offset);
if (dst_port == 80)   return ExtractHttpHost(packet, tcp_payload_offset);
```

### 8.2 ExtractTlsSni (port 443)

- Validate TLS record header: `content_type=0x16` (Handshake), version ≥ `0x0301`.
- **METHOD check** cho TLS: chỉ nhận `handshake_type=0x01` (ClientHello). Reject:
  - `0x02` ServerHello (response direction)
  - `0x0E` ServerHelloDone
  - `0x14` ChangeCipherSpec, `0x15` Alert
- Walk past preamble (random, session_id, cipher_suites, compression_methods).
- Tìm extension SNI (`type=0x0000`), trả về `(hostname_ptr, hostname_len)` zero-copy trỏ vào mbuf.

**Cost**: ~200 cycles (theo doc 09 benchmark).

### 8.3 ExtractHttpHost (port 80)

**METHOD check** (trước khi scan Host header):

```cpp
bool IsHttpRequestStart(data) {
  // Chỉ chấp nhận method REQUEST, reject method RESPONSE
  return data[0..3] == "GET "  || data[0..3] == "POST" ||
         data[0..3] == "HEAD" || data[0..3] == "PUT " ||
         data[0..3] == "DELE" || data[0..3] == "PATC" ||
         data[0..3] == "OPTI";
  // Response "HTTP/1.x" sẽ bị reject (bắt đầu bằng 'H' nhưng ký tự thứ 2 khác)
}
```

- Sau khi pass METHOD check, scan tìm `\r\nHost: ` header.
- Trả về `(host_ptr, host_len)`.

**Tác dụng của METHOD check**: response packet `HTTP/1.1 200 OK\r\n...` không có `Host:` header → parse nhanh (~5 cycles skip) thay vì scan 256 bytes vô ích.

### 8.4 Hostname cache (per-worker)

```cpp
auto cached_idx = hostname_cache.Lookup(hostname, generation);
if (cached_idx != kNoMatchIdx) {
  // HIT — không cần chạy Match nữa
  ++counters.dpi_cache_hits;
  return ResultAt(cached_idx);
}

// MISS — chạy Match
auto result = dpi_rules->Match(hostname);
hostname_cache.Insert(hostname, result.filter_index, generation);
++counters.dpi_cache_misses;
return result;
```

**Generation check** quan trọng: nếu config reload, generation thay đổi → cache invalid → re-Match với rule table mới. Tránh TOCTOU (xem `docs_search/13` §M1).

### 8.5 DpiRuleTable::Match

- Ưu tiên `exact_list_` (≤ 10 rule, linear scan).
- Nếu không exact → scan `suffix_list_` (~25 rule, sorted by domain ASC, early-exit khi gặp mismatch).
- Cuối cùng: `catch_all_idx_` (`*` rule).
- Trả về filter đầu tiên match theo `priority ASC`.

---

## 9. DISPATCH — Quyết định output port

### 9.1 SPI matched + có action

- `action == Drop` → `++dropped_by_rule`, `rte_pktmbuf_free(packet)`.
- `action == Forward` → tìm transmit port.

### 9.2 L3 mode (`l3_forward.enabled: true`)

```cpp
auto port = LookupL3TransmitPort(l3_routes, metadata);
if (!port || port == receive_port) drop;
```

LPM trên `dst_ip` → `output_port`. Sau đó:

```cpp
// Decrement TTL, recompute IP checksum
ipv4_hdr->time_to_live--;
ipv4_hdr->hdr_checksum = 0;
ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

// Recompute L4 checksum (đã fix bug "cksum incorrect" trên instruction.md)
tcp_hdr->cksum = 0;
tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);

// Rewrite MAC: src = port's MAC, dst = destination VM's MAC (từ ethernet_destinations[])
ether_hdr->src_addr = port_mac;
ether_hdr->dst_addr = destination_mac;
```

### 9.3 L2 mode (mặc định)

- `transmit_port = receive_port ^ 1` (ghép cặp 0↔1, 2↔3, ...).
- Chỉ rewrite MAC (không TTL, không checksum).

### 9.4 Fallback

- Không match route / không tìm được destination MAC → drop.

---

## 10. WORKER PROCESS — TX Burst

Sau khi mỗi packet có `(transmit_port, mbuf)`:
- Push vào `transmit_buffers[port]`.
- Cuối vòng lặp (sau khi xử lý hết burst RX):
  ```cpp
  for (port in active_ports) {
    auto sent = rte_eth_tx_burst(port, queue, tx_buf[port], tx_count[port]);
    tx_count[port] -= sent;
    // Free mbuf không gửi được
    for (mbuf in tx_buf[port] unsent) rte_pktmbuf_free(mbuf);
  }
  ```

---

## 11. STATISTICS — In định kỳ

Mỗi `timer_period_sec` (mặc định 5s), main lcore in stats line:

```
SPI stats: received=N matched=M flow_table_full=F dpi_skipped_by_spi=K
           elapsed=Ts Mpps=X
```

Các counter quan trọng cần theo dõi:

| Counter | Ý nghĩa | Hành động nếu bất thường |
|---|---|---|
| `received` | Tổng gói nhận | baseline |
| `matched` | Match được ở SPI hoặc DPI | nếu thấp → check rule |
| `flow_cache_hits` | Trúng cache | nếu thấp → check TTL, key |
| `dpi_cache_hits` | Trúng hostname cache | nếu thấp → check reload |
| `dpi_cache_misses` | Phải chạy DPI Match | **nếu cao → SPI gating không hiệu quả** |
| **`dpi_skipped_by_spi`** | **SPI short-circuit DPI** | **nếu thấp → set `l7_required` lại** |
| `flow_table_full` | `rte_hash_add_key → -ENOSPC` | nếu > 0 → tăng `max_concurrent_flows` hoặc giảm TTL |

### 11.1 Quan hệ giữa các counter

Quy luật cân bằng:
```
parsed = flow_cache_hits + (cache miss path)
       ≈ flow_cache_hits + dpi_skipped_by_spi + dpi_cache_misses
```

Trên traffic có coarse L4 groups (Facebook, YouTube, DNS):
- `flow_cache_hits` ≈ 95% (steady state, sau warm-up)
- `dpi_skipped_by_spi` ≈ 4% (TCP/80-443 đến unknown IP, SPI forward không l7_required)
- `dpi_cache_misses` < 1% (chỉ VM-pair với l7_required: true)

→ DPI chạy rất ít, throughput tiến về baseline SPI.

---

## 12. HOT-RELOAD qua SIGUSR1

```
kill -USR1 $(pidof FastAPI)
```

- Signal handler set `reload_flag = 1`.
- Main lcore (idle loop) phát hiện, gọi `MaybeReload`:
  1. Set `reload_barrier = true` → workers busy-wait cuối burst.
  2. `rte_eal_mp_wait_lcore()` — chờ tất cả worker thật sự dừng.
  3. `LoadConfig()` parse YAML mới.
  4. `CompileRuleTable()` + `RuleTable::RebuildInPlace()` (zero heap alloc).
  5. `DpiRuleTableManager::Swap()` atomic publish table mới.
  6. Clear `reload_barrier` → workers tiếp tục burst.
- Hostname cache per-worker **giữ nguyên**; generation check ở bước 8.4 sẽ tự re-Match khi cần.

---

## Phụ lục A: Ví dụ HTTP flow qua VM-pair

```
VM1 (192.168.100.130) → VM2 (192.168.200.180)
─────────────────────────
SYN      (src=54321, dst=80)
   ↓ RX port 0
   ↓ Parse → TCP, dst=80
   ↓ Flow cache lookup → MISS (chưa từng thấy)
   ↓ SPI Match: fg_l34_http_vm_pair precedence=100, l7_required=true ✓
   ↓ SPI-Gates-DPI Decision: (C) matched Forward + l7_required=true → RUN DPI
   ↓ ExtractHttpHost: METHOD="GET ", Host="example.com"
   ↓ Hostname cache lookup → MISS
   ↓ DpiRuleTable::Match("example.com") → no specific match → catch-all "*" → fg_l7_http_default (priority 900)
   ↓ Insert flow cache: action=forward, label=http_default
   ↓ Dispatch L3: 192.168.200.180 → port 1
   ↓ Rewrite MAC, TTL--, IP+TCP cksum recompute
   ↓ TX port 1 → VM2

SYN-ACK  (src=80, dst=54321)      ← response direction
   ↓ RX port 1
   ↓ Parse → TCP, src=80
   ↓ MakeCanonical(...) → SAME key as SYN
   ↓ Flow cache lookup → HIT (req-side cached) ✓
   ↓ forward (no SPI Match, no DPI) → port 0
   ↓ TX port 0 → VM1

HTTP GET (src=54321, dst=80)
   ↓ Flow cache lookup → HIT (same key) → forward

HTTP 200 (src=80, dst=54321)     ← response
   ↓ Flow cache lookup → HIT → forward

ACK     (src=54321, dst=80)
   ↓ Flow cache lookup → HIT → forward
```

**Tổng DPI work cho 1 HTTP connection = 1 lần** (chỉ trên gói request đầu tiên).

---

## Phụ lục B: Ví dụ Facebook flow (không qua DPI)

```
VM1 → Facebook IP (31.13.64.0/18)
─────────────────────────
SYN  (dst=443)
   ↓ RX
   ↓ Parse → TCP
   ↓ Flow cache lookup → MISS
   ↓ SPI Match: fg_l34_facebook precedence=110, l7_required=false ✓
   ↓ SPI-Gates-DPI Decision: (C) matched Forward + !l7_required → SKIP DPI
   ↓++counters.dpi_skipped_by_spi
   ↓ Insert flow cache: action=forward, label=facebook
   ↓ Dispatch → port ra
   ↓ TX

SYN-ACK (src=443)
   ↓ Flow cache lookup → HIT → forward (canonical key)
```

**DPI work = 0**. Flow chỉ chạm SPI 1 lần (cache miss) + 1 lần insert cache.

---

## Phụ lục C: Cấu hình mẫu (rút gọn từ CSV của mentor)

### SPI (lấy từ `docs/spi rules.csv`)

```yaml
spi:
  filter_groups:
  # Specific IP groups — match đầu tiên, l7_required: false → skip DPI
  - name: fg_l34_facebook
    precedence: 100
    action: forward
    # l7_required: false  (mặc định)
    filters:
    - {destination_ip_address: 31.13.64.0/18, protocol: tcp, label: facebook_1}
    - {destination_ip_address: 66.220.144.0/20, protocol: tcp, label: facebook_2}
    - {destination_ip_address: 69.63.176.0/20, protocol: tcp, label: facebook_3}
    - {destination_ip_address: 157.240.0.0/16, protocol: tcp, label: facebook_4}
    - {destination_ip_address: 69.220.144.5, protocol: tcp, label: facebook_5}

  - name: fg_l34_youtube
    precedence: 101
    action: forward
    filters:
    - {destination_ip_address: 142.250.0.0/15, destination_port: 443, protocol: tcp, label: youtube_1}
    - {destination_ip_address: 172.217.0.0/16, destination_port: 443, protocol: tcp, label: youtube_2}
    - {destination_ip_address: 216.58.192.0/19, destination_port: 443, protocol: tcp, label: youtube_3}
    - {destination_ip_address: 74.125.0.1, destination_port: 443, protocol: tcp, label: youtube_4}

  # Generic port-80/443 catch-alls — match traffic không rơi vào IP-specific ở trên
  # l7_required: true → vẫn chạy DPI để xác định app qua SNI/Host
  - name: fg_l34_http_sdf1003
    precedence: 102
    action: forward
    l7_required: true
    filters:
    - {destination_port: 80, protocol: tcp, label: http_all}

  - name: fg_l34_https_sdf1004
    precedence: 103
    action: forward
    l7_required: true
    filters:
    - {destination_port: 443, protocol: tcp, label: https_all}

  # DNS — không cần DPI
  - name: fg_l34_dns_sdf1005
    precedence: 104
    action: forward
    filters:
    - {destination_port: 53, protocol: udp, label: dns_udp}
    - {destination_port: 53, protocol: tcp, label: dns_tcp}

  # UDP drop
  - name: fg_l34_udp_sdf1006
    precedence: 106
    action: drop
    filters:
    - {destination_port: 9999, protocol: udp, label: udp_drop}
```

### DPI (rút gọn từ `docs/dpi rules.csv`)

```yaml
dpi:
  enabled: true
  filters:
  # Specific app groups — priority thấp (cao hơn về độ ưu tiên)
  - {hostname_pattern: '*.facebook.com', filter_group: fg_l7_facebook, priority: 10, label: facebook}
  - {hostname_pattern: '*.fbcdn.net', filter_group: fg_l7_facebook, priority: 10, label: fbcdn}
  - {hostname_pattern: '*.messenger.com', filter_group: fg_l7_facebook, priority: 10, label: messenger}
  - {hostname_pattern: '*.instagram.com', filter_group: fg_l7_facebook, priority: 10, label: instagram}
  - {hostname_pattern: '*.whatsapp.net', filter_group: fg_l7_facebook, priority: 10, label: whatsapp}
  - {hostname_pattern: '*.youtube.com', filter_group: fg_l7_youtube, priority: 20, label: youtube}
  # ... (xem CSV đầy đủ)
  - {hostname_pattern: '*.google.com', filter_group: fg_l7_google, priority: 30, label: google}
  - {hostname_pattern: '*.tiktok.com', filter_group: fg_l7_tiktok, priority: 40, label: tiktok}
  # ...

  # Catch-all — priority cao (cuối cùng)
  - {hostname_pattern: '*', filter_group: fg_l7_http_default, priority: 900, label: http_default}
  - {hostname_pattern: '*', filter_group: fg_l7_https_default, priority: 999, label: https_default}
```

---

## Phụ lục D: Cấu hình tối ưu (lựa chọn nhẹ — chỉ thay `l7_required`)

So với config hiện tại (đã có sẵn cấu trúc group của mentor), thay đổi **tối thiểu** để đạt hiệu năng tối đa:

```yaml
spi:
  filter_groups:
  # ... giữ nguyên các group từ CSV ...

  # Generic port-80/443 catch-alls cần DPI để phân loại app
  - name: fg_l34_http_sdf1003
    l7_required: true        # ← DÒNG DUY NHẤT CẦN THÊM
  - name: fg_l34_https_sdf1004
    l7_required: true        # ← DÒNG DUY NHẤT CẦN THÊM

  # Coarse IP groups không cần DPI → để mặc định l7_required: false
  - name: fg_l34_facebook
  - name: fg_l34_youtube
  - name: fg_l34_dns_sdf1005
  # ...
```

**Tác động**:
- Facebook / YouTube traffic (hầu hết web traffic thực tế) → SPI forward → skip DPI.
- Traffic đến IP không xác định trên port 80/443 → SPI forward + DPI.
- DNS, drop → không qua DPI.
- Counter `dpi_skipped_by_spi` ≈ tổng flow cache misses của traffic Facebook/YouTube/DNS.

**Không cần** xóa bất kỳ group nào, không cần thay đổi structure, không cần code change.
Chỉ 2 dòng YAML `l7_required: true` là đủ.

---

## Phụ lục E: Lưu ý

- **Firewall host**: DPDK dùng AF_PACKET, Linux kernel vẫn thấy gói. Nếu firewall gửi ICMP unreachable → VM hủy kết nối. Cần iptables rule chặn ICMP từ địa chỉ bridge (xem `instruction.md`).
- **Checksum**: VM gửi có thể bật tx checksum offload → tcpdump hiển thị "cksum incorrect" là bình thường. Kiểm tra thực tế ở đầu nhận sau FastSPI.
- **Routing VM**: VM1 cần route `192.168.200.0/24 via 192.168.100.1`, VM2 cần route `192.168.100.0/24 via 192.168.200.1`.
- **Reload an toàn**: `kill -USR1 $(pidof FastAPI)` — không cần restart, không mất flow cache.