# Luồng Hoạt Động FastSPI DPDK

Kiến trúc tổng thể:

```
[VM1] <--> [virbr1] <--> [FastSPI/DPDK] <--> [virbr2] <--> [VM2]
```

FastSPI là ứng dụng chạy trên host, dùng DPDK để bắt và chuyển tiếp gói tin giữa hai máy ảo qua bridge ảo virbr1, virbr2.

Luồng hoạt động gồm 8 bước chính:

```
START -> INIT DPDK -> RECEIVE PACKET -> PARSE HEADER -> RULE MATCH -> DISPATCH -> WORKER PROCESS -> STATISTICS
```

---

## 1. START

- Đọc file cấu hình `config.yaml`.
- Lấy thông tin: core nào, port nào, mempool bao nhiêu, luật SPI ra sao, định tuyến L3 thế nào.
- Biên dịch luật SPI từ dạng text (IP dạng chuỗi, port, protocol) sang dạng nhị phân.
- Các trường không chỉ định trong luật → wildcard (tự động match tất cả).

---

## 2. INIT DPDK

- **Khởi tạo EAL**: nạp tham số core list, memory channels, virtual devices (`net_af_packet0` gắn virbr1, `net_af_packet1` gắn virbr2).
- **Tạo mempool**: cấp phát trước vùng nhớ cho các packet buffer (mbuf).
- **Thiết lập port**: config queue, start port, bật promiscuous mode.
- **Kiểm tra link**: poll đến khi port sẵn sàng.

Sau bước này, DPDK đã sẵn sàng nhận/gửi gói tin.

---

## 3. RECEIVE PACKET

- Worker đọc một burst gói tin từ mỗi port DPDK (cơ chế poll-mode).
- Gói tin trả về dưới dạng mbuf — vùng nhớ chứa raw packet data.
- Prefetch dữ liệu để tối ưu cache CPU.
- Có thể chạy single worker (1 core) hoặc multi worker (nhiều core).

---

## 4. PARSE HEADER

Với mỗi gói tin, phân tích các lớp header:

- **Ethernet**: đọc EtherType, chỉ chấp nhận IPv4 (0x0800).
- **IPv4**: đọc IP header, kiểm tra độ dài header hợp lệ.
- **Layer 4**: đọc TCP hoặc UDP dựa trên trường `next_proto_id`.
- Trích xuất: protocol, source IP, destination IP, source port, destination port.

Nếu gói không phải IPv4 hoặc không phải TCP/UDP → bỏ qua (không match SPI).

---

## 5. RULE MATCH (SPI Matching)

- Duyệt tuần tự danh sách luật SPI theo thứ tự ưu tiên (first-match-wins).
- Mỗi luật gồm: protocol, source IP, dest IP, source port, dest port, label.
- Wildcard: nếu trường không được chỉ định → match mọi giá trị.
- Nếu match → trả về label (ví dụ: `HTTP_REQUEST`).
- Nếu không match → drop gói (khi `drop_unmatched: true`).

---

## 6. DISPATCH (Xác định port đầu ra)

- **L3 mode**: tra bảng LPM (Longest Prefix Match) dựa trên destination IP.
  - `192.168.100.0/24` → port 0 (virbr1)
  - `192.168.200.0/24` → port 1 (virbr2)
  - Không route hoặc route về port cũ → drop.
- **L2 mode**: port ra = port vào + 1 (ghép cặp 0↔1, 2↔3...).

Quyết định forwarding hay drop tại bước này.

---

## 7. WORKER PROCESS (Xử lý và gửi gói)

Worker thực hiện các thao tác trên gói tin trước khi gửi đi:

### 7.1. Ghi đè MAC

- **Source MAC** = MAC thật của port đầu ra.
- **Destination MAC (L3)** = MAC của VM đích (tra bảng `ethernet_destinations`).
  - Port 0 → MAC VM1 (`52:54:00:5a:2c:95`)
  - Port 1 → MAC VM2 (`52:54:00:fe:7b:5d`)
- **Destination MAC (L2)** = địa chỉ dạng `02:...:<port_id>` (không cần ARP).

### 7.2. Giảm TTL và tính lại Checksum

- Giảm TTL đi 1. Nếu TTL = 0 → drop.
- Tính lại IP header checksum.
- Tính lại TCP/UDP checksum.

Bước này rất quan trọng: nếu không tính lại checksum, máy nhận sẽ thấy "cksum incorrect" và drop gói ở kernel.

### 7.3. Gửi gói (TX)

- Xếp gói vào TX buffer của port đầu ra.
- Cuối vòng lặp, flush tất cả TX buffer bằng burst gửi.
- Các gói gửi không thành công → free.

---

## 8. STATISTICS

- Worker cập nhật bộ đếm atomic cho mỗi burst.
- Các chỉ số: số gói RX, TX, parse thành công, match, drop, unknown, malformed.
- Đếm riêng cho từng luật SPI.
- In thống kê định kỳ.

---

## Phụ lục: Ví dụ luồng HTTP

```
VM1 (192.168.100.130)                  VM2 (192.168.200.180)
        |                                    |
        |--- SYN --> port 80                  |
        |    (FastSPI RX port 0)              |
        |    Parse: TCP, dst_port 80          |
        |    Match: HTTP_REQUEST              |
        |    LPM: 192.168.200.0/24 -> port 1  |
        |    Rewrite MAC, TTL--, checksum     |
        |    TX port 1 ---------------------->|
        |                                    |
        |<-- SYN-ACK -------------------------|
        |    (FastSPI RX port 1)              |
        |    Parse: TCP, src_port 80          |
        |    Match: HTTP_RESPONSE             |
        |    LPM: 192.168.100.0/24 -> port 0  |
        |    Rewrite MAC, TTL--, checksum     |
        |<-- TX port 0 -----------------------|
        |                                    |
        |--- ACK -->                          |
        |--- HTTP Request -->                 |
        |<-- HTTP Response -------------------|
```

## Phụ lục: Cấu hình

### Port mapping

| DPDK Port | Bridge | Subnet VM       |
|-----------|--------|-----------------|
| 0         | virbr1 | 192.168.100.0/24 |
| 1         | virbr2 | 192.168.200.0/24 |

### L3 Routing Table

| Destination   | Prefix | Port ra |
|---------------|--------|---------|
| 192.168.100.0 | /24    | 0       |
| 192.168.200.0 | /24    | 1       |

### SPI Rules

| Label         | Protocol | Source IP       | Dest IP         | Src Port | Dst Port |
|---------------|----------|-----------------|-----------------|----------|----------|
| HTTP_REQUEST  | TCP      | 192.168.100.130 | 192.168.200.180 | *        | 80       |
| HTTP_RESPONSE | TCP      | 192.168.200.180 | 192.168.100.130 | 80       | *        |

## Phụ lục: Lưu ý

- **Firewall host**: DPDK dùng AF_PACKET nên Linux kernel vẫn thấy gói tin. Nếu firewall gửi ICMP unreachable → VM hủy kết nối. Cần iptables rule chặn ICMP từ địa chỉ bridge.
- **Checksum**: VM gửi có thể bật tx checksum offload → tcpdump hiển thị "cksum incorrect" là bình thường. Kiểm tra thực tế ở đầu nhận sau FastSPI.
- **Routing VM**: VM1 cần route `192.168.200.0/24 via 192.168.100.1`, VM2 cần route `192.168.100.0/24 via 192.168.200.1`.
