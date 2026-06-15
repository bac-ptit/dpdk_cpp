SPIFast: Hệ thống kiểm tra gói tin nông hiệu năng cao (SPI) sử dụng DPDK
1. Bối cảnh
   Trong các hệ thống mạng hiện đại như firewall, router, load balancer, UPF trong 5G hoặc các hệ thống security gateway, việc phân tích nhanh header của gói tin để xác định loại traffic là một chức năng quan trọng.

Shallow Packet Inspection (SPI) là kỹ thuật kiểm tra các trường header của packet ở lớp L2/L3/L4 nhằm phân loại lưu lượng mà không cần phân tích sâu payload.

Với tốc độ mạng ngày càng cao (10G/40G/100G), việc thực hiện SPI yêu cầu các cơ chế xử lý packet hiệu năng cao. DPDK là thư viện packet processing cho phép xử lý packet ở user-space với độ trễ thấp.

Mini Project này mô phỏng cơ chế SPI thực tế bằng cách sử dụng DPDK để phân tích packet header và phân loại packet theo rule.
2. Mục tiêu
   Mini Project hướng tới xây dựng chương trình SPI đơn giản sử dụng DPDK với các mục tiêu:

• Nhận packet bằng DPDK
• Parse Ethernet/IP/TCP/UDP header
• Phân loại packet theo rule kiểm soát source/destination IP, port, protocol
• Phân phối packet tới worker/queue xử lý tương ứng
• In kết quả phân loại và thống kê runtime

Thông qua project, sinh viên hiểu cơ chế packet classification trong hệ thống data-plane thực tế.
3. Giải pháp kỹ thuật
   Các thành phần chính:

• Packet Receiver: nhận packet bằng rte_eth_rx_burst
• Header Parser: parse Ethernet, IPv4, TCP, UDP
• Rule Engine: match packet với rule IP/port/protocol
• Dispatcher: phân phối packet theo worker/queue
• Worker Processor: xử lý packet theo nhóm
• Statistics Collector: thống kê throughput

Ví dụ rule:

TCP src_ip 10.17.50.1 dst_ip 10.17.50.12 dst port 80 -> HTTP
TCP src_ip 10.17.50.2 dst_ip 10.17.50.12 dst port 443 -> HTTPS
UDP src_ip 10.17.50.3 dst_ip 10.17.50.53 dst port 53 -> DNS
UDP src_ip 10.17.50.4 dst_ip 10.17.50.215 dst port 2152 -> GTP-U
4. Quy trình triển khai
   • Khởi tạo DPDK
   • Cấu hình NIC và mempool
   • Nhận packet
   • Parse header
   • Áp dụng rule classification
   • Dispatch packet
   • Worker xử lý
   • In kết quả thống kê

Luồng xử lý:

Start
|
Init DPDK
|
Receive Packet
|
Parse Header
|
Rule Match
|
Dispatch
|
Worker Process
|
Statistics
5. Lợi ích nổi bật
   • Hiểu cách firewall/load balancer phân loại packet
   • Làm quen với DPDK
   • Hiểu packet pipeline tốc độ cao
   • Tiếp cận lập trình networking đa luồng

Tính năng nâng cao:

• Dynamic rule update
• Multi-thread optimization
• Throughput benchmark
• Core affinity
• Packet replay
Ghi chú
Sinh viên sau khi lựa chọn mini project vui lòng liên hệ mentor để được hướng dẫn chi tiết hơn về cách cài đặt DPDK, cấu hình hugepage và tối ưu hiệu năng hệ thống.
