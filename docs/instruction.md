# FastSPI DPDK L3 Forwarding Instructions

## Topology

Current test setup:

```text
VM1/Kali                    Host                    VM2/Kali
192.168.100.130/24  <->  virbr1 192.168.100.1
                             FastSPI/DPDK
192.168.200.180/24  <->  virbr2 192.168.200.1
```

DPDK uses two AF_PACKET virtual devices:

```yaml
eal:
  virtual_devices:
  - net_af_packet0,iface=virbr1,qpairs=1
  - net_af_packet1,iface=virbr2,qpairs=1
```

Port mapping:

```text
DPDK port 0 -> virbr1 -> VM1 subnet 192.168.100.0/24
DPDK port 1 -> virbr2 -> VM2 subnet 192.168.200.0/24
```

## Root Causes Found

There were three separate issues during debugging.

1. VM routes were missing.

   VM1 only knows `192.168.100.0/24` by default, so it cannot send traffic to
   `192.168.200.0/24` unless a route via `192.168.100.1` exists. The same is
   true in reverse for VM2.

2. L3 forwarding originally forwarded TCP packets with bad L4 checksum.

   VM2 tcpdump showed:

   ```text
   cksum ... (incorrect -> ...)
   ```

   The SYN reached VM2, but the VM2 kernel dropped it before the packet reached
   the listening socket. This was fixed in:

   ```text
   include/dpdk/spi_pipeline.cpp
   ```

   The L3 path now recomputes TCP/UDP checksum after rewriting MAC addresses
   and decrementing IPv4 TTL.

3. The host firewall sent ICMP unreachable and broke the TCP handshake.

   After the checksum fix, SYN and SYN-ACK were both forwarded correctly, but
   VM1 still sent RST. VM1 tcpdump showed:

   ```text
   192.168.100.1 > 192.168.100.130:
   ICMP 192.168.200.180 tcp port 80 unreachable
   ```

   `192.168.100.1` is the host bridge address. Because `net_af_packet` does not
   take exclusive ownership of the bridge, the Linux host networking stack still
   sees the packets and UFW/libvirt can send ICMP reject packets. VM1 receives
   that ICMP and aborts the TCP connection, then sends RST.

## Required VM1 Configuration

VM1 should have:

```text
IP:  192.168.100.130/24
MAC: 52:54:00:5a:2c:95
GW for VM2 subnet: 192.168.100.1
```

Check:

```bash
ip -br addr
ip route
```

Add the route:

```bash
sudo ip route replace 192.168.200.0/24 via 192.168.100.1 dev eth0
```

Optional, if tcpdump output is confusing because of virtio checksum offload:

```bash
sudo ethtool -K eth0 tx off rx off tso off gso off gro off lro off
```

Test from VM1:

```bash
curl -v http://192.168.200.180
```

Useful tcpdump on VM1:

```bash
sudo tcpdump -vvv -eni eth0 'icmp or (host 192.168.200.180 and tcp port 80)'
```

Expected after everything is correct:

```text
VM1 -> VM2: SYN
VM2 -> VM1: SYN-ACK, checksum correct
VM1 -> VM2: ACK
VM2 -> VM1: HTTP response
```

VM1 should not receive ICMP unreachable from `192.168.100.1`.

## Required VM2 Configuration

VM2 should have:

```text
IP:  192.168.200.180/24
MAC: 52:54:00:fe:7b:5d
GW for VM1 subnet: 192.168.200.1
```

Check:

```bash
ip -br addr
ip route
```

Add the route:

```bash
sudo ip route replace 192.168.100.0/24 via 192.168.200.1 dev eth0
```

Run an HTTP server on port 80:

```bash
sudo python3 -m http.server 80 --bind 0.0.0.0
```

Verify the listener:

```bash
sudo ss -lntp | grep ':80'
```

Optional checksum-offload cleanup:

```bash
sudo ethtool -K eth0 tx off rx off tso off gso off gro off lro off
```

Useful tcpdump on VM2:

```bash
sudo tcpdump -vvv -eni eth0 'host 192.168.100.130 and tcp port 80'
```

Expected after the checksum fix:

```text
192.168.100.130.<ephemeral> > 192.168.200.180.80: Flags [S], cksum ... correct
```

## Required Host Configuration

Host bridge addresses:

```text
virbr1: 192.168.100.1/24
virbr2: 192.168.200.1/24
```

Check:

```bash
ip -br addr show virbr1
ip -br addr show virbr2
ip -br link show virbr1
ip -br link show virbr2
```

Both bridges should be `UP`.

### Stop Host ICMP Rejects

The confirmed runtime blocker was ICMP unreachable from the host bridge IP.
For the current test, this rule fixed the TCP reset problem:

```bash
sudo iptables -I OUTPUT 1 -p icmp --icmp-type destination-unreachable -s 192.168.100.1 -d 192.168.100.130 -j DROP
sudo iptables -I OUTPUT 1 -p icmp --icmp-type destination-unreachable -s 192.168.200.1 -d 192.168.200.180 -j DROP
```

These rules are temporary and will usually disappear after reboot. For a stable
setup, make the equivalent rule persistent in UFW/nftables, or configure the
host firewall so it does not reject this inter-VM traffic while FastSPI is the
forwarder.

If testing only and you want to confirm the firewall is the issue:

```bash
sudo ufw disable
```

Re-enable it after testing if needed:

```bash
sudo ufw enable
```

### DPDK Config Requirements

`config.yaml` should keep L3 enabled:

```yaml
l3_forward:
  enabled: true
  lookup_method: lpm
  ipv4_routes:
  - destination_ip_address: 192.168.100.0
    prefix_length: 24
    output_port: 0
  - destination_ip_address: 192.168.200.0
    prefix_length: 24
    output_port: 1
  ethernet_destinations:
  - port_id: 0
    mac_address: 52:54:00:5a:2c:95
  - port_id: 1
    mac_address: 52:54:00:fe:7b:5d
```

Important:

- `ethernet_destinations` must use the VM MAC addresses, not the host bridge
  MAC addresses.
- `output_port: 0` means traffic goes out `virbr1`.
- `output_port: 1` means traffic goes out `virbr2`.
- `app.mac_updating` does not control this L3 path when
  `l3_forward.enabled: true`.

SPI rules should allow both directions:

```yaml
spi:
  drop_unmatched: true
  rules:
  - source_ip_address: 192.168.100.130
    destination_ip_address: 192.168.200.180
    destination_port: 80
    label: HTTP_REQUEST
    protocol: tcp
  - source_ip_address: 192.168.200.180
    destination_ip_address: 192.168.100.130
    source_port: 80
    label: HTTP_RESPONSE
    protocol: tcp
```

If `drop_unmatched: true`, any packet that does not match one of these rules is
dropped by FastSPI.

### Build And Run

Build from the host repo:

```bash
pixi run build
```

Run FastSPI/DPDK:

```bash
pixi run run
```

The runtime config is copied into:

```text
cmake-build-debug/config.yaml
```

So run `pixi run build` after changing `config.yaml`.

## End-to-End Test Procedure

1. On VM2, start the HTTP server:

   ```bash
   sudo python3 -m http.server 80 --bind 0.0.0.0
   ```

2. On host, start FastSPI:

   ```bash
   pixi run run
   ```

3. On VM1, run:

   ```bash
   curl -v http://192.168.200.180
   ```

4. If it fails, capture on VM1:

   ```bash
   sudo tcpdump -vvv -eni eth0 'icmp or (host 192.168.200.180 and tcp port 80)'
   ```

5. If VM1 sees ICMP from `192.168.100.1`, the host firewall is still rejecting
   the flow. Fix host firewall/ICMP rules first.

6. If VM2 sees SYN with `cksum incorrect`, rebuild and restart FastSPI so the
   L3 checksum fix is active:

   ```bash
   pixi run build
   pixi run run
   ```

## Notes About tcpdump Checksum Output

On the sending VM, tcpdump may show:

```text
cksum ... incorrect
```

This can be normal when TX checksum offload is enabled. The packet may be
fixed later by the virtual NIC path. The more reliable check is the receiving
side after FastSPI forwards the packet.

For this setup:

- On VM2, SYN from VM1 must be `cksum correct`.
- On VM1, SYN-ACK from VM2 must be `cksum correct`.
- Any ICMP unreachable from `192.168.100.1` or `192.168.200.1` is a host
  firewall/routing problem, not an L3 checksum problem.
