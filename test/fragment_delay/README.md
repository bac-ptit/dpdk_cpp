# Delayed IPv4 fragment test

This fixture sends one IPv4/TCP fragment immediately and the matching final
fragment three seconds later. The delay is produced by the sender's wall-clock
sleep; PCAP timestamps alone are not replay delays for the DPDK net_pcap PMD.

Generate or regenerate the PCAP files from the repository root:

```bash
.pixi/envs/default/bin/python script/gen_delayed_fragments_pcap.py
```

Create a temporary veth pair for the AF_PACKET PMD:

```bash
sudo ip link add frag_sender type veth peer name frag_dpdk
sudo ip link set frag_sender up
sudo ip link set frag_dpdk up
```

Build, then start FastAPI from this directory so it reads this `config.yaml`:

```bash
cmake --build --preset pixi-debug
cd test/fragment_delay
sudo ../../cmake-build-debug/FastAPI
```

In another terminal, send the two fragments with a real three-second delay:

```bash
sudo .pixi/envs/default/bin/python script/send_delayed_fragments.py \
  --interface frag_sender --delay-sec 3
```

The first fragment remains in the worker's DPDK fragment table only until
`spi.fragment_timeout_sec` elapses. The current test config deliberately sets
this to `2`, while the sender waits `3` seconds; therefore the expected result
is that the incomplete packet is discarded and `matched` stays `0`. Set the
timeout to at least `4` to verify successful reassembly (`matched` changes
from `0` to `1` after the second fragment). The test config uses queue mode
and one worker. Because this fixture forwards back through the same AF_PACKET port,
the Linux capture path may also report outgoing copies as extra RX/malformed
packets; they do not represent additional reassembly matches.

Inspect the combined capture:

```bash
tshark -r test/fragment_delay/delayed_fragments_3s.pcap \
  -o ip.defragment:TRUE \
  -T fields -e frame.time_relative -e ip.id -e ip.flags.mf \
  -e ip.frag_offset -e tcp.srcport -e tcp.dstport
```

Generate the equivalent direct-Fragment-Header IPv6 fixture:

```bash
.pixi/envs/default/bin/python script/gen_delayed_ipv6_fragments_pcap.py
```

It writes `first_ipv6_fragment.pcap` and `second_ipv6_fragment.pcap`; use the
same sender with explicit paths. The supplied SPI rule is IPv4-only, so this
fixture verifies parsing/reassembly (`parsed` increases) but intentionally
does not increment `matched`.

Cleanup:

```bash
sudo ip link delete frag_sender
```
