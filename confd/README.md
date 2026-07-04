# ConfD Integration for FastAPI DPDK

NETCONF-based configuration management for the DPDK SPI/DPI packet processor.

## Architecture

```
OSS/NMS → NETCONF → ConfD → CDB callback → Write YAML → kill -USR1
                                                          ↓
                                    Main lcore detects flag → LoadConfig() → CompileRuleTable() → Swap()
```

## Files

| File | Description |
|------|-------------|
| `fastapi.yang` | YANG model mirroring `DpdkConfig` structure |
| `fastapi_confd.c` | CDB callback daemon — reads CDB, writes YAML, signals FastAPI |
| `Makefile` | Build script for the callback daemon |

## Prerequisites

1. **ConfD developer kit** — Download from Tail-f/ConfD (requires license)
2. **pkg-config** — for finding ConfD headers/libraries

## Build

```bash
# Set ConfD installation path
export CONFD_DIR=/opt/confd

# Build the callback daemon
make

# Install to ConfD bin directory
make install
```

## Configuration

### 1. Install YANG model

```bash
# Copy YANG model to ConfD init directory
cp fastapi.yang $CONFD_DIR/etc/confd/init/

# Load into ConfD
confd_cli -C -u admin -P admin <<EOF
load-config fastapi.yang
commit
EOF
```

### 2. Start the callback daemon

```bash
# Start with config path and optional FastAPI PID
./fastapi_confd --config /path/to/config.yaml --pid $(pidof FastAPI)
```

### 3. Push configuration via NETCONF

```bash
# From OSS/NMS, edit the configuration tree
confd_cli -C -u admin -P admin <<EOF
configure
set fastapi spi filter-groups fg_dns precedence 104
set fastapi spi filter-groups fg_dns action drop
commit
EOF
```

## How it Works

1. **ConfD CDB** stores the running configuration as a YANG-modeled tree
2. When configuration is committed, the CDB callback (`fastapi_confd`) is triggered
3. The callback reads all CDB values and writes them to `config.yaml`
4. It sends `SIGUSR1` to the FastAPI process
5. FastAPI detects the signal, reloads the config, recompiles rules, and swaps atomically

## Notes

- ConfD does NOT touch the hot path — only the control plane
- The callback daemon runs as a separate process
- SPI filter groups and DPI filters are complex nested structures; the current implementation handles the top-level config and signals reload. For full nested config sync, extend `write_config_yaml()` with `cdb_get_num_instances()` iteration
- The existing `SIGUSR1` reload mechanism in FastAPI handles the actual hot-swap
