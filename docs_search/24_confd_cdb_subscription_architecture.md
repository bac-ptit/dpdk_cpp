# ConfD CDB Subscription Architecture & Integration

- **Date Verified**: 2026-08-01
- **Component**: `confd/fastapi_confd.c`, `confd/fastapi.yang`, `include/dpdk/app_signal.hpp`

## 1. ConfD CDB Subscription Overview

ConfD provides the Configuration Database (CDB) Subscription API (`cdb_subscribe`, `cdb_read_subscription_socket`, `confd_fd_loop`). When a NETCONF/CLI/RESTCONF client commits a change matching a registered YANG path, ConfD triggers the registered CDB subscription callback.

In this DPDK project, dynamic configuration reload using ConfD subscription is fully implemented via a two-tier architecture:

```
[NETCONF / YANG Client]
         │
         ▼ (commit via NETCONF / CLI)
     [ConfD Daemon]
         │
         ▼ (CDB Notification trigger)
 [fastapi_confd] (CDB Subscriber Daemon using cdb_subscribe("/fastapi:fastapi"))
         │
         ├── 1. Reads changed CDB nodes (cdb_get_string, cdb_get_uint32)
         ├── 2. Writes updated config.yaml
         └── 3. Sends SIGUSR1 signal (kill -USR1 <FastAPI_PID>)
                 │
                 ▼
          [FastAPI (DPDK App)]
                 │
                 ├── Signal handler sets atomic reload flag (AppSignal::ReloadFlag())
                 ├── Main lcore detects flag in idle loop
                 ├── LoadConfig() parses updated YAML & compiles new RuleTable
                 └── RuleTableManager::Swap() atomically swaps active rule table (Zero Lock, Zero Downtime)
```

## 2. Verification of cdb_subscribe Usage

In `confd/fastapi_confd.c`:
- **API Call**: `cdb_subscribe(sock, 30, &cdb_sub_callback, NULL, 1, "/fastapi:fastapi")` (Line 259)
- **Event Loop**: `confd_fd_loop(sock)` (Line 271)
- **Callback Execution**: `cdb_sub_callback()` (Line 182) invoked on commit.

## 3. Options for Mentor Presentation / Architecture

### Option A: Out-of-Process CDB Subscriber Daemon (Current Architecture)
- **Advantages**: Keeps DPDK data plane completely decoupled from ConfD C client library (`libconfd.so`), avoiding any potential blocking or memory overhead inside DPDK lcore threads.
- **Signal**: Communicates via standard Unix signal `SIGUSR1`.

### Option B: In-Process Control Thread Subscriber (Alternative Integration)
- **Implementation**: Launch a dedicated pthread inside `FastAPI` main initialization, calling `cdb_subscribe` and running `confd_fd_loop` directly in that control thread.
- **Trigger**: Upon notification, the internal thread sets `AppSignal::SetReloadFlag()` directly, omitting `fastapi_confd` and `SIGUSR1`.
