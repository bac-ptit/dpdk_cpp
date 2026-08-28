# 38. DPDK EAL Main Lcore Thread Affinity Inheritance Bottleneck

**Verified Date:** 2026-08-04  
**Sources:**  
- Linux `pthread_create(3)` POSIX specification (inherits parent thread affinity mask `cpuset`).
- DPDK EAL Core Initialization (`rte_eal_init()` sets main thread CPU mask via `pthread_setaffinity_np`).

---

## 1. Problem Root Cause

When DPDK initializes via `rte_eal_init()`, DPDK pins the main process thread to the master lcore (typically CPU 0) using `pthread_setaffinity_np`.

When `CompileRuleTable()` is invoked on the main thread:
1. `std::async(std::launch::async, ...)` creates new POSIX threads to parse and compile ACL rules.
2. By POSIX design, new threads **inherit the exact CPU affinity mask of the parent thread**.
3. Because the parent thread (Main Lcore) is pinned to CPU 0, **all `std::async` compilation worker threads inherit affinity `{0}`**.
4. The Linux OS scheduler is forced to execute all 4 (or 16) worker threads on CPU 0 sequentially/time-shared, resulting in 100% load on 1 CPU core while all other CPU cores remain at 0% utilization.

---

## 2. Solution

Unpin the worker thread's CPU affinity at the start of each `std::async` execution lambda:

```cpp
auto unpin_thread_affinity = [sys_cpus]() noexcept {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  for (std::size_t cpu = 0; cpu < sys_cpus; ++cpu) {
    CPU_SET(cpu, &cpuset);
  }
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
};
```

By unpinning the worker threads to allow execution across all system CPUs (`0..sys_cpus-1`), the Linux kernel scheduler immediately distributes the compilation workload across all 4 (or 16) CPU cores simultaneously.
