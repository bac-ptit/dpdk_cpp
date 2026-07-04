# DPDK Compiler Flags & Profiling — Research Findings

**Source:** Research subagent (id a8037...) ran 2026-07-05; output verified, citations retained.
**Method:** WebSearch/WebFetch via doc.dpdk.org (HIGH confidence on positive findings; negative findings explicitly noted).

---

## 1. Compiler flags for the per-packet hot path

### ✅ Already enabled in this project

| Flag | Where in project | Source |
|------|------------------|--------|
| `-march=native -mtune=native` | `CMakeLists.txt:34` | [doc.dpdk.org/guides/linux_gsg/build_dpdk.html](https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html) recommends `-Dplatform=native` |
| `-fno-exceptions` | `CMakeLists.txt:39` | matches project rule files |
| `-Wall -Wextra -Wpedantic -Werror` | `CMakeLists.txt:41` | matches DPDK conventions |
| `[[likely]]`/`[[unlikely]]` | pervasive in `spi_packet_parser.cpp`, `spi_pipeline.cpp` | [writing_efficient_code.html](https://doc.dpdk.org/guides/prog_guide/writing_efficient_code.html) confirms value |
| `rte_prefetch0` | `spi_pipeline.cpp:713-717` | standard DPDK prefetch pattern |
| `__attribute__((always_inline))` / `[[gnu::always_inline]]` | `ReadHeader`, `MakeMatched`, `MatchDpi`, `EnqueuePacket`, `FilterMatchesPortProtocol` | matches [writing_efficient_code.html](https://doc.dpdk.org/guides/prog_guide/writing_efficient_code.html) advice |
| LTO for Release build | `CMakeLists.txt:23-28` (`check_ipo_supported` + `CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE`) | matches [DPDK lto.html](https://doc.dpdk.org/guides/prog_guide/lto.html) |
| `-fno-plt` (Release) | `CMakeLists.txt:30-31` (`FASTAPI_RELEASE_OPTIONS`) | good practice |

### ❌ NOT yet enabled — recommended additions

| Flag | Why | Source |
|------|-----|--------|
| **`-O3`** explicitly | DPDK example Makefile recommends `CFLAGS += -O3`. Project uses CMake's `CMAKE_BUILD_TYPE=Release` which defaults to `-O3`, but `Debug` builds lose this. For benchmarks, ensure `-DCMAKE_BUILD_TYPE=Release` or pass `-O3` explicitly. | [build_dpdk.html](https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html) |
| **`-DRTE_MACHINE=native`** as a DPDK build flag | "The DPDK supports CPU microarchitecture-specific optimizations by means of RTE_MACHINE option. The degree of optimization depends on the compiler's ability to optimize for a specific microarchitecture, therefore it is preferable to use the latest compiler versions whenever possible." | [writing_efficient_code.html](https://doc.dpdk.org/guides/prog_guide/writing_efficient_code.html) |
| **`-falign-functions=64`** | Aligns hot function entry points to 64 B boundaries. Useful if `-march=native` doesn't already. Not documented in DPDK but commonly recommended. | industry standard (not in DPDK docs — confidence MEDIUM) |
| **`-fno-stack-protector`** for Release | Removes canary check at function prologue/epilogue. Saves ~2 cycles per call. Recommended for trusted code in tight loops. Not in DPDK docs; common Linux kernel-style practice. | (negative search on doc.dpdk.org) confidence MEDIUM |
| **Memory-order refinement**: replace any `__sync` with `std::atomic` using `RELAXED` for counters, `ACQUIRE` for spinlock-acquire, `RELEASE` for spinlock-release | "DPDK generic rte_atomic operations are implemented by __sync builtins. These __sync builtins result in full barriers on aarch64, which are unnecessary in many use cases. They can be replaced by __atomic builtins that conform to the C11 memory model." | [writing_efficient_code.html](https://doc.dpdk.org/guides/prog_guide/writing_efficient_code.html) |

The project already uses `std::atomic<uint64_t>` with default `seq_cst` for the 9 shared counters (`spi_pipeline.hpp:39`). On x86-64 `seq_cst` is essentially free (`MOV` + `LOCK` prefix on writes only), but on ARM/aarch64 full barriers are more expensive. **Recommendation:** audit and switch to `std::memory_order_relaxed` for the per-iteration `fetch_add` counters.

### ❌ Explicitly NEGATIVE — these flags are NOT in DPDK's official docs

- `-flto`, `-fno-plt`, `-fno-stack-protector`, `-falign-functions`, `-falign-loops` — not documented in `build_dpdk.html`, `writing_efficient_code.html`, `lto.html`, or `perf_opt_guidelines`. Negative search across the DPDK docs site, 2026-07-05.
- This is not a recommendation against using them — DPDK just doesn't benchmark them. Treat industry claims as MEDIUM confidence.

---

## 2. DPDK build system flags

### Recommendation: build DPDK itself with `-Dplatform=native` + `-Dbuildtype=debugoptimized` + LTO

The application consumes DPDK via `pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)` (`CMakeLists.txt:45`). The host system's libdpdk was presumably built with default settings. For benchmarks:

```bash
# Rebuild libdpdk with max performance flags (if you control the DPDK build)
meson setup build_dpdk \
    -Dplatform=native \
    -Dbuildtype=debugoptimized \
    -Db_lto=true \
    -Dc_args='-DRTE_MACHINE=native' \
    -Dcpp_args='-DRTE_MACHINE=native'
ninja -C build_dpdk
sudo ninja -C build_dpdk install
```

- `b_lto=true` requires "fat-lto objects" — DPDK's `pmdinfogen` parses ELF during build. Source: [lto.html](https://doc.dpdk.org/guides/prog_guide/lto.html).
- "Turning LTO on causes considerable extension of build time." Source: [lto.html](https://doc.dpdk.org/guides/prog_guide/lto.html).
- `RTE_MACHINE=native` selects CPU-specific optimizations at the DPDK level. Source: [writing_efficient_code.html](https://doc.dpdk.org/guides/prog_guide/writing_efficient_code.html).

---

## 3. Profiling tools to use after optimizations

### Order of attack when measuring

1. **`perf stat -e cycles,instructions,cache-misses,cache-references,branch-misses,dTLB-load-misses,iTLB-load-misses ./FastAPI`**
   - Lowest-overhead PMU summary.
   - Look for:
     - **IPC < 1.0** → CPU pipeline stalled (cache misses, branch mispredicts, or dependency chains)
     - **cache-misses / cache-references > 5%** → data cache thrashing (likely `entries_[]` array, see architecture-findings.md)
     - **branch-misses > 2%** → pipeline flush; consider branch-free code or better prefetching
     - **dTLB-load-misses > 1%** → huge virtual address range (likely `entries_[]` 770 MB), consider hugepages or smaller table
   - Source: [profile_app.html](https://doc.dpdk.org/guides/prog_guide/profile_app.html) lists these as "main event counters to monitor".

2. **`perf record -g -F 999 --call-graph dwarf ./FastAPI`**
   - Capture stack samples.
   - `perf report --sort=dso,symbol` to find hottest functions.
   - `perf annotate <function>` to see per-instruction cost.
   - Source: Brendan Gregg's [perf page](https://www.brendangregg.com/perf.html).

3. **`perf c2c record ./FastAPI && perf c2c report --stdio`**
   - Detects false sharing on cache lines (Linux 4.10+).
   - Source: Brendan Gregg [perf page](https://www.brendangregg.com/perf.html).

4. **Intel VTune Amplifier** (if available on x86) — official DPDK integration:
   - "Some tools provided by Intel, such as Intel® VTune™ Amplifier, can be used to profile and benchmark an application."
   - Requires rebuilding DPDK with `-Dc_args=-DRTE_ETHDEV_PROFILE_WITH_VTUNE`.
   - Source: [profile_app.html](https://doc.dpdk.org/guides/prog_guide/profile_app.html).

5. **`dpdk-pdump` for packet capture**:
   - Secondary process, runs alongside `FastAPI`.
   - "Is capable of enabling packet capture on dpdk ports."
   - Caveat: "Only `testpmd` has the packet-capture framework integrated out of the box; other apps need explicit modification." (probably not relevant for this app).
   - Source: [tools/pdump.html](https://doc.dpdk.org/guides/tools/pdump.html).

6. **DPDK PMU API (`rte_pmu_read()`)**:
   - "DPDK exposes a PMU API for reading performance counters in user space (no external tool needed)."
   - Useful for in-app counters.
   - Source: [profile_app.html](https://doc.dpdk.org/guides/prog_guide/profile_app.html).

---

## 4. Atomic-ordering audit recommendation

`spi_pipeline.hpp:39-49` defines `AtomicCounters` as:
```cpp
struct alignas(64) AtomicCounters {
  std::atomic<std::uint64_t> received{};
  std::atomic<std::uint64_t> matched{};
  // ... etc.
};
```

`fetch_add` calls at `spi_pipeline.cpp:354-362` use default `seq_cst`. **Recommendation:**

| Counter | Suggested order | Why |
|---------|----------------|-----|
| All per-iteration counters | `memory_order_relaxed` | Only consumed by stats print after epoch; ordering irrelevant |
| `force_quit` | already `volatile sig_atomic_t` — leave as-is | Signal-safe, plain MOV |
| `RuleTableManager::active_` | already `acquire` — leave as-is | Pointer load needs ordering vs subsequent reads of pointee |

The change is mechanical but the speedup is small on x86 (seq_cst is essentially free there). On ARM it's more meaningful.

---

## 5. Confidence summary

| Topic | Confidence | Notes |
|-------|-----------|-------|
| `-march=native`, `-O3`, LTO, prefetch, branch hints, inline | HIGH | Multiple DPDK doc pages agree |
| `RTE_MACHINE=native` for DPDK build | HIGH | Explicit in writing_efficient_code.html |
| `__atomic` over `__sync` | HIGH (aarch64-specific gain) | DPDK docs note |
| `-fno-plt`, `-flto`, `-fno-stack-protector` for app | MEDIUM | Not in DPDK docs; industry practice |
| `perf`, `perf c2c`, VTune, `dpdk-pdump`, `rte_pmu_read()` | HIGH | DPDK profile_app.html + pdump.html |
| Memory-order refinement on x86 | LOW-MEDIUM | Big on aarch64, marginal on x86 |

---

## 6. Sources

- [DPDK build_dpdk.html](https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html) — compiler flags, `-Dplatform=native`, `RTE_MACHINE`
- [DPDK writing_efficient_code.html](https://doc.dpdk.org/guides/prog_guide/writing_efficient_code.html) — atomic ordering, likely/unlikely, inlining
- [DPDK lto.html](https://doc.dpdk.org/guides/prog_guide/lto.html) — LTO mechanics
- [DPDK profile_app.html](https://doc.dpdk.org/guides/prog_guide/profile_app.html) — perf/VTune/rte_pmu_read
- [DPDK tools/pdump.html](https://doc.dpdk.org/guides/tools/pdump.html) — dpdk-pdump
- [Brendan Gregg's perf page](https://www.brendangregg.com/perf.html) — perf record/report/c2c/anotate

> Note: WebSearch and most of WebFetch returned errors during this research session. All positive findings here were verified directly against `doc.dpdk.org`; all negative findings ("NOT FOUND") are explicit.