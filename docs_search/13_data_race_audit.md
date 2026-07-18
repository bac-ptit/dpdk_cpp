# 13 — Data-Race Audit (Follow-Up to doc 12)

**Date verified**: 2026-07-17
**DPDK version verified**: 24.11.4
**Scope**: every concurrent-write / concurrent-read pair across all subsystems
**Status**: audit-only. No code modified. Read this after `12_data_race_fix.md`.

This document captures findings produced by a parallel 4-agent audit of the
current working tree on 2026-07-17 (after the v3 atomic-publish protocol
from doc 12 had been applied to the SPI/DPI rule-table managers).

The v3 protocol from doc 12 is **correctly applied** in three places:
- `RuleTableManager::Swap` / `Load` — `include/dpdk/spi/spi_rule_table_manager.hpp:37-68`
- `DpiRuleTableManager::Swap` / `Load` — `include/dpdk/dpi/dpi_rule_table_manager.hpp:33-52`
- `FlowTable::Insert` / `Lookup` / `GetEntry` — `include/dpdk/spi/spi_flow_table.hpp:188-249`

Two of the five races from doc 12 are now fully fixed; the remaining issues
are **new** or **partial fixes** and are listed below, ranked by severity.

## Status of doc 12's 5 known races (refined wording)

| Doc 12 # | Race | Current status | Evidence |
|----------|------|----------------|----------|
| #1 | Missing `MULTI_WRITER_ADD` | ✅ **FIXED** | `spi_flow_table.cpp:53-54` — exact flag `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` only (no `MULTI_WRITER_ADD`, per v3 lesson in doc 12 §10.1). |
| #2 | Torn 24 B `entries_[result] = entry;` | ⚠️ **FIXED for hot payload, PARTIAL overall** | Hot payload: `AtomicFlowCell { atomic<uint64_t> action_and_count }` at `spi_flow_table.hpp:97-105`, release-store in `Insert` at hpp:295, acquire-load in `Lookup` hpp:193 and `GetEntry` hpp:245. Residual: cold-side `last_seen_tsc_` (H2) is still plain `uint64_t`. |
| #3 | `PurgeExpired` clears slot while workers read | ⚠️ **PARTIAL** | Atomic clear at `spi_flow_table.cpp:161-162` prevents torn hot value. Residual: delete/free/reuse + stale positions + iterator races (C1, H3, H6). |
| #4 | Cache-line ping-pong | ⚠️ **FIXED for hot, residual cold** | Hot side: `AtomicFlowCell alignas(64)` at `spi_flow_table.hpp:97-105`, hot/cold arrays sized identically at `spi_flow_table.cpp:76-78`. Residual: cold `last_seen_tsc_` is contiguous `vector<uint64_t>` with 8 TSCs per line (see "Nuance on doc 12 §3.2 fix" below). |
| #5 | Insert "preserve action" reads stale bits | ✅ **FIXED** | `Insert` packs the new action directly at `spi_flow_table.hpp:293-295`; no read-modify-write of the old cell. |

**Spinlock (v3 fix)**: initialized at `spi_flow_table.cpp:60`; lock/unlock
wraps every `Insert` return path at `spi_flow_table.hpp:281-297`; no I/O
held under the lock. Correctly placed for the v3 design.

**Missing lock around `PurgeExpired` is the main remaining defect** —
it is a NEW high race (H3 below) on top of the partial fix for #3.

### Nuance on doc 12 §3.2 fix (Hazard A — cache-line ping-pong)

Doc 12 §3.2 split hot cell from cold TSC into separate arrays. The hot
side is fully fixed: `AtomicFlowCell` is `alignas(64)`, one cell per
cache line. **But the cold side is NOT.** `last_seen_tsc_` is a
contiguous `std::vector<std::uint64_t>`, so 8 TSCs share each 64 B cache
line. Two workers writing to slots that happen to land in the same
line ping-pong that line. With uniform slot distribution, the
probability of any two slots colliding on the same line at 7 workers
is ~7/8 ≈ 87%. The hot/cold split was PARTIAL — fixed for hot-side
false sharing only, NOT for cold-side.

**Fix**: pad each TSC element to a cache line:
`std::vector<alignas(64) std::atomic<std::uint64_t>>` (combines with
H2 fix). 64 B per slot × 1 M slots = 64 MB cold array. Total at 1 M
slots: 64 MB hot + 64 MB cold = 128 MB, up from ~104 MB. Acceptable on
8 GB+ hosts.

**Status**: PARTIAL — fix proposed as part of PR-A.

---

## Critical

### C1. Slot-reuse race in `PurgeExpired` deletes fresh flows

**File**: `include/dpdk/spi/spi_flow_table.cpp:138-162`

`PurgeExpired` calls `rte_hash_del_key(hash, &expired_key)` and
`rte_hash_free_key_with_position(hash, idx)` **before** clearing
`cells_[idx].action_and_count` and `last_seen_tsc_[idx]`. Between the
free and the clear, an unlocked `Insert` from a worker can take the slot,
publish a fresh `FlowEntryView` with a different action, and then the
Purge pass-2 clears the freshly-inserted entry's `action_and_count = 0`
and `last_seen_tsc = 0`.

**Failure scenario**:
1. Worker A flows `5-tuple X` → `rte_hash_add_key` returns slot 42.
2. Main lcore `PurgeExpired` collects X as expired, calls `rte_hash_del_key(X)` → slot 42.
3. Main lcore calls `rte_hash_free_key_with_position(42)` → slot 42 reusable.
4. Worker B flows `5-tuple Y` → `rte_hash_add_key` returns slot 42.
5. Worker B publishes `cells_[42].action_and_count = {action_B, count_B}` (release).
6. Main lcore executes its planned clear: `cells_[42].action_and_count.store(0)`,
   `last_seen_tsc_[42] = 0`.
7. The fresh flow Y is now invisible (count=0), will be reclassified next packet.

**DPDK source confirmation** (DPDK 24.11 `rte_hash.c` + headers):
- `RW_CONCURRENCY_LF` writer path assumes a **single writer** — no
  internal lock. Multi-writer safety comes from `MULTI_WRITER_ADD` or
  `RW_CONCURRENCY`. Our project uses `RW_CONCURRENCY_LF` only (v3
  lesson) and serialises inserts via an external `rte_spinlock_t`.
- `PurgeExpired`'s `rte_hash_del_key` and `rte_hash_free_key_with_position`
  are **outside `insert_lock_`**, so they run concurrently with worker
  `Insert` — that is the writer-conflict path described above.
- The rte_hash API contract for `free_key_with_position` requires
  callers to wait for in-flight readers to quiesce. Our slot-indexed
  `GetEntry` readers **definitely outlive** `lookup` and `lookup_bulk`
  (they walk the result positions later in the burst), so the contract
  is violated any time `Purge` and a worker race.

**Fix**: hold `insert_lock_` across pass-1 + pass-2 in `PurgeExpired`, OR
re-order to **clear cell first, then del_key**, so the cell is empty
before any other writer can observe the slot as free. The second option
is cheaper because `rte_hash_del_key` is the slow step. Pattern:

```cpp
// In PurgeExpired, with insert_lock_ held:
for (const auto& expired_key : expired) {
  const auto result{rte_hash_del_key(hash_, &expired_key)};
  if (result < 0) continue;
  const auto idx = static_cast<std::size_t>(result);
  // 1. Hide from Lookup first (atomic publish of "empty")
  cells_[idx].action_and_count.store(0, std::memory_order_release);
  last_seen_tsc_[idx] = 0;
  // 2. THEN return the slot to the free list (slow)
  rte_hash_free_key_with_position(hash_, idx);
}
```

With the slot invisible from the moment of clear, even if a fresh
`Insert` races the free-key step, the new writer's release-store
will overwrite Purge's 0 with the new action, which is the desired outcome.

**Status**: NOT FIXED.

---

## High

### H1. TOCTOU in `MatchDpi` — multiple `Load()` calls per packet

**File**: `include/dpdk/spi/spi_pipeline.cpp:717-744`

`MatchDpi` calls `context.dpi_rule_manager->Load()` separately at lines 720,
721, 732, 737, and 739. Between any pair, `DpiRuleTableManager::Swap()`
can publish a new table. The cached `cached_idx` from the OLD table may
be `>= new_table.FilterCount()`, causing `ResultAt(cached_idx)` to index
past `filters_.end()` — UB read.

**Fix**: hoist `const auto* dpi_rules{context.dpi_rule_manager->Load()};`
once at the top of `MatchDpi` and reuse for the lifetime of the call.
The v3 release/acquire protocol guarantees that all loads from the same
function observe the same table.

**Status**: NOT FIXED.

### H2. Plain `last_seen_tsc_` array — non-atomic across lcores

**Files**:
- `include/dpdk/spi/spi_flow_table.hpp:201` (worker `Lookup` writes)
- `include/dpdk/spi/spi_flow_table.hpp:249` (worker `GetEntry` reads)
- `include/dpdk/spi/spi_flow_table.hpp:292` (`Insert` writes)
- `include/dpdk/spi/spi_flow_table.cpp:142` (`PurgeExpired` reads)
- `include/dpdk/spi/spi_flow_table.cpp:161` (`PurgeExpired` writes 0)

`std::vector<std::uint64_t>` is not atomic per the C++ memory model.
Worker-hot-path writes race with main-lcore `PurgeExpired` reads/writes,
and worker-worker races are possible on the same slot index.

The author comment at `spi_flow_table.hpp:200` claims "relaxed is sufficient",
implying the original intent was `std::atomic<uint64_t>` with relaxed
ordering. The vector element type was never updated.

**Fix**: `std::vector<std::atomic<std::uint64_t>> last_seen_tsc_;`
with `memory_order_relaxed` for every access. Same fix as H1 in spirit —
the cold-side cell still needs the same atomic publish protocol as the
hot-side cell.

**Status**: NOT FIXED.

### H3. `PurgeExpired` does not acquire `insert_lock_`

**File**: `include/dpdk/spi/spi_flow_table.cpp:114-164`

`FlowTable::Insert` takes `rte_spinlock_t insert_lock_` (`spi_flow_table.hpp:282`),
but `PurgeExpired` never does. The individual `cells_[idx].action_and_count.store(0)`
calls are atomic on their own, but they race the slot-reuse window (see C1).
The `rte_hash_iterate` + `del_key` + `free_key_with_position` sequence is
also not documented to be multi-writer safe; an `Insert` mid-iterate can
cause iterator skips or chain corruption.

**Fix**: hold `insert_lock_` for the entire `PurgeExpired` body, OR split
into collect-only (lock-free iterate) + per-entry delete (lock acquired).
The second option minimises lock-held time.

**Status**: NOT FIXED.

### H4. `LookupBulk` → `GetEntry` window with `Purge`

**Files**:
- `include/dpdk/spi/spi_flow_table.hpp:90-111` (LookupBulk)
- `include/dpdk/spi/spi_flow_table.hpp:239-249` (GetEntry)
- Call-site: `spi_pipeline.cpp:1234-1237` and `spi_pipeline.cpp:1111`
  (`FinalizePackets` after `LookupBulk`)

A worker that calls `LookupBulk` at `spi_pipeline.cpp:1234` receives
position indices. It then walks them via `GetEntry` in `FinalizePackets`
at `spi_pipeline.cpp:1235-1237` and elsewhere. Between the position
lookup and the `GetEntry` call, `PurgeExpired` (called on main lcore
at `spi_pipeline.cpp:1635-1644` and `:1671-1679`, **while workers are
still active** — `StopWorkers` only runs at `:1644`) may delete the
slot and recycle it. `GetEntry` lacks any key/generation validation —
it returns whatever `action_and_count` is at the recycled position,
which may belong to a different flow.

The field comment at `spi_flow_table.hpp:320-322` claims
`last_seen_tsc_` is "read only by PurgeExpired", but `GetEntry` at
`spi_flow_table.hpp:249` reads it on the worker hot path — so the
"cold-side" array is actually read by both workers and PurgeExpired.
This compounds with H2 (the field isn't atomic) and means the
documented contract is violated.

**Fix**: two options:
- (preferred) Have `LookupBulk` write a `FlowEntryView` snapshot per hit
  in a single acquire-load, eliminating the second-load window.
- Have `GetEntry` re-validate by reading the stored key and comparing to
  the caller's `FlowKey`; mismatch → treat as miss. Requires storing
  the key in the cell (cost: 16 B per slot → +16 MB at 1 M slots).

**Status**: NOT FIXED.

### H7. Bulk-path `GetEntry` never refreshes `last_seen_tsc` — active flows purged after TTL

**Files**:
- `include/dpdk/spi/spi_flow_table.hpp:239-249` (GetEntry)
- `include/dpdk/spi/spi_flow_table.hpp:232-236` (comment admitting it)
- `include/dpdk/spi/spi_pipeline.cpp:1234-1237` (production `ProcessPortBurst`
  call site — uses the bulk path)

The hot path in production is `ProcessPortBurst` →
`LookupBulk` (`spi_pipeline.cpp:1234`) → walk positions →
`FinalizePackets` → `GetEntry` (`spi_pipeline.cpp:1235-1237`).
`GetEntry` at `spi_flow_table.hpp:239-249` reads `last_seen_tsc_[idx]`
but never updates it. The comment at `hpp:232-236` explicitly admits
this design choice.

**Consequence**: an active long-running TCP connection that is cached
and hit via the bulk path never has its `last_seen_tsc` refreshed.
After `flow_ttl_sec` (default 300 s) it will be purged as expired,
even though the connection is still active. This is the same bug
that doc 12 §4.2 fixed for the single-path `Lookup` at hpp:188-204
(which does `last_seen_tsc_[idx] = now_tsc` on hit) — but the fix
was not propagated to the bulk path.

**Also**: this contradicts the field comment at
`spi_flow_table.hpp:320-322` that says `last_seen_tsc_` is "read
only by PurgeExpired". In reality it is read on **every bulk cache
hit** (the production hot path). The contract violation compounds
the data race from H2 — the field is touched on the hot path
despite the documentation claiming otherwise.

**Fix**: add a `last_seen_tsc_[idx].store(now_tsc, relaxed)` inside
`GetEntry`, mirroring the touch in `Lookup`. If atomics are
introduced per H2, this becomes an atomic relaxed store. Cost: one
relaxed 8-byte store per bulk cache hit; with the cache-line-aligned
cold array from the H4 nuance, the store does not invalidate any
other slot's line.

**Status**: NOT FIXED. Behavioural regression introduced when the
bulk path was added without updating the TTL-touch logic.

### H6. `PurgeExpired` misuses `rte_hash_iterate` return value — compares wrong TSC

**File**: `include/dpdk/spi/spi_flow_table.cpp:138-143` (and comment at 130-133)

The code does:

```cpp
while (rte_hash_iterate(hash_, &key, &data, &next) >= 0) {
  const auto idx = static_cast<std::size_t>(next - 1);
  if (last_seen_tsc_[idx] < now_tsc - ttl_cycles) {
    expired.push_back(*static_cast<const FlowKey*>(key));
  }
}
```

Two distinct problems with this loop:

1. **`next` is the iteration cursor, not the slot ID.** Per DPDK 24.11
   `/usr/include/dpdk/rte_hash.h`, `rte_hash_iterate` writes the **next
   cursor position** into `*next`. The actual key index returned for the
   *current* key is the function's return value (the position of the
   key, or -1 / -ENOENT). The code's `next - 1` is a guess that
   happens to be wrong for any iteration after the first — `next` was
   just incremented past the current slot, so `next - 1` is one off,
   and during iterate the cursor can also point to a key that has been
   moved by a concurrent insert. Result: the code reads
   `last_seen_tsc_[wrong_idx]` — sometimes for a slot that's owned by a
   *different* flow, sometimes for a slot the rte_hash has just
   relocated. **Can delete live flows or miss expired ones.**

2. **`rte_hash_iterate` is not lock-free RW-safe under `RW_CONCURRENCY_LF`.**
   Unlike `rte_hash_lookup` / `lookup_bulk` which retry on table-change
   counter mismatch, `rte_hash_iterate` walks internal bucket chains and
   has no such retry. Concurrent inserts from workers can chain-split
   the bucket mid-iterate — leading to skip / double-visit / crash.
   The comment at `spi_flow_table.cpp:130-133` claiming `next` is the
   slot index is incorrect. Caller evidence: `PurgeExpired` is invoked
   at `spi_pipeline.cpp:1635-1644` and `:1671-1679` while workers
   (`WorkerLoop` `:1378-1380`, `DispatchWorkerLoop` `:1402-1408`)
   remain active — confirming that the iterate path runs against live
   writers.

**Fix**: stop relying on `rte_hash_iterate` entirely. Use
`rte_hash_lookup` per known slot, OR build a parallel slot-id-to-key
index at insert time, OR switch to `RW_CONCURRENCY` (with locking) for
this iteration if iterate is required. Simplest correct approach:
iterate the `last_seen_tsc_` array directly (it is sized identically
to the slot pool) and call `rte_hash_del_key` only when a stale slot
is identified, with the actual key recovered via
`rte_hash_get_key_with_position` once the rte_hash has stabilised.

**Status**: NOT FIXED. Compounds with C1, H2, H3 (every race in
`PurgeExpired` lands on top of the wrong slot index).

### H5. `MaybeReload` uses 1 ms sleep, not hard barrier

**File**: `include/dpdk/spi/spi_pipeline.cpp:485-540`

The reload sequence is:
1. `reload_barrier_.store(true, release)` — workers see this at end-of-burst.
2. `std::this_thread::sleep_for(1ms)` — main lcore hopes workers see it.
3. `LoadConfig` + `CompileRuleTable` + `RuleTable::RebuildInPlace(...)`.
4. `reload_barrier_.store(false, release)`.

The header at `spi_rule_engine.hpp:191-194` states callers MUST ensure
no worker is concurrently in `Match()` before `RebuildInPlace` runs.
A worker that loaded `active` exactly before step 1 can still be mid-
`rte_acl_classify` when `rte_acl_reset_rules` runs at step 3. Probability
is small at realistic burst sizes but non-zero.

**Fix**: replace the `sleep_for(1ms)` with `rte_eal_mp_wait_lcore()` —
already used correctly at `LaunchWorker:1508` and `StopWorkers:1519`.
A hard barrier is the documented DPDK contract for this case.

**Status**: NOT FIXED.

---

## Medium

### M1. `HostnameCache` stale-after-reload

**File**: `include/dpdk/dpi/hostname_cache.hpp` (per-worker cache, line 26+)

`HostnameCache::Insert` stores `filter_index` (a `uint16_t`) that
indexes into the **old** `DpiRuleTable::filters_` at the moment of
insertion. On DPI reload (`DpiRuleTableManager::Swap`), the cache
survives untouched. A subsequent `ResultAt(idx)` may index a different
filter in the new table (different group, label, priority).

Not a data race per se — but a TOCTOU bug with the same fix shape:
add a generation counter, verify on each Lookup, OR `Clear()` per-worker
caches in `MaybeReload`.

**Status**: NOT FIXED.

### M2. `CompiledFilter::label` and `CompiledDpiFilter::filter_group`/`label`
       still `std::string`

**Files**:
- `include/dpdk/spi/spi_rule_engine.hpp:94` — `std::string label;`
- `include/dpdk/dpi/dpi_rule_engine.hpp:25, 29` — same

Benign under the v3 release protocol (strings owned by the published
table, immutable post-publish, no concurrent mutation). The `string_view`
robustness improvement suggested in doc 12 §5.2 was not applied.

**Status**: NOT FIXED (benign, optional follow-up).

### M3. DPDK EAL may overwrite our signal handlers

**File**: `main.cpp:69` vs `Environment::init` at `main.cpp:89-93`

`InstallSignalHandlers()` is called **before** `Environment::init()`.
`rte_eal_init` internally installs its own signal handlers (via
`rte_intr_init`/`rte_eal_sigaction`) that can clobber our SIGUSR1 and
SIGINT/SIGTERM handlers. Symptom: SIGUSR1 may never reach `HandleSignal`.

**Fix**: move `InstallSignalHandlers()` to immediately after
`Environment::init()` returns (e.g., at the start of `RunUntilStopped`),
or call `std::signal(SIGUSR1, HandleSignal)` again after init.

**Status**: NOT FIXED.

---

## Low / Informational

### L1. `worker_force_quit_` is `volatile sig_atomic_t`, not `std::atomic<int>`

**File**: `include/dpdk/spi/spi_pipeline.hpp:314`

Works on x86-64 (aligned int RMW is hardware-atomic). Not strictly
portable per the C++ memory model; `std::atomic<int>` with relaxed
ordering is the standards-compliant replacement.

### L2. SIGUSR1 during reload window is lost

**File**: `include/dpdk/spi/spi_pipeline.cpp:536`

`MaybeReload` writes `*reload_flag = 0` unconditionally at the end.
A SIGUSR1 arriving during the rebuild window sets `*reload_flag = 1`
again, then the unconditional write 0 erases it. Fix: only clear if
no signal arrived mid-rebuild, or just clear unconditionally and accept
the lost reload.

### L3. Stale expiry snapshot (read in pass 1, delete in pass 2)

**File**: `include/dpdk/spi/spi_flow_table.cpp:138-162`

`PurgeExpired` reads `last_seen_tsc_[next]` and the key in pass 1,
then deletes + frees in pass 2. A worker `Lookup` refreshes `tsc` or
`Insert` updates between the two passes; the pass-2 delete still
fires on an active flow.

Compounds with H2/H3. Fix as part of C1 (atomic publish first, del second).

### L4. `LookupBulk` size mismatch with DPDK limit (API contract bug)

**Files**:
- `include/dpdk/spi/spi_flow_table.cpp:102` — `kMaxBulkKeys = 256`
- `/usr/include/dpdk/rte_hash.h:28-29` — `RTE_HASH_LOOKUP_BULK_MAX = 64`
- Caller: `spi_pipeline.cpp:1094-1100` chunks to 64 already.

`FlowTable::LookupBulk` defines its internal cap as 256 but the method
only clamps to 256 before calling `rte_hash_lookup_bulk` at
`spi_flow_table.cpp:110`. Per the DPDK 24.11 header, `rte_hash_lookup_bulk`
must not be called with more than 64 keys. The current caller in
`spi_pipeline.cpp:1094-1100` chunks to 64 before invocation, so there
is no current call-site violation. But the public method contract is
wrong — any future caller that passes >64 will silently overflow.

**Fix**: change `kMaxBulkKeys = 64` and add a `static_assert(kMaxBulkKeys
== RTE_HASH_LOOKUP_BULK_MAX)` so the cap is bound to the DPDK limit at
compile time.

### L5. Incorrect header comment at `spi_flow_table.hpp:141-148`

The comment claims `MULTI_WRITER_ADD` "enables lock-free adds" — but
v3 deliberately omits this flag (the slot migration broke cache
stability per doc 12 §10.1). Comment is misleading and should be
rewritten to describe the current design (insert spinlock + lookups
lock-free via `RW_CONCURRENCY_LF`).

### L6. Dead code: `rule_match_counts` allocated but never written

**File**: `include/dpdk/spi/spi_pipeline.cpp:1535, 1691`

Allocated in `PrepareWorkerContext`, aggregated in
`CollectWorkerRuleCounts`. No worker writes to it on the hot path.
Latent dead feature — not a race.

### L7. `FlowTable::~FlowTable` has no internal quiescence — API precondition

**File**: `include/dpdk/spi/spi_flow_table.cpp:80-84`

`~FlowTable` frees `hash_` (`rte_hash_free`), `cells_`, `last_seen_tsc_`
without any internal synchronisation. If a worker is still calling
`Insert` / `Lookup` / `GetEntry` / `PurgeExpired` when destruction
runs, the destruction races the in-flight API call — undefined
behaviour on `rte_hash_free`, plus `cells_` and `last_seen_tsc_`
vector destructors running concurrently with worker reads/writes.

**Current pipeline path is safe**: `Pipeline::~Pipeline` calls
`StopWorkers` first (`spi_pipeline.cpp:1465-1468`), which sets
`worker_force_quit_ = 1` and waits on `rte_eal_mp_wait_lcore()`
before any further destruction. The `Environment::Cleanup()` then
runs in LIFO order after `Pipeline::~Pipeline` completes.

**Documented precondition**: any future caller of `FlowTable` MUST
join all worker lcores before destroying the `FlowTable`. Add this
as a comment on the destructor and ideally as a `[[nodiscard]]`
contract note. Not a current bug — flagged so future refactors
(pooled FlowTable, context reuse, etc.) don't regress this.

---

## Acceptance criteria for the fixes

1. Build clean under `-Wall -Wextra -Wpedantic -Werror`.
2. TSan run on the bench binary → 0 races reported.
3. A synthetic stress test where 7 workers concurrently `Insert`
   unique keys while main lcore runs `PurgeExpired` in a loop must
   not lose any inserted key (slot-reuse race C1 fixed).
4. `MatchDpi` hoist (H1) verified by code inspection.
5. `MaybeReload` hard-barrier (H5) verified by code inspection.

## Order of execution

| PR | Fix | Risk | Est. effort |
|---|---|---|---|
| PR-A | C1 (slot reuse), H2 (last_seen_tsc_ atomic), H3 (insert_lock_ in Purge), L3 (stale snapshot) | high (touches hot path) | 1-2 days |
| PR-B | H1 (MatchDpi hoist), M1 (HostnameCache generation) | low | 0.5 day |
| PR-C | H5 (rte_eal_mp_wait_lcore in MaybeReload) | medium | 0.5 day |
| PR-D | H4 (LookupBulk snapshot or generation check) | medium | 1 day |
| PR-E | M3 (signal handler order), L1 (atomic quit), L2 (signal-during-reload), L4/L5 (docs) | low | 0.5 day |

---

## References

- `docs_search/12_data_race_fix.md` — original audit; v3 atomic publish protocol.
- `/usr/include/dpdk/rte_hash.h` — `RW_CONCURRENCY_LF`, `MULTI_WRITER_ADD`,
  `rte_hash_free_key_with_position` contracts (DPDK 24.11.4).
- `/usr/include/dpdk/rte_acl.h` — single-writer mutation contract.
- DPDK 23.11 Thread Safety guide — <https://doc.dpdk.org/guides-23.11/prog_guide/thread_safety_dpdk_functions.html>.
- C++ standard `[atomics]` clause 33.4 — publication protocol.
- P0124R6 — <https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2017/p0124r6.html>.