# PGO attempt — did not help

**Date:** 2026-07-05
**Compiler:** Clang 22.1.6 (already what the project uses)
**Profile tool:** `llvm-profdata merge`
**Target:** Hash-heavy packet pipeline, 99.9% cache hit rate

## Process

1. Built instrumented binary with `-fprofile-instr-generate`
2. Ran training for ~32s under 1M-packet bench harness
3. Profile produced: 195 functions, 828 blocks, 10.8B block executions
4. Built optimized binary with `-fprofile-instr-use=/tmp/pgo-merged.profdata`
5. Bench + perf stat, 2 runs

## Results (PGO vs Phase 1 = CRC32 pin only)

| Metric | Phase 1 | PGO run 1 | PGO run 2 |
|---|---|---|---|
| cycles | 1.464T | 1.473T | 1.470T |
| instructions | 1.851T | 1.730T | 1.637T |
| **branch-misses** | 1.418B | 1.733B (+22%) | **1.995B (+30%)** |
| L1-dcache-load-misses | 43.6B | 46.4B | 44.9B |
| **IPC** | **1.264** | 1.174 | 1.114 |

PGO consistently hurt:
- Branch-misses +22% to +30%
- IPC -7% to -12%
- L1-dcache-load-misses +6-7%

## Why PGO failed

The instrumented binary ran at **6.91 Mpps** (instrumentation overhead — typical 10-20×
slowdown), vs the optimized binary's **~120 Mpps**. The branch frequencies and
code-layout characteristics differ drastically between these two regimes:

- At 6.91 Mpps the main loop is "bursty stalls" — most time spent waiting on
  instrumentation metadata writes / instrumentation counters
- At 120 Mpps the main loop is "tight pipeline" — instruction-level parallelism,
  dcache access patterns, branch predictor behavior are different

Clang's PGO used the instrumented distribution to optimize for code paths that
are not actually hot in production. Result: branch placement and code layout
optimizations went the wrong direction.

## Caveats / things that might make PGO work

1. **Train with the optimized binary** — i.e., build a PGO-instrumented
   binary whose PGO output is fed into another PGO-instrumented build whose
   output is fed into the optimized build. Two-stage PGO (PGoPGo). This is
   `-fprofile-instr-generate` + `-fprofile-sample-use=...` in newer LLVM.
2. **Train with longer runs** — 30+ minutes of representative traffic. The
   30s training run may not have captured enough variance.
3. **Train with diverse traffic patterns** — different shard mixes, different
   match percentages, etc., so the profile is robust.
4. **Use PGO with sampling rather than instrumentation** — `-fprofile-sample-accurate`
   has lower overhead, can run at production speed.

## Files

- Raw data: `bench-results/pgo-use.perf`, `bench-results/pgo-use-run2.perf`
- PGO builds removed: `cmake-build-pgo-gen/`, `cmake-build-pgo-use/` cleaned up
- Profile data still in `/tmp/pgo-merged.profdata` (38 KB)

## Conclusion

Skip PGO for this project unless training-time matches production-time.
The current best is **Phase 1 (CRC32 pin only)** with +7-16% IPC and -16%
branch-misses over the 121 Mpps baseline.
