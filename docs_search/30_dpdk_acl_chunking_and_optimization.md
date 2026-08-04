# DPDK ACL Chunking Scaling and Performance Optimization

## Source & Date Verified
- DPDK Official Documentation (Writing Efficient Code & ACL Library): https://doc.dpdk.org/guides-24.07/prog_guide/writing_efficient_code.html
- Intel DPDK Performance Optimization Guidelines
- Date verified: 2026-08-02

## Finding Summary
1. **RTE_ACL_MAX_CATEGORIES Limit (16 categories)**:
   DPDK's `rte_acl` library caps the maximum number of classification categories per context at `RTE_ACL_MAX_CATEGORIES` (16).
   When scaling to millions of rules across thousands of filter groups (e.g. 4098 filter groups in `rules_8m.beve`), the rules are partitioned across **257 separate ACL contexts** (`acl_chunks_`).

2. **Linear Chunk Walk Overhead**:
   In `MatchBulk` and `Match`, walking 257 ACL contexts sequentially causes 257 `rte_acl_classify` SIMD calls per burst when packets miss the Flow Cache. This scales linearly with rule count ($O(N_{\text{chunks}})$), causing per-packet latency to jump from ~15 cycles (1 chunk) to ~1500 cycles (257 chunks).

3. **Optimizations Identified**:
   - **Early Exit / Short-Circuiting**: Track whether all packets in a burst have matched a rule. As soon as `all_matched == true`, break out of the `acl_chunks_` loop immediately.
   - **Single-Context Category Packing**: Group multiple filter groups with identical actions into unified categories to minimize total chunk count.
   - **LPM / Trie Pre-filtering for CIDR rules**: Utilize DPDK `rte_lpm` (DIR-24-8 algorithm, 1 memory access for 24-bit IPv4 prefix) for pure IP range matching before falling back to ACL multi-field tries.

## Applicability to Codebase
- File: [`include/dpdk/spi/spi_rule_engine.cpp`](file:///home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_rule_engine.cpp#L376)
- Target: `RuleTable::MatchBulk` and `RuleTable::Match`
