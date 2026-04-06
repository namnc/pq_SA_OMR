# pq_SA_OMR

**Replacing Regev with Pasta in the OMR Table**

Standard OMR tables contain Regev ciphertexts (~1-2 KB per entry) for detection — too large for on-chain calldata. We replace Regev with Pasta-4 (~64 B), enabled by the stealth address pairwise key `k_pairwise` from [pq_SA](https://github.com/namnc/pq_SA). The tradeoff: the FHE server must transcipher Pasta-4 → BFV before evaluation, adding computational overhead.

The same substitution applies beyond stealth addresses — any system where a server must match encrypted entries to recipients without seeing the plaintext. Examples: on-chain note discovery, encrypted messaging, and private notification services.

**Status**: B0-B3 complete. 0 FN, 0 FP on Anvil. 23 Rust + 7 Foundry = 30 tests.

## The Substitution

| | Standard OMR | This work |
|--|-------------|-----------|
| Detection entry | Regev ciphertext (~1-2 KB) | **Pasta-4 ciphertext (~128 B)** |
| On-chain viable? | No (too expensive) | **Yes** |
| Server evaluation | Direct (Regev is already lattice-compatible with BFV) | Transcipher Pasta → BFV, then evaluate |
| Shared key required? | No (Regev uses recipient's public key) | Yes (`k_pairwise` from stealth address first contact) |

The two numbers that define the tradeoff:
1. **Ciphertext size**: Regev ~1-2 KB vs Pasta ~64 B → **~10-15x calldata reduction**
2. **Transcipher overhead**: 19.3s/note measured (ARM64, unoptimized) — the cost of the size savings

## Why k_pairwise

Standard OMR uses Regev (public-key) encryption because the sender has no shared key with the recipient. Pasta-4 is a symmetric cipher — it requires a shared key.

The stealth address pairwise key provides this for free. `k_pairwise` is already established via hybrid KEM first contact in [pq_SA](https://github.com/namnc/pq_SA). No additional key exchange or on-chain setup needed.

```
pq_SA first contact → k_pairwise (32 B)
                        └─ LWR PRF(k_pairwise, epoch) → Pasta-4 key
                            └─ Pasta4.Encrypt(key, detection_signal) → ~128 B
                                └─ FHE server transciphers into BFV → evaluates detection
```

## Measured Results

### B0: Depth Gate (PASSED)

| Metric | Value |
|--------|-------|
| BFV parameters | N=32768, t=65537, 15×54-bit primes, log2(Q)=810 |
| Security | tc128 (accepted by SEAL 4.1.2) |
| Pasta-4 depth consumed | **1 level** (budget: 14, spare: 13) |
| Pasta-4 transcipher time | **19.3s per note** (ARM64 without NEON, unoptimized) |

### B3: End-to-End on Anvil

| Metric | 10-note test | 5-note FHE test |
|--------|-------------|----------------|
| Notes (pertinent) | 10 (3) | 5 (2) |
| False negatives | **0** | **0** |
| False positives | **0** | **0** |
| postNoteOMR gas (first) | 55,418 | 55,418 |
| postNoteOMR gas (subsequent) | 38,306 | 38,306 |

PVW parameters: n=25, q=65537, threshold=128 (q/512), error=16. Analytical FP rate: ~0.39%.

### Server Performance

| | ARM64 (no NEON) | x86 AVX2 (est. 4x) |
|--|-----------------|---------------------|
| Per note transcipher | **19.3s** | ~4.8s |
| 10K notes, 8 cores | 6.7 hr | 1.7 hr |
| Cloud cost/day | $3.35 | $0.84 |

ARM64 without NEON — SEAL 4.1.2 falls back to scalar arithmetic. x86 AVX2 should give 3-5x improvement. The 128 BFV rotations per note (Pasta-4 affine layers) dominate.

### What to Benchmark Next

The key comparison is transcipher overhead vs direct Regev evaluation:
- **Pasta transcipher**: 19.3s/note (measured, ARM64)
- **Direct Regev evaluation under BFV**: not yet benchmarked at our parameters (N=32768, t=65537)
- The difference quantifies the cost of ~20-30x ciphertext size reduction

## Project Structure

```
pq_SA_OMR/
├── README.md
├── Cargo.toml                        Rust workspace
├── test_vectors_pasta4.json          100 C++ reference vectors
├── b0/                               Depth benchmark (C++)
│   ├── b0_bench.cpp                  Depth + correctness + timing
│   └── hybrid-HE-framework/         SEAL 4.1.2 + Pasta-4 HE
├── omr-core/                         C++ FHE evaluation binary
│   └── src/
│       ├── main.cpp                  CLI: evaluate-test | keygen | decrypt
│       └── pvw_he.cpp                PVW detection under BFV
├── contracts/
│   ├── src/NoteRegistryOMR.sol       postNoteOMR with 128B Pasta-4 ct (7 tests)
│   └── test/NoteRegistryOMR.t.sol
└── crates/
    ├── primitives-omr/               Plaintext Rust primitives (19 unit + 4 e2e)
    │   └── src/
    │       ├── pasta4.rs             Pasta-4 cipher (100 C++ cross-validated)
    │       ├── pvw.rs                PVW detection (10K zero-FN verified)
    │       └── lwr_prf.rs            LWR PRF key derivation
    └── omr-server/                   Rust orchestrator (Anvil e2e demo)
        └── src/main.rs
```

## Build & Test

```bash
# Rust tests (23 tests)
cargo test --release

# Foundry tests (10 tests)
cd contracts && forge test -vv

# Demo on Anvil
anvil &
cargo run -p omr-server --release
```

## Related Work

**OMR:**
- [Liu & Tromer 2021](https://eprint.iacr.org/2021/1256) — Oblivious Message Retrieval (original, Regev-based)
- [SophOMR](https://github.com/keewoolee/SophOMR) — BFV-based OMR with SRLC compression
- [PerfOMR](https://eprint.iacr.org/2024/204) — 15x improvement (USENIX Sec 2024)
- [InstantOMR](https://eprint.iacr.org/2025/2317) — TFHE+RLWE, 860x faster than SophOMR

**Transciphering:**
- [Pasta cipher](https://eprint.iacr.org/2021/731) — FHE-friendly symmetric encryption
- [hybrid-HE-framework](https://github.com/isec-tugraz/hybrid-HE-framework) — Pasta HE evaluation under SEAL

**PQ stealth addresses:**
- [pq_SA](https://github.com/namnc/pq_SA) — PQ key exchange for stealth addresses (provides k_pairwise)

## Acknowledgements

- Keewoo Lee — Discussion on OMR architecture and SophOMR
- IAIK TU Graz — hybrid-HE-framework (Pasta-4 reference implementation)
- Vikas — Sepolia ETH for testnet deployment

## License

MIT
