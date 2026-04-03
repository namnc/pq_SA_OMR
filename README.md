# pq_SA_OMR

**Post-Quantum Stealth Address — Oblivious Message Retrieval**

PoC B: Transciphered OMR using Pasta-4 symmetric encryption evaluated homomorphically under BFV FHE with PVW detection. This is the companion to [pq_SA](https://github.com/namnc/pq_SA) (PoC A: pairwise channels).

**Status**: B0-B3 complete. All core components working. 23 Rust + 10 Foundry = 33 tests. C++ omr-core: 0 false negatives, 0 false positives on 20-note test.

## Measured Results

### B0: Depth Gate (PASSED)

| Metric | Value |
|--------|-------|
| BFV parameters | N=32768, t=65537, 15×54-bit primes, log2(Q)=810 |
| Security | tc128 (accepted by SEAL 4.1.2) |
| Pasta-4 depth consumed | **1 level** (budget: 14, spare: 13) |
| PVW detection depth | **0** (plaintext-ciphertext multiply, sum on recipient side) |
| Pasta-4 transcipher time | **19.3s per note** (ARM64 without NEON, unoptimized) |

### B2b: OMR Detection (20-note test)

| Metric | Value |
|--------|-------|
| Notes | 20 (5 pertinent, 15 non-pertinent) |
| False negatives | **0** |
| False positives | **0** |
| Pertinent detected | **5/5 (100%)** |
| Total time | 385s (20 notes × ~19.3s each) |
| PVW parameters | n=25, q=65537, threshold=128 (q/512), error=16 |
| FP rate (analytical) | **~0.39%** (<4 per 1000 notes) |

## Architecture

```
Sender (Rust)                 Ethereum                  OMR Server (C++)        Recipient (Rust)
    │                            │                          │                       │
    │─ postNoteOMR ─────────────>│ calldata: 104 B          │                       │
    │  (commit+nonce+pvwClue)    │                          │                       │
    │─ sidecar write ────────────────────────────────────────>│                       │
    │                            │── pvwClue events ────────>│                       │
    │                            │                          │─ Pasta-4 transcipher  │
    │                            │                          │─ PVW detect (FHE)     │
    │                            │                          │── digest ───────────>│
    │                            │                          │                       │
    │                            │                          │  BFV decrypt → IDs    │
    │                            │                          │  padded fetch (k=50)  │
    │                            │                          │  AEAD decrypt          │
```

## Project Structure

```
pq_SA_OMR/
├── README.md
├── Cargo.toml                        Rust workspace
├── test_vectors_pasta4.json          100 C++ reference vectors for cross-validation
├── b0/                               B0: depth benchmark (C++)
│   ├── CMakeLists.txt
│   ├── b0_bench.cpp                  Depth + correctness + timing benchmark
│   ├── extract_vectors.cpp           Test vector generator
│   └── hybrid-HE-framework/         SEAL 4.1.2 + Pasta-4 HE evaluation
├── crates/
│   └── primitives-omr/              Rust plaintext primitives
│       └── src/
│           ├── lib.rs
│           └── pasta4.rs             Pasta-4 cipher (cross-validated against C++)
└── (planned)
    ├── omr-core/                     C++ FHE evaluation binary
    └── crates/omr-server/            Rust orchestrator
```

## Build

### B0 (C++ depth benchmark)

```bash
# Build SEAL 4.1.2
cd b0/hybrid-HE-framework/thirdparty/SEAL
git checkout v4.1.2
mkdir build && cd build
cmake .. -DSEAL_USE_INTEL_HEXL=OFF -DSEAL_BUILD_DEPS=OFF -DSEAL_USE_MSGSL=OFF \
  -DSEAL_BUILD_SEAL_C=OFF -DSEAL_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/opt/homebrew -DCMAKE_POLICY_VERSION_MINIMUM=3.5
make -j4

# Build and run benchmark
cd ../../../../
mkdir build && cd build
cmake .. -DCMAKE_POLICY_VERSION_MINIMUM=3.5
make -j4
./b0_bench
```

### B1 (Rust primitives)

```bash
cargo test --release
```

## Server Performance (Measured)

| | ARM64 (current, no NEON) | x86 AVX2 (estimated 4x) |
|--|-------------------------|------------------------|
| Per note | **19.3s** | ~4.8s |
| 10K notes, 1 core | 53.6 hr | 13.4 hr |
| 10K notes, 8 cores | 6.7 hr | 1.7 hr |
| Cloud cost/day ($0.50/hr) | $3.35 | $0.84 |

The ARM64 measurement is WITHOUT NEON intrinsics — SEAL 4.1.2 on this machine falls back to scalar arithmetic. Enabling NEON or running on x86 AVX2 hardware should give 3-5x improvement. The 128 BFV rotations per note (for Pasta-4 affine layers) dominate wall-clock time.

## Relationship to PoC A

| Aspect | PoC A (pq_SA) | PoC B (pq_SA_OMR) |
|--------|--------------|-------------------|
| Language | Rust | Rust + C++ |
| FHE | None | BFV (SEAL 4.1.2) |
| Scanning | O(N×S) trial decrypt | Sublinear (digest-based) |
| Calldata/note | 680 B | 104 B (C3-only prototype) |
| Status | Complete, Sepolia | B0 passed, B1 in progress |

PoC B builds on PoC A's pairwise channels — `k_pairwise` established in PoC A is used to derive the Pasta-4 key and PVW secret key.

## Acknowledgements

- Keewoo Lee — Discussion on OMR architecture and SophOMR
- IAIK TU Graz — hybrid-HE-framework (Pasta-4 reference implementation)
