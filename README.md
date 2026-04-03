# pq_SA_OMR

**Post-Quantum Stealth Address — Oblivious Message Retrieval**

PoC B: Transciphered OMR using Pasta-4 symmetric encryption evaluated homomorphically under BFV FHE with PVW detection. This is the companion to [pq_SA](https://github.com/namnc/pq_SA) (PoC A: pairwise channels).

**Status**: B0-B2 complete. B0 (depth gate) passed with 13 spare levels. B1 (Rust primitives) 23 tests. B2a (contract) 10 tests. B2b (C++ FHE core) 0 false negatives. B3 (integration) plaintext pipeline verified.

## B0 Results (Depth Gate — PASSED)

```
  N = 32768, t = 65537
  log2(Q) = 810 bits (15 primes)
  Security: tc128 (accepted by SEAL)
  Pasta-4 depth consumed: 1 level
  Spare levels: 13 out of 14
  Transcipher time: 19.7s per note (ARM64 without NEON, unoptimized)
  Correctness: PASS (0 mismatches)
```

The hard gate passed decisively — 1 depth level consumed vs budget of 14. Built with SEAL 4.1.2 + hybrid-HE-framework Pasta-4 on macOS ARM64.

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
