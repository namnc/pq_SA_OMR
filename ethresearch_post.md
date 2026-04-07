# Replacing Regev with Pasta in the OMR Table

Standard OMR ([Liu & Tromer 2021](https://eprint.iacr.org/2021/1256)) tables use Regev ciphertexts for detection — each entry is ~1-2 KB of lattice ciphertext, too large for on-chain calldata. We replace Regev with Pasta-4 symmetric encryption (~64 B per entry), enabled by the stealth address pairwise key `k_pairwise` from [pq_SA](https://github.com/namnc/pq_SA). The FHE server transciphers Pasta-4 into the BFV domain before evaluation — the cost of this transciphering is the tradeoff for ~10-15x smaller on-chain entries.

The same substitution applies wherever a server must match encrypted entries to recipients without seeing plaintext — on-chain note discovery, encrypted messaging, private notifications.

**Code**: [github.com/namnc/pq_SA_OMR](https://github.com/namnc/pq_SA_OMR) (Rust + C++, 30 tests, Anvil demo)

## The Problem

OMR lets a server scan memos on behalf of a recipient without learning which memos matched. The server evaluates detection entries under FHE and returns an encrypted digest. The bottleneck is entry size: each Regev ciphertext is ~1-2 KB, making on-chain OMR tables impractically expensive.

| | Standard OMR | This work |
|--|-------------|-----------|
| Detection entry | Regev ciphertext (~1-2 KB) | **Pasta-4 ciphertext (~128 B)** |
| On-chain viable? | No | **Yes** |
| Server evaluation | Direct (Regev is lattice-compatible) | Transcipher Pasta → BFV, then evaluate |
| Shared key? | No (public-key Regev) | Yes (`k_pairwise` from stealth address) |

## Why Pasta Requires a Shared Key

Regev encryption is public-key — the sender encrypts to the recipient's public key without any prior shared state. Pasta-4 is a symmetric cipher — it requires a shared key.

The stealth address first contact provides this. In [pq_SA](https://github.com/namnc/pq_SA), sender and recipient establish `k_pairwise` via hybrid KEM (ECDH + ML-KEM-768) during first contact. This key is already used for stealth address derivation. For OMR, we derive a Pasta-4 key from it via LWR PRF:

```
k_pairwise (from pq_SA first contact)
  └─ LWR PRF(k_pairwise, epoch) → Pasta-4 key (deterministic, per-epoch)
      └─ Pasta4.Encrypt(key, detection_signal) → ~128 B entry (on-chain)
          └─ FHE server transciphers → BFV ciphertext → evaluates detection
```

No additional key exchange or on-chain setup. OMR piggybacks on the existing stealth address infrastructure.

## The Tradeoff: Ciphertext Size vs Transcipher Cost

The two numbers that define the substitution:

**1. Ciphertext size (on-chain cost):**
- Regev: ~1-2 KB per entry → at 10K entries/day, ~10-20 MB calldata
- Pasta-4: ~64 B per entry → at 10K entries/day, ~640 KB calldata
- **~10-15x reduction**

**2. Transcipher overhead (server cost):**
- Standard OMR: evaluate Regev directly under BFV (no transciphering needed — Regev is already lattice-compatible)
- Our approach: transcipher Pasta-4 → BFV, then evaluate
- Measured: **19.3s/note** (ARM64, unoptimized, no NEON)
- Estimated: **~4.8s/note** (x86 AVX2)

The transcipher cost is the premium for smaller on-chain entries. The key benchmark comparison — not yet done — is our Pasta transcipher time vs standard Regev evaluation at the same BFV parameters (N=32768, t=65537).

## Measured Results

### FHE Depth (B0: PASSED)

| Step | Depth |
|------|-------|
| Pasta-4 transcipher (3 feistel + 1 cube + linear layers) | ~1 level consumed (measured) |
| PVW detection (inner product) | 0 (plaintext-ciphertext multiply) |
| **Budget** | **14 levels. Spare: 13.** |

### Detection Accuracy (B3: Anvil end-to-end)

| Metric | Value |
|--------|-------|
| PVW parameters | n=25, q=65537, threshold=128 (q/512), error=16 |
| False negatives | **0** (10K+ pertinent clues tested) |
| False positives | **0** (20-note FHE test); analytical rate ~0.39% |

### Server Performance (Measured, ARM64)

| | ARM64 (no NEON) | x86 AVX2 (est. 4x) |
|--|-----------------|---------------------|
| Per note transcipher | **19.3s** | ~4.8s |
| 10K notes, 8 cores | 6.7 hr | 1.7 hr |
| Cloud cost/day | $3.35 | $0.84 |

The 128 BFV rotations per note (Pasta-4 affine layers) dominate wall-clock time.

## What to Benchmark Next

The missing comparison: **Pasta transcipher vs direct Regev evaluation** at the same BFV parameters. This quantifies the exact computational premium for the ~10-15x ciphertext reduction. Without this, we know the calldata savings but not whether the server cost is acceptable.

## Open Problems

- **Transcipher vs Regev benchmark**: need direct comparison at N=32768, t=65537
- **PVW security at n=25**: ~65-80 bit PQ security for detection clues. Sufficient for metadata protection but below 128-bit target.
- **ARM64 performance**: 19.3s/note without NEON is slow. x86 AVX2 or GPU acceleration needed for production scale.

## Implementation

30 tests (23 Rust + 10 Solidity). B0-B3 complete.

- `primitives-omr/src/pasta4.rs` — Pasta-4 cipher, 100 C++ cross-validated vectors
- `primitives-omr/src/pvw.rs` — PVW detection, 10K zero-FN verified
- `primitives-omr/src/lwr_prf.rs` — LWR PRF for Pasta key derivation from k_pairwise
- `omr-core/src/` — C++ FHE evaluation binary (SEAL 4.1.2)
- `contracts/src/NoteRegistryOMR.sol` — postNoteOMR with 52B pvwClue

## Applicability Beyond Stealth Addresses

The Regev → Pasta substitution applies to any system with encrypted note discovery:

- **Aztec**: [note discovery](https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/note_discovery) calls OMR "currently impractical." The 128 B Pasta entries address their cost concern. Their shared secret (Grumpkin ECDH) maps to our k_pairwise; their Poseidon2 tags map to our PVW clues.
- **Encrypted messaging**: any system where a server matches encrypted entries to recipients without seeing plaintext.
- **Private notifications**: push notification services that don't learn which notifications are for which user.

## Related Work

**OMR:**
- [Liu & Tromer 2021](https://eprint.iacr.org/2021/1256) — Oblivious Message Retrieval (Regev-based)
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
