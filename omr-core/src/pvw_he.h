#pragma once
#include "seal/seal.h"
#include <vector>

namespace omr {

/// PVW parameters matching the Rust primitives-omr crate.
constexpr size_t PVW_N = 25;
constexpr uint64_t PVW_Q = 65537;
constexpr uint64_t PVW_THRESHOLD = PVW_Q / 512;  // 128 (FP rate ~0.39%)

/// Evaluate PVW detection under BFV FHE.
///
/// Given:
///   - encrypted_sk: FHE.Enc(sk_pvw) as batch-encoded ciphertext
///     (sk elements in slots 0..PVW_N-1)
///   - clue_a: plaintext PVW clue vector (from calldata)
///   - clue_b: plaintext PVW clue scalar
///   - evaluator, batch_encoder, relin_keys
///
/// Returns: FHE.Enc(detection_value) where detection_value ≈ 0 if pertinent.
/// The caller must decrypt and threshold locally.
seal::Ciphertext evaluate_pvw(
    const seal::Ciphertext& encrypted_sk,
    const std::vector<uint64_t>& clue_a,
    uint64_t clue_b,
    seal::Evaluator& evaluator,
    seal::BatchEncoder& encoder,
    const seal::RelinKeys& relin_keys,
    size_t slot_count);

/// Encrypt PVW secret key into BFV ciphertext (batch encoded).
/// sk elements go into slots 0..PVW_N-1, rest are zero.
seal::Ciphertext encrypt_pvw_sk(
    const std::vector<uint64_t>& sk,
    seal::Encryptor& encryptor,
    seal::BatchEncoder& encoder,
    size_t slot_count);

}  // namespace omr
