#pragma once
#include "seal/seal.h"
#include <vector>

namespace omr {

/// PVW parameters matching the Rust primitives-omr crate.
constexpr size_t PVW_N = 25;
constexpr uint64_t PVW_Q = 65537;
constexpr uint64_t PVW_THRESHOLD = PVW_Q / 512;  // 128 (FP rate ~0.39%)

/// Encrypt PVW secret key into BFV ciphertext (batch encoded).
/// sk elements go into slots 0..PVW_N-1, rest are zero.
seal::Ciphertext encrypt_pvw_sk(
    const std::vector<uint64_t>& sk,
    seal::Encryptor& encryptor,
    seal::BatchEncoder& encoder,
    size_t slot_count);

/// Evaluate PVW detection on plaintext clue (depth 0: plaintext × ciphertext).
/// Used when PVW clue is NOT inside a Pasta ciphertext.
seal::Ciphertext evaluate_pvw_plain(
    const seal::Ciphertext& encrypted_sk,
    const std::vector<uint64_t>& clue_a,
    seal::Evaluator& evaluator,
    seal::BatchEncoder& encoder,
    size_t slot_count);

/// Evaluate PVW detection on transciphered clue (depth 1: ciphertext × ciphertext).
/// Used when PVW clue was embedded in a Pasta ciphertext and transciphered to BFV.
/// he_signal slots 0..PVW_N-1 contain BFV(a[i]), slot PVW_N contains BFV(b).
seal::Ciphertext evaluate_pvw_on_transciphered(
    const seal::Ciphertext& encrypted_sk,
    const seal::Ciphertext& he_signal,
    seal::Evaluator& evaluator,
    const seal::RelinKeys& relin_keys);

}  // namespace omr
