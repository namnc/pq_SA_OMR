#include "pvw_he.h"
#include <iostream>

namespace omr {

seal::Ciphertext encrypt_pvw_sk(
    const std::vector<uint64_t>& sk,
    seal::Encryptor& encryptor,
    seal::BatchEncoder& encoder,
    size_t slot_count) {

    std::vector<uint64_t> slots(slot_count, 0);
    for (size_t i = 0; i < PVW_N && i < sk.size(); i++) {
        slots[i] = sk[i];
    }

    seal::Plaintext pt;
    encoder.encode(slots, pt);
    seal::Ciphertext ct;
    encryptor.encrypt(pt, ct);
    return ct;
}

seal::Ciphertext evaluate_pvw_plain(
    const seal::Ciphertext& encrypted_sk,
    const std::vector<uint64_t>& clue_a,
    seal::Evaluator& evaluator,
    seal::BatchEncoder& encoder,
    size_t slot_count) {

    // Encode clue_a as plaintext (slots 0..PVW_N-1)
    std::vector<uint64_t> a_slots(slot_count, 0);
    for (size_t i = 0; i < PVW_N && i < clue_a.size(); i++) {
        a_slots[i] = clue_a[i];
    }
    seal::Plaintext a_pt;
    encoder.encode(a_slots, a_pt);

    // a * sk: plaintext-ciphertext multiply (depth 0)
    seal::Ciphertext product;
    evaluator.multiply_plain(encrypted_sk, a_pt, product);

    // Recipient sums slots 0..PVW_N-1 locally after decryption
    return product;
}

seal::Ciphertext evaluate_pvw_on_transciphered(
    const seal::Ciphertext& encrypted_sk,
    const seal::Ciphertext& he_signal,
    seal::Evaluator& evaluator,
    const seal::RelinKeys& relin_keys) {

    // he_signal slots 0..PVW_N-1 contain BFV(a[i]) from transciphered Pasta ct.
    // encrypted_sk slots 0..PVW_N-1 contain BFV(sk[i]).
    // Compute BFV(a[i] * sk[i]) = ciphertext × ciphertext (depth 1).
    seal::Ciphertext product;
    evaluator.multiply(he_signal, encrypted_sk, product);
    evaluator.relinearize_inplace(product, relin_keys);

    // Recipient decrypts, sums slots 0..PVW_N-1, compares with slot PVW_N (b).
    return product;
}

}  // namespace omr
