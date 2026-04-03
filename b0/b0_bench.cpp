// B0 Depth Benchmark: Validate Pasta-4 HE evaluation at our exact BFV parameters
// Parameters: N=32768, t=65537, 15 primes of 54 bits
//
// This measures:
// 1. Depth consumed by Pasta-4 HE transciphering
// 2. Correctness of decryption after HE evaluation
// 3. Wall-clock time per operation

#include <iostream>
#include <vector>
#include <chrono>
#include <cassert>
#include "seal/seal.h"
#include "pasta_4_seal.h"
#include "pasta_4_plain.h"

using namespace std;
using namespace seal;
using namespace PASTA_4;

int main() {
    cout << "==========================================================\n";
    cout << "  B0: Pasta-4 BFV Depth Benchmark\n";
    cout << "==========================================================\n\n";

    // =====================================================================
    //  Step 1: BFV parameter setup
    // =====================================================================
    uint64_t plain_mod = 65537;  // t = F4 (Fermat prime)
    size_t poly_modulus_degree = 32768;  // N = 2^15

    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_plain_modulus(plain_mod);

    // 15 primes of ~54 bits each
    auto coeff_mod = CoeffModulus::Create(poly_modulus_degree,
        {54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54});
    parms.set_coeff_modulus(coeff_mod);

    cout << "[params] N = " << poly_modulus_degree << "\n";
    cout << "[params] t = " << plain_mod << "\n";
    cout << "[params] Primes: " << coeff_mod.size() << " x ~54 bits\n";

    size_t total_bits = 0;
    for (auto& m : coeff_mod) total_bits += m.bit_count();
    cout << "[params] log2(Q) = " << total_bits << " bits\n";

    SEALContext context(parms, true, sec_level_type::tc128);
    if (!context.parameters_set()) {
        cout << "ERROR: Invalid parameters!\n";
        cout << "  " << context.parameter_error_message() << "\n";
        return 1;
    }
    cout << "[params] Security level: tc128 (accepted by SEAL)\n";
    cout << "[params] Initial coeff_modulus_size: "
         << context.first_context_data()->parms().coeff_modulus().size() << "\n\n";

    // =====================================================================
    //  Step 2: Key generation
    // =====================================================================
    cout << "--- Key generation ---\n";
    auto t0 = chrono::high_resolution_clock::now();

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;

    auto t1 = chrono::high_resolution_clock::now();
    cout << "  Basic keygen: "
         << chrono::duration_cast<chrono::milliseconds>(t1-t0).count() << " ms\n";

    // =====================================================================
    //  Step 3: Generate Pasta-4 key and encrypt it under BFV
    // =====================================================================
    cout << "\n--- Pasta-4 key generation ---\n";

    // Random Pasta key (64 elements of F_t for the two state halves)
    vector<uint64_t> pasta_key(64);
    for (size_t i = 0; i < 64; i++) {
        pasta_key[i] = rand() % plain_mod;
    }

    // Create Pasta-4 SEAL cipher object
    shared_ptr<SEALContext> ctx_ptr = make_shared<SEALContext>(context);
    PASTA_SEAL pasta_he(pasta_key, ctx_ptr);

    // Generate Galois keys needed for Pasta-4 rotations
    cout << "  Setting up Galois key indices...\n";
    pasta_he.add_gk_indices();

    cout << "  Generating Galois keys (this takes a while at N=32768)...\n";
    auto t2 = chrono::high_resolution_clock::now();
    pasta_he.create_gk();
    auto t3 = chrono::high_resolution_clock::now();
    cout << "  Galois key generation: "
         << chrono::duration_cast<chrono::milliseconds>(t3-t2).count() << " ms\n";

    // Encrypt the Pasta key under BFV (use batch encoder)
    cout << "  Encrypting Pasta key under BFV...\n";
    auto t4 = chrono::high_resolution_clock::now();
    pasta_he.encrypt_key(/*batch_encoder=*/true);
    auto t5 = chrono::high_resolution_clock::now();
    cout << "  Key encryption: "
         << chrono::duration_cast<chrono::milliseconds>(t5-t4).count() << " ms\n";

    // =====================================================================
    //  Step 4: Pasta-4 plaintext encryption (simulating sender)
    // =====================================================================
    cout << "\n--- Pasta-4 plaintext encryption ---\n";

    // Create plaintext message (32 elements of F_t)
    vector<uint64_t> message(32);
    for (size_t i = 0; i < 32; i++) {
        message[i] = (i + 1) * 1000 % plain_mod;
    }

    // Encrypt with Pasta-4 in plaintext domain
    PASTA pasta_plain(pasta_key, plain_mod);
    vector<uint64_t> pasta_ct = pasta_plain.encrypt(message);
    cout << "  Pasta-4 ciphertext: " << pasta_ct.size() << " elements\n";

    // Verify plaintext roundtrip
    vector<uint64_t> pasta_dec = pasta_plain.decrypt(pasta_ct);
    bool roundtrip_ok = true;
    for (size_t i = 0; i < 32; i++) {
        if (pasta_dec[i] != message[i]) {
            roundtrip_ok = false;
            break;
        }
    }
    cout << "  Plaintext roundtrip: " << (roundtrip_ok ? "OK" : "FAILED") << "\n";
    if (!roundtrip_ok) {
        cout << "ERROR: Pasta-4 plaintext roundtrip failed!\n";
        return 1;
    }

    // =====================================================================
    //  Step 5: HE transciphering (the depth benchmark!)
    // =====================================================================
    cout << "\n--- HE Transciphering (depth benchmark) ---\n";

    auto t6 = chrono::high_resolution_clock::now();
    vector<Ciphertext> he_result = pasta_he.HE_decrypt(pasta_ct, /*batch_encoder=*/true);
    auto t7 = chrono::high_resolution_clock::now();

    double transcipher_ms = chrono::duration_cast<chrono::microseconds>(t7-t6).count() / 1000.0;
    cout << "  Transcipher time: " << transcipher_ms << " ms\n";

    // Check remaining depth (coeff_modulus_size after evaluation)
    size_t remaining_primes = he_result[0].coeff_modulus_size();
    size_t initial_primes = coeff_mod.size();
    size_t depth_consumed = initial_primes - remaining_primes;

    cout << "  Initial primes: " << initial_primes << "\n";
    cout << "  Remaining primes: " << remaining_primes << "\n";
    cout << "  ** DEPTH CONSUMED: " << depth_consumed << " **\n";
    cout << "  ** SPARE LEVELS: " << (remaining_primes - 1) << " **\n";
    //   -1 because one remaining prime is needed for decryption

    // =====================================================================
    //  Step 6: Decrypt and verify correctness
    // =====================================================================
    cout << "\n--- Decryption + correctness check ---\n";

    vector<uint64_t> he_decrypted = pasta_he.decrypt_result(he_result, /*batch_encoder=*/true);

    // Compare with original message
    bool correct = true;
    size_t mismatches = 0;
    for (size_t i = 0; i < min(message.size(), he_decrypted.size()); i++) {
        if (he_decrypted[i] != message[i]) {
            correct = false;
            mismatches++;
            if (mismatches <= 5) {
                cout << "  MISMATCH at [" << i << "]: expected "
                     << message[i] << ", got " << he_decrypted[i] << "\n";
            }
        }
    }

    cout << "  ** CORRECTNESS: " << (correct ? "PASS" : "FAIL")
         << " (" << mismatches << " mismatches out of " << message.size() << ") **\n";

    // =====================================================================
    //  Summary
    // =====================================================================
    cout << "\n==========================================================\n";
    cout << "  B0 RESULTS\n";
    cout << "  N = " << poly_modulus_degree << ", t = " << plain_mod << "\n";
    cout << "  log2(Q) = " << total_bits << " bits (" << initial_primes << " primes)\n";
    cout << "  Security: tc128 (accepted by SEAL)\n";
    cout << "  Pasta-4 depth consumed: " << depth_consumed << "\n";
    cout << "  Spare levels: " << (remaining_primes - 1) << "\n";
    cout << "  Transcipher time: " << transcipher_ms << " ms\n";
    cout << "  Correctness: " << (correct ? "PASS" : "FAIL") << "\n";
    cout << "==========================================================\n";

    if (correct && depth_consumed <= 10) {
        cout << "\n  *** B0 HARD GATE: PASS ***\n";
        cout << "  Proceed to B1.\n";
    } else if (!correct) {
        cout << "\n  *** B0 HARD GATE: FAIL (incorrect output) ***\n";
    } else {
        cout << "\n  *** B0 WARNING: depth " << depth_consumed
             << " > 10, investigate ***\n";
    }

    return correct ? 0 : 1;
}
