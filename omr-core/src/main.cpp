// omr-core: FHE evaluation binary for transciphered OMR.
//
// Subcommands:
//   omr-core keygen     — Generate BFV key pair + encrypt PVW sk
//   omr-core evaluate   — Run Pasta-4 transcipher + PVW detection on a batch of notes
//   omr-core decrypt    — Decrypt a BFV digest to plaintext
//
// This is a C++ binary called as a subprocess by the Rust omr-server.

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <cstdlib>
#include "seal/seal.h"
#include "pasta_4_seal.h"
#include "pasta_4_plain.h"
#include "pvw_he.h"

using namespace std;
using namespace seal;
using namespace PASTA_4;

// BFV parameters (same as B0 benchmark)
constexpr uint64_t PLAIN_MOD = 65537;
constexpr size_t POLY_MOD_DEGREE = 32768;

shared_ptr<SEALContext> create_context() {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(POLY_MOD_DEGREE);
    parms.set_plain_modulus(PLAIN_MOD);
    parms.set_coeff_modulus(CoeffModulus::Create(POLY_MOD_DEGREE,
        {54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54}));
    return make_shared<SEALContext>(parms, true, sec_level_type::tc128);
}

void cmd_keygen(const string& output_dir) {
    cout << "Generating BFV keys...\n";
    auto context = create_context();

    KeyGenerator keygen(*context);
    SecretKey sk = keygen.secret_key();
    PublicKey pk;
    keygen.create_public_key(pk);
    RelinKeys rk;
    keygen.create_relin_keys(rk);

    // Save keys
    {
        ofstream f(output_dir + "/secret_key.bin", ios::binary);
        sk.save(f);
    }
    {
        ofstream f(output_dir + "/public_key.bin", ios::binary);
        pk.save(f);
    }
    {
        ofstream f(output_dir + "/relin_keys.bin", ios::binary);
        rk.save(f);
    }

    cout << "Keys saved to " << output_dir << "/\n";
}

void cmd_evaluate_test(int num_notes, int num_pertinent) {
    // Self-contained test: generate keys, create notes, transcipher, detect
    cout << "=== OMR Evaluation Test ===\n";
    cout << "Notes: " << num_notes << ", Pertinent: " << num_pertinent << "\n\n";

    auto ctx = create_context();
    auto context = *ctx;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    // Generate random Pasta key and PVW secret key
    srand(42);
    vector<uint64_t> pasta_key(64);
    for (auto& k : pasta_key) k = rand() % PLAIN_MOD;

    vector<uint64_t> pvw_sk(omr::PVW_N);
    for (auto& s : pvw_sk) s = rand() % PLAIN_MOD;

    // Create Pasta-4 cipher objects
    PASTA pasta_plain(pasta_key, PLAIN_MOD);
    PASTA_SEAL pasta_he(pasta_key, ctx);

    // Setup Galois keys for Pasta-4 HE
    pasta_he.add_gk_indices();
    cout << "Generating Galois keys...\n";
    pasta_he.create_gk();
    pasta_he.encrypt_key(true);

    // Encrypt PVW secret key under BFV
    auto encrypted_pvw_sk = omr::encrypt_pvw_sk(pvw_sk, encryptor, encoder, slot_count);

    // Generate test notes
    cout << "Generating " << num_notes << " test notes...\n";
    struct Note {
        vector<uint64_t> pasta_ct;  // Pasta-encrypted signal
        vector<uint64_t> pvw_a;     // PVW clue a-vector
        uint64_t pvw_b;             // PVW clue b-value
        bool is_pertinent;
    };
    vector<Note> notes;

    for (int i = 0; i < num_notes; i++) {
        Note note;
        note.is_pertinent = (i < num_pertinent);

        // Create plaintext signal (32 elements)
        vector<uint64_t> signal(32);
        for (auto& s : signal) s = rand() % PLAIN_MOD;

        // Encrypt with Pasta-4
        note.pasta_ct = pasta_plain.encrypt(signal);

        // Generate PVW clue
        note.pvw_a.resize(omr::PVW_N);
        for (auto& a : note.pvw_a) a = rand() % PLAIN_MOD;

        if (note.is_pertinent) {
            // b = a·sk + e (small error)
            uint128_t inner = 0;
            for (size_t j = 0; j < omr::PVW_N; j++) {
                inner += (uint128_t)note.pvw_a[j] * pvw_sk[j];
            }
            int64_t e = (rand() % 33) - 16; // error in [-16, 16]
            note.pvw_b = ((int64_t)(inner % PLAIN_MOD) + e + PLAIN_MOD) % PLAIN_MOD;
        } else {
            note.pvw_b = rand() % PLAIN_MOD;
        }

        notes.push_back(note);
    }

    // === FHE Evaluation ===
    cout << "\n--- FHE Evaluation ---\n";
    auto t_start = chrono::high_resolution_clock::now();

    int detected_count = 0;
    int false_neg = 0;
    int false_pos = 0;

    for (int i = 0; i < num_notes; i++) {
        // Step 1: Pasta-4 HE transcipher (get FHE.Enc(signal))
        vector<Ciphertext> he_signal = pasta_he.HE_decrypt(notes[i].pasta_ct, true);

        // Step 2: PVW evaluation (plaintext-ciphertext multiply, depth 0)
        auto pvw_result = omr::evaluate_pvw(
            encrypted_pvw_sk, notes[i].pvw_a, notes[i].pvw_b,
            evaluator, encoder, relin_keys, slot_count);

        // Step 3: Decrypt PVW result and check locally
        Plaintext pt_result;
        decryptor.decrypt(pvw_result, pt_result);
        vector<uint64_t> result_slots;
        encoder.decode(pt_result, result_slots);

        // Sum slots 0..PVW_N-1 to get inner product a·sk
        uint64_t inner_sum = 0;
        for (size_t j = 0; j < omr::PVW_N; j++) {
            inner_sum = (inner_sum + result_slots[j]) % PLAIN_MOD;
        }

        // Check: |b - inner_sum| < threshold?
        int64_t diff = ((int64_t)notes[i].pvw_b - (int64_t)inner_sum) % (int64_t)PLAIN_MOD;
        if (diff < 0) diff += PLAIN_MOD;
        if (diff > (int64_t)PLAIN_MOD / 2) diff -= PLAIN_MOD;
        bool detected = (abs(diff) < (int64_t)omr::PVW_THRESHOLD);

        if (detected) detected_count++;
        if (notes[i].is_pertinent && !detected) false_neg++;
        if (!notes[i].is_pertinent && detected) false_pos++;
    }

    auto t_end = chrono::high_resolution_clock::now();
    double total_ms = chrono::duration_cast<chrono::milliseconds>(t_end - t_start).count();

    cout << "\n=== Results ===\n";
    cout << "Total time: " << total_ms << " ms\n";
    cout << "Per note: " << total_ms / num_notes << " ms\n";
    cout << "Detected: " << detected_count << "/" << num_notes << "\n";
    cout << "False negatives: " << false_neg << " (must be 0)\n";
    cout << "False positives: " << false_pos << "\n";
    cout << "Pertinent correctly detected: " << (num_pertinent - false_neg)
         << "/" << num_pertinent << "\n";

    if (false_neg == 0) {
        cout << "\n*** PASS: 0 false negatives ***\n";
    } else {
        cout << "\n*** FAIL: " << false_neg << " false negatives ***\n";
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Usage:\n";
        cout << "  omr-core keygen <output_dir>\n";
        cout << "  omr-core evaluate-test [num_notes] [num_pertinent]\n";
        return 1;
    }

    string cmd = argv[1];

    if (cmd == "keygen") {
        string dir = (argc > 2) ? argv[2] : "bfv_keys";
        cmd_keygen(dir);
    } else if (cmd == "evaluate-test") {
        int num_notes = (argc > 2) ? atoi(argv[2]) : 10;
        int num_pertinent = (argc > 3) ? atoi(argv[3]) : 3;
        cmd_evaluate_test(num_notes, num_pertinent);
    } else {
        cerr << "Unknown command: " << cmd << endl;
        return 1;
    }

    return 0;
}
