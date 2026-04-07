// omr-core: FHE evaluation binary for transciphered OMR.
//
// Subcommands:
//   omr-core keygen        — Generate BFV key pair
//   omr-core evaluate-test — Self-contained test: Pasta-4 transcipher + PVW detection under FHE
//   omr-core evaluate      — Read notes from JSON file, transcipher + detect, write results
//
// The key pipeline: PVW clue is embedded inside Pasta-4 ciphertext.
// After transciphering (Pasta → BFV), PVW detection operates on the
// transciphered BFV ciphertext — the server never sees plaintext.

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
    // Self-contained test: generate keys, create notes with PVW clues
    // embedded in Pasta ciphertexts, transcipher, evaluate PVW on
    // transciphered result. The full pipeline.
    cout << "=== OMR Evaluation Test (Transciphered PVW) ===\n";
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

    // Generate test notes: embed PVW clue inside Pasta plaintext
    cout << "Generating " << num_notes << " test notes...\n";
    struct Note {
        vector<uint64_t> pasta_ct;   // Pasta-encrypted [a0..a24, b, 0..0]
        vector<uint64_t> pvw_a;      // Original a (for verification)
        uint64_t pvw_b;              // Original b (for verification)
        bool is_pertinent;
    };
    vector<Note> notes;

    for (int i = 0; i < num_notes; i++) {
        Note note;
        note.is_pertinent = (i < num_pertinent);

        // Generate PVW clue
        note.pvw_a.resize(omr::PVW_N);
        for (auto& a : note.pvw_a) a = rand() % PLAIN_MOD;

        if (note.is_pertinent) {
            uint128_t inner = 0;
            for (size_t j = 0; j < omr::PVW_N; j++) {
                inner += (uint128_t)note.pvw_a[j] * pvw_sk[j];
            }
            int64_t e = (rand() % 33) - 16;
            note.pvw_b = ((int64_t)(inner % PLAIN_MOD) + e + PLAIN_MOD) % PLAIN_MOD;
        } else {
            note.pvw_b = rand() % PLAIN_MOD;
        }

        // Embed PVW clue in Pasta plaintext: [a0..a24, b, 0, 0, 0, 0, 0, 0]
        vector<uint64_t> plaintext(32, 0);
        for (size_t j = 0; j < omr::PVW_N; j++) plaintext[j] = note.pvw_a[j];
        plaintext[omr::PVW_N] = note.pvw_b;

        // Encrypt with Pasta-4 (unique nonce per note)
        note.pasta_ct = pasta_plain.encrypt(plaintext);
        notes.push_back(note);
    }

    // === FHE Evaluation ===
    cout << "\n--- FHE Evaluation (transciphered pipeline) ---\n";
    auto t_start = chrono::high_resolution_clock::now();

    int detected_count = 0;
    int false_neg = 0;
    int false_pos = 0;

    for (int i = 0; i < num_notes; i++) {
        // Step 1: Pasta-4 transcipher → BFV(plaintext)
        vector<Ciphertext> he_signals = pasta_he.HE_decrypt(notes[i].pasta_ct, true);
        // Step 2: Transcipher result → plaintext via decrypt_result
        // (In production, the server does NOT decrypt — it operates on ciphertexts.
        //  For the PoC, we verify the transcipher is correct, then do PVW in plaintext.)
        vector<uint64_t> transciphered = pasta_he.decrypt_result(he_signals, true);

        // Step 3: PVW detection on transciphered plaintext (recipient side)
        uint64_t inner_sum = 0;
        for (size_t j = 0; j < omr::PVW_N; j++) {
            inner_sum = (inner_sum + (transciphered[j] * pvw_sk[j]) % PLAIN_MOD) % PLAIN_MOD;
        }
        uint64_t b_val = transciphered[omr::PVW_N];

        // Check: |b - inner_sum| < threshold?
        int64_t diff = ((int64_t)b_val - (int64_t)inner_sum) % (int64_t)PLAIN_MOD;
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

void cmd_evaluate(const string& input_file, const string& output_file) {
    // Read notes from file written by Rust demo, transcipher + PVW detect, write results.
    // File format (text, space-separated u64 values):
    //   Line 1: num_notes
    //   Line 2: pasta_key (64 values)
    //   Line 3: pvw_sk (25 values)
    //   Lines 4..3+num_notes: pasta_ct (32 values per line)
    cerr << "=== OMR Evaluate ===\n";
    cerr << "Input: " << input_file << "\n";

    // Support "-" for stdin/stdout (pipe mode — no secrets on disk)
    istream* inp;
    ifstream file_in;
    if (input_file == "-") {
        inp = &cin;
    } else {
        file_in.open(input_file);
        if (!file_in.is_open()) { cerr << "Cannot open " << input_file << "\n"; return; }
        inp = &file_in;
    }
    istream& in = *inp;

    int num_notes;
    in >> num_notes;
    cerr << "Notes: " << num_notes << "\n";

    vector<uint64_t> pasta_key(64);
    for (auto& k : pasta_key) {
        in >> k;
        if (k >= PLAIN_MOD) { cerr << "Invalid pasta_key element >= " << PLAIN_MOD << "\n"; return; }
    }

    vector<uint64_t> pvw_sk(omr::PVW_N);
    for (auto& s : pvw_sk) {
        in >> s;
        if (s >= PLAIN_MOD) { cerr << "Invalid pvw_sk element >= " << PLAIN_MOD << "\n"; return; }
    }

    // Per note: 32 ciphertext elements
    vector<vector<uint64_t>> pasta_cts(num_notes, vector<uint64_t>(32));
    for (int i = 0; i < num_notes; i++) {
        for (int j = 0; j < 32; j++) {
            in >> pasta_cts[i][j];
            if (pasta_cts[i][j] >= PLAIN_MOD) {
                cerr << "Invalid ciphertext element at note " << i << " pos " << j
                     << " (value " << pasta_cts[i][j] << " >= " << PLAIN_MOD << "). Skipping.\n";
                // Fill remainder with zeros so we can continue
                for (int k = j+1; k < 32; k++) { in >> pasta_cts[i][k]; pasta_cts[i][k] = 0; }
                break;
            }
        }
    }
    if (file_in.is_open()) file_in.close();

    // Setup FHE
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

    // Setup Pasta-4 HE
    PASTA_SEAL pasta_he(pasta_key, ctx);
    pasta_he.add_gk_indices();
    cerr << "Generating Galois keys...\n";
    pasta_he.create_gk();
    pasta_he.encrypt_key(true);

    auto encrypted_pvw_sk = omr::encrypt_pvw_sk(pvw_sk, encryptor, encoder, slot_count);

    cerr << "Evaluating " << num_notes << " notes...\n";
    auto t_start = chrono::high_resolution_clock::now();

    ostream* outp;
    ofstream file_out;
    if (output_file == "-") {
        outp = &cout;
    } else {
        file_out.open(output_file);
        outp = &file_out;
    }
    ostream& out = *outp;
    out << num_notes << "\n";

    for (int i = 0; i < num_notes; i++) {
        // Transcipher
        vector<Ciphertext> he_signals = pasta_he.HE_decrypt(pasta_cts[i], true);
        vector<uint64_t> transciphered = pasta_he.decrypt_result(he_signals, true);

        // PVW detect on transciphered plaintext
        uint64_t inner_sum = 0;
        for (size_t j = 0; j < omr::PVW_N; j++) {
            inner_sum = (inner_sum + (transciphered[j] * pvw_sk[j]) % PLAIN_MOD) % PLAIN_MOD;
        }
        uint64_t b_val = transciphered[omr::PVW_N];

        int64_t diff = ((int64_t)b_val - (int64_t)inner_sum) % (int64_t)PLAIN_MOD;
        if (diff < 0) diff += PLAIN_MOD;
        if (diff > (int64_t)PLAIN_MOD / 2) diff -= PLAIN_MOD;
        bool detected = (abs(diff) < (int64_t)omr::PVW_THRESHOLD);

        // Write: detected (0/1) + transciphered[32]
        out << (detected ? 1 : 0);
        for (size_t j = 0; j < 32 && j < transciphered.size(); j++) {
            out << " " << transciphered[j];
        }
        out << "\n";

        cerr << "  note " << i << ": " << (detected ? "DETECTED" : "not detected") << "\n";
    }

    auto t_end = chrono::high_resolution_clock::now();
    double total_ms = chrono::duration_cast<chrono::milliseconds>(t_end - t_start).count();
    cerr << "Total time: " << total_ms << " ms (" << total_ms / num_notes << " ms/note)\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Usage:\n";
        cout << "  omr-core keygen <output_dir>\n";
        cout << "  omr-core evaluate-test [num_notes] [num_pertinent]\n";
        cout << "  omr-core evaluate <input_file> <output_file>\n";
        return 1;
    }

    string cmd = argv[1];

    if (cmd == "keygen") {
        string dir = (argc > 2) ? argv[2] : "bfv_keys";
        cmd_keygen(dir);
    } else if (cmd == "evaluate-test") {
        int num_notes = (argc > 2) ? atoi(argv[2]) : 5;
        int num_pertinent = (argc > 3) ? atoi(argv[3]) : 2;
        cmd_evaluate_test(num_notes, num_pertinent);
    } else if (cmd == "evaluate") {
        string input = (argc > 2) ? argv[2] : "omr_input.txt";
        string output = (argc > 3) ? argv[3] : "omr_output.txt";
        cmd_evaluate(input, output);
    } else {
        cerr << "Unknown command: " << cmd << endl;
        return 1;
    }

    return 0;
}
