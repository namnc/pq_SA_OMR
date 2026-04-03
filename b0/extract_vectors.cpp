// Extract Pasta-4 test vectors for Rust cross-validation
// Outputs JSON with 100 encrypt/decrypt pairs at t=65537

#include <iostream>
#include <vector>
#include <cstdlib>
#include <ctime>
#include "pasta_4_plain.h"

using namespace std;
using namespace PASTA_4;

int main() {
    uint64_t modulus = 65537;
    int num_vectors = 100;

    // Fixed seed for reproducibility
    srand(42);

    // Generate a fixed key (64 elements)
    vector<uint64_t> key(64);
    for (int i = 0; i < 64; i++) {
        key[i] = rand() % modulus;
    }

    PASTA pasta(key, modulus);

    cout << "{\n";
    cout << "  \"modulus\": " << modulus << ",\n";
    cout << "  \"key\": [";
    for (int i = 0; i < 64; i++) {
        if (i > 0) cout << ", ";
        cout << key[i];
    }
    cout << "],\n";
    cout << "  \"vectors\": [\n";

    for (int v = 0; v < num_vectors; v++) {
        // Generate plaintext (32 elements)
        vector<uint64_t> plaintext(32);
        for (int i = 0; i < 32; i++) {
            plaintext[i] = rand() % modulus;
        }

        // Encrypt
        vector<uint64_t> ciphertext = pasta.encrypt(plaintext);

        // Verify decrypt
        vector<uint64_t> decrypted = pasta.decrypt(ciphertext);
        for (int i = 0; i < 32; i++) {
            if (decrypted[i] != plaintext[i]) {
                cerr << "ERROR: roundtrip failed at vector " << v << " index " << i << endl;
                return 1;
            }
        }

        cout << "    {\n";
        cout << "      \"plaintext\": [";
        for (int i = 0; i < 32; i++) {
            if (i > 0) cout << ", ";
            cout << plaintext[i];
        }
        cout << "],\n";
        cout << "      \"ciphertext\": [";
        for (size_t i = 0; i < ciphertext.size(); i++) {
            if (i > 0) cout << ", ";
            cout << ciphertext[i];
        }
        cout << "]\n";
        cout << "    }";
        if (v < num_vectors - 1) cout << ",";
        cout << "\n";
    }

    cout << "  ]\n";
    cout << "}\n";

    cerr << "Generated " << num_vectors << " test vectors (all roundtrips verified)" << endl;

    return 0;
}
