//! Pasta-4 symmetric cipher over F_65537.
//!
//! Deterministic stream cipher: each (key, nonce, block_counter) produces
//! a unique 32-element keystream block over F_p where p = 65537.
//!
//! Structure: 4 rounds, each with linear_layer + S-box.
//! Rounds 0-2: sbox_feistel (depth 1 under BFV)
//! Round 3: sbox_cube (depth 2 under BFV)
//! Final: linear_layer (no S-box)
//!
//! Cross-validated against the C++ reference in hybrid-HE-framework.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;

/// Plaintext modulus (Fermat prime F4 = 2^16 + 1)
pub const PASTA_P: u64 = 65537;

/// State size (number of field elements per half-state)
pub const PASTA_T: usize = 32;

/// Number of rounds
pub const PASTA_R: usize = 4;

/// Key size (two half-states)
pub const KEY_SIZE: usize = PASTA_T * 2; // 64

type Block = [u64; PASTA_T];

/// Pasta-4 cipher instance.
pub struct Pasta {
    key: Vec<u64>,
    modulus: u64,
    max_prime_mask: u64,
}

/// SHAKE128-based random generator for matrix/RC derivation.
struct PastaShake {
    reader: sha3::Shake128Reader,
    max_prime_mask: u64,
    modulus: u64,
}

impl PastaShake {
    fn new(nonce: u64, block_counter: u64, modulus: u64, max_prime_mask: u64) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(&nonce.to_be_bytes());
        hasher.update(&block_counter.to_be_bytes());
        let reader = hasher.finalize_xof();
        Self { reader, max_prime_mask, modulus }
    }

    /// Generate a random field element via rejection sampling.
    fn random_field_element(&mut self, allow_zero: bool) -> u64 {
        loop {
            let mut buf = [0u8; 8];
            self.reader.read(&mut buf);
            let ele = u64::from_be_bytes(buf) & self.max_prime_mask;
            if !allow_zero && ele == 0 {
                continue;
            }
            if ele < self.modulus {
                return ele;
            }
        }
    }

    /// Generate a random vector of PASTA_T field elements.
    fn random_vector(&mut self, allow_zero: bool) -> Vec<u64> {
        (0..PASTA_T).map(|_| self.random_field_element(allow_zero)).collect()
    }
}

impl Pasta {
    pub fn new(key: Vec<u64>, modulus: u64) -> Self {
        assert_eq!(key.len(), KEY_SIZE, "key must be {} elements", KEY_SIZE);
        // Compute bitmask: smallest mask covering modulus
        let mut mask = 0u64;
        let mut p = modulus;
        while p > 0 {
            mask += 1;
            p >>= 1;
        }
        mask = (1u64 << mask) - 1;

        Self { key, modulus, max_prime_mask: mask }
    }

    /// Generate keystream block for (nonce, block_counter).
    pub fn keystream(&self, nonce: u64, block_counter: u64) -> Block {
        let mut shake = PastaShake::new(nonce, block_counter, self.modulus, self.max_prime_mask);

        // Initialize state from key
        let mut state1 = [0u64; PASTA_T];
        let mut state2 = [0u64; PASTA_T];
        for i in 0..PASTA_T {
            state1[i] = self.key[i];
            state2[i] = self.key[PASTA_T + i];
        }

        // 4 rounds
        for r in 0..PASTA_R {
            Self::linear_layer(&mut state1, &mut state2, &mut shake, self.modulus);
            if r == PASTA_R - 1 {
                Self::sbox_cube(&mut state1, self.modulus);
                Self::sbox_cube(&mut state2, self.modulus);
            } else {
                Self::sbox_feistel(&mut state1, self.modulus);
                Self::sbox_feistel(&mut state2, self.modulus);
            }
        }

        // Final linear layer (no S-box)
        Self::linear_layer(&mut state1, &mut state2, &mut shake, self.modulus);

        state1
    }

    /// Encrypt plaintext (additive stream cipher).
    pub fn encrypt(&self, plaintext: &[u64]) -> Vec<u64> {
        let nonce: u64 = 123456789; // Fixed nonce (matches C++ reference)
        let block_size = PASTA_T; // 32 elements per block
        let mut ciphertext = Vec::with_capacity(plaintext.len());

        for (b, chunk) in plaintext.chunks(block_size).enumerate() {
            let ks = self.keystream(nonce, b as u64);
            for (i, &pt) in chunk.iter().enumerate() {
                ciphertext.push((pt + ks[i]) % self.modulus);
            }
        }
        ciphertext
    }

    /// Decrypt ciphertext (subtractive stream cipher).
    pub fn decrypt(&self, ciphertext: &[u64]) -> Vec<u64> {
        let nonce: u64 = 123456789;
        let block_size = PASTA_T;
        let mut plaintext = Vec::with_capacity(ciphertext.len());

        for (b, chunk) in ciphertext.chunks(block_size).enumerate() {
            let ks = self.keystream(nonce, b as u64);
            for (i, &ct) in chunk.iter().enumerate() {
                let pt = if ks[i] > ct {
                    ct + self.modulus - ks[i]
                } else {
                    ct - ks[i]
                };
                plaintext.push(pt);
            }
        }
        plaintext
    }

    // --- Internal operations ---

    fn sbox_cube(state: &mut Block, p: u64) {
        for el in state.iter_mut() {
            let sq = (*el as u128 * *el as u128) % p as u128;
            *el = (sq * *el as u128 % p as u128) as u64;
        }
    }

    fn sbox_feistel(state: &mut Block, p: u64) {
        let mut new_state = [0u64; PASTA_T];
        new_state[0] = state[0];
        for i in 1..PASTA_T {
            let sq = (state[i - 1] as u128 * state[i - 1] as u128) % p as u128;
            new_state[i] = ((sq + state[i] as u128) % p as u128) as u64;
        }
        *state = new_state;
    }

    fn linear_layer(state1: &mut Block, state2: &mut Block, shake: &mut PastaShake, p: u64) {
        Self::matmul(state1, shake, p);
        Self::matmul(state2, shake, p);
        Self::add_rc(state1, shake, p);
        Self::add_rc(state2, shake, p);
        Self::mix(state1, state2, p);
    }

    fn matmul(state: &mut Block, shake: &mut PastaShake, p: u64) {
        let mut new_state = [0u64; PASTA_T];

        // First row (non-zero elements)
        let first_row = shake.random_vector(false);
        let mut curr_row = first_row.clone();

        for i in 0..PASTA_T {
            let mut acc = 0u128;
            for j in 0..PASTA_T {
                acc += curr_row[j] as u128 * state[j] as u128;
            }
            new_state[i] = (acc % p as u128) as u64;

            if i != PASTA_T - 1 {
                curr_row = Self::calculate_row(&curr_row, &first_row, p);
            }
        }
        *state = new_state;
    }

    fn calculate_row(prev_row: &[u64], first_row: &[u64], p: u64) -> Vec<u64> {
        let mut out = vec![0u64; PASTA_T];
        for j in 0..PASTA_T {
            let tmp = (first_row[j] as u128 * prev_row[PASTA_T - 1] as u128) % p as u128;
            if j > 0 {
                out[j] = ((tmp + prev_row[j - 1] as u128) % p as u128) as u64;
            } else {
                out[j] = tmp as u64;
            }
        }
        out
    }

    fn add_rc(state: &mut Block, shake: &mut PastaShake, p: u64) {
        for el in state.iter_mut() {
            let rc = shake.random_field_element(true);
            *el = ((*el as u128 + rc as u128) % p as u128) as u64;
        }
    }

    fn mix(state1: &mut Block, state2: &mut Block, p: u64) {
        for i in 0..PASTA_T {
            let sum = ((state1[i] as u128 + state2[i] as u128) % p as u128) as u64;
            state1[i] = ((state1[i] as u128 + sum as u128) % p as u128) as u64;
            state2[i] = ((state2[i] as u128 + sum as u128) % p as u128) as u64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::path::Path;

    #[derive(Deserialize)]
    struct TestVectors {
        modulus: u64,
        key: Vec<u64>,
        vectors: Vec<TestVector>,
    }

    #[derive(Deserialize)]
    struct TestVector {
        plaintext: Vec<u64>,
        ciphertext: Vec<u64>,
    }

    fn load_test_vectors() -> TestVectors {
        // Try multiple paths (run from workspace root or crate dir)
        let paths = [
            "../../test_vectors_pasta4.json",
            "test_vectors_pasta4.json",
        ];
        for p in &paths {
            if Path::new(p).exists() {
                let data = std::fs::read_to_string(p).unwrap();
                return serde_json::from_str(&data).unwrap();
            }
        }
        panic!("test_vectors_pasta4.json not found — run extract_vectors first");
    }

    #[test]
    fn test_encrypt_matches_cpp() {
        let tv = load_test_vectors();
        let pasta = Pasta::new(tv.key.clone(), tv.modulus);

        for (i, v) in tv.vectors.iter().enumerate() {
            let ct = pasta.encrypt(&v.plaintext);
            assert_eq!(ct, v.ciphertext,
                "encrypt mismatch at vector {}: expected {:?}, got {:?}",
                i, &v.ciphertext[..4], &ct[..4]);
        }
    }

    #[test]
    fn test_decrypt_matches_cpp() {
        let tv = load_test_vectors();
        let pasta = Pasta::new(tv.key.clone(), tv.modulus);

        for (i, v) in tv.vectors.iter().enumerate() {
            let pt = pasta.decrypt(&v.ciphertext);
            assert_eq!(pt, v.plaintext,
                "decrypt mismatch at vector {}", i);
        }
    }

    #[test]
    fn test_roundtrip() {
        let tv = load_test_vectors();
        let pasta = Pasta::new(tv.key.clone(), tv.modulus);

        for (i, v) in tv.vectors.iter().enumerate() {
            let ct = pasta.encrypt(&v.plaintext);
            let pt = pasta.decrypt(&ct);
            assert_eq!(pt, v.plaintext, "roundtrip failed at vector {}", i);
        }
    }

    #[test]
    fn test_keystream_deterministic() {
        let key: Vec<u64> = (0..64).map(|i| i * 1000 % PASTA_P).collect();
        let pasta = Pasta::new(key, PASTA_P);

        let ks1 = pasta.keystream(42, 0);
        let ks2 = pasta.keystream(42, 0);
        assert_eq!(ks1, ks2, "keystream must be deterministic");

        let ks3 = pasta.keystream(42, 1);
        assert_ne!(ks1, ks3, "different block_counter must produce different keystream");
    }

    #[test]
    fn test_sbox_cube() {
        let p = PASTA_P;
        let mut state = [0u64; PASTA_T];
        state[0] = 2; // 2^3 = 8
        state[1] = 3; // 3^3 = 27
        state[2] = 256; // 256^3 mod 65537
        Pasta::sbox_cube(&mut state, p);
        assert_eq!(state[0], 8);
        assert_eq!(state[1], 27);
        assert_eq!(state[2], (256u128 * 256 % p as u128 * 256 % p as u128) as u64);
    }

    #[test]
    fn test_sbox_feistel() {
        let p = PASTA_P;
        let mut state = [0u64; PASTA_T];
        state[0] = 5;
        state[1] = 10;
        state[2] = 20;
        Pasta::sbox_feistel(&mut state, p);
        assert_eq!(state[0], 5); // unchanged
        assert_eq!(state[1], (5 * 5 + 10) % p); // 35
        // state[2] = state[1]_old^2 + state[2]_old = 10^2 + 20 = 120
        // Note: feistel uses ORIGINAL state values, not the new ones
        assert_eq!(state[2], (10 * 10 + 20) % p); // 120
    }
}
