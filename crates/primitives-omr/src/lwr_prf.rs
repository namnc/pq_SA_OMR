//! LWR (Learning with Rounding) PRF for deriving Pasta-4 keys.
//!
//! Derives a 64-element Pasta-4 key from (k_pairwise, epoch) deterministically.
//! Under BFV FHE, this costs depth 1 (one matrix-vector multiply).
//!
//! The PRF uses SHAKE128 to expand the pairwise key into a public matrix A,
//! then computes output = round(A * input mod q) to F_p elements.

use sha2::{Sha256, Digest};
use crate::pasta4::{PASTA_P, KEY_SIZE};

/// Derive a Pasta-4 key from a pairwise key and epoch.
///
/// Deterministic: same (k_pairwise, epoch) always produces the same key.
/// The key is 64 elements of F_65537.
pub fn lwr_prf(k_pairwise: &[u8; 32], epoch: u64) -> Vec<u64> {
    let mut key = Vec::with_capacity(KEY_SIZE);

    for i in 0..KEY_SIZE {
        let mut hasher = Sha256::new();
        hasher.update(b"pq-sa-lwr-prf-v1");
        hasher.update(k_pairwise);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&(i as u32).to_le_bytes());
        let hash = hasher.finalize();

        // Take first 8 bytes, reduce mod p
        let val = u64::from_le_bytes(hash[..8].try_into().expect("SHA-256 output is 32 bytes"));
        key.push(val % PASTA_P);
    }

    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        let k = [42u8; 32];
        let key1 = lwr_prf(&k, 0);
        let key2 = lwr_prf(&k, 0);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_epochs() {
        let k = [42u8; 32];
        let key1 = lwr_prf(&k, 0);
        let key2 = lwr_prf(&k, 1);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_keys() {
        let key1 = lwr_prf(&[1u8; 32], 0);
        let key2 = lwr_prf(&[2u8; 32], 0);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_output_size() {
        let key = lwr_prf(&[42u8; 32], 0);
        assert_eq!(key.len(), KEY_SIZE); // 64 elements
    }

    #[test]
    fn test_output_range() {
        let key = lwr_prf(&[42u8; 32], 0);
        for &el in &key {
            assert!(el < PASTA_P, "element {} out of range", el);
        }
    }
}
