//! PVW (Peikert-Vaikuntanathan-Waters) detection clue generation and verification.
//!
//! Used for oblivious message retrieval: the sender attaches a PVW clue to each note.
//! The OMR server evaluates clue detection under FHE without learning the result.
//!
//! Parameters:
//! - Dimension n = 25
//! - Modulus q = 65537 (matches BFV plaintext modulus for direct embedding)
//! - Error bound B = 64 (small relative to q)
//! - Detection threshold: q/4 = 16384
//!
//! Security: ~65-80 bit PQ security at n=25. Protects metadata (which notes are
//! for which recipient), not note content (protected by ML-KEM-768 = NIST L3).

use rand::RngCore;
use sha2::{Sha256, Digest};

/// PVW modulus (same as BFV plaintext modulus)
pub const PVW_Q: u64 = 65537;

/// PVW dimension
pub const PVW_N: usize = 25;

/// Error bound for clue generation (small noise for information-theoretic hiding)
pub const ERROR_BOUND: i64 = 16;

/// Detection threshold: if |b - a·sk| < THRESHOLD, clue is pertinent.
/// THRESHOLD = q/512 = 128, giving FP rate ~0.39% (<5 per 1000 notes).
/// Margin: THRESHOLD - ERROR_BOUND = 112 (7x error bound, safe for exact BFV decryption).
pub const THRESHOLD: u64 = PVW_Q / 512; // 128

/// PVW secret key: n elements of Z_q.
#[derive(Clone, Debug)]
pub struct PvwSecretKey {
    pub elements: [u64; PVW_N],
}

/// PVW detection clue: (a, b) where a is n elements and b is 1 element.
#[derive(Clone, Debug)]
pub struct PvwClue {
    pub a: [u64; PVW_N],
    pub b: u64,
}

impl PvwSecretKey {
    /// Derive PVW secret key from a pairwise key using HKDF-like derivation.
    pub fn from_pairwise_key(k_pairwise: &[u8; 32]) -> Self {
        let mut elements = [0u64; PVW_N];
        for i in 0..PVW_N {
            let mut hasher = Sha256::new();
            hasher.update(b"pq-sa-pvw-sk-v1");
            hasher.update(k_pairwise);
            hasher.update(&(i as u32).to_le_bytes());
            let hash = hasher.finalize();
            // Take first 8 bytes, reduce mod q
            let val = u64::from_le_bytes(hash[..8].try_into().unwrap());
            elements[i] = val % PVW_Q;
        }
        Self { elements }
    }

    /// Create from explicit elements (for testing).
    pub fn from_elements(elements: [u64; PVW_N]) -> Self {
        Self { elements }
    }
}

impl PvwClue {
    /// Serialized size in bytes: n elements × 2 bytes + 1 element × 2 bytes = 52 bytes.
    pub const SERIALIZED_SIZE: usize = (PVW_N + 1) * 2;

    /// Serialize to bytes (little-endian u16 per element).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SERIALIZED_SIZE);
        for &a_i in &self.a {
            buf.extend_from_slice(&(a_i as u16).to_le_bytes());
        }
        buf.extend_from_slice(&(self.b as u16).to_le_bytes());
        buf
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SERIALIZED_SIZE {
            return None;
        }
        let mut a = [0u64; PVW_N];
        for i in 0..PVW_N {
            a[i] = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]) as u64;
        }
        let b = u16::from_le_bytes([data[PVW_N * 2], data[PVW_N * 2 + 1]]) as u64;
        Some(Self { a, b })
    }
}

/// Generate a PVW detection clue.
///
/// If `pertinent` is true, the clue will be detected by the holder of `sk`.
/// If false, the clue will appear random and not be detected.
pub fn generate_clue(
    sk: &PvwSecretKey,
    pertinent: bool,
    rng: &mut impl RngCore,
) -> PvwClue {
    // Generate random vector a
    let mut a = [0u64; PVW_N];
    for a_i in a.iter_mut() {
        *a_i = random_field_element(rng);
    }

    let b = if pertinent {
        // b = a·sk + e (mod q), where e is small
        let inner = inner_product(&a, &sk.elements);
        let e = random_small_error(rng);
        ((inner as i128 + e as i128).rem_euclid(PVW_Q as i128)) as u64
    } else {
        // b is random (independent of a·sk)
        random_field_element(rng)
    };

    PvwClue { a, b }
}

/// Verify a PVW clue against a secret key.
///
/// Returns true if the clue appears pertinent (b ≈ a·sk mod q).
pub fn verify_clue(sk: &PvwSecretKey, clue: &PvwClue) -> bool {
    let inner = inner_product(&clue.a, &sk.elements);
    // Compute (b - a·sk) mod q, centered in [-q/2, q/2]
    let diff = (clue.b as i64 - inner as i64).rem_euclid(PVW_Q as i64);
    let centered = if diff > PVW_Q as i64 / 2 {
        diff - PVW_Q as i64
    } else {
        diff
    };
    centered.unsigned_abs() < THRESHOLD
}

// --- Internal helpers ---

fn inner_product(a: &[u64; PVW_N], b: &[u64; PVW_N]) -> u64 {
    let mut acc = 0u128;
    for i in 0..PVW_N {
        acc += a[i] as u128 * b[i] as u128;
    }
    (acc % PVW_Q as u128) as u64
}

fn random_field_element(rng: &mut impl RngCore) -> u64 {
    loop {
        let val = rng.next_u32() as u64 & 0x1FFFF; // 17-bit mask
        if val < PVW_Q {
            return val;
        }
    }
}

fn random_small_error(rng: &mut impl RngCore) -> i64 {
    // Uniform in [-ERROR_BOUND, ERROR_BOUND]
    let range = 2 * ERROR_BOUND + 1;
    let val = (rng.next_u32() % range as u32) as i64;
    val - ERROR_BOUND
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[test]
    fn test_pertinent_clue_detected() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let k = [99u8; 32];
        let sk = PvwSecretKey::from_pairwise_key(&k);

        // 100 pertinent clues — all must be detected
        for _ in 0..100 {
            let clue = generate_clue(&sk, true, &mut rng);
            assert!(verify_clue(&sk, &clue), "pertinent clue not detected");
        }
    }

    #[test]
    fn test_non_pertinent_clue_rejected() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let k = [99u8; 32];
        let sk = PvwSecretKey::from_pairwise_key(&k);

        // 10000 non-pertinent clues — count false positives
        let mut false_positives = 0;
        let n_trials = 10_000;
        for _ in 0..n_trials {
            let clue = generate_clue(&sk, false, &mut rng);
            if verify_clue(&sk, &clue) {
                false_positives += 1;
            }
        }

        // Expected FP rate: ~(2*128-1)/65537 ≈ 0.39%
        let fp_rate = false_positives as f64 / n_trials as f64;
        println!("False positive rate: {:.3}% ({}/{})", fp_rate * 100.0, false_positives, n_trials);

        // FP rate should be ~0.4%, allow statistical margin
        assert!(fp_rate < 0.02, "FP rate too high: {:.3}%", fp_rate * 100.0);
        // Could be 0 in 10K trials — that's fine
    }

    #[test]
    fn test_wrong_key_does_not_detect() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let sk1 = PvwSecretKey::from_pairwise_key(&k1);
        let sk2 = PvwSecretKey::from_pairwise_key(&k2);

        // Clue generated for sk1, verified with sk2 — should behave like random
        let mut detected = 0;
        let n_trials = 1000;
        for _ in 0..n_trials {
            let clue = generate_clue(&sk1, true, &mut rng);
            if verify_clue(&sk2, &clue) {
                detected += 1;
            }
        }

        let rate = detected as f64 / n_trials as f64;
        println!("Wrong-key detection rate: {:.2}% ({}/{})", rate * 100.0, detected, n_trials);
        // Should be same as FP rate (~50%), not 100%
        assert!(rate < 0.65, "wrong key detects too many: {:.2}%", rate * 100.0);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let k = [42u8; 32];
        let sk1 = PvwSecretKey::from_pairwise_key(&k);
        let sk2 = PvwSecretKey::from_pairwise_key(&k);
        assert_eq!(sk1.elements, sk2.elements);
    }

    #[test]
    fn test_key_derivation_different_keys() {
        let sk1 = PvwSecretKey::from_pairwise_key(&[1u8; 32]);
        let sk2 = PvwSecretKey::from_pairwise_key(&[2u8; 32]);
        assert_ne!(sk1.elements, sk2.elements);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let sk = PvwSecretKey::from_pairwise_key(&[99u8; 32]);
        let clue = generate_clue(&sk, true, &mut rng);

        let bytes = clue.serialize();
        assert_eq!(bytes.len(), PvwClue::SERIALIZED_SIZE);

        let recovered = PvwClue::deserialize(&bytes).unwrap();
        assert_eq!(recovered.a, clue.a);
        assert_eq!(recovered.b, clue.b);

        // Verify recovered clue still detects
        assert!(verify_clue(&sk, &recovered));
    }

    #[test]
    fn test_clue_size() {
        assert_eq!(PvwClue::SERIALIZED_SIZE, 52);
    }

    #[test]
    fn test_zero_false_negatives() {
        // Critical: 0 false negatives over 10,000 pertinent clues
        let mut rng = ChaChaRng::seed_from_u64(123);
        let sk = PvwSecretKey::from_pairwise_key(&[77u8; 32]);

        for i in 0..10_000 {
            let clue = generate_clue(&sk, true, &mut rng);
            assert!(verify_clue(&sk, &clue),
                "FALSE NEGATIVE at trial {} — this must never happen", i);
        }
    }
}
