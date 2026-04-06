//! End-to-end test: sender creates OMR note, recipient detects it.
//! Tests the full plaintext pipeline: LWR PRF → Pasta-4 encrypt → PVW clue → PVW verify.

use primitives_omr::*;
use rand::SeedableRng;
use rand::RngCore;
use rand_chacha::ChaChaRng;

#[test]
fn test_omr_sender_to_recipient_plaintext() {
    let mut rng = ChaChaRng::seed_from_u64(42);

    let k_pairwise = [77u8; 32];
    let epoch = 0u64;

    // === SENDER SIDE ===
    let pasta_key = lwr_prf::lwr_prf(&k_pairwise, epoch);
    let pasta = pasta4::Pasta::new(pasta_key.clone(), pasta4::PASTA_P);
    let pvw_sk = pvw::PvwSecretKey::from_pairwise_key(&k_pairwise);

    // Generate PVW clue and encrypt under Pasta-4 with per-note nonce
    let clue = pvw::generate_clue(&pvw_sk, true, &mut rng);
    let mut plaintext = vec![0u64; pasta4::PASTA_T];
    for (i, &a_i) in clue.a.iter().enumerate() { plaintext[i] = a_i; }
    plaintext[pvw::PVW_N] = clue.b;

    let mut nonce_bytes = [0u8; 8];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = u64::from_le_bytes(nonce_bytes);
    let pasta_ct = pasta.encrypt(&plaintext, nonce);
    assert_eq!(pasta_ct.len(), pasta4::PASTA_T);

    // === RECIPIENT SIDE ===
    let pvw_sk_recv = pvw::PvwSecretKey::from_pairwise_key(&k_pairwise);

    // Decrypt Pasta-4 → recover PVW clue
    let recovered = pasta.decrypt(&pasta_ct, nonce);
    let mut a = [0u64; pvw::PVW_N];
    a.copy_from_slice(&recovered[..pvw::PVW_N]);
    let recovered_clue = pvw::PvwClue { a, b: recovered[pvw::PVW_N] };

    assert!(pvw::verify_clue(&pvw_sk_recv, &recovered_clue), "pertinent clue not detected");
}

#[test]
fn test_omr_non_pertinent_not_detected() {
    let mut rng = ChaChaRng::seed_from_u64(99);

    let k_sender = [1u8; 32];
    let k_wrong = [2u8; 32];

    let pvw_sk_sender = pvw::PvwSecretKey::from_pairwise_key(&k_sender);
    let pvw_sk_wrong = pvw::PvwSecretKey::from_pairwise_key(&k_wrong);

    let clue = pvw::generate_clue(&pvw_sk_sender, true, &mut rng);
    assert!(pvw::verify_clue(&pvw_sk_sender, &clue));

    let mut wrong_detected = 0;
    for _ in 0..100 {
        let c = pvw::generate_clue(&pvw_sk_sender, true, &mut rng);
        if pvw::verify_clue(&pvw_sk_wrong, &c) {
            wrong_detected += 1;
        }
    }
    assert!(wrong_detected < 90, "wrong key detected too many: {}/100", wrong_detected);
}

#[test]
fn test_multiple_senders_multiple_notes() {
    let mut rng = ChaChaRng::seed_from_u64(42);

    let keys: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let epoch = 0u64;

    for (sender_idx, k) in keys.iter().enumerate() {
        let pasta_key = lwr_prf::lwr_prf(k, epoch);
        let pasta = pasta4::Pasta::new(pasta_key.clone(), pasta4::PASTA_P);
        let pvw_sk = pvw::PvwSecretKey::from_pairwise_key(k);

        for note_idx in 0..5u64 {
            // Generate PVW clue → encrypt under Pasta-4 with unique nonce
            let clue = pvw::generate_clue(&pvw_sk, true, &mut rng);
            let mut plaintext = vec![0u64; pasta4::PASTA_T];
            for (i, &a_i) in clue.a.iter().enumerate() { plaintext[i] = a_i; }
            plaintext[pvw::PVW_N] = clue.b;

            let nonce = (sender_idx as u64) * 1000 + note_idx;
            let ct = pasta.encrypt(&plaintext, nonce);

            // Recipient decrypts and verifies
            let recovered = pasta.decrypt(&ct, nonce);
            let mut a = [0u64; pvw::PVW_N];
            a.copy_from_slice(&recovered[..pvw::PVW_N]);
            let recovered_clue = pvw::PvwClue { a, b: recovered[pvw::PVW_N] };

            assert!(pvw::verify_clue(&pvw_sk, &recovered_clue),
                "sender {} note {} not detected", sender_idx, note_idx);
        }
    }
}

#[test]
fn test_pasta_different_nonces_different_ciphertexts() {
    let k = [42u8; 32];
    let epoch = 0u64;
    let pasta_key = lwr_prf::lwr_prf(&k, epoch);
    let pasta = pasta4::Pasta::new(pasta_key, pasta4::PASTA_P);

    let plaintext: Vec<u64> = (0..pasta4::PASTA_T).map(|i| i as u64).collect();
    let ct1 = pasta.encrypt(&plaintext, 1);
    let ct2 = pasta.encrypt(&plaintext, 2);
    assert_ne!(ct1, ct2, "different nonces must produce different ciphertexts");

    // Both decrypt correctly
    assert_eq!(pasta.decrypt(&ct1, 1), plaintext);
    assert_eq!(pasta.decrypt(&ct2, 2), plaintext);
}
