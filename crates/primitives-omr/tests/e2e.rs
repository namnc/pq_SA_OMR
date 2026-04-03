//! End-to-end test: sender creates OMR note, recipient detects it.
//! Tests the full plaintext pipeline: LWR PRF → Pasta-4 encrypt → PVW clue → PVW verify.

use primitives_omr::*;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

#[test]
fn test_omr_sender_to_recipient_plaintext() {
    let mut rng = ChaChaRng::seed_from_u64(42);

    // Simulate k_pairwise from PoC A hybrid KEM
    let k_pairwise = [77u8; 32];
    let epoch = 0u64;

    // === SENDER SIDE ===

    // Derive Pasta-4 key from k_pairwise
    let pasta_key = lwr_prf::lwr_prf(&k_pairwise, epoch);
    assert_eq!(pasta_key.len(), pasta4::KEY_SIZE);

    // Create a detection signal (32 elements, could be key derivation metadata)
    let signal: Vec<u64> = (0..pasta4::PASTA_T).map(|i| (i as u64 * 1000) % pasta4::PASTA_P).collect();

    // Encrypt signal with Pasta-4
    let pasta_ct = {
        let pasta = pasta4::Pasta::new(pasta_key.clone(), pasta4::PASTA_P);
        pasta.encrypt(&signal)
    };
    assert_eq!(pasta_ct.len(), pasta4::PASTA_T);

    // Derive PVW secret key from k_pairwise
    let pvw_sk = pvw::PvwSecretKey::from_pairwise_key(&k_pairwise);

    // Generate pertinent PVW clue
    let clue = pvw::generate_clue(&pvw_sk, true, &mut rng);

    // === RECIPIENT SIDE ===

    // Recipient also derives PVW secret key from the same k_pairwise
    let pvw_sk_recv = pvw::PvwSecretKey::from_pairwise_key(&k_pairwise);
    assert_eq!(pvw_sk.elements, pvw_sk_recv.elements);

    // Verify PVW clue → should detect as pertinent
    assert!(pvw::verify_clue(&pvw_sk_recv, &clue), "pertinent clue not detected");

    // Decrypt Pasta-4 ciphertext to recover signal
    let recovered_signal = {
        let pasta = pasta4::Pasta::new(pasta_key.clone(), pasta4::PASTA_P);
        pasta.decrypt(&pasta_ct)
    };
    assert_eq!(recovered_signal, signal, "signal mismatch after Pasta-4 decrypt");
}

#[test]
fn test_omr_non_pertinent_not_detected() {
    let mut rng = ChaChaRng::seed_from_u64(99);

    let k_sender = [1u8; 32];
    let k_wrong = [2u8; 32];

    // Sender's PVW key
    let pvw_sk_sender = pvw::PvwSecretKey::from_pairwise_key(&k_sender);

    // Wrong recipient's PVW key
    let pvw_sk_wrong = pvw::PvwSecretKey::from_pairwise_key(&k_wrong);

    // Generate clue for the sender's recipient (pertinent for k_sender, not for k_wrong)
    let clue = pvw::generate_clue(&pvw_sk_sender, true, &mut rng);

    // Correct recipient detects it
    assert!(pvw::verify_clue(&pvw_sk_sender, &clue));

    // Wrong recipient: detection behaves like random (should not reliably detect)
    // We can't assert !verify_clue because FP rate is ~50%, but we can check
    // that over many trials, the wrong key doesn't detect 100%
    let mut wrong_detected = 0;
    for _ in 0..100 {
        let c = pvw::generate_clue(&pvw_sk_sender, true, &mut rng);
        if pvw::verify_clue(&pvw_sk_wrong, &c) {
            wrong_detected += 1;
        }
    }
    // Should be ~50% (random), definitely not 100%
    assert!(wrong_detected < 90, "wrong key detected too many: {}/100", wrong_detected);
}

#[test]
fn test_multiple_senders_multiple_notes() {
    let mut rng = ChaChaRng::seed_from_u64(42);

    // 3 senders, each with a different k_pairwise to the same recipient
    let keys: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let epoch = 0u64;

    for (sender_idx, k) in keys.iter().enumerate() {
        // Derive per-sender keys
        let pasta_key = lwr_prf::lwr_prf(k, epoch);
        let pvw_sk = pvw::PvwSecretKey::from_pairwise_key(k);

        // Send 5 notes per sender
        for note_idx in 0..5 {
            // Create signal
            let signal: Vec<u64> = (0..32).map(|i| {
                ((sender_idx as u64 * 1000 + note_idx * 100 + i as u64) % pasta4::PASTA_P)
            }).collect();

            // Encrypt with Pasta-4
            let pasta = pasta4::Pasta::new(pasta_key.clone(), pasta4::PASTA_P);
            let ct = pasta.encrypt(&signal);

            // Generate PVW clue
            let clue = pvw::generate_clue(&pvw_sk, true, &mut rng);

            // Recipient verifies
            assert!(pvw::verify_clue(&pvw_sk, &clue),
                "sender {} note {} not detected", sender_idx, note_idx);

            // Recipient decrypts
            let recovered = pasta.decrypt(&ct);
            assert_eq!(recovered, signal,
                "sender {} note {} signal mismatch", sender_idx, note_idx);
        }
    }
}

#[test]
fn test_pvw_clue_serialization_in_pipeline() {
    let mut rng = ChaChaRng::seed_from_u64(42);
    let k = [42u8; 32];
    let pvw_sk = pvw::PvwSecretKey::from_pairwise_key(&k);

    // Generate clue, serialize (what goes on calldata), deserialize, verify
    let clue = pvw::generate_clue(&pvw_sk, true, &mut rng);
    let bytes = clue.serialize();
    assert_eq!(bytes.len(), 52); // matches contract pvwClue length

    let recovered = pvw::PvwClue::deserialize(&bytes).unwrap();
    assert!(pvw::verify_clue(&pvw_sk, &recovered));
}
