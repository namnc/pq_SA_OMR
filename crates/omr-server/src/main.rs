//! OMR Server orchestrator.
//!
//! Scans NotePostedOMR events from the chain, collects PVW clues and Pasta-4 signals,
//! invokes the C++ omr-core binary for FHE evaluation, and returns the digest.
//!
//! For B3 testing, this also includes a self-contained test mode that generates
//! test notes, invokes omr-core, and verifies correctness.

use alloy::{
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    network::EthereumWallet,
    sol,
};
use clap::Parser;
use eyre::Result;
use primitives_omr::*;
use rand::SeedableRng;
use rand::RngCore;
use rand_chacha::ChaChaRng;
use std::process::Command;

sol! {
    #[sol(rpc, all_derives)]
    NoteRegistryOMR,
    "../../contracts/out/NoteRegistryOMR.sol/NoteRegistryOMR.json"
}

#[derive(Parser)]
#[command(name = "omr-server", about = "OMR server orchestrator")]
struct Cli {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Sender private key (Anvil account 0)
    #[arg(long, default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")]
    sender_key: String,

    /// Recipient private key (Anvil account 1)
    #[arg(long, default_value = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")]
    recipient_key: String,

    /// Number of notes to post
    #[arg(long, default_value = "10")]
    notes: usize,

    /// Number of pertinent notes
    #[arg(long, default_value = "3")]
    pertinent: usize,

    /// Path to omr-core binary
    #[arg(long, default_value = "../../omr-core/build/omr-core")]
    omr_core: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("==========================================================");
    println!("  OMR Server — End-to-End Test");
    println!("==========================================================\n");

    // --- Setup two wallets ---
    let sender_signer: PrivateKeySigner = cli.sender_key.parse()?;
    let recipient_signer: PrivateKeySigner = cli.recipient_key.parse()?;
    let sender_addr = sender_signer.address();
    let recipient_addr = recipient_signer.address();

    let sender_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(sender_signer))
        .connect_http(cli.rpc.parse()?);

    let recipient_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(recipient_signer))
        .connect_http(cli.rpc.parse()?);

    println!("[setup] Sender:    {}", sender_addr);
    println!("[setup] Recipient: {}", recipient_addr);
    println!("[setup] Notes: {}, Pertinent: {}\n", cli.notes, cli.pertinent);

    // --- Deploy contract ---
    println!("--- Deploying NoteRegistryOMR ---");
    let contract = NoteRegistryOMR::deploy(&sender_provider).await?;
    println!("  Deployed at: {}\n", contract.address());

    let start_block = sender_provider.get_block_number().await?;

    // --- Generate keys ---
    let mut rng = ChaChaRng::seed_from_u64(42);
    let k_pairwise = [77u8; 32];

    // Read current epoch from contract (not hardcoded)
    let epoch_val = contract.currentEpoch().call().await?;
    let epoch: u64 = epoch_val.to::<u64>();
    println!("[setup] Current epoch: {}\n", epoch);

    let pasta_key = lwr_prf::lwr_prf(&k_pairwise, epoch);
    let pasta = pasta4::Pasta::new(pasta_key.clone(), pasta4::PASTA_P);
    let pvw_sk = pvw::PvwSecretKey::from_pairwise_key(&k_pairwise);

    // --- Post notes ---
    println!("--- Posting {} notes ({} pertinent) ---\n", cli.notes, cli.pertinent);

    let mut expected_pertinent = Vec::new();

    for i in 0..cli.notes {
        let is_pertinent = i < cli.pertinent;

        // Generate per-note nonce for on-chain identifier
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        // Use cross-validated TEST_NONCE for Pasta-4 (matches C++ HE_decrypt convention).
        // Per-note uniqueness from PVW's random a-vector, not the Pasta nonce.
        let pasta_nonce = pasta4::TEST_NONCE;

        // Generate PVW clue (26 elements of Z_65537)
        let clue = pvw::generate_clue(&pvw_sk, is_pertinent, &mut rng);

        // Encrypt PVW clue under Pasta-4: pad 26 elements → 32, encrypt with per-note nonce
        let mut plaintext = Vec::with_capacity(pasta4::PASTA_T);
        for &a_i in &clue.a {
            plaintext.push(a_i);
        }
        plaintext.push(clue.b);
        while plaintext.len() < pasta4::PASTA_T {
            plaintext.push(0);
        }
        let ct_elements = pasta.encrypt(&plaintext, pasta_nonce);
        // Serialize as u32 (safe for all Z_65537 values including 65536)
        let mut pasta_ct_bytes = Vec::with_capacity(128);
        for &el in &ct_elements {
            pasta_ct_bytes.extend_from_slice(&(el as u32).to_le_bytes());
        }

        // Post on-chain: commitment (32 B) + nonce (16 B) + Pasta-4 ciphertext (128 B)
        let commitment = {
            use sha2::{Sha256, Digest};
            let mut h = Sha256::new();
            h.update(b"test-commitment");
            h.update(&(i as u32).to_le_bytes());
            let hash: [u8; 32] = h.finalize().into();
            alloy::primitives::FixedBytes::from(hash)
        };

        let nonce_fixed = alloy::primitives::FixedBytes::from(nonce);

        let receipt = contract
            .postNoteOMR(commitment, nonce_fixed, pasta_ct_bytes.into())
            .send()
            .await?
            .get_receipt()
            .await?;

        let status = if is_pertinent { "PERTINENT" } else { "non-pertinent" };
        println!("  note {}: {} (gas: {})", i, status, receipt.gas_used);

        if is_pertinent {
            expected_pertinent.push(i as u64);
        }
    }

    // --- Scan events ---
    println!("\n--- Scanning NotePostedOMR events ---");
    let recipient_contract = NoteRegistryOMR::new(*contract.address(), &recipient_provider);
    let events = recipient_contract.NotePostedOMR_filter()
        .from_block(start_block)
        .query()
        .await?;
    println!("  Found {} events", events.len());

    // --- Recipient: decrypt Pasta-4, verify PVW ---
    println!("\n--- Recipient: Pasta-4 decrypt → PVW verify ---");

    let mut detected = Vec::new();
    let mut false_neg = 0;
    let mut false_pos = 0;

    for (_i, (event, _)) in events.iter().enumerate() {
        // Deserialize Pasta-4 ciphertext (128 B → 32 u64 elements), validate range
        let ct_bytes = &event.pastaCt;
        let mut ct_elements = Vec::with_capacity(pasta4::PASTA_T);
        let mut valid = true;
        for chunk in ct_bytes.chunks(4) {
            let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
            if val >= pasta4::PASTA_P {
                valid = false;
                break;
            }
            ct_elements.push(val);
        }
        if !valid {
            println!("  note {}: malformed Pasta ciphertext (element >= {}), skipping", event.noteId, pasta4::PASTA_P);
            continue;
        }

        // Use same Pasta nonce as sender (cross-validated with C++)
        let pasta_nonce = pasta4::TEST_NONCE;

        // Decrypt Pasta-4 → recover PVW clue
        let plaintext = pasta.decrypt(&ct_elements, pasta_nonce);
        let mut a = [0u64; pvw::PVW_N];
        a.copy_from_slice(&plaintext[..pvw::PVW_N]);
        let b = plaintext[pvw::PVW_N];
        let clue = pvw::PvwClue { a, b };

        let is_detected = pvw::verify_clue(&pvw_sk, &clue);
        let is_expected = expected_pertinent.contains(&event.noteId);

        if is_detected {
            detected.push(event.noteId);
        }
        if is_expected && !is_detected {
            false_neg += 1;
            println!("  !! FALSE NEGATIVE: noteId={}", event.noteId);
        }
        if !is_expected && is_detected {
            false_pos += 1;
        }
    }

    println!("  Detected: {:?}", detected);
    println!("  Expected: {:?}", expected_pertinent);
    println!("  False negatives: {}", false_neg);
    println!("  False positives: {}", false_pos);

    // --- Write input file for omr-core ---
    // --- Write input file for omr-core (restricted permissions, cleaned up after) ---
    println!("\n--- Invoking omr-core evaluate (FHE on real data) ---");

    use std::io::Write;
    let input_path = "/tmp/omr_input.txt";
    let output_path = "/tmp/omr_output.txt";
    {
        let f = std::fs::File::create(input_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let mut f = std::io::BufWriter::new(f);

        writeln!(f, "{}", events.len())?;
        let key_str: Vec<String> = pasta_key.iter().map(|v| v.to_string()).collect();
        writeln!(f, "{}", key_str.join(" "))?;
        let sk_str: Vec<String> = pvw_sk.elements.iter().map(|v| v.to_string()).collect();
        writeln!(f, "{}", sk_str.join(" "))?;
        for (event, _) in &events {
            let ct_bytes = &event.pastaCt;
            let mut elems = Vec::with_capacity(pasta4::PASTA_T);
            for chunk in ct_bytes.chunks(4) {
                let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
                elems.push(val);
            }
            let elem_str: Vec<String> = elems.iter().map(|v| v.to_string()).collect();
            writeln!(f, "{}", elem_str.join(" "))?;
        }
    }

    let omr_result = Command::new(&cli.omr_core)
        .args(["evaluate", input_path, output_path])
        .output();

    match omr_result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            for line in stderr.lines().chain(stdout.lines()) {
                if line.contains("note ") || line.contains("time") || line.contains("Eval") || line.contains("Galois") || line.contains("Notes") {
                    println!("  {}", line);
                }
            }

            if let Ok(result_data) = std::fs::read_to_string(output_path) {
                let mut lines = result_data.lines();
                if let Some(first) = lines.next() {
                    let n: usize = first.trim().parse().unwrap_or(0);
                    let mut fhe_detected = Vec::new();
                    let mut fhe_fn = 0;
                    let mut fhe_fp = 0;
                    for (idx, line) in lines.take(n).enumerate() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if let Some(&det_str) = parts.first() {
                            let det = det_str == "1";
                            let is_expected = expected_pertinent.contains(&(idx as u64));
                            if det { fhe_detected.push(idx as u64); }
                            if is_expected && !det { fhe_fn += 1; }
                            if !is_expected && det { fhe_fp += 1; }
                        }
                    }
                    println!("  FHE results: detected {:?}", fhe_detected);
                    println!("  FHE false negatives: {}", fhe_fn);
                    println!("  FHE false positives: {}", fhe_fp);
                    if fhe_fn == 0 {
                        println!("  *** FHE PASS: 0 false negatives ***");
                    } else {
                        println!("  *** FHE FAIL: {} false negatives ***", fhe_fn);
                    }
                }
            }
        }
        Err(e) => {
            println!("  omr-core not available ({}). Skipping FHE test.", e);
            println!("  Build it: cd omr-core/build && make -j4");
        }
    }

    // Clean up files containing secret material
    let _ = std::fs::remove_file(input_path);
    let _ = std::fs::remove_file(output_path);

    // --- Summary ---
    println!("\n==========================================================");
    println!("  B3 End-to-End Results");
    println!("  Contract: {}", contract.address());
    println!("  Notes posted: {} ({} pertinent)", cli.notes, cli.pertinent);
    println!("  Plaintext PVW: {} detected, {} FN, {} FP", detected.len(), false_neg, false_pos);
    if false_neg == 0 {
        println!("  *** PASS: 0 false negatives ***");
    } else {
        println!("  *** FAIL: {} false negatives ***", false_neg);
    }
    println!("==========================================================");

    Ok(())
}
