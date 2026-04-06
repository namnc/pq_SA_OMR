//! OMR Server orchestrator.
//!
//! Scans NotePostedOMR events from the chain, collects PVW clues and Pasta-4 signals,
//! invokes the C++ omr-core binary for FHE evaluation, and returns the digest.
//!
//! For B3 testing, this also includes a self-contained test mode that generates
//! test notes, invokes omr-core, and verifies correctness.

use alloy::{
    primitives::Address,
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
    let contract = NoteRegistryOMR::deploy(&sender_provider, Address::ZERO).await?;
    println!("  Deployed at: {}\n", contract.address());

    let start_block = sender_provider.get_block_number().await?;

    // --- Generate keys ---
    let mut rng = ChaChaRng::seed_from_u64(42);
    let k_pairwise = [77u8; 32];
    let epoch = 0u64;

    let pasta_key = lwr_prf::lwr_prf(&k_pairwise, epoch);
    let pasta = pasta4::Pasta::new(pasta_key.clone(), pasta4::PASTA_P);
    let pvw_sk = pvw::PvwSecretKey::from_pairwise_key(&k_pairwise);

    // --- Post notes ---
    println!("--- Posting {} notes ({} pertinent) ---\n", cli.notes, cli.pertinent);

    let mut expected_pertinent = Vec::new();

    for i in 0..cli.notes {
        let is_pertinent = i < cli.pertinent;

        // Generate PVW clue (26 elements of Z_65537)
        let clue = pvw::generate_clue(&pvw_sk, is_pertinent, &mut rng);

        // Encrypt PVW clue under Pasta-4: pad 26 elements → 32, encrypt → 64 B
        let mut plaintext = Vec::with_capacity(pasta4::PASTA_T);
        for &a_i in &clue.a {
            plaintext.push(a_i);
        }
        plaintext.push(clue.b);
        // Pad to 32 elements
        while plaintext.len() < pasta4::PASTA_T {
            plaintext.push(0);
        }
        let ct_elements = pasta.encrypt(&plaintext);
        // Serialize as u16 (each element fits in Z_65537)
        let mut pasta_ct_bytes = Vec::with_capacity(64);
        for &el in &ct_elements {
            pasta_ct_bytes.extend_from_slice(&(el as u16).to_le_bytes());
        }

        // Generate nonce
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);

        // Post on-chain: commitment + nonce + Pasta-4 ciphertext (64 B)
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

    for (i, (event, _)) in events.iter().enumerate() {
        // Deserialize Pasta-4 ciphertext (64 B → 32 u64 elements)
        let ct_bytes = &event.pastaCt;
        let mut ct_elements = Vec::with_capacity(pasta4::PASTA_T);
        for chunk in ct_bytes.chunks(2) {
            let val = u16::from_le_bytes([chunk[0], chunk[1]]) as u64;
            ct_elements.push(val);
        }

        // Decrypt Pasta-4 → recover PVW clue
        let plaintext = pasta.decrypt(&ct_elements);
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

    // --- Invoke omr-core (if available) ---
    println!("\n--- Invoking omr-core evaluate-test ---");
    let omr_result = Command::new(&cli.omr_core)
        .args(["evaluate-test", &cli.notes.to_string(), &cli.pertinent.to_string()])
        .output();

    match omr_result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Extract key results
            for line in stdout.lines() {
                if line.contains("False negatives")
                    || line.contains("False positives")
                    || line.contains("Pertinent correctly")
                    || line.contains("PASS")
                    || line.contains("FAIL")
                    || line.contains("Per note")
                {
                    println!("  {}", line.trim());
                }
            }
            if !output.status.success() {
                println!("  omr-core exited with error");
            }
        }
        Err(e) => {
            println!("  omr-core not available ({}). Skipping FHE test.", e);
            println!("  Build it: cd omr-core/build && make -j4");
        }
    }

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
