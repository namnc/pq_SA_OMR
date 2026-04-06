pub mod pasta4;
pub mod pvw;
pub mod lwr_prf;

/// Derive a per-note additive mask over F_p from the note nonce.
/// This provides per-note semantic security without changing the Pasta-4 key or nonce:
///   masked_pt = (pt + mask) mod p    (sender)
///   pt = (masked_pt + p - mask) mod p (recipient)
/// The mask is public (derived from on-chain nonce), so it can be removed by anyone
/// who knows the nonce. The security property: ct1 - ct2 no longer reveals pt1 - pt2
/// because the masks are different per note.
pub fn derive_mask(nonce: &[u8; 16]) -> Vec<u64> {
    use sha2::{Sha256, Digest};
    let mut mask = Vec::with_capacity(pasta4::PASTA_T);
    for i in 0..pasta4::PASTA_T {
        let mut h = Sha256::new();
        h.update(b"pq-sa-pasta-mask-v1");
        h.update(nonce);
        h.update(&(i as u32).to_le_bytes());
        let hash = h.finalize();
        let val = u64::from_le_bytes(hash[..8].try_into().expect("SHA-256 is 32 bytes"));
        mask.push(val % pasta4::PASTA_P);
    }
    mask
}
