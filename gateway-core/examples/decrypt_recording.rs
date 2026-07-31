//! Full-stack harness helper (SEC-LOW-1): ECIES-open a finalized SLREC1 recording object with
//! the customer PRIVATE key and write the decrypted asciicast to stdout, so `tests/fullstack/
//! run.sh` can assert the real session bytes are PRESENT and recoverable — turning "no plaintext
//! in the ciphertext" into a positive capture+seal+recoverability proof (an empty/header-only
//! SLREC1 finalize would pass every negative check). Reuses the exact production `seal::` code so
//! there is no re-implementation drift.
//!
//! Usage: decrypt_recording <customer_key.pkcs8.der> <object.bin>
//! Output: a first line `CHAIN_HEAD=sha256:<hex>` (the hash-chain recomputed from the decrypted
//! asciicast — SEC-LOW-2, compare to the finalized hash_chain_head), followed by the raw
//! decrypted plaintext (grep the session marker — SEC-LOW-1).

use gateway_core::ssh::recorder::{chain::HashChain, seal};
use p256::pkcs8::DecodePrivateKey;
use std::io::Write;

/// Recompute the hash-chain head from a decrypted asciicast object exactly as the recorder does
/// (each `\n`-terminated line is one record; a trailing partial line is the last record).
fn recompute_chain(plaintext: &[u8]) -> String {
    let mut c = HashChain::new();
    let mut start = 0;
    for i in 0..plaintext.len() {
        if plaintext[i] == b'\n' {
            c.extend(&plaintext[start..=i]);
            start = i + 1;
        }
    }
    if start < plaintext.len() {
        c.extend(&plaintext[start..]);
    }
    c.head_hex()
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let key_path = args.next().ok_or_else(|| {
        anyhow::anyhow!("usage: decrypt_recording <customer_key.pkcs8.der> <object.bin>")
    })?;
    let obj_path = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing <object.bin>"))?;

    let secret = p256::SecretKey::from_pkcs8_der(&std::fs::read(&key_path)?)
        .map_err(|e| anyhow::anyhow!("parse customer key {key_path}: {e}"))?;
    let object = std::fs::read(&obj_path)?;

    let header =
        seal::parse_header(&object).map_err(|e| anyhow::anyhow!("parse SLREC1 header: {e:?}"))?;
    let data_key = seal::unseal_data_key(&header, &secret)
        .map_err(|e| anyhow::anyhow!("unseal data key (wrong customer key?): {e:?}"))?;
    let plaintext = seal::decrypt_frames(&object, &header, &data_key)
        .map_err(|e| anyhow::anyhow!("decrypt frames: {e:?}"))?;

    let mut out = std::io::stdout().lock();
    writeln!(out, "CHAIN_HEAD={}", recompute_chain(&plaintext))?;
    out.write_all(&plaintext)?;
    Ok(())
}
