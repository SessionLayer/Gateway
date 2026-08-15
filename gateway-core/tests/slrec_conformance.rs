//! Cross-language SLREC1 golden conformance. The committed golden object
//! is sealed by the REAL `RecordingCipher::seal_to_customer` + `seal_frame` path
//! (`src/ssh/recorder/seal.rs`), never a reimplementation, and decrypted here by
//! the real Rust unseal path AND by Dashboard's production
//! `src/crypto/slrec.ts` (see that repo's `src/crypto/__tests__/slrecConformance.test.ts`).
//!
//! Why this exists: `seal.rs`'s own unit tests round-trip Rust-seal ->
//! Rust-unseal, and the Dashboard's `slrec.test.ts` round-trips a TS-only mirror
//! (`src/test/recordingFixture.ts`) -> TS-unseal. Neither ever ties the two
//! languages together, so a framing drift (header layout, nonce derivation, AAD
//! composition, length prefixes) between the two independently hand-maintained
//! mirrors would pass both test suites and surface only when a customer can't
//! decrypt their own recording. This golden is the tie: one object, sealed once
//! by the real Gateway code, decrypted by both real production paths.
//!
//! Regenerate ONLY when the on-wire format intentionally changes (manual dev
//! tool, mirrors `framegen`'s role for the agent-wire golden -- never runs in
//! CI):
//!
//!   cargo test --test slrec_conformance -- --ignored regenerate_golden --nocapture
//!
//! then review the `object_hex` diff and copy `tests/fixtures/slrec_conformance/
//! golden.json` verbatim into `Dashboard/src/crypto/__fixtures__/
//! slrec-golden.json`.

use gateway_core::pb::KeySealAlgorithm;
use gateway_core::ssh::recorder::seal::{self, RecordingCipher};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use serde_json::json;

const GOLDEN_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/slrec_conformance/golden.json"
);
const GOLDEN_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/slrec_conformance/golden.json"
));

// Deliberately not aligned to any line boundary -- includes an empty middle
// frame -- so the golden exercises the per-frame counter-nonce + index-AAD
// framing across an uneven, zero-length-inclusive chunking (mirrors seal.rs's
// own `seals_and_unseals_multiframe` and slrec.test.ts's multi-frame case).
const PLAINTEXT: &str = "{\"version\":2,\"width\":80,\"height\":24,\"timestamp\":1700000000}\n\
[0.10,\"o\",\"$ whoami\\r\\n\"]\n\
[0.20,\"i\",\"ls\\r\"]\n\
[0.30,\"o\",\"admin\\r\\n\"]\n\
[0.40,\"m\",\"sftp: GET /etc/hosts (312 bytes)\"]\n";

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Splits `plaintext` into the uneven, zero-length-inclusive chunks fed to
/// successive `seal_frame` calls when (re)generating the golden.
fn frame_chunks(plaintext: &[u8]) -> Vec<&[u8]> {
    let lens = [40usize, 35, 0, plaintext.len().saturating_sub(75)];
    assert_eq!(
        lens.iter().sum::<usize>(),
        plaintext.len(),
        "frame lengths must cover PLAINTEXT exactly"
    );
    let mut out = Vec::new();
    let mut off = 0;
    for l in lens {
        out.push(&plaintext[off..off + l]);
        off += l;
    }
    out
}

fn golden() -> serde_json::Value {
    serde_json::from_str(GOLDEN_JSON).expect("parse golden.json")
}

/// The standing conformance check: the committed golden -- produced by the REAL
/// seal path -- still decrypts via the REAL Rust unseal path (`parse_header` /
/// `unseal_data_key` / `decrypt_frames`) to the exact known plaintext. A
/// Rust-side format change that breaks this fails HERE, before it would
/// otherwise only be noticed by a customer failing to decrypt a real recording.
#[test]
fn golden_slrec1_object_decrypts_via_production_path() {
    let g = golden();
    let object = unhex(g["object_hex"].as_str().unwrap());
    let secret_der = unhex(g["customer_private_key_pkcs8_der_hex"].as_str().unwrap());
    let secret = p256::SecretKey::from_pkcs8_der(&secret_der).expect("golden customer key parses");
    let expected = g["plaintext_utf8"].as_str().unwrap();

    let header = seal::parse_header(&object).expect("golden header parses");
    let key = seal::unseal_data_key(&header, &secret).expect("golden data key unseals");
    let plaintext = seal::decrypt_frames(&object, &header, &key).expect("golden frames decrypt");

    assert_eq!(
        String::from_utf8(plaintext).unwrap(),
        expected,
        "golden SLREC1 object must decrypt to the exact committed plaintext"
    );
}

/// Pins the wire-format bytes both languages hard-code independently (MAGIC,
/// the algorithm byte, the reserved byte) against the golden itself, the same
/// way `wire_conformance.rs` pins the agent-wire type bytes.
#[test]
fn golden_header_bytes_are_pinned() {
    let object = unhex(golden()["object_hex"].as_str().unwrap());
    assert_eq!(&object[0..6], b"SLREC1", "magic");
    assert_eq!(
        object[6],
        KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm as u8,
        "algorithm byte"
    );
    assert_eq!(object[7], 0, "reserved byte");
}

/// A byte flipped in the golden's frame region must be rejected, not silently
/// return garbage -- proven here Rust-side; the TS side proves the same thing
/// independently against this exact object (`slrecConformance.test.ts`).
#[test]
fn golden_object_tamper_is_rejected() {
    let mut object = unhex(golden()["object_hex"].as_str().unwrap());
    let secret_der = unhex(
        golden()["customer_private_key_pkcs8_der_hex"]
            .as_str()
            .unwrap(),
    );
    let secret = p256::SecretKey::from_pkcs8_der(&secret_der).unwrap();
    let header = seal::parse_header(&object).unwrap();

    let last = object.len() - 1;
    object[last] ^= 0x01;
    let key = seal::unseal_data_key(&header, &secret).unwrap();
    assert!(
        matches!(
            seal::decrypt_frames(&object, &header, &key),
            Err(seal::SealError::Aead)
        ),
        "a tampered golden frame must be rejected, not decrypt to garbage"
    );
}

/// Manual dev tool: NEVER runs in CI (see module docs for invocation).
/// Regenerates `golden.json` via the real `seal_to_customer` / `seal_frame`
/// path. Reuses the existing committed customer key across regenerations --
/// only the sealed bytes change (ECIES re-randomizes the ephemeral key + all
/// nonces on every seal) -- so the Dashboard's copy of the key never has to move.
#[test]
#[ignore]
fn regenerate_golden() {
    let existing = std::fs::read_to_string(GOLDEN_PATH)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());

    let secret = match existing
        .as_ref()
        .and_then(|v| v["customer_private_key_pkcs8_der_hex"].as_str())
        .filter(|hex_str| !hex_str.is_empty())
    {
        Some(hex_str) => {
            p256::SecretKey::from_pkcs8_der(&unhex(hex_str)).expect("existing golden key parses")
        }
        None => p256::SecretKey::random(&mut rand_core::OsRng),
    };
    let pub_der = secret
        .public_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();

    let cipher =
        RecordingCipher::seal_to_customer(KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm, &pub_der)
            .expect("seal_to_customer");

    let mut object = cipher.header().to_vec();
    let chunks = frame_chunks(PLAINTEXT.as_bytes());
    let frame_count = chunks.len();
    for (i, chunk) in chunks.into_iter().enumerate() {
        object.extend_from_slice(&cipher.seal_frame(i as u64, chunk).unwrap());
    }

    // Self-check with the real unseal path before committing -- a golden that
    // doesn't even decrypt to itself would be a worse oracle than none.
    let header = seal::parse_header(&object).unwrap();
    let key = seal::unseal_data_key(&header, &secret).unwrap();
    let roundtrip = seal::decrypt_frames(&object, &header, &key).unwrap();
    assert_eq!(String::from_utf8(roundtrip).unwrap(), PLAINTEXT);

    let secret_der = secret.to_pkcs8_der().unwrap().as_bytes().to_vec();

    let out = json!({
        "schema": "sessionlayer.recording.slrec1-conformance/v1",
        "note": "Golden SLREC1 object, sealed by the REAL RecordingCipher::seal_to_customer + seal_frame path (gateway-core/src/ssh/recorder/seal.rs), never a reimplementation. DO NOT hand-edit. Regenerate via `cargo test --test slrec_conformance -- --ignored regenerate_golden --nocapture` in the Gateway repo, review the object_hex diff, then copy this file verbatim into Dashboard/src/crypto/__fixtures__/slrec-golden.json. The private key here is a TEST-ONLY fixture key with no other purpose; it protects nothing and is not a real customer secret.",
        "algorithm": "ecies-p256-hkdf-sha256-aes256gcm",
        "customer_private_key_pkcs8_der_hex": hex(&secret_der),
        "customer_public_key_spki_der_hex": hex(&pub_der),
        "plaintext_utf8": PLAINTEXT,
        "frame_count": frame_count,
        "object_hex": hex(&object),
    });

    std::fs::create_dir_all(std::path::Path::new(GOLDEN_PATH).parent().unwrap()).unwrap();
    std::fs::write(
        GOLDEN_PATH,
        serde_json::to_string_pretty(&out).unwrap() + "\n",
    )
    .unwrap();
    eprintln!("wrote {GOLDEN_PATH}");
}
