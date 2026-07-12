//! Customer-held encryption of the recording object (Design §12.2/§15; FR-AUD-2).
//!
//! The recording is sealed so **no platform-held key can decrypt it**:
//!
//! - a fresh **AES-256-GCM data key** encrypts the asciicast plaintext as a chain
//!   of length-prefixed frames (per-frame counter nonce + frame-index AAD, so
//!   removing/reordering a frame breaks decryption);
//! - the data key is **wrapped to the customer's P-256 public key via ECIES**
//!   (ephemeral-static ECDH → HKDF-SHA256 → AES-256-GCM key wrap). The ephemeral
//!   private scalar is dropped (zeroized) after the wrap, so recovering the data
//!   key needs the customer *private* key — which the platform never holds.
//!
//! The object layout is `SealHeader ‖ Frame*` (see [`SealHeader`]); the header
//! carries only the ephemeral public key + wrapped key + algorithm — public
//! material. [`unseal_data_key`] + [`decrypt_frames`] are the reference the S15
//! customer-side replay path re-implements; they also power the tests that prove
//! a platform actor cannot decrypt.

use aes_gcm::aead::{Aead, Nonce as AeadNonce, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePublicKey;
use p256::PublicKey;
use rand_core::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::pb::KeySealAlgorithm;

/// Object magic + format version (`SLREC` + version 1).
const MAGIC: &[u8; 6] = b"SLREC1";
/// HKDF `info` domain separation for the ECIES key-wrap KEK derivation.
const KEK_INFO: &[u8] = b"SessionLayer/recording/ECIES-P256-HKDF-SHA256/kek/v1";
/// AEAD associated data domain-separating the key-wrap ciphertext.
const WRAP_AAD: &[u8] = b"SessionLayer/recording/data-key-wrap/v1";

/// A failure sealing or unsealing a recording (operator log; the user sees only
/// the generic recording-unavailable outcome).
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// The customer public key was missing, malformed, or the algorithm is not
    /// one this Gateway implements (only ECIES-P256 is compiled; RSA is not — the
    /// `rsa` crate is deliberately never built).
    #[error("unusable customer key seal parameters")]
    CustomerKey,
    /// An AEAD operation failed (encrypt error, or a decrypt tag mismatch).
    #[error("recording AEAD failure")]
    Aead,
    /// The sealed object was malformed / truncated on the decrypt path.
    #[error("malformed sealed recording object")]
    Malformed,
}

/// A per-recording AES-256-GCM data key sealed to a customer public key. Holds the
/// live cipher (used to seal each frame) + the object header bytes to prepend.
pub struct RecordingCipher {
    cipher: Aes256Gcm,
    header: Vec<u8>,
}

impl RecordingCipher {
    /// Generate a fresh data key and seal it to `customer_public_key_der` (DER
    /// SubjectPublicKeyInfo) under `algorithm`. Only ECIES-P256 is supported.
    pub fn seal_to_customer(
        algorithm: KeySealAlgorithm,
        customer_public_key_der: &[u8],
    ) -> Result<Self, SealError> {
        if algorithm != KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm {
            return Err(SealError::CustomerKey);
        }
        let customer_pub = PublicKey::from_public_key_der(customer_public_key_der)
            .map_err(|_| SealError::CustomerKey)?;

        // Fresh 256-bit data key. Held zeroized; the plaintext copy dies with this
        // buffer once the cipher schedule is built.
        let mut data_key = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(&mut data_key[..]);
        let cipher =
            Aes256Gcm::new_from_slice(&data_key[..]).map_err(|_| SealError::CustomerKey)?;

        // ECIES wrap: ephemeral-static ECDH → HKDF-SHA256 KEK → AES-256-GCM wrap.
        let ephemeral = EphemeralSecret::random(&mut rand_core::OsRng);
        let eph_pub = ephemeral.public_key().to_encoded_point(false);
        let eph_pub_bytes = eph_pub.as_bytes();
        let shared = ephemeral.diffie_hellman(&customer_pub);
        let kek = derive_kek(shared.raw_secret_bytes().as_slice(), eph_pub_bytes)?;
        drop(shared); // SharedSecret + the ephemeral scalar zeroize on drop
        drop(ephemeral);

        let mut wrap_nonce = [0u8; 12];
        rand_core::OsRng.fill_bytes(&mut wrap_nonce);
        let wrap_cipher =
            Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| SealError::CustomerKey)?;
        let wrapped_key = wrap_cipher
            .encrypt(
                &gcm_nonce(wrap_nonce),
                Payload {
                    msg: &data_key[..],
                    aad: WRAP_AAD,
                },
            )
            .map_err(|_| SealError::Aead)?;

        let header = encode_header(algorithm, eph_pub_bytes, &wrap_nonce, &wrapped_key);
        Ok(Self { cipher, header })
    }

    /// The object header to prepend to the frame stream (public material only).
    pub fn header(&self) -> &[u8] {
        &self.header
    }

    /// Seal one frame of plaintext at sequence `frame_index`, returning the
    /// length-prefixed frame bytes to append to the object. The nonce is the
    /// frame index (a counter — safe under a fresh per-recording key) and the AAD
    /// binds the index so a removed/reordered frame fails to decrypt.
    pub fn seal_frame(&self, frame_index: u64, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let nonce = counter_nonce(frame_index);
        let aad = frame_index.to_be_bytes();
        let ct = self
            .cipher
            .encrypt(
                &gcm_nonce(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| SealError::Aead)?;
        let mut framed = Vec::with_capacity(4 + ct.len());
        framed.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        framed.extend_from_slice(&ct);
        Ok(framed)
    }
}

/// The parsed cleartext object header (public material only).
pub struct SealHeader {
    /// The ephemeral public key (SEC1 uncompressed) used for the ECIES wrap.
    pub ephemeral_public: Vec<u8>,
    /// The AES-GCM nonce over the wrapped data key.
    pub wrap_nonce: [u8; 12],
    /// The wrapped (ciphertext) data key.
    pub wrapped_key: Vec<u8>,
    /// Byte length of the header (where the frame stream begins).
    pub len: usize,
}

/// Parse the object header. Fails closed on truncation / bad magic.
pub fn parse_header(object: &[u8]) -> Result<SealHeader, SealError> {
    let mut c = Cursor::new(object);
    let magic = c.take(MAGIC.len()).ok_or(SealError::Malformed)?;
    if magic != MAGIC {
        return Err(SealError::Malformed);
    }
    let _alg = c.u8().ok_or(SealError::Malformed)?;
    let _reserved = c.u8().ok_or(SealError::Malformed)?;
    let eph_len = c.u16().ok_or(SealError::Malformed)? as usize;
    let ephemeral_public = c.take(eph_len).ok_or(SealError::Malformed)?.to_vec();
    let wrap_nonce: [u8; 12] = c
        .take(12)
        .ok_or(SealError::Malformed)?
        .try_into()
        .map_err(|_| SealError::Malformed)?;
    let wrap_len = c.u16().ok_or(SealError::Malformed)? as usize;
    let wrapped_key = c.take(wrap_len).ok_or(SealError::Malformed)?.to_vec();
    Ok(SealHeader {
        ephemeral_public,
        wrap_nonce,
        wrapped_key,
        len: c.pos,
    })
}

/// Unwrap the data key with the customer **private** key (S15 replay reference).
/// `customer_secret` is the customer's P-256 secret. Returns the raw data key.
pub fn unseal_data_key(
    header: &SealHeader,
    customer_secret: &p256::SecretKey,
) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let eph_pub =
        PublicKey::from_sec1_bytes(&header.ephemeral_public).map_err(|_| SealError::Malformed)?;
    let shared =
        p256::ecdh::diffie_hellman(customer_secret.to_nonzero_scalar(), eph_pub.as_affine());
    let kek = derive_kek(
        shared.raw_secret_bytes().as_slice(),
        &header.ephemeral_public,
    )?;
    let wrap_cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| SealError::CustomerKey)?;
    let key = wrap_cipher
        .decrypt(
            &gcm_nonce(header.wrap_nonce),
            Payload {
                msg: &header.wrapped_key,
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| SealError::Aead)?;
    let arr: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| SealError::Malformed)?;
    let mut key = key;
    key.zeroize();
    Ok(Zeroizing::new(arr))
}

/// Decrypt every frame after `header` with `data_key`, concatenating the
/// plaintext (the original asciicast v2 file bytes). Reference for S15 replay +
/// the round-trip / tamper tests.
pub fn decrypt_frames(
    object: &[u8],
    header: &SealHeader,
    data_key: &[u8; 32],
) -> Result<Vec<u8>, SealError> {
    let cipher = Aes256Gcm::new_from_slice(data_key).map_err(|_| SealError::CustomerKey)?;
    let mut c = Cursor::new(&object[header.len..]);
    let mut out = Vec::new();
    let mut frame_index: u64 = 0;
    while !c.at_end() {
        let ct_len = c.u32().ok_or(SealError::Malformed)? as usize;
        let ct = c.take(ct_len).ok_or(SealError::Malformed)?;
        let nonce = counter_nonce(frame_index);
        let aad = frame_index.to_be_bytes();
        let pt = cipher
            .decrypt(&gcm_nonce(nonce), Payload { msg: ct, aad: &aad })
            .map_err(|_| SealError::Aead)?;
        out.extend_from_slice(&pt);
        frame_index += 1;
    }
    Ok(out)
}

/// HKDF-SHA256 over the ECDH shared secret → a 256-bit KEK, binding the ephemeral
/// public key into the derivation. Held zeroized.
fn derive_kek(shared: &[u8], eph_pub: &[u8]) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut info = Vec::with_capacity(KEK_INFO.len() + eph_pub.len());
    info.extend_from_slice(KEK_INFO);
    info.extend_from_slice(eph_pub);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut kek[..])
        .map_err(|_| SealError::CustomerKey)?;
    Ok(kek)
}

/// The 96-bit counter nonce for `frame_index` (big-endian in the low 8 bytes).
/// Unique per frame; safe because the data key is fresh per recording.
fn counter_nonce(frame_index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&frame_index.to_be_bytes());
    nonce
}

/// The typed AES-256-GCM nonce for a 12-byte value.
fn gcm_nonce(bytes: [u8; 12]) -> AeadNonce<Aes256Gcm> {
    AeadNonce::<Aes256Gcm>::from(bytes)
}

fn encode_header(
    algorithm: KeySealAlgorithm,
    eph_pub: &[u8],
    wrap_nonce: &[u8; 12],
    wrapped_key: &[u8],
) -> Vec<u8> {
    let mut h = Vec::with_capacity(MAGIC.len() + 6 + eph_pub.len() + 12 + wrapped_key.len());
    h.extend_from_slice(MAGIC);
    h.push(algorithm as u8);
    h.push(0); // reserved
    h.extend_from_slice(&(eph_pub.len() as u16).to_be_bytes());
    h.extend_from_slice(eph_pub);
    h.extend_from_slice(wrap_nonce);
    h.extend_from_slice(&(wrapped_key.len() as u16).to_be_bytes());
    h.extend_from_slice(wrapped_key);
    h
}

/// A minimal fail-closed big-endian byte cursor for header/frame parsing.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn customer_keypair() -> (Vec<u8>, p256::SecretKey) {
        use p256::pkcs8::EncodePublicKey;
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let der = secret.public_key().to_public_key_der().unwrap();
        (der.as_bytes().to_vec(), secret)
    }

    /// Round-trip: seal a plaintext across several frames, then unseal with the
    /// customer private key → exact original bytes.
    #[test]
    fn seals_and_unseals_multiframe() {
        let (pub_der, secret) = customer_keypair();
        let cipher = RecordingCipher::seal_to_customer(
            KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
            &pub_der,
        )
        .unwrap();

        let mut object = cipher.header().to_vec();
        let parts: [&[u8]; 3] = [b"asciicast-header-line\n", b"[0.1,\"o\",\"hello\"]\n", b""];
        for (i, p) in parts.iter().enumerate() {
            object.extend_from_slice(&cipher.seal_frame(i as u64, p).unwrap());
        }

        let header = parse_header(&object).unwrap();
        let key = unseal_data_key(&header, &secret).unwrap();
        let plaintext = decrypt_frames(&object, &header, &key).unwrap();
        assert_eq!(plaintext, b"asciicast-header-line\n[0.1,\"o\",\"hello\"]\n");
    }

    /// A platform actor holding only the customer PUBLIC key (what the CP stores)
    /// and the object cannot recover the data key: unsealing with any other
    /// private key fails, and the wrapped key never appears in the clear.
    #[test]
    fn platform_cannot_decrypt_without_customer_private_key() {
        let (pub_der, secret) = customer_keypair();
        let cipher = RecordingCipher::seal_to_customer(
            KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
            &pub_der,
        )
        .unwrap();
        let mut object = cipher.header().to_vec();
        object.extend_from_slice(&cipher.seal_frame(0, b"secret keystrokes").unwrap());
        let header = parse_header(&object).unwrap();

        // The correct private key works…
        let key = unseal_data_key(&header, &secret).unwrap();
        assert_eq!(
            decrypt_frames(&object, &header, &key).unwrap(),
            b"secret keystrokes"
        );

        // …but a DIFFERENT private key (all a platform could ever forge from the
        // public material) does not: ECDH yields a different secret → wrong KEK →
        // GCM tag mismatch. This is the crown-jewels invariant (§15).
        let (_other_pub, other_secret) = customer_keypair();
        assert!(matches!(
            unseal_data_key(&header, &other_secret),
            Err(SealError::Aead)
        ));

        // The plaintext data key is never present in the object bytes.
        let recovered: [u8; 32] = *key;
        assert!(
            !object.windows(32).any(|w| w == recovered),
            "the data key must never appear in the sealed object"
        );
    }

    /// Removing or reordering a frame breaks decryption (per-frame index AAD +
    /// counter nonce): tamper-evidence at the cipher layer.
    #[test]
    fn frame_tamper_breaks_decryption() {
        let (pub_der, secret) = customer_keypair();
        let cipher = RecordingCipher::seal_to_customer(
            KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
            &pub_der,
        )
        .unwrap();
        let mut object = cipher.header().to_vec();
        let f0 = cipher.seal_frame(0, b"one").unwrap();
        let f1 = cipher.seal_frame(1, b"two").unwrap();
        // Swap frame order in the object.
        object.extend_from_slice(&f1);
        object.extend_from_slice(&f0);
        let header = parse_header(&object).unwrap();
        let key = unseal_data_key(&header, &secret).unwrap();
        assert!(matches!(
            decrypt_frames(&object, &header, &key),
            Err(SealError::Aead)
        ));
    }

    #[test]
    fn rsa_algorithm_is_refused_no_rsa_crate() {
        let (pub_der, _s) = customer_keypair();
        assert!(matches!(
            RecordingCipher::seal_to_customer(KeySealAlgorithm::RsaOaepSha256, &pub_der),
            Err(SealError::CustomerKey)
        ));
    }
}
