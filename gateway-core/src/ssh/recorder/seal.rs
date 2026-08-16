//! Customer key encryption (no platform-held key can decrypt; customer PRIVATE key needed to recover data key via ECIES; ephemeral scalar zeroized).

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

const MAGIC: &[u8; 6] = b"SLREC1";
const KEK_INFO: &[u8] = b"SessionLayer/recording/ECIES-P256-HKDF-SHA256/kek/v1";
const WRAP_AAD: &[u8] = b"SessionLayer/recording/data-key-wrap/v1";

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("unusable customer key seal parameters")]
    CustomerKey,
    #[error("recording AEAD failure")]
    Aead,
    #[error("malformed sealed recording object")]
    Malformed,
}

pub struct RecordingCipher {
    cipher: Aes256Gcm,
    header: Vec<u8>,
}

impl RecordingCipher {
    pub fn seal_to_customer(
        algorithm: KeySealAlgorithm,
        customer_public_key_der: &[u8],
    ) -> Result<Self, SealError> {
        if algorithm != KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm {
            return Err(SealError::CustomerKey);
        }
        let customer_pub = PublicKey::from_public_key_der(customer_public_key_der)
            .map_err(|_| SealError::CustomerKey)?;

        let mut data_key = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(&mut data_key[..]);
        let cipher =
            Aes256Gcm::new_from_slice(&data_key[..]).map_err(|_| SealError::CustomerKey)?;

        let ephemeral = EphemeralSecret::random(&mut rand_core::OsRng);
        let eph_pub = ephemeral.public_key().to_encoded_point(false);
        let eph_pub_bytes = eph_pub.as_bytes();
        let shared = ephemeral.diffie_hellman(&customer_pub);
        let kek = derive_kek(shared.raw_secret_bytes().as_slice(), eph_pub_bytes)?;
        drop(shared);
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

    pub fn header(&self) -> &[u8] {
        &self.header
    }

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

pub struct SealHeader {
    pub ephemeral_public: Vec<u8>,
    pub wrap_nonce: [u8; 12],
    pub wrapped_key: Vec<u8>,
    pub len: usize,
}

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

fn counter_nonce(frame_index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&frame_index.to_be_bytes());
    nonce
}

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
    h.push(0);
    h.extend_from_slice(&(eph_pub.len() as u16).to_be_bytes());
    h.extend_from_slice(eph_pub);
    h.extend_from_slice(wrap_nonce);
    h.extend_from_slice(&(wrapped_key.len() as u16).to_be_bytes());
    h.extend_from_slice(wrapped_key);
    h
}

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

        let key = unseal_data_key(&header, &secret).unwrap();
        assert_eq!(
            decrypt_frames(&object, &header, &key).unwrap(),
            b"secret keystrokes"
        );

        let (_other_pub, other_secret) = customer_keypair();
        assert!(matches!(
            unseal_data_key(&header, &other_secret),
            Err(SealError::Aead)
        ));

        let recovered: [u8; 32] = *key;
        assert!(
            !object.windows(32).any(|w| w == recovered),
            "the data key must never appear in the sealed object"
        );
    }

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
