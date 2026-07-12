//! Tamper-evident hash-chain over a recording's records (Design §12.2, Part D;
//! FR-AUD-3).
//!
//! The recording is a sequence of records — asciicast events **and** SFTP/SCP
//! file-transfer audit entries, in the order they occurred. Each record extends
//! the chain: `record_hash = SHA-256(prev_hash ‖ canonical(record))`, starting
//! from a fixed zero seed. The recording's `hash_chain_head` (sent in
//! FinalizeRecording) is the final `record_hash`, so it commits to the whole
//! content and its order: altering, removing, or reordering any record changes
//! the head.

use sha2::{Digest, Sha256};

/// A running hash-chain over a recording's records.
#[derive(Debug, Clone)]
pub struct HashChain {
    prev: [u8; 32],
    count: u64,
}

impl Default for HashChain {
    fn default() -> Self {
        Self::new()
    }
}

impl HashChain {
    /// A fresh chain seeded with the zero hash.
    pub fn new() -> Self {
        Self {
            prev: [0u8; 32],
            count: 0,
        }
    }

    /// Extend the chain by one record's canonical bytes.
    pub fn extend(&mut self, canonical_record: &[u8]) {
        let mut h = Sha256::new();
        h.update(self.prev);
        h.update(canonical_record);
        self.prev = h.finalize().into();
        self.count += 1;
    }

    /// The current chain head as `sha256:<64-hex>` (the FinalizeRecording value).
    pub fn head_hex(&self) -> String {
        format!("sha256:{}", hex_lower(&self.prev))
    }

    /// The number of records folded into the chain.
    pub fn len(&self) -> u64 {
        self.count
    }

    /// Whether no records have been folded in yet.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Lowercase hex of a byte slice (no external hex dependency on the hot path).
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// The SHA-256 of `bytes` as `sha256:<64-hex>` (content digests + empty-content
/// file-transfer records).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex_lower(&digest))
}

/// Format an already-computed 32-byte SHA-256 digest as `sha256:<64-hex>` (for a
/// streaming hasher's `finalize()` output — does NOT hash again).
pub fn format_sha256(digest: &[u8]) -> String {
    format!("sha256:{}", hex_lower(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_changes_when_a_record_is_altered() {
        let mut a = HashChain::new();
        for r in [&b"rec-0"[..], b"rec-1", b"rec-2"] {
            a.extend(r);
        }
        let head_a = a.head_hex();

        let mut b = HashChain::new();
        for r in [&b"rec-0"[..], b"rec-XX", b"rec-2"] {
            b.extend(r);
        }
        assert_ne!(
            head_a,
            b.head_hex(),
            "altering a record must change the head"
        );
    }

    #[test]
    fn head_changes_when_a_record_is_removed_or_reordered() {
        let mut full = HashChain::new();
        for r in [&b"a"[..], b"b", b"c"] {
            full.extend(r);
        }

        let mut removed = HashChain::new();
        for r in [&b"a"[..], b"c"] {
            removed.extend(r);
        }
        assert_ne!(
            full.head_hex(),
            removed.head_hex(),
            "removal breaks the head"
        );

        let mut reordered = HashChain::new();
        for r in [&b"a"[..], b"c", b"b"] {
            reordered.extend(r);
        }
        assert_ne!(
            full.head_hex(),
            reordered.head_hex(),
            "reordering breaks the head"
        );
    }

    #[test]
    fn head_format_is_sha256_hex() {
        let mut c = HashChain::new();
        c.extend(b"x");
        let head = c.head_hex();
        assert!(head.starts_with("sha256:"));
        assert_eq!(head.len(), "sha256:".len() + 64);
        assert!(head["sha256:".len()..]
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }
}
