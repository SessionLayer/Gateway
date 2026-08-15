//! Tamper-evident hash-chain over recording's records.
//! Each record extends chain: `record_hash = SHA-256(prev_hash ‖ record)` from zero seed.
//! hash_chain_head commits to whole content and order.

use sha2::{Digest, Sha256};

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
    pub fn new() -> Self {
        Self {
            prev: [0u8; 32],
            count: 0,
        }
    }

    pub fn extend(&mut self, canonical_record: &[u8]) {
        let mut h = Sha256::new();
        h.update(self.prev);
        h.update(canonical_record);
        self.prev = h.finalize().into();
        self.count += 1;
    }

    pub fn head_hex(&self) -> String {
        format!("sha256:{}", hex_lower(&self.prev))
    }

    pub fn len(&self) -> u64 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex_lower(&digest))
}

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
