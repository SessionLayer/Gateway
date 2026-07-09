//! Placeholder for the CP <-> Gateway mTLS plane (Session Four).
//!
//! `rustls` is a dependency from Session One so the TLS supply chain is under
//! cargo-audit / cargo-deny from day one, even though the mutually-authenticated
//! channel itself is built in Session Four. Session One's handshake smoke runs
//! over PLAINTEXT localhost (dev-only, insecure-by-design — see the SECURITY
//! note in `handshake.proto` and CLAUDE.md's Tier-0 caution).

/// Whether a process-wide rustls
/// [`CryptoProvider`](rustls::crypto::CryptoProvider) has been installed.
///
/// Session One installs none (there is no TLS yet). This references `rustls` so
/// it is compiled and audited now, and marks the seam where Session Four
/// installs the provider before building the mTLS channel.
pub fn crypto_provider_installed() -> bool {
    rustls::crypto::CryptoProvider::get_default().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_crypto_provider_in_session_one() {
        // Session One does not install a rustls provider; the mTLS plane is S4.
        assert!(!crypto_provider_installed());
    }
}
