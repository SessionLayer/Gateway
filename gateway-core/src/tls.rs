//! rustls crypto-provider install for the CP <-> Gateway mTLS plane (§10, §15).
//!
//! The whole plane runs over **TLS 1.3, mutually authenticated** (VERSIONING §7).
//! rustls needs a process-wide [`CryptoProvider`](rustls::crypto::CryptoProvider)
//! installed before any `ServerConfig::builder()` (the mock CP) or custom
//! certificate verifier is constructed. We deliberately use the **ring** provider
//! (not aws-lc-rs) to avoid a C/asm build toolchain and license churn; `rustls`
//! is built with `default-features = false, features = ["ring", ...]`.
//!
//! `rustls` has been a dependency since Session One so the TLS supply chain has
//! been under cargo-audit / cargo-deny from day one; Session Four is where the
//! provider is actually installed and the channel built (see [`crate::mtls`]).

/// Install the process-wide **ring** rustls crypto provider, idempotently.
///
/// Safe to call from every entry point (daemon start, each test). Returns `true`
/// if this call installed the provider, `false` if one was already installed
/// (by us or anyone else) — either way a provider is guaranteed present on
/// return. rustls' `install_default` errors if a provider already exists; we
/// treat that as success, since the postcondition ("a provider is installed") is
/// what callers depend on.
pub fn install_ring_provider() -> bool {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return false;
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .is_ok()
}

/// Whether a process-wide rustls
/// [`CryptoProvider`](rustls::crypto::CryptoProvider) has been installed.
pub fn crypto_provider_installed() -> bool {
    rustls::crypto::CryptoProvider::get_default().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installing_the_provider_is_idempotent_and_leaves_one_installed() {
        // First call may or may not be the installer (another test in this
        // binary might have raced us), but the postcondition must hold.
        let _ = install_ring_provider();
        assert!(crypto_provider_installed());
        // A second call must never fail or panic and must keep a provider in
        // place — this is the property every entry point relies on.
        let _ = install_ring_provider();
        assert!(crypto_provider_installed());
    }
}
