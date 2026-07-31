//! rustls crypto-provider installation.

pub fn install_ring_provider() -> bool {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return false;
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .is_ok()
}

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
