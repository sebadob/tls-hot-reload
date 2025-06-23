// Copyright 2025 Sebastian Dobe <sebastiandobe@mailbox.org>

#![forbid(unsafe_code)]

use rustls::crypto::CryptoProvider;

#[cfg(all(not(feature = "ring"), not(feature = "aws_lc_rs")))]
compile_error!("You must activate either `ring` or `aws_lc_rs`");

pub mod certified_key;
pub mod certified_keys;
pub mod error;

/// Creates a simple `rustls::ServerConfig` with automatic hot-reloading of TLS certificates
/// whenever the given `key_path` / `cert_path` are updated.
///
/// If you want to create a custom config:
///
/// ```rust,notest
/// let ck = CertifiedKeyWatched::new(key_path, cert_path).await?;
/// rustls::ServerConfig::builder()
///     .with_no_client_auth()
///     .with_cert_resolver(ck)
/// ```
///
/// # Panics
///
/// If the given paths or key + cert combination is invalid.
pub async fn load_server_config(key_path: String, cert_path: String) -> rustls::ServerConfig {
    install_crypto_provider();

    let ck = match certified_key::CertifiedKeyWatched::new(key_path, cert_path).await {
        Ok(ck) => ck,
        Err(err) => {
            panic!("Cannot load TLS certificates: {:?}", err)
        }
    };

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(ck)
}

/// Checks if the `rustls::CryptoProvider` is already installed and installs it, if not.
pub fn install_crypto_provider() {
    if CryptoProvider::get_default().is_none() {
        #[cfg(feature = "ring")]
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Cannot install rustls crypto provider");
        #[cfg(feature = "aws_lc_rs")]
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Cannot install rustls crypto provider");
    }
}
