// Copyright 2026 Sebastian Dobe <sebastiandobe@mailbox.org>

#![forbid(unsafe_code)]

use rustls::crypto::CryptoProvider;
use std::time::Duration;

#[cfg(all(not(feature = "ring"), not(feature = "aws_lc_rs")))]
compile_error!("You must activate either `ring` or `aws_lc_rs`");

#[cfg(all(feature = "ring", feature = "aws_lc_rs"))]
compile_error!("You must activate only one of `ring` or `aws_lc_rs`");

pub use certified_key::CertifiedKeyWatched;
pub use certified_keys::{BundleCert, CertifiedKeysWatched};

mod certified_key;
mod certified_keys;
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
pub async fn load_server_config<K, C>(key_path: K, cert_path: C) -> rustls::ServerConfig
where
    K: Into<String>,
    C: Into<String>,
{
    install_crypto_provider();

    let ck = match CertifiedKeyWatched::new(key_path, cert_path).await {
        Ok(ck) => ck,
        Err(err) => {
            panic!("Cannot load TLS certificates: {:?}", err)
        }
    };

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(ck)
}

/// The same as `load_server_config`, but will use a polling file watcher as the backend. This will
/// detect changes not instantly, but fix issues on filesystems like NFS, where `inotify` event do
/// not work.
pub async fn load_server_config_polling<K, C>(
    key_path: K,
    cert_path: C,
    poll_interval: Duration,
) -> rustls::ServerConfig
where
    K: Into<String>,
    C: Into<String>,
{
    install_crypto_provider();

    let ck = match CertifiedKeyWatched::new_polling(key_path, cert_path, poll_interval).await {
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
        // A failure here can only happen during a race condition, e.g. from inside tests, or when
        // a user initializes multiple single keys concurrently. We don't care if that fails, since
        // they would all be the same provider anyway.
        #[cfg(feature = "ring")]
        let _ = rustls::crypto::ring::default_provider().install_default();
        #[cfg(feature = "aws_lc_rs")]
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}
