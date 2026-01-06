use crate::error::Error;
use arc_swap::ArcSwap;
use notify::event::CreateKind;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task;
use tracing::{debug, error, info};

/// A TLS Key / Certificate combination created from files. The files are automatically watched and
/// the internal TLS data will be rebuilt automatically, if a new matching key + cert has been
/// found. This makes any server using `rustls` capable of hot-reloading certificates without any
/// other modification.
#[derive(Debug)]
pub struct CertifiedKeyWatched {
    key_path: String,
    cert_path: String,
    cert_key: ArcSwap<CertifiedKey>,
    watcher: Mutex<Option<RecommendedWatcher>>,
}

impl ResolvesServerCert for CertifiedKeyWatched {
    #[inline(always)]
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.cloned())
    }
}

impl CertifiedKeyWatched {
    #[inline(always)]
    pub fn cloned(&self) -> Arc<CertifiedKey> {
        self.cert_key.load_full()
    }

    pub async fn new(key_path: String, cert_path: String) -> Result<Arc<Self>, Error> {
        let kp_cloned = key_path.clone();
        let cp_cloned = cert_path.clone();
        let cert_key =
            task::spawn_blocking(move || Self::try_load(&kp_cloned, &cp_cloned)).await??;

        let slf = Arc::new(Self {
            key_path,
            cert_path,
            cert_key: ArcSwap::new(cert_key),
            watcher: Mutex::new(None),
        });

        let watcher = Self::watch_files(slf.clone())?;
        *slf.watcher.lock().await = Some(watcher);

        Ok(slf)
    }

    fn try_load(key_path: &str, cert_path: &str) -> Result<Arc<CertifiedKey>, Error> {
        let key = if key_path.ends_with(".der") {
            let key_file = fs::read(key_path)?;
            PrivateKeyDer::try_from(key_file).map_err(|err| Error::PrivateKey(err.to_string()))?
        } else {
            PrivateKeyDer::from_pem_file(key_path)
                .map_err(|err| Error::PrivateKey(err.to_string()))?
        };

        let certs_file = fs::read(cert_path)?;
        let mut cert_chain = Vec::with_capacity(2);

        if cert_path.ends_with(".der") {
            let cert = CertificateDer::from(certs_file);
            if cert.is_empty() {
                return Err(Error::InvalidData(format!(
                    "Cannot parse certificate from {cert_path}"
                )));
            }
            cert_chain.push(cert);
        } else {
            for res in CertificateDer::pem_slice_iter(&certs_file) {
                match res {
                    Ok(cert) => {
                        cert_chain.push(cert);
                    }
                    Err(err) => return Err(Error::InvalidData(err.to_string())),
                }
            }
        };

        let provider = CryptoProvider::get_default().expect("rustls CryptoProvider not installed");
        let ck = CertifiedKey::from_der(cert_chain, key, provider)
            .map_err(|err| Error::InvalidData(err.to_string()))?;
        ck.keys_match()
            .map_err(|err| Error::KeyMismatch(err.to_string()))?;

        Ok(Arc::new(ck))
    }

    fn watch_files(slf: Arc<Self>) -> Result<RecommendedWatcher, Error> {
        let key_path = slf.key_path.clone();
        let cert_path = slf.cert_path.clone();

        let mut watcher =
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
                Ok(ev) => {
                    let should_reload = matches!(
                        ev.kind,
                        EventKind::Create(CreateKind::File) | EventKind::Modify(_)
                    );

                    if should_reload {
                        match Self::try_load(&slf.key_path, &slf.cert_path) {
                            Ok(ck) => {
                                info!("Reloading TLS Key + Certificates");
                                slf.cert_key.store(ck);
                            }
                            Err(err) => {
                                debug!("Error loading TLS after file watch event: {:?}", err);
                            }
                        }
                    }
                }
                Err(err) => {
                    error!("File watch error: {:?}", err);
                }
            })?;

        watcher.watch(Path::new(&key_path), RecursiveMode::NonRecursive)?;
        watcher.watch(Path::new(&cert_path), RecursiveMode::NonRecursive)?;

        Ok(watcher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install_crypto_provider;

    #[test]
    fn load_der() {
        install_crypto_provider();

        let ck = CertifiedKeyWatched::try_load("test_data/key.der", "test_data/certs.der").unwrap();
        ck.keys_match().unwrap();
        // TODO the DER loading currently can only load the first certificate and not a full chain
        assert_eq!(ck.cert.len(), 1);
    }

    #[test]
    fn load_pem() {
        install_crypto_provider();

        let ck = CertifiedKeyWatched::try_load("test_data/key.pem", "test_data/certs.pem").unwrap();
        ck.keys_match().unwrap();
        assert_eq!(ck.cert.len(), 2);
    }
}
