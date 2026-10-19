use crate::error::Error;
use arc_swap::ArcSwap;
use notify::event::CreateKind;
use notify::{EventKind, RecursiveMode, Watcher};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use std::fmt::{Debug, Formatter};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task;
use tracing::{debug, error, info};

/// A TLS Key / Certificate combination created from files. The files are automatically watched, and
/// the internal TLS data will be rebuilt automatically if a new matching key + cert was found. This
/// makes any server using `rustls` capable of hot-reloading certificates without any other
/// modification.
pub struct CertifiedKeyWatched {
    key_path: String,
    cert_path: String,
    cert_key: ArcSwap<CertifiedKey>,
    watcher: Mutex<Option<KeyWatcher>>,
}

#[allow(unused)]
enum KeyWatcher {
    INotify(notify::INotifyWatcher),
    Poll(notify::PollWatcher),
}

impl Debug for CertifiedKeyWatched {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CertifiedKeyWatched {{ key_path: {}, cert_path: {}, cert_key: {:?} }}",
            self.key_path, self.cert_path, self.cert_key
        )
    }
}

impl Drop for CertifiedKeyWatched {
    fn drop(&mut self) {
        // Synchronously stop the file watcher so its event thread exits with us.
        // `get_mut` is safe here: the only other lock holder was `new()`, which
        // released the guard long before this point.
        let _ = self.watcher.get_mut().take();
    }
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

    /// Load a key/certificate pair and register native file and directory watches.
    ///
    /// Both containing directories must permit watch registration. On Linux this requires directory
    /// read access even when the files themselves are readable. Failure to register any required
    /// watch is returned to the caller.
    pub async fn new<K, C>(key_path: K, cert_path: C) -> Result<Arc<Self>, Error>
    where
        K: Into<String>,
        C: Into<String>,
    {
        Self::new_with(key_path, cert_path, None).await
    }

    /// Load a key/certificate pair and register native file and directory watches.
    ///
    /// This runs a polling watcher in the background. This may be used in situations like when NFA
    /// is your backend, since Linux cannot forward `inotify` events properly in that case. In
    /// comparison to the default watcher, this will not detect changes instantly, but depending on
    /// the given `poll_interval`.
    pub async fn new_polling<K, C>(
        key_path: K,
        cert_path: C,
        poll_interval: Duration,
    ) -> Result<Arc<Self>, Error>
    where
        K: Into<String>,
        C: Into<String>,
    {
        Self::new_with(key_path, cert_path, Some(poll_interval)).await
    }

    async fn new_with<K, C>(
        key_path: K,
        cert_path: C,
        poll_interval: Option<Duration>,
    ) -> Result<Arc<Self>, Error>
    where
        K: Into<String>,
        C: Into<String>,
    {
        let key_path = key_path.into();
        let cert_path = cert_path.into();

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

        let watcher = Self::watch_files(slf.clone(), poll_interval)?;
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

    fn watch_files(slf: Arc<Self>, poll_interval: Option<Duration>) -> Result<KeyWatcher, Error> {
        let key_path = slf.key_path.clone();
        let cert_path = slf.cert_path.clone();

        // Capture only a weak reference: a strong `Arc` here would form the cycle
        // struct -> watcher -> callback -> Arc<struct>, preventing the last caller
        // from ever dropping us (and with it this watcher).
        let weak = Arc::downgrade(&slf);

        // Atomic replacements can detach file watches from the current inode.
        // Parent watches also observe Kubernetes projected Secret symlink swaps.
        let key_parent = Path::new(&key_path)
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let cert_parent = Path::new(&cert_path)
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));

        let watch_files = |watcher: &mut dyn Watcher| {
            watcher.watch(Path::new(&key_path), RecursiveMode::NonRecursive)?;
            watcher.watch(Path::new(&cert_path), RecursiveMode::NonRecursive)?;
            watcher.watch(key_parent, RecursiveMode::NonRecursive)?;
            if cert_parent != key_parent {
                watcher.watch(cert_parent, RecursiveMode::NonRecursive)?;
            }
            Ok::<_, Error>(())
        };

        if let Some(interval) = poll_interval {
            let mut watcher = notify::poll::PollWatcher::new(
                move |res| {
                    let Some(slf) = weak.upgrade() else {
                        return;
                    };
                    Self::handle_watch_event(slf, res);
                },
                notify::Config::default().with_poll_interval(interval),
            )?;
            watch_files(&mut watcher)?;
            Ok(KeyWatcher::Poll(watcher))
        } else {
            let mut watcher = notify::inotify::INotifyWatcher::new(
                move |res| {
                    // Once the last strong reference is gone, stop processing events.
                    let Some(slf) = weak.upgrade() else {
                        return;
                    };
                    Self::handle_watch_event(slf, res);
                },
                notify::Config::default(),
            )?;
            watch_files(&mut watcher)?;
            Ok(KeyWatcher::INotify(watcher))
        }
    }

    fn handle_watch_event(slf: Arc<Self>, res: notify::Result<notify::Event>) {
        match res {
            Ok(ev) => {
                let should_reload = matches!(
                    ev.kind,
                    EventKind::Create(CreateKind::File) | EventKind::Modify(_)
                );

                let affects_source = should_reload
                    && (ev.paths.is_empty()
                        || ev.paths.iter().any(|changed| {
                            let resolved_change = changed.canonicalize().ok();
                            [&slf.key_path, &slf.cert_path].iter().any(|source| {
                                changed == Path::new(source.as_str())
                                    || resolved_change.as_ref().is_some_and(|changed| {
                                        Path::new(source.as_str())
                                            .canonicalize()
                                            .is_ok_and(|source| source.starts_with(changed))
                                    })
                            })
                        }));
                if affects_source {
                    match Self::try_load(&slf.key_path, &slf.cert_path) {
                        Ok(ck) => {
                            // Duplicate or directory events may describe unchanged material.
                            if slf.cert_key.load().cert != ck.cert {
                                slf.cert_key.store(ck);
                                info!("Reloading TLS Key + Certificates");
                            }
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install_crypto_provider;
    use std::os::unix::fs::symlink;
    use std::sync::Once;
    use std::time::Duration;
    use tokio::time::{Instant, sleep};

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

    #[tokio::test]
    async fn key_drop_terminates_watcher() {
        install_crypto_provider();

        let resolver = CertifiedKeyWatched::new("test_data/key.pem", "test_data/certs.pem")
            .await
            .unwrap();
        let weak = Arc::downgrade(&resolver);
        drop(resolver);

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            weak.upgrade().is_none(),
            "resolver retained after caller dropped it"
        );
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const KEY: &[u8] = include_bytes!("../test_data/key.pem");
    const CERTS: [&[u8]; 3] = [
        include_bytes!("../test_data/certs.pem"),
        include_bytes!("../test_data/reload-a.pem"),
        include_bytes!("../test_data/reload-b.pem"),
    ];

    static CRYPTO: Once = Once::new();

    fn write_pair(directory: &Path, cert: &[u8]) -> TestResult {
        fs::create_dir_all(directory)?;
        fs::write(directory.join("tls.key"), KEY)?;
        fs::write(directory.join("tls.crt"), cert)?;
        Ok(())
    }

    async fn reader(
        directory: &Path,
    ) -> Result<std::sync::Arc<CertifiedKeyWatched>, Box<dyn std::error::Error>> {
        CRYPTO.call_once(crate::install_crypto_provider);
        Ok(CertifiedKeyWatched::new(
            directory.join("tls.key").to_string_lossy().into_owned(),
            directory.join("tls.crt").to_string_lossy().into_owned(),
        )
        .await?)
    }

    #[derive(Debug, Clone, Copy)]
    enum Replacement {
        Projected,
        Atomic,
        InPlace,
    }

    async fn check_replacements(replacement: Replacement) -> TestResult {
        let tmp = tempfile::tempdir()?;
        let mounted = tmp.path().join("mounted");
        fs::create_dir(&mounted)?;

        if matches!(replacement, Replacement::Projected) {
            write_pair(&mounted.join("revision-0"), CERTS[0])?;
            symlink("revision-0", mounted.join("..data"))?;
            symlink("..data/tls.key", mounted.join("tls.key"))?;
            symlink("..data/tls.crt", mounted.join("tls.crt"))?;
        } else {
            write_pair(&mounted, CERTS[0])?;
        }

        let watched = reader(&mounted).await?;
        let initial = watched.cloned().cert[0].clone();
        for (revision, cert) in CERTS.iter().enumerate().skip(1) {
            let expected = CertificateDer::pem_slice_iter(cert)
                .next()
                .ok_or("missing test certificate")??;
            assert_ne!(initial, expected);

            if matches!(replacement, Replacement::Projected) {
                write_pair(&mounted.join(format!("revision-{revision}")), cert)?;
                symlink(format!("revision-{revision}"), mounted.join("..data_tmp"))?;
                fs::rename(mounted.join("..data_tmp"), mounted.join("..data"))?;
                fs::remove_dir_all(mounted.join(format!("revision-{}", revision - 1)))?;
            } else if matches!(replacement, Replacement::Atomic) {
                fs::write(mounted.join("tls.crt.tmp"), cert)?;
                fs::rename(mounted.join("tls.crt.tmp"), mounted.join("tls.crt"))?;
            } else {
                fs::write(mounted.join("tls.crt"), cert)?;
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            while watched.cloned().cert[0] != expected && Instant::now() < deadline {
                sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(
                watched.cloned().cert[0],
                expected,
                "certificate revision {revision} was not loaded ({replacement:?})"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn reloads_after_two_projected_secret_rotations() -> TestResult {
        check_replacements(Replacement::Projected).await
    }

    #[tokio::test]
    async fn reloads_after_two_atomic_file_replacements() -> TestResult {
        check_replacements(Replacement::Atomic).await
    }

    #[tokio::test]
    async fn preserves_in_place_certificate_reloading() -> TestResult {
        check_replacements(Replacement::InPlace).await
    }
}
