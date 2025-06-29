use crate::certified_key::CertifiedKeyWatched;
use crate::error::Error;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Used to create a new `CertifiedKeysWatched`. If you want to resolve a wildcard certificate, you
/// need to specify it for each SNI. It does not resolve SNIs like `*.example.com`, only absolute
/// ones.
#[derive(Debug)]
pub struct BundleCert {
    pub sni: String,
    pub cert_path: String,
    pub key_path: String,
}

/// Holds multiple certificate bundles and resolves them depending on the SNI from the
/// `ClientHello`. Does not dynamically resolve wildcard certificates. You need to add them for
/// each SNI you want to use it with.
#[derive(Debug)]
pub struct CertifiedKeysWatched {
    keys: BTreeMap<String, Arc<CertifiedKeyWatched>>,
}

impl ResolvesServerCert for CertifiedKeysWatched {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?;
        let key = self.keys.get(sni)?;
        Some(key.cloned())
    }
}

impl CertifiedKeysWatched {
    pub async fn new(bundle: Vec<BundleCert>) -> Result<Arc<Self>, Error> {
        let mut keys = BTreeMap::new();
        for b in bundle {
            let ck = CertifiedKeyWatched::new(b.key_path, b.cert_path).await?;
            keys.insert(b.sni, ck);
        }
        Ok(Arc::new(Self { keys }))
    }
}
