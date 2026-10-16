#![cfg(unix)]

use rustls_pki_types::{CertificateDer, pem::PemObject};
use std::{fs, os::unix::fs::symlink, path::Path, sync::Once, time::Duration};
use tls_hot_reload::CertifiedKeyWatched;
use tokio::time::{Instant, sleep};

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
    CRYPTO.call_once(tls_hot_reload::install_crypto_provider);
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
    let temporary = tempfile::tempdir()?;
    let mounted = temporary.path().join("mounted");
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
