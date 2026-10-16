use std::{fs, sync::Mutex, time::Duration};
use tls_hot_reload::CertifiedKeyWatched;
use tokio::time::{Instant, sleep};

#[tokio::test]
async fn sibling_log_does_not_trigger_a_reload_feedback_loop()
-> Result<(), Box<dyn std::error::Error>> {
    tls_hot_reload::install_crypto_provider();
    let directory = tempfile::tempdir()?;
    let key = directory.path().join("tls.key");
    let cert = directory.path().join("tls.crt");
    let log = directory.path().join("application.log");
    fs::write(&key, include_bytes!("../test_data/key.pem"))?;
    fs::write(&cert, include_bytes!("../test_data/certs.pem"))?;
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(Mutex::new(fs::File::create(&log)?))
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    let watched = CertifiedKeyWatched::new(
        key.to_string_lossy().into_owned(),
        cert.to_string_lossy().into_owned(),
    )
    .await?;
    let initial = watched.cloned().cert[0].clone();
    fs::write(&cert, include_bytes!("../test_data/reload-a.pem"))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while watched.cloned().cert[0] == initial && Instant::now() < deadline {
        sleep(Duration::from_millis(20)).await;
    }
    assert_ne!(
        watched.cloned().cert[0],
        initial,
        "positive-control certificate update was not observed"
    );
    tracing::info!("ordinary application log message");
    sleep(Duration::from_millis(300)).await;
    let events = fs::read_to_string(log)?;
    assert_eq!(
        events.matches("Reloading TLS Key + Certificates").count(),
        1,
        "one certificate change should emit one reload event, without sibling-log feedback"
    );
    Ok(())
}
