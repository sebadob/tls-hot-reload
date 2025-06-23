use ::time::OffsetDateTime;
use actix_web::http::header::ContentType;
use actix_web::{App, HttpResponse, HttpServer, web};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use std::ops::{Add, Sub};
use std::sync::LazyLock;
use std::time::Duration;
use tokio::{fs, task, time};

static PATH_CERT: &str = "tls/cert.pem";
static PATH_KEY: &str = "tls/key.pem";

static KEY_PAIR_CA: LazyLock<rcgen::KeyPair> =
    LazyLock::new(|| rcgen::KeyPair::generate().unwrap());
static CA: LazyLock<(CertificateParams, Certificate)> = LazyLock::new(|| {
    let mut params = CertificateParams::default();

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Hot-Reload Example CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Hot-Reload Example Org");
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    let one_day = time::Duration::from_secs(24 * 3600);
    let now = OffsetDateTime::now_utc();
    params.not_before = now.add(one_day);
    params.not_after = now.sub(one_day);

    let cert = params.clone().self_signed(&KEY_PAIR_CA).unwrap();
    (params, cert)
});

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    tracing::subscriber::set_global_default(tracing_subscriber::FmtSubscriber::default()).unwrap();

    fs::create_dir_all("tls").await?;
    create_end_entity().await?;

    // This task will re-create certificates every 10 seconds to see reloading in action.
    // Typically, you would see the `Reloading TLS Key + Certificates` logging message twice.
    // If you see it once or twice depends a lot on the OS, how fast the update is, and so on.
    //
    // Both the Cert and Key are watched and they are never updated at the same time. This means
    // you will also see `debug` logs with errors because of key mismatch, which is to be expected,
    // when only one file have been updated but the other one not yet.
    //
    // Both files are watched independently and if anything changes, it will try to build a valid
    // key + cert combination from it. If you see a key mismatch log, or updating the certs twice,
    // depends a lot on your OS.
    //
    // In the "worst case", it loads the TLS certs twice, but with the same output, which is a
    // really small overhead.
    spawn_recreate();

    // This command is usually all you need, as long as you don't want to create a custom server
    // config.
    let tls_config =
        tls_hot_reload::load_server_config(PATH_KEY.to_string(), PATH_CERT.to_string()).await;

    HttpServer::new(|| App::new().service(web::resource("/").to(index)))
        .bind_rustls_0_23(("localhost", 8443), tls_config)?
        .workers(1)
        .run()
        .await?;

    Ok(())
}

async fn create_end_entity() -> anyhow::Result<()> {
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();

    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.use_authority_key_identifier_extension = true;

    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);

    let now = OffsetDateTime::now_utc();
    params.not_before = now.sub(time::Duration::from_secs(5));
    params.not_after = now.add(time::Duration::from_secs(30));

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key_pair, &CA.1, &KEY_PAIR_CA).unwrap();

    fs::write(PATH_KEY, key_pair.serialize_pem()).await?;
    fs::write(PATH_CERT, cert.pem()).await?;

    Ok(())
}

fn spawn_recreate() {
    task::spawn(async {
        loop {
            time::sleep(Duration::from_secs(10)).await;
            create_end_entity().await.unwrap();
        }
    });
}

async fn index() -> HttpResponse {
    HttpResponse::Ok().content_type(ContentType::html()).body(
        "<!DOCTYPE html><html><body>\
            <p>Welcome to your TLS-secured homepage!</p>\
        </body></html>",
    )
}
