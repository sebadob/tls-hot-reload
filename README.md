# tls-hot-reload

This is a tiny crate that brings wait- and lock-free TLS hot-reloading to `rustls`. It has minimal overhead and no
internal locking when it comes to resolving TLS certificates.

The main thing it provides is `CertifiedKeyWatched`. It implements `rustls::server::ResolvesServerCert` and can be used
directly inside a `rustls::ServerConfig` as a certificate resolver. When you create a new `CertifiedKeyWatched`, it
automatically spawns file watchers in the background that listen to modifications on these files and if they notice any,
they will try to reload TLS certificates without any interruption in service.

The implementation is completely framework / server agnostic and works anywhere, where you can provide a
`rustls::ServerConfig`. The `tokio` dependency only exists for spawning background tasks and async file access.

In the most simple form, the only thing you need to do is:

```rust
let tls_config =
tls_hot_reload::load_server_config("tls/key.pem".to_string(), "tls/cert.pem".to_string()).await;
```

If you want to build your own custom `ServerConfig`, you can create the `CertifiedKeyWatched` directly:

```rust
let ck = CertifiedKeyWatched::new(key_path, cert_path).await?;
ServerConfig::builder().with_no_client_auth().with_cert_resolver(ck)
```

You can also use `CertifiedKeysWatched::new()` to provide a `Vec<BundleCert>` of certificates / paths which then will be
resolved via SNI from the `ClientHello`.
