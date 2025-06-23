# simple-hot-reload

This very simple example shows the hot-reload in action. This example uses `actix-web`, but it will work the same with
anything, where you can provide a `rustls::ServerConfig`. It's completely framework / server agnostic.

Most of the code is actually about generating TLS certificates and not about the impl itself, but this is mandatory to
show that it's actually doing something and not just logging, that it updates the certificates.

When you `cargo run`, you can access the server on `https://localhost:8443`. You then inspect the certificate and check
the `nbf` and `exp`. These will be shifted in 35 second windows each 10 seconds, when a new certificate is being
created.

The easiest way to check, that it's actually doing something, is via `openssl s_client`:

```
openssl s_client -connect host:port 2>/dev/null | openssl x509 -noout -dates
```

If you don't have this available, you can also use your browser, but keep in mind, that you most probably need to use
private windows or different browsers to actually see the newly created certificates, because if you just refresh in
the same window, you probably still have a valid TLS session in the background, which is based on the old certificate.

> Note: The `openssl s_client` command does not return by default and you need to CTRL + C it.
