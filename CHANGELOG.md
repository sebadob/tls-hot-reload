## v0.4.1

`v0.4.0` broke the compilation on MacOS and Windows. With the introduction of the new `PollWatcher`,
the `INotifyWatcher` was used as the default part specifically instead of the platform-neutral `RecommendedWatcher`.

## v0.4.0

Observe parent directories so repeated atomic file replacements and projected Secret rotations continue to reload certificates.

A watch registration now includes the containing directories. On Linux, those directories require read permission. A resolver that previously worked with readable files in an execute-only directory can now fail to initialize. This changes filesystem permission requirements.

There is now an alternative poll-based backend for watching files. Either via `load_server_config_polling()` or `CertifiedKeyWatched::new_polling()`. This is useful when you have your certs on e.g. NFS where the kernel cannot send `inotify` events.

## v0.3.0

Bumps `aws-lc` dependencies to mitigate some security vulnerabilities.

## v0.2.0

The unmaintained `rustls-pemfile` crate was dropped in favor of directly using the lower level `rustls-pki-types`.

## v0.1.0

Initial Release
