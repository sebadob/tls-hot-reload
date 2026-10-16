## Unreleased

- Observe parent directories so repeated atomic file replacements and projected
  Secret rotations continue to reload certificates.
- Native watch registration now includes the containing directories. On Linux,
  those directories require read permission. A resolver that previously worked
  with readable files in an execute-only directory can now fail to initialize.
  This changes filesystem permission requirements.

## v0.3.0

Bumps `aws-lc` dependencies to mitigate some security vulnerabilities.

## v0.2.0

The unmaintained `rustls-pemfile` crate was dropped in favor of directly using the lower level `rustls-pki-types`.

## v0.1.0

Initial Release
