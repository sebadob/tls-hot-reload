set shell := ["bash", "-uc"]

export TAG := `cat Cargo.toml | grep '^version =' | cut -d " " -f3 | xargs`

# prints out the currently set version
version:
    #!/usr/bin/env bash
    echo "v$TAG"

# clippy lint + check with minimal versions from nightly
check:
    #!/usr/bin/env bash
    set -euxo pipefail
    clear
    cargo update

    # nightly check currently throws errors
    #cargo +nightly clippy -- -D warnings
    cargo clippy -- -D warnings

    cd examples/simple-hot-reload
    cargo clippy -- -D warnings

    cd ../..

    echo 'Checking minimal versions'
    cargo minimal-versions check
    cargo update

# verifies the MSRV
msrv-verify:
    cargo msrv verify

# find's the new MSRV, if it needs a bump
msrv-find:
    cargo msrv --min 1.70.0

# verify thats everything is good
verify: check msrv-verify

# makes sure everything is fine
verfiy-is-clean: verify
    #!/usr/bin/env bash
    set -euxo pipefail

    # make sure everything has been committed
    git diff --exit-code

    echo all good

# sets a new git tag and pushes it
release: verfiy-is-clean
    #!/usr/bin/env bash
    set -euxo pipefail

    git tag "v$TAG"
    git push origin "v$TAG"

# publishes the current version to cargo.io
publish: verfiy-is-clean
    #!/usr/bin/env bash
    set -euxo pipefail

    # We must delete the pre-built binaries to not push them to crates.io
    rm -rf out/*

    cargo publish

# dry run for publishing to crates.io
publish-dry: verfiy-is-clean
    #!/usr/bin/env bash
    set -euxo pipefail

    # We must delete the pre-built binaries to not push them to crates.io
    rm -rf out/*

    cargo publish --dry-run
