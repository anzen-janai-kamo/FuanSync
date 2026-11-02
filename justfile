set shell := ["bash", "-euo", "pipefail", "-c"]

fmt:
    cargo fmt --check

lint:
    cargo clippy --all-targets --locked -- -D warnings

test:
    cargo test --all-targets --locked

build:
    cargo build --release --locked

# Install standard libraries used by the Linux-hosted cross build.
cross-setup:
    rustup target add aarch64-unknown-linux-gnu x86_64-pc-windows-gnullvm x86_64-apple-darwin

cross-build-linux:
    cargo build --release --locked --target x86_64-unknown-linux-gnu

cross-build-aarch64:
    ./scripts/cross-cargo aarch64-unknown-linux-gnu build --release --locked

cross-build-windows:
    ./scripts/cross-cargo x86_64-pc-windows-gnullvm build --release --locked

cross-build-macos:
    ./scripts/cross-cargo x86_64-apple-darwin build --release --locked

cross-build: cross-build-linux cross-build-aarch64 cross-build-windows cross-build-macos

# Set FUANSYNC_RUNNER to an external runtime for cross-run/test
# recipes. The runtime path stays outside the repository.
# Additional Cargo test options may select a suite or pass --no-run.
cross-test-windows *args="--all-targets":
    ./scripts/cross-cargo x86_64-pc-windows-gnullvm test --release --locked {{args}}

cross-test-macos *args="--all-targets":
    ./scripts/cross-cargo x86_64-apple-darwin test --release --locked {{args}}

cross-run-windows *args="--version":
    ./scripts/cross-cargo x86_64-pc-windows-gnullvm run --release --locked -- {{args}}

cross-run-macos *args="--version":
    ./scripts/cross-cargo x86_64-apple-darwin run --release --locked -- {{args}}
