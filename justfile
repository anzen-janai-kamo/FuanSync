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
    rustup target add aarch64-unknown-linux-gnu x86_64-pc-windows-gnullvm x86_64-apple-darwin x86_64-unknown-linux-musl aarch64-unknown-linux-musl

cross-build-linux:
    cargo build --release --locked --target x86_64-unknown-linux-gnu

cross-build-aarch64:
    ./scripts/cross-cargo aarch64-unknown-linux-gnu build --release --locked

cross-build-linux-musl:
    ./scripts/cross-cargo x86_64-unknown-linux-musl build --release --locked

cross-build-aarch64-musl:
    ./scripts/cross-cargo aarch64-unknown-linux-musl build --release --locked

cross-build-musl: cross-build-linux-musl cross-build-aarch64-musl

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

cross-test-linux-musl *args="--all-targets":
    ./scripts/cross-cargo x86_64-unknown-linux-musl test --release --locked {{args}}

cross-test-aarch64-musl *args="--lib":
    ./scripts/cross-cargo aarch64-unknown-linux-musl test --release --locked {{args}}

cross-run-windows *args="--version":
    ./scripts/cross-cargo x86_64-pc-windows-gnullvm run --release --locked -- {{args}}

cross-run-macos *args="--version":
    ./scripts/cross-cargo x86_64-apple-darwin run --release --locked -- {{args}}

cross-run-aarch64-musl *args="--version":
    ./scripts/cross-cargo aarch64-unknown-linux-musl run --release --locked -- {{args}}
