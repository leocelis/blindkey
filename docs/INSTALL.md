# Installation

> **Pre-alpha:** there is no installable release yet. These are the intended install paths.

## From crates.io (intended)

```sh
cargo install vault-cli
```

One statically-linked binary, no runtime dependencies (no JVM/Python/Node) — constraint C20.

## Pre-built binaries (intended)

Download from the [GitHub Releases](https://github.com/leocelis/vault/releases) page, then
**verify the signature and checksum** before running — see [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md).

## From source

```sh
git clone https://github.com/leocelis/vault
cd vault
cargo build --release --locked
# Binary at target/release/vault
```

### Fully static Linux build

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
ldd target/x86_64-unknown-linux-musl/release/vault   # → "not a dynamic executable"
```

## Supported platforms

`x86_64-unknown-linux-musl` · `aarch64-apple-darwin` · `x86_64-apple-darwin` ·
`x86_64-pc-windows-msvc`.

## Optional hardware features

FIDO2 / TPM / OS-keystore stanzas are behind the `vault-hardware` crate's feature flags and may
require system libraries (e.g. `libfido2`). They are **optional** — the password stanza always works.
