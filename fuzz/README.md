# Fuzz targets (constraint C30)

Parser fuzzing for untrusted vault input. Requires nightly Rust and `cargo-fuzz`:

```sh
cargo install cargo-fuzz
just fuzz                  # smoke-run header_parse (30s)
cargo +nightly fuzz run header_parse
```

Targets live in `fuzz/fuzz_targets/`:

| Target | Parser |
|--------|--------|
| `header_parse` | Vault header TLV |
| `file_archive_parse` | UC-23 inner file-archive TLV (C65/C30) |

Smoke locally: `just fuzz` (requires `cargo-fuzz`).
