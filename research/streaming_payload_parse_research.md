# Streaming payload parse — Research

> **Task:** Protected fields never in a contiguous full-payload plaintext buffer during open.

## Problem

Pre-1.0 open path:

```text
stream_ct → decrypt() → Zeroizing<Vec<u8>> (full outer plaintext)
         → PageLock(full buffer) → Payload::parse
```

C19 already **seals** Protected entry fields in RAM after parse (`Entry::parse` + `SealKey`).
The gap was the **transient** full outer plaintext during `Blindkey::open`.

## Verdict (2026-06-26)

| Question | Answer |
|----------|--------|
| Feasible on v1 format? | **Yes** — outer STREAM is 64 KiB AEAD chunks; inner payload is TLV |
| Full elimination of plaintext? | **No** — each chunk is verified plaintext briefly; entry blobs are copied into `Entry` |
| C19 post-open posture | **Unchanged** — Protected fields stay ciphertext until `expose()` |
| Record order | **Canonical** — inner header before entries (all vault-written files) |

## Design

1. `StreamDecryptor::next_plaintext_chunk()` — incremental outer decrypt (C1 tag-before-release).
2. `IncrementalTlv` — parse TLV from chunked feeds; pending tail only (≤ max record).
3. `Payload::parse_from_stream_ciphertext()` — wire decrypt + TLV + `Entry::parse` per entry.
4. `Blindkey::open_inner` uses streaming path only; `Payload::parse(&[u8])` kept for tests/fuzz.

## Residual exposure (accepted)

- Up to one STREAM chunk (~64 KiB) plaintext at a time during open.
- `IncrementalTlv` pending buffer ≤ largest TLV value (bounded by `MAX_ENTRY_LEN`).
- Inner-stream key and entry field blobs in heap until sealed — same as before, without full payload copy.

## References

- `crates/blindkey-core/src/crypto/stream.rs` — `decrypt_streaming`
- `crates/blindkey-core/src/format/tlv_incremental.rs`
- `crates/blindkey-core/src/format/payload.rs` — `parse_from_stream_ciphertext`
- Constraint C19 (in-memory sealing), C12 (PageLock on save-path serialize buffer)
