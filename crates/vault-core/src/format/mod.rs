//! On-disk file format and integrity — constraints **C7–C10, C18, C19, C2, C30**.
//!
//! This module parses **untrusted bytes** (a synced or restored vault file). It must never panic,
//! hang, or over-allocate on hostile input: every length field is bounded against the remaining
//! buffer *before* allocation (via [`cursor::Cursor`]), and KDF params are range-checked *before*
//! Argon2id runs. The parsers here are the primary targets in `fuzz/` (constraint C30).
//!
//! See `docs/FILE_FORMAT.md` for the byte layout.

pub mod block_stream;
mod cursor;
pub mod entry;
pub mod header;
mod inner_stream;
pub mod payload;
pub mod stanza;
mod tlv;
mod tlv_incremental;

pub use entry::{CustomField, CustomValue, Entry, Protected};
pub use header::{Header, KdfParams};
pub use payload::Payload;
pub use stanza::Stanza;

/// Maximum number of stanzas in a v1 vault (constraint C5).
pub const MAX_STANZAS: u8 = 8;
/// Maximum size of a single stanza's data blob (constraint C5).
pub const MAX_STANZA_DATA_LEN: u32 = 4096;
/// HmacBlockStream block size: 1 MiB (constraint C10).
pub const BLOCK_SIZE: usize = 1024 * 1024;
