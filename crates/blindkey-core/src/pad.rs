//! Payload size padding — Padmé / PURBs (UC-07 §3.2). **Optional, default off.**
//!
//! A single encrypted blob still leaks its *length* to an untrusted backend, which is roughly affine
//! in the entry count (UC-07 §3.1). Padmé rounds the plaintext payload length up so that only
//! `⌊log₂ log₂ L⌋ + 1` mantissa bits of the length are significant — leaking `O(log log L)` bits at
//! `≤ ~12 %` overhead (decreasing with size). The padding is appended **inside** the AEAD payload
//! (after the `END` marker, which the parser already ignores), so it is encrypted and authenticated
//! and invisible to the backend.
//!
//! Reference: Nikitin, Barman, Lueks, Underwood, Hubaux, Ford, *"Reducing Metadata Leakage from
//! Encrypted Files and Communication with PURBs"*, PoPETS 2019(4) — <https://arxiv.org/abs/1806.03160>.

/// Padding policy for a vault's payload (persisted inside the encrypted payload; UC-07 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PadMode {
    /// No padding — the on-disk size reflects the exact payload length (the v1 default).
    #[default]
    None,
    /// Padmé bucketing — round the payload length up to a Padmé bucket (`≤ ~12 %` overhead).
    Padme,
}

impl PadMode {
    /// Wire encoding (one byte) stored in the inner header.
    pub(crate) fn to_byte(self) -> u8 {
        match self {
            PadMode::None => 0,
            PadMode::Padme => 1,
        }
    }

    /// Decode the wire byte; any unknown value is treated as `None` (forward compatible).
    pub(crate) fn from_byte(b: u8) -> PadMode {
        match b {
            1 => PadMode::Padme,
            _ => PadMode::None,
        }
    }

    /// The padded length (`>= len`) for a payload of `len` bytes under this policy.
    pub fn padded_len(self, len: usize) -> usize {
        match self {
            PadMode::None => len,
            PadMode::Padme => padme(len),
        }
    }
}

/// Round `len` up to its Padmé bucket (PoPETS 2019). For tiny inputs (`< 4`) returns `len` unchanged.
pub fn padme(len: usize) -> usize {
    if len < 4 {
        return len;
    }
    let e = bit_length(len) - 1; // ⌊log₂ len⌋
    let s = bit_length(e as usize); // ⌊log₂ e⌋ + 1
    if e <= s {
        return len;
    }
    let last_bits = e - s;
    let mask = (1usize << last_bits) - 1;
    (len + mask) & !mask
}

/// Number of significant bits in `x` (`0` for `x == 0`), i.e. `⌊log₂ x⌋ + 1` for `x > 0`.
fn bit_length(x: usize) -> u32 {
    usize::BITS - x.leading_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padme_never_shrinks_and_is_bounded() {
        for len in [
            0usize, 1, 2, 3, 4, 9, 10, 100, 1000, 1024, 65_536, 1_000_000,
        ] {
            let p = padme(len);
            assert!(p >= len, "padme({len}) = {p} must not shrink");
            // Overhead ≤ ~12% (paper bound), with slack for tiny inputs.
            assert!(
                p as f64 <= len as f64 * 1.12 + 16.0,
                "padme({len}) = {p} exceeds the ~12% bound"
            );
        }
    }

    #[test]
    fn padme_known_buckets() {
        assert_eq!(padme(100), 104);
        assert_eq!(padme(1000), 1024);
        assert_eq!(padme(2), 2);
    }

    #[test]
    fn padme_buckets_collapse_nearby_sizes() {
        // Two payloads of slightly different size should often share a bucket (the privacy goal).
        assert_eq!(padme(1000), padme(1024));
    }

    #[test]
    fn pad_mode_roundtrips_through_byte() {
        for m in [PadMode::None, PadMode::Padme] {
            assert_eq!(PadMode::from_byte(m.to_byte()), m);
        }
        assert_eq!(PadMode::from_byte(99), PadMode::None); // unknown → None
    }
}
