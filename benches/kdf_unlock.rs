//! KDF / unlock timing benchmark (constraint C22).
//!
//! Target: with default Argon2id params (m=64 MiB, t=3, p=4), the unlock phase completes in
//! < 500 ms on a 4-core / 8 GiB reference machine. `vault tune` uses the same measurement to
//! recommend parameters at ~300 ms ± 100 ms.
//!
//! Run with `cargo bench`. (Implementation lands in M3; this is the harness skeleton.)

fn main() {
    eprintln!("kdf_unlock benchmark: pending Argon2id implementation (M3). See constraint C22.");
    // TODO(M3): time vault_core::crypto::kdf with default params; assert < 500ms on reference HW.
}
