//! Clipboard delivery for the desktop app (constraints C13, C33).

use std::time::Duration;

use zeroize::Zeroizing;

pub use blindkey_clip::{clipboard_still_ours, copy_secret as copy, read_clipboard as read};

/// After `secs`, clear the clipboard **iff** it still holds `secret` (tolerating a trailing newline).
pub fn schedule_clear(secret: Zeroizing<Vec<u8>>, secs: u64) {
    if secs == 0 {
        return;
    }
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(secs));
        if let Some(cur) = read() {
            let cur = Zeroizing::new(cur);
            if clipboard_still_ours(&cur, &secret) {
                let _ = copy(&[]);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn c33_uses_blindkey_clip() {
        let src = include_str!("clip.rs");
        assert!(src.contains("blindkey_clip"));
    }
}
