//! Clipboard delivery for the TUI.
//!
//! Copy a secret via the OS tool (secret over **stdin**, never argv — C29), and clear it after a
//! timeout **iff** it is still our secret (C13). The TUI process is long-lived, so the auto-clear
//! runs as a background thread; the one-shot CLI uses a detached helper process for the same effect.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use zeroize::Zeroizing;

fn copy_tools() -> &'static [(&'static str, &'static [&'static str])] {
    if cfg!(target_os = "macos") {
        &[("pbcopy", &[])]
    } else if cfg!(target_os = "windows") {
        &[("clip", &[])]
    } else {
        &[
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["-b", "-i"]),
        ]
    }
}

fn read_tools() -> &'static [(&'static str, &'static [&'static str])] {
    if cfg!(target_os = "macos") {
        &[("pbpaste", &[])]
    } else if cfg!(target_os = "windows") {
        &[("powershell", &["-NoProfile", "-Command", "Get-Clipboard"])]
    } else {
        &[
            ("wl-paste", &["--no-newline"]),
            ("xclip", &["-selection", "clipboard", "-o"]),
            ("xsel", &["-b", "-o"]),
        ]
    }
}

/// Write `data` to the OS clipboard via the platform tool (stdin). Empty `data` clears it.
pub fn copy(data: &[u8]) -> Result<(), String> {
    for (cmd, args) in copy_tools() {
        let child = Command::new(cmd)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(_) => continue,
        };
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data).map_err(|e| e.to_string())?;
        }
        if child.wait().map_err(|e| e.to_string())?.success() {
            return Ok(());
        }
    }
    Err("no clipboard tool found (install pbcopy / wl-copy / xclip)".to_string())
}

/// Read the current clipboard contents, if a tool is available.
pub fn read() -> Option<Vec<u8>> {
    for (cmd, args) in read_tools() {
        if let Ok(out) = Command::new(cmd).args(*args).stderr(Stdio::null()).output() {
            if out.status.success() {
                return Some(out.stdout);
            }
        }
    }
    None
}

/// After `secs`, clear the clipboard **iff** it still holds `secret` (tolerating a trailing newline).
pub fn schedule_clear(secret: Zeroizing<Vec<u8>>, secs: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(secs));
        if let Some(cur) = read() {
            let cur = Zeroizing::new(cur);
            let (c, s): (&[u8], &[u8]) = (&cur, &secret);
            let unchanged =
                c == s || c.strip_suffix(b"\n") == Some(s) || c.strip_suffix(b"\r\n") == Some(s);
            if unchanged {
                let _ = copy(&[]);
            }
        }
    });
}
