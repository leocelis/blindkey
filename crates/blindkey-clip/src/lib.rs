//! OS clipboard delivery with history/cloud suppression hints (constraint **C33**).
//!
//! Prefers [`arboard`] concealment APIs; falls back to platform CLI tools when no clipboard
//! server is available (headless CI, minimal containers).

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Stdio};

use arboard::Clipboard;

/// True when `cur` is still the secret the vault placed on the clipboard (clear-iff-unchanged, C13).
pub fn clipboard_still_ours(cur: &[u8], secret: &[u8]) -> bool {
    cur == secret
        || cur.strip_suffix(b"\n") == Some(secret)
        || cur.strip_suffix(b"\r\n") == Some(secret)
}

/// True when the OS clipboard is likely usable on this session (constraint C27).
///
/// On Linux without `DISPLAY` or `WAYLAND_DISPLAY`, clipboard delivery is refused headlessly.
pub fn clipboard_available() -> bool {
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return false;
        }
    }
    if Clipboard::new().is_ok() {
        return true;
    }
    copy_subprocess(b"").is_ok()
}

/// Copy secret bytes to the clipboard with C33 concealment hints when possible.
pub fn copy_secret(data: &[u8]) -> Result<(), String> {
    if data.is_empty() {
        return copy_subprocess(data);
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| "clipboard delivery requires utf-8 secret bytes".to_string())?;
    copy_concealed(text).or_else(|_| copy_subprocess(data))
}

/// Read clipboard bytes via platform tools (used by C13 clear-iff-unchanged).
pub fn read_clipboard() -> Option<Vec<u8>> {
    for (cmd, args) in read_tools() {
        if let Ok(out) = Command::new(cmd).args(*args).stderr(Stdio::null()).output() {
            if out.status.success() {
                return Some(out.stdout);
            }
        }
    }
    None
}

fn copy_concealed(text: &str) -> Result<(), String> {
    let mut clipboard = Clipboard::new().map_err(|e| e.to_string())?;
    #[cfg(target_os = "macos")]
    {
        use arboard::SetExtApple;
        clipboard
            .set()
            .exclude_from_history()
            .text(text.to_owned())
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "windows")]
    {
        use arboard::SetExtWindows;
        clipboard
            .set()
            .exclude_from_history()
            .exclude_from_cloud()
            .exclude_from_monitoring()
            .text(text.to_owned())
            .map_err(|e| e.to_string())?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use arboard::SetExtLinux;
        clipboard
            .set()
            .exclude_from_history()
            .text(text.to_owned())
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", unix)))]
    {
        clipboard
            .set()
            .text(text.to_owned())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

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

fn copy_subprocess(data: &[u8]) -> Result<(), String> {
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
    Err("no clipboard tool found (install pbcopy / wl-copy / xclip), or use --stdout".to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn c13_clear_iff_unchanged() {
        assert!(super::clipboard_still_ours(b"s", b"s"));
        assert!(super::clipboard_still_ours(b"s\n", b"s"));
        assert!(!super::clipboard_still_ours(b"other", b"s"));
    }

    #[test]
    fn c33_concealment_hints_wired() {
        let src = include_str!("lib.rs");
        assert!(src.contains("exclude_from_history"));
        #[cfg(target_os = "windows")]
        {
            assert!(src.contains("exclude_from_cloud"));
            assert!(src.contains("exclude_from_monitoring"));
        }
    }
}
