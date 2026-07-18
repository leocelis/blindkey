//! GUI preferences and enterprise deployment paths (UC-06 / UC-21 / UC-22).

use std::path::PathBuf;

/// Default idle auto-lock (seconds). `0` = never.
pub const DEFAULT_AUTOLOCK_SECS: u64 = 300;
/// Default clipboard auto-clear (C13).
pub const DEFAULT_CLIPBOARD_TIMEOUT_SECS: u64 = 30;
/// Auto re-mask on-screen reveal (C46).
pub const REVEAL_TIMEOUT_SECS: u64 = 15;

/// Persisted GUI settings (key=value lines).
#[derive(Clone, Debug)]
pub struct GuiConfig {
    pub auto_lock_secs: u64,
    pub clipboard_timeout_secs: u64,
    pub lock_on_blur: bool,
    pub dismissed_pre10: bool,
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            auto_lock_secs: DEFAULT_AUTOLOCK_SECS,
            clipboard_timeout_secs: DEFAULT_CLIPBOARD_TIMEOUT_SECS,
            lock_on_blur: false,
            dismissed_pre10: false,
        }
    }
}

impl GuiConfig {
    pub fn load() -> Self {
        let Some(p) = config_file_path() else {
            return Self::apply_env_overrides(Self::default());
        };
        let Ok(text) = std::fs::read_to_string(&p) else {
            return Self::apply_env_overrides(Self::default());
        };
        let mut cfg = Self::default();
        for line in text.lines() {
            let line = line.trim();
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let v = v.trim();
            match k.trim() {
                "auto_lock_secs" => {
                    if let Ok(n) = v.parse() {
                        cfg.auto_lock_secs = n;
                    }
                }
                "clipboard_timeout_secs" => {
                    if let Ok(n) = v.parse() {
                        cfg.clipboard_timeout_secs = n;
                    }
                }
                "lock_on_blur" => {
                    cfg.lock_on_blur = matches!(v, "1" | "true" | "yes");
                }
                "dismissed_pre10" => {
                    cfg.dismissed_pre10 = matches!(v, "1" | "true" | "yes");
                }
                _ => {}
            }
        }
        Self::apply_env_overrides(cfg)
    }

    pub fn save(&self) {
        if let Some(p) = config_file_path() {
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(
                &p,
                format!(
                    "auto_lock_secs={}\nclipboard_timeout_secs={}\nlock_on_blur={}\ndismissed_pre10={}\n",
                    self.auto_lock_secs,
                    self.clipboard_timeout_secs,
                    if self.lock_on_blur { 1 } else { 0 },
                    if self.dismissed_pre10 { 1 } else { 0 },
                ),
            );
        }
    }

    fn apply_env_overrides(mut cfg: Self) -> Self {
        if env_truthy("BLINDKEY_LOCK_ON_BLUR") {
            cfg.lock_on_blur = true;
        }
        cfg
    }
}

/// Config directory: `BLINDKEY_CONFIG_DIR` or `~/.vault`.
pub fn config_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("BLINDKEY_CONFIG_DIR") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".vault"))
}

fn config_file_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("config"))
}

/// Vault file path: `BLINDKEY_VAULT_PATH` or `<config_dir>/vault.vlt`.
pub fn resolve_vault_path() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("BLINDKEY_VAULT_PATH") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    let dir = config_dir().ok_or("cannot determine config directory")?;
    Ok(dir.join("vault.vlt"))
}

fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = GuiConfig::default();
        assert_eq!(c.auto_lock_secs, DEFAULT_AUTOLOCK_SECS);
        assert_eq!(c.clipboard_timeout_secs, DEFAULT_CLIPBOARD_TIMEOUT_SECS);
        assert!(!c.lock_on_blur);
    }

    #[test]
    fn config_dir_ends_with_dot_vault_when_home_set() {
        if std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .is_some()
            && std::env::var("BLINDKEY_CONFIG_DIR").is_err()
        {
            let d = config_dir().expect("home");
            assert!(
                d.ends_with(".vault"),
                "default config dir should be ~/.vault, got {}",
                d.display()
            );
        }
    }
}
