//! UC-26 information architecture — Credentials vs Workspace (Seal is not a mode).

/// Primary product modes for `blindkey-gui` (UC-26 C77).
///
/// Seal files is a **secondary CTA / dialog**, never a third variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GuiMode {
    #[default]
    Credentials,
    Workspace,
}

impl GuiMode {
    pub fn label(self) -> &'static str {
        match self {
            GuiMode::Credentials => "Credentials",
            GuiMode::Workspace => "Workspace",
        }
    }
}

/// Persistent chrome status (IA-01). Eject is a closure event, not a status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Locked,
    Unlocked,
    /// Volume validated and OS mount path available.
    Mounted,
}

impl SessionStatus {
    pub fn label(self) -> &'static str {
        match self {
            SessionStatus::Locked => "Locked",
            SessionStatus::Unlocked => "Unlocked",
            SessionStatus::Mounted => "Mounted",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_is_not_a_mode_variant() {
        // Compile-time / API contract: only two modes exist.
        let modes = [GuiMode::Credentials, GuiMode::Workspace];
        assert_eq!(modes.len(), 2);
        assert_eq!(GuiMode::Credentials.label(), "Credentials");
        assert_eq!(GuiMode::Workspace.label(), "Workspace");
    }

    #[test]
    fn eject_is_not_a_persistent_status() {
        let labels: Vec<_> = [
            SessionStatus::Locked,
            SessionStatus::Unlocked,
            SessionStatus::Mounted,
        ]
        .into_iter()
        .map(SessionStatus::label)
        .collect();
        assert!(!labels.contains(&"Ejected"));
    }
}
