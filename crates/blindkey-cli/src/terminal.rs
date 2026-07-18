//! Terminal output sanitization (C28).

/// True when `c` must be rendered as a visible escape (C0 except \\n/\\t, or C1 controls).
fn should_escape(c: char) -> bool {
    if c == '\n' || c == '\t' {
        return false;
    }
    let u = c as u32;
    c.is_control() || (0x80..=0x9F).contains(&u)
}

/// Render control / ANSI bytes as visible escapes before writing to a TTY (constraint C28).
pub fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .map(|c| {
            if should_escape(c) {
                format!("\\x{:02x}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c28_escapes_ansi_csi() {
        assert_eq!(sanitize_for_terminal("ok\x1b[31m"), "ok\\x1b[31m");
    }

    #[test]
    fn c28_preserves_tab_and_newline() {
        assert_eq!(sanitize_for_terminal("a\tb"), "a\tb");
        assert_eq!(sanitize_for_terminal("line1\nline2"), "line1\nline2");
    }

    #[test]
    fn c28_escapes_c1_controls() {
        assert_eq!(sanitize_for_terminal("\u{0080}"), "\\x80");
    }

    #[test]
    fn c28_escapes_bell_in_notes() {
        assert_eq!(sanitize_for_terminal("a\x07b"), "a\\x07b");
    }
}
