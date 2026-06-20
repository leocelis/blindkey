//! TPM stanza policy strings (constraint **C15**) — documented before full TPM integration lands.

/// User-visible message on PCR mismatch (constraint C15 — verbatim strings in intent).
pub const PCR_MISMATCH_MESSAGE: &str =
    "TPM stanza failed (PCR mismatch — firmware or kernel may have changed). \
     Run `vault re-enroll-tpm` or unlock with password.";

/// CLI command names frozen by C21 / UC-09.
pub const ENROLL_COMMAND: &str = "vault enroll-tpm";
pub const RE_ENROLL_COMMAND: &str = "vault re-enroll-tpm";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c15_pcr_mismatch_message_names_re_enroll() {
        assert!(PCR_MISMATCH_MESSAGE.contains("PCR mismatch"));
        assert!(PCR_MISMATCH_MESSAGE.contains(RE_ENROLL_COMMAND));
        assert!(PCR_MISMATCH_MESSAGE.contains("unlock with password"));
    }

    #[test]
    fn c15_command_names_are_stable() {
        assert_eq!(ENROLL_COMMAND, "vault enroll-tpm");
        assert_eq!(RE_ENROLL_COMMAND, "vault re-enroll-tpm");
    }
}
