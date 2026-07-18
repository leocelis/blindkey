//! TPM PCR mock + mismatch helper (constraint **C15** integration tests without hardware).

use crate::tpm_policy::PCR_MISMATCH_MESSAGE;

/// Simulate PCR seal check — returns the C15 user-visible error on mismatch.
pub fn open_with_pcr(current_pcr: u32, sealed_pcr: u32) -> Result<(), &'static str> {
    if current_pcr == sealed_pcr {
        Ok(())
    } else {
        Err(PCR_MISMATCH_MESSAGE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm_policy::RE_ENROLL_COMMAND;

    #[test]
    fn c15_pcr_mismatch_emits_documented_message() {
        let err = open_with_pcr(7, 8).unwrap_err();
        assert!(err.contains("PCR mismatch"));
        assert!(err.contains(RE_ENROLL_COMMAND));
        assert!(err.contains("unlock with password"));
    }
}
