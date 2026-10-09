//! Read a measurement and guest policy out of an attestation report.
//!
//! Calls `zns_canon::attestation::stored`: parse the SNP report, fetch
//! AMD endorsement material, and check the pinned ARK before `report_data`
//! is accepted. There is no development path: migration is a ceremony.

use crate::error::MigrateError;

pub(crate) struct VerifiedReport {
    pub measurement: [u8; 48],
    pub guest_policy: u64,
}

pub(crate) fn verified_report(
    report: &[u8],
    expected: &[u8; 64],
) -> Result<VerifiedReport, MigrateError> {
    let attestation = zns_canon::attestation::stored(report.to_vec(), expected);
    Ok(VerifiedReport {
        measurement: attestation.measurement,
        guest_policy: attestation.guest_policy,
    })
}

pub(crate) fn require_measurement(
    got: &[u8; 48],
    expected: &[u8; 48],
    mismatch: MigrateError,
) -> Result<(), MigrateError> {
    if got.iter().all(|byte| *byte == 0) {
        return Err(MigrateError::ZeroMeasurement);
    }
    if got != expected {
        return Err(mismatch);
    }
    Ok(())
}

pub(crate) fn require_policy(
    got: u64,
    expected: u64,
    mismatch: MigrateError,
) -> Result<(), MigrateError> {
    if got == 0 {
        return Err(MigrateError::ZeroGuestPolicy);
    }
    if got != expected {
        return Err(mismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_policy_must_match_and_must_not_be_zero() {
        require_policy(0x30000, 0x30000, MigrateError::GuestPolicy).unwrap();
        assert!(matches!(
            require_policy(0, 0x30000, MigrateError::GuestPolicy),
            Err(MigrateError::ZeroGuestPolicy)
        ));
        assert!(matches!(
            require_policy(0x70000, 0x30000, MigrateError::GuestPolicy),
            Err(MigrateError::GuestPolicy)
        ));
    }
}
