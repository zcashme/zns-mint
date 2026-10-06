//! Read a measurement out of an attestation report.
//!
//! Calls `zns_canon::attestation::stored`: parse the SNP report, fetch
//! AMD endorsement material, and check the pinned ARK before `report_data`
//! is accepted. There is no development path: migration is a ceremony.

use crate::error::MigrateError;

pub(crate) fn measurement(report: &[u8], expected: &[u8; 64]) -> Result<[u8; 48], MigrateError> {
    let attestation = zns_canon::attestation::stored(report.to_vec(), expected);
    Ok(attestation.measurement)
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
