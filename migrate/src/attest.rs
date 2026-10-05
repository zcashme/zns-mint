//! Read a measurement out of an attestation report.
//!
//! Production builds call `zns_canon::attestation::stored`: parse the SNP
//! report, fetch AMD endorsement material, and check the pinned ARK before
//! `report_data` is accepted. Development builds read a `FakeTee` report
//! instead, because `stored` cannot parse one.

use crate::error::MigrateError;

pub(crate) fn measurement(report: &[u8], expected: &[u8; 64]) -> Result<[u8; 48], MigrateError> {
    #[cfg(feature = "fake-tee")]
    {
        crate::report::measurement(report, expected)
    }
    #[cfg(not(feature = "fake-tee"))]
    {
        let attestation = zns_canon::attestation::stored(report.to_vec(), expected);
        Ok(attestation.measurement)
    }
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
