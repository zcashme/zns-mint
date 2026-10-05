//! Development-only reading of a `FakeTee` report.
//!
//! Production builds do not include this module. They call
//! `zns_canon::attestation::stored`, which parses the SNP report, fetches
//! AMD endorsement material, and checks the pinned ARK. `stored` cannot parse
//! a fake report, and the fake signing key is not an SNP key. The layout
//! mirrored here is the one `FakeTee::get_attestation` writes:
//! domain || measurement || report_data || SHA-256(signing_key || body).

use sha2::{Digest, Sha256};

use crate::error::MigrateError;

const DOMAIN: &[u8] = b"ZNS_FAKE_TEE/attestation/v1";
const MEASUREMENT_LEN: usize = 48;
const REPORT_DATA_LEN: usize = 64;
const TAG_LEN: usize = 32;

/// Public test key from `zns-canon`'s `FakeTee`. Anyone can forge a report
/// with it; that is why this path cannot be built into a release binary.
const FAKE_SIGNING_KEY: [u8; 32] = [
    0xF1, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x1F, 0x2E, 0x3D, 0x4C, 0x5B, 0x6A, 0x79, 0x88,
];

pub fn measurement(
    bytes: &[u8],
    expected_report_data: &[u8; 64],
) -> Result<[u8; 48], MigrateError> {
    let measurement_at = DOMAIN.len();
    let report_at = measurement_at + MEASUREMENT_LEN;
    let tag_at = report_at + REPORT_DATA_LEN;
    let end = tag_at + TAG_LEN;
    if bytes.len() != end || &bytes[..DOMAIN.len()] != DOMAIN {
        return Err(MigrateError::transport(
            "attestation is not a development TEE report",
        ));
    }
    let mut measurement = [0u8; MEASUREMENT_LEN];
    measurement.copy_from_slice(&bytes[measurement_at..report_at]);
    let mut report_data = [0u8; REPORT_DATA_LEN];
    report_data.copy_from_slice(&bytes[report_at..tag_at]);
    if report_data != *expected_report_data {
        return Err(MigrateError::transport(
            "development attestation report_data does not match the offer",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(FAKE_SIGNING_KEY);
    hasher.update(&bytes[..tag_at]);
    let tag = hasher.finalize();
    if !ct_eq(&bytes[tag_at..], &tag) {
        return Err(MigrateError::transport(
            "development attestation tag does not match",
        ));
    }
    Ok(measurement)
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use zns_canon::sealing::{FakeTee, Tee};

    #[test]
    fn fake_report_measurement_and_report_data_are_checked() {
        let report_data = [7u8; 64];
        let attestation = FakeTee.get_attestation(&report_data).unwrap();
        assert_eq!(
            measurement(attestation.as_bytes(), &report_data).unwrap(),
            [0xFAu8; 48]
        );

        let mut flipped = attestation.as_bytes().to_vec();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        assert!(measurement(&flipped, &report_data).is_err());

        let mut other = report_data;
        other[0] ^= 0x01;
        assert!(measurement(attestation.as_bytes(), &other).is_err());
    }
}
