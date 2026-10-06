//! The TEE seam: the two capabilities boot needs from the enclave —
//! a per-instance sealing key for [`crate::capsule`], and an attestation
//! report binding the mint's identity in `report_data`.
//!
//! Both talk to `/dev/sev-guest` and fail with [`TeeError::Unavailable`]
//! wherever there is no SNP guest device. There is no fake: code running
//! off the enclave either build with the `non-tee` feature and use
//! [`dev_sealing_key`], or they have no attestation at all.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TeeError {
    /// The TEE could not derive a sealing key (firmware unavailable, IOCTL
    /// failure, wrong platform).
    #[error("TEE sealing-key derivation failed: {0}")]
    SealingKey(String),

    /// The TEE could not produce a signed attestation report.
    #[error("TEE attestation report generation failed: {0}")]
    Attestation(String),

    /// No SNP guest device on this platform. `non-tee` builds fall back to
    /// [`dev_sealing_key`]; there is no dev attestation.
    #[error("TEE not available on this platform")]
    Unavailable,
}

/// A signed attestation report from the AMD Secure Processor.
///
/// The wire form (`bytes`) is what an external verifier parses; the mint
/// treats it as opaque past this seam. `report_data` is the exact 64-byte
/// binding the caller passed in, retained for logs and tests without
/// re-parsing the report.
#[derive(Clone, Debug)]
pub struct Attestation {
    bytes: Vec<u8>,
    report_data: [u8; 64],
}

impl Attestation {
    pub fn new(bytes: Vec<u8>, report_data: [u8; 64]) -> Self {
        Self { bytes, report_data }
    }

    /// The signed report as bytes; verifier-facing.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The 64-byte identity binding this report attests to.
    pub fn report_data(&self) -> &[u8; 64] {
        &self.report_data
    }
}

/// A sealing key: hardware-derived on the enclave, or the public
/// dev-escape key in `non-tee` builds. Zeroized on drop; not `Clone`.
pub struct SealingKey([u8; 32]);

impl SealingKey {
    /// Wraps raw key bytes. Prefer the constructors: this exists for
    /// callers who already hold the bytes (e.g. test fixtures).
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The key bytes, for keying an AEAD.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealingKey(REDACTED)")
    }
}

impl Drop for SealingKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// Domain string mixed into [`dev_sealing_key`].
#[cfg(feature = "non-tee")]
const DEV_SEALING_DOMAIN: &[u8] = b"ZNS_DEV/sealing-key/v1";

/// Development sealing key (`non-tee` builds): deterministic SHA-256 over a public domain
/// string and the caller's context. **Anyone can derive this key** — it
/// exists so development builds can seal and unseal their own capsules
/// off the enclave. A dev-key boot cannot unseal a production capsule:
/// the AEAD tag is the boundary between the two worlds.
#[cfg(feature = "non-tee")]
pub fn dev_sealing_key(context: &[u8]) -> SealingKey {
    use sha2::{Digest, Sha256};

    let mut h = Sha256::new();
    h.update(DEV_SEALING_DOMAIN);
    h.update((context.len() as u32).to_le_bytes());
    h.update(context);
    SealingKey::new(h.finalize().into())
}

/// Derives the per-instance sealing key from the SEV-SNP firmware:
/// `firmware.get_derived_key` returns a VCEK-rooted, per-chip key mixed
/// from exactly two guest fields, matching the capsule creator:
///   guest_policy — launch conditions (debug, SMT, migration)
///   measurement  — code identity (hash of the guest image)
///
/// `image_id` and `family_id` are deliberately excluded: they are
/// hypervisor-supplied labels with no security content, and including
/// them makes the key brittle to launch-blob drift. VCEK
/// (`root_key_select = false`) is stable across reboots; VMRK is random
/// per launch without a Migration Agent and would brick the capsule on
/// Classifies a guest-firmware open failure. A missing `/dev/sev-guest`
/// means "this is not an SNP guest" — [`TeeError::Unavailable`], the
/// promised off-platform signal. Any other failure is operational for
/// the specific operation and carries the detail.
#[cfg(target_os = "linux")]
fn guest_open_error(
    e: std::io::Error,
    operation: &str,
    operational: fn(String) -> TeeError,
) -> TeeError {
    use std::io::ErrorKind;

    if e.kind() == ErrorKind::NotFound {
        TeeError::Unavailable
    } else {
        operational(format!("SEV-SNP {operation}: {e}"))
    }
}

/// first reboot.
#[cfg(target_os = "linux")]
pub fn derive_sealing_key(_context: &[u8]) -> Result<SealingKey, TeeError> {
    use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};

    let mut firmware =
        Firmware::open().map_err(|e| guest_open_error(e, "firmware open", TeeError::SealingKey))?;
    let mut guest_fields = GuestFieldSelect::default();
    guest_fields.set_guest_policy(true);
    guest_fields.set_measurement(true);
    let request = DerivedKey::new(false, guest_fields, 0, 0, 0, None);
    firmware
        .get_derived_key(Some(1), request)
        .map(|key| SealingKey::new(key))
        .map_err(|e| TeeError::SealingKey(format!("SEV-SNP get_derived_key: {e}")))
}

/// Requests an attestation report from the AMD Secure Processor whose
/// `report_data` field carries the given 64 bytes verbatim.
#[cfg(target_os = "linux")]
pub fn get_attestation(report_data: &[u8; 64]) -> Result<Attestation, TeeError> {
    use sev::firmware::guest::Firmware;

    let mut firmware = Firmware::open()
        .map_err(|e| guest_open_error(e, "firmware open", TeeError::Attestation))?;
    let bytes = firmware
        .get_report(None, Some(*report_data), None)
        .map_err(|e| TeeError::Attestation(format!("SEV-SNP get_report: {e}")))?;
    Ok(Attestation::new(bytes, *report_data))
}

/// Non-SNP platforms compile the same functions; they fail with
/// [`TeeError::Unavailable`] at runtime. Development uses
/// [`dev_sealing_key`] and simply has no attestation.
#[cfg(not(target_os = "linux"))]
pub fn derive_sealing_key(_context: &[u8]) -> Result<SealingKey, TeeError> {
    Err(TeeError::Unavailable)
}

#[cfg(not(target_os = "linux"))]
pub fn get_attestation(_report_data: &[u8; 64]) -> Result<Attestation, TeeError> {
    Err(TeeError::Unavailable)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "non-tee"))]
mod tests {
    use super::*;

    /// The missing-device classification: NotFound is the promised
    /// off-platform signal, everything else stays operational.
    #[cfg(target_os = "linux")]
    #[test]
    fn missing_guest_device_is_unavailable() {
        use std::io::ErrorKind;

        let missing = std::io::Error::from(ErrorKind::NotFound);
        assert!(matches!(
            guest_open_error(missing, "firmware open", TeeError::SealingKey),
            TeeError::Unavailable
        ));
        let denied = std::io::Error::from(ErrorKind::PermissionDenied);
        assert!(matches!(
            guest_open_error(denied, "firmware open", TeeError::SealingKey),
            TeeError::SealingKey(_)
        ));
    }

    #[test]
    fn dev_sealing_key_is_deterministic() {
        assert_eq!(
            dev_sealing_key(b"ctx").expose(),
            dev_sealing_key(b"ctx").expose()
        );
    }

    #[test]
    fn dev_sealing_key_scoped_by_context() {
        assert_ne!(
            dev_sealing_key(b"ctx-a").expose(),
            dev_sealing_key(b"ctx-b").expose()
        );
    }
}
