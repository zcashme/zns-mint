//! The TEE seam: the two capabilities `boot` needs from the enclave.
//!
//! 1. A per-instance sealing key for [`crate::capsule`] (production: VCEK-rooted, SNP-derived).
//! 2. A signed attestation report binding the mint's identity (Treasury address + Registry FVK,
//!    in `report_data`) to the measured guest image.
//!
//! The trait lets integration tests swap in [`FakeTee`] and boot the same code path off SNP.
//! `FakeTee` is `fake-tee`-gated and blocked from release by `compile_error!` in `crate::lib`;
//! its "signature" is a SHA-256 tag over a public constant, rejected by any real verifier.

use thiserror::Error;

// The production KDF is only compiled on Linux (the sole
// `RealSnpTee::derive_sealing_key` caller) and in tests (which exercise
// `bind_context` directly, independent of `/dev/sev-guest`).
#[cfg(any(target_os = "linux", test))]
use hmac::{Hmac, Mac};
#[cfg(any(target_os = "linux", test))]
use sha2::Sha256;

#[cfg(any(target_os = "linux", test))]
type HmacSha256 = Hmac<Sha256>;

/// Domain separator for the production sealing-key KDF. Distinct from
/// `FakeTee`'s domain so a fake key never collides with a production
/// one derived under the same `context`.
#[cfg(any(target_os = "linux", test))]
const SEALING_DOMAIN: &[u8] = b"ZNS_TEE/sealing-key/v1";

/// Mixes `context` into an SNP-derived root key via
/// `HMAC-SHA256(root, SEALING_DOMAIN || LE32(len(context)) || context)`.
/// Length-prefixing rules out any two contexts that share a prefix
/// producing the same key.
#[cfg(any(target_os = "linux", test))]
fn bind_context(root: &[u8; 32], context: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(root).expect("HMAC-SHA256 accepts any key length");
    mac.update(SEALING_DOMAIN);
    mac.update(&(context.len() as u32).to_le_bytes());
    mac.update(context);
    let bytes = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    key
}

#[derive(Debug, Error)]
pub enum TeeError {
    /// The TEE could not derive a sealing key (firmware unavailable, IOCTL
    /// failure, wrong platform).
    #[error("TEE sealing-key derivation failed: {0}")]
    SealingKey(String),

    /// The TEE could not produce a signed attestation report.
    #[error("TEE attestation report generation failed: {0}")]
    Attestation(String),

    /// The requested TEE is not available on this platform (e.g.
    /// RealSnpTee on macOS without the fake-tee feature).
    #[error("TEE not available on this platform")]
    Unavailable,
}

/// A signed attestation report emitted by a [`Tee`].
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

/// The TEE boundary. See the module docs for the split of concerns.
pub trait Tee: Send + Sync {
    /// Derive a per-instance sealing key. `context` disambiguates keys
    /// derived by the same TEE for different purposes: distinct
    /// contexts must always produce distinct keys. Callers today:
    /// `CAPSULE_KEY_CONTEXT` (seed capsule) and `ACCESS_CODE_KEY_CONTEXT`
    /// (pre-sale root).
    fn derive_sealing_key(&self, context: &[u8]) -> Result<[u8; 32], TeeError>;

    /// Produce a signed attestation report whose `report_data` field
    /// carries the given 64 bytes verbatim.
    fn get_attestation(&self, report_data: &[u8; 64]) -> Result<Attestation, TeeError>;
}

// ---------------------------------------------------------------------------
// RealSnpTee — production path
// ---------------------------------------------------------------------------

/// The production TEE: AMD SEV-SNP via `/dev/sev-guest`. All SNP-specific
/// types (`Firmware`, `DerivedKey`, `GuestFieldSelect`) are contained
/// inside this impl; boot never sees them.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealSnpTee;

/// Two-step derivation: SNP-firmware root → context-bound sealing key.
///
/// Step 1 — `firmware.get_derived_key` returns a VCEK-rooted, per-chip
/// key mixed from exactly two guest fields, matching the capsule
/// creator:
///   guest_policy — launch conditions (debug, SMT, migration)
///   measurement  — code identity (hash of the guest image)
///
/// `image_id` and `family_id` are deliberately excluded: they are
/// hypervisor-supplied labels with no security content, and including
/// them makes the key brittle to launch-blob drift. VCEK
/// (`root_key_select = false`) is stable across reboots; VMRK is random
/// per launch without a Migration Agent and would brick the capsule on
/// first reboot.
///
/// Step 2 — `bind_context` HMACs the root with the caller's `context`,
/// so `CAPSULE_KEY_CONTEXT` and `ACCESS_CODE_KEY_CONTEXT` derive
/// disjoint keys from the same chip. Without this step both callers
/// would share one SNP-derived key — the [`Tee`] trait contract on
/// `context` would be silently false in production.
#[cfg(target_os = "linux")]
impl Tee for RealSnpTee {
    fn derive_sealing_key(&self, context: &[u8]) -> Result<[u8; 32], TeeError> {
        use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
        use zeroize::Zeroize;

        let mut firmware = Firmware::open()
            .map_err(|e| TeeError::SealingKey(format!("SEV-SNP firmware open: {e}")))?;
        let mut guest_fields = GuestFieldSelect::default();
        guest_fields.set_guest_policy(true);
        guest_fields.set_measurement(true);
        let request = DerivedKey::new(false, guest_fields, 0, 0, 0, None);
        let mut root = firmware
            .get_derived_key(Some(1), request)
            .map_err(|e| TeeError::SealingKey(format!("SEV-SNP get_derived_key: {e}")))?;
        let key = bind_context(&root, context);
        root.zeroize();
        Ok(key)
    }

    fn get_attestation(&self, report_data: &[u8; 64]) -> Result<Attestation, TeeError> {
        use sev::firmware::guest::Firmware;

        let mut firmware = Firmware::open()
            .map_err(|e| TeeError::Attestation(format!("SEV-SNP firmware open: {e}")))?;
        let bytes = firmware
            .get_report(None, Some(*report_data), None)
            .map_err(|e| TeeError::Attestation(format!("SEV-SNP get_report: {e}")))?;
        Ok(Attestation::new(bytes, *report_data))
    }
}

#[cfg(not(target_os = "linux"))]
impl Tee for RealSnpTee {
    fn derive_sealing_key(&self, _context: &[u8]) -> Result<[u8; 32], TeeError> {
        Err(TeeError::Unavailable)
    }

    fn get_attestation(&self, _report_data: &[u8; 64]) -> Result<Attestation, TeeError> {
        Err(TeeError::Unavailable)
    }
}

// ---------------------------------------------------------------------------
// FakeTee — development-only path (feature = "fake-tee")
// ---------------------------------------------------------------------------

#[cfg(feature = "fake-tee")]
pub use fake::FakeTee;

#[cfg(feature = "fake-tee")]
mod fake {
    use super::{Attestation, Tee, TeeError};
    use sha2::{Digest, Sha256};

    /// Domain string mixed into the sealing key derivation. Purely
    /// dev-only: anyone can recompute this key.
    const SEALING_DOMAIN: &[u8] = b"ZNS_FAKE_TEE/sealing-key/v1";

    /// Domain string prefixed to the report body.
    const ATTEST_DOMAIN: &[u8] = b"ZNS_FAKE_TEE/attestation/v1";

    /// Fixed "measurement" value the fake TEE reports — stands in for
    /// the SNP-measured guest image hash. Not secret.
    const FAKE_MEASUREMENT: [u8; 48] = [0xFA; 48];

    /// The hard-coded signing key. A real verifier trivially forges
    /// reports with this key; that is the point — no fake report can
    /// ever be mistaken for a production SNP report.
    const FAKE_SIGNING_KEY: [u8; 32] = [
        0xF1, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x1F, 0x2E, 0x3D, 0x4C, 0x5B, 0x6A,
        0x79, 0x88,
    ];

    /// Development-only [`Tee`]: deterministic sealing key from a domain
    /// string, and a synthetic signed report that embeds the same
    /// `report_data` and a fixed test measurement. Boots outside SEV-SNP
    /// on macOS/Linux without `/dev/sev-guest`.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct FakeTee;

    impl Tee for FakeTee {
        fn derive_sealing_key(&self, context: &[u8]) -> Result<[u8; 32], TeeError> {
            // SHA256(DOMAIN || LP(context)). Length-prefixed so distinct
            // contexts always produce distinct keys.
            let mut h = Sha256::new();
            h.update(SEALING_DOMAIN);
            h.update((context.len() as u32).to_le_bytes());
            h.update(context);
            Ok(h.finalize().into())
        }

        fn get_attestation(&self, report_data: &[u8; 64]) -> Result<Attestation, TeeError> {
            // Report body: DOMAIN || measurement || report_data.
            let mut body = Vec::with_capacity(ATTEST_DOMAIN.len() + FAKE_MEASUREMENT.len() + 64);
            body.extend_from_slice(ATTEST_DOMAIN);
            body.extend_from_slice(&FAKE_MEASUREMENT);
            body.extend_from_slice(report_data);

            // Test-only signature slot: SHA256(FAKE_SIGNING_KEY || body).
            // Not an HMAC — a public constant "key" is by definition
            // forgeable. It exists so the fake report's shape (body +
            // signature suffix) mirrors the SNP layout.
            let mut h = Sha256::new();
            h.update(FAKE_SIGNING_KEY);
            h.update(&body);
            let tag = h.finalize();

            let mut bytes = Vec::with_capacity(body.len() + tag.len());
            bytes.extend_from_slice(&body);
            bytes.extend_from_slice(&tag);
            Ok(Attestation::new(bytes, *report_data))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Cross-platform tests for the production KDF's context-binding step.
/// These do not exercise `/dev/sev-guest`; they exercise the pure step
/// that turns the SNP root into a context-scoped key. Runnable on any
/// target and any feature set — the pre-audit gap was that the
/// production keying model went untested even under `fake-tee`.
#[cfg(test)]
mod bind_context_tests {
    use super::*;
    use crate::capsule::CAPSULE_KEY_CONTEXT;
    use crate::mint::presale::ACCESS_CODE_KEY_CONTEXT;

    /// A synthetic root. Not a real SNP key — the point is only to fix
    /// the KDF's inputs so the output is reproducible.
    const ZERO_ROOT: [u8; 32] = [0u8; 32];

    #[test]
    fn deterministic() {
        assert_eq!(
            bind_context(&ZERO_ROOT, b"ctx"),
            bind_context(&ZERO_ROOT, b"ctx")
        );
    }

    /// The property this whole fix delivers: distinct contexts under
    /// the same root produce distinct keys. Without this, the capsule
    /// and access-code roots would share one SNP-derived key.
    #[test]
    fn distinct_contexts_disjoint_keys() {
        assert_ne!(
            bind_context(&ZERO_ROOT, CAPSULE_KEY_CONTEXT),
            bind_context(&ZERO_ROOT, ACCESS_CODE_KEY_CONTEXT)
        );
    }

    /// Length-prefixing rules out extension/prefix collisions: two
    /// contexts where one is a prefix of the other must derive
    /// different keys, even though a naive `domain || context`
    /// concatenation would treat some of them identically.
    #[test]
    fn length_prefix_defeats_prefix_collisions() {
        let a = bind_context(&ZERO_ROOT, b"foo");
        let b = bind_context(&ZERO_ROOT, b"foobar");
        assert_ne!(a, b);
    }

    /// Pinned bytes for `HMAC-SHA256(zero_root, SEALING_DOMAIN ||
    /// LE32(len) || context)` at each live context. Any independent
    /// implementation of the KDF must reproduce them; a change to the
    /// domain, length prefix, or MAC construction turns this red.
    #[test]
    fn reference_vectors() {
        assert_eq!(
            hex::encode(bind_context(&ZERO_ROOT, CAPSULE_KEY_CONTEXT)),
            "7aebe36ce1fe731c1a916d8925c3373608da202490eec602d9acbe91042030f8"
        );
        assert_eq!(
            hex::encode(bind_context(&ZERO_ROOT, ACCESS_CODE_KEY_CONTEXT)),
            "88b9a54ffa3b7d305c6bd1f90c7543329e9b383510e789ff765f9c262761a3d0"
        );
    }
}

#[cfg(all(test, feature = "fake-tee"))]
mod tests {
    use super::*;

    #[test]
    fn fake_sealing_key_is_deterministic() {
        let tee = FakeTee;
        let k1 = tee.derive_sealing_key(b"ctx").unwrap();
        let k2 = tee.derive_sealing_key(b"ctx").unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn fake_sealing_key_scoped_by_context() {
        let tee = FakeTee;
        let k1 = tee.derive_sealing_key(b"ctx-a").unwrap();
        let k2 = tee.derive_sealing_key(b"ctx-b").unwrap();
        assert_ne!(k1, k2);
    }

    /// The whole point of the attestation seam: the 64-byte identity
    /// binding the caller passes in appears verbatim in the report and
    /// is retrievable through `report_data()` without re-parsing.
    #[test]
    fn fake_attestation_carries_report_data_verbatim() {
        let tee = FakeTee;
        let rd = [42u8; 64];
        let att = tee.get_attestation(&rd).unwrap();
        assert_eq!(att.report_data(), &rd);
        assert!(
            att.as_bytes().windows(64).any(|w| w == rd),
            "report_data must be embedded verbatim in the report bytes"
        );
    }

    /// Different `report_data` inputs yield different report bytes —
    /// otherwise the seam would silently accept identity confusion.
    #[test]
    fn fake_attestation_bytes_depend_on_report_data() {
        let tee = FakeTee;
        let a = tee.get_attestation(&[1u8; 64]).unwrap();
        let b = tee.get_attestation(&[2u8; 64]).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
