//! The custody manifest, `keys/zns_custody_manifest.toml`: which seed the
//! capsule beside it holds, and how keygen sealed and attested it.
//!
//! keygen writes the [`Record`] once, at the ceremony. Every boot reads its
//! [`Custody`]. migrate carries the file's bytes to the next guest unparsed.
//! The same file also records where the Registry starts: that is
//! [`crate::genesis::Anchor`].

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The manifest's file name, beside the capsule.
pub const FILE: &str = "zns_custody_manifest.toml";

/// The manifest's path in the guest's working directory.
pub const PATH: &str = "keys/zns_custody_manifest.toml";

/// Why a manifest's custody fields were refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CustodyError {
    #[error("is invalid: {0}")]
    Invalid(String),
    #[error("has no network")]
    NoNetwork,
    #[error("has no seed fingerprint")]
    NoSeedFingerprint,
}

/// The custody fields every boot checks: the build's network and the seed
/// the capsule must hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Custody {
    pub network: String,
    pub seed_fingerprint: String,
}

impl Custody {
    /// Reads the custody fields out of a manifest's text. Other fields are
    /// ignored.
    pub fn read(text: &str) -> Result<Self, CustodyError> {
        #[derive(Deserialize)]
        struct Raw {
            network: Option<String>,
            seed_fingerprint: Option<String>,
        }
        let raw: Raw =
            toml::from_str(text).map_err(|error| CustodyError::Invalid(error.to_string()))?;
        Ok(Self {
            network: raw.network.ok_or(CustodyError::NoNetwork)?,
            seed_fingerprint: raw
                .seed_fingerprint
                .ok_or(CustodyError::NoSeedFingerprint)?,
        })
    }
}

/// The whole file as keygen writes it, in its order.
#[derive(Clone, Debug, Serialize)]
pub struct Record {
    pub manifest_version: u32,
    pub network: String,
    pub seed_fingerprint: String,
    pub capsule_file: String,
    pub capsule_hash_blake2b256: String,
    pub capsule_format: String,
    pub seed_length: usize,
    pub treasury_account: u32,
    pub registry_account: u32,
    pub treasury_address: String,
    pub anchor_txid: String,
    pub birthday: u32,
    pub sealing: String,
    pub sealing_root_key: String,
    pub sealing_guest_fields: String,
    pub guest_policy: String,
    pub tcb_version: String,
    pub rng: String,
    pub attestation_file: String,
    pub attestation_hash_blake2b256: String,
    pub report_data_hash_blake2b256: String,
    pub measurement: String,
    pub attestation_sig_algo: String,
    pub migration: String,
    pub signer_socket: String,
}

impl Record {
    pub fn to_toml(&self) -> String {
        toml::to_string(self).expect("a flat record serializes")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// keygen's output for its `finalize_writes_the_manifest` inputs,
    /// written with `toml` 0.8 before this module existed.
    pub(crate) const KEYGEN_MANIFEST: &str = "manifest_version = 1
network = \"mainnet\"
seed_fingerprint = \"zip32seedfp1y4g3culaawgkav3nuhhdt5rnxv0vxncv2xc5aen20sgpvds4zevql4zs7n\"
capsule_file = \"keys/zns_seed.capsule\"
capsule_hash_blake2b256 = \"4444444444444444444444444444444444444444444444444444444444444444\"
capsule_format = \"ZNS_SEED\"
seed_length = 32
treasury_account = 0
registry_account = 1
treasury_address = \"t1gASwBju9UHFeDPQEFuBKbWePSBEF8LMu3\"
anchor_txid = \"abababababababababababababababababababababababababababababababab\"
birthday = 4408922
sealing = \"amd-sev-snp-derived-key\"
sealing_root_key = \"vcek\"
sealing_guest_fields = \"guest_policy,measurement\"
guest_policy = \"0x0000000000030000\"
tcb_version = \"bootloader=1 tee=2 snp=3 microcode=4\"
rng = \"rdseed\"
attestation_file = \"keys/zns_attestation.bin\"
attestation_hash_blake2b256 = \"6dd83b43bfc3b3542aad908a2b607f2be449c57b9bd284eee73ed77726dd9bfa\"
report_data_hash_blake2b256 = \"0eb923b0cbd24df54401d998531feead35a47a99f4deed205de4af81120f9761\"
measurement = \"7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a\"
attestation_sig_algo = \"ecdsa-p384-sha384\"
migration = \"none\"
signer_socket = \"none\"
";

    #[test]
    fn the_record_is_written_as_keygen_wrote_it() {
        let record = Record {
            manifest_version: 1,
            network: "mainnet".into(),
            seed_fingerprint:
                "zip32seedfp1y4g3culaawgkav3nuhhdt5rnxv0vxncv2xc5aen20sgpvds4zevql4zs7n".into(),
            capsule_file: "keys/zns_seed.capsule".into(),
            capsule_hash_blake2b256: "44".repeat(32),
            capsule_format: "ZNS_SEED".into(),
            seed_length: 32,
            treasury_account: 0,
            registry_account: 1,
            treasury_address: "t1gASwBju9UHFeDPQEFuBKbWePSBEF8LMu3".into(),
            anchor_txid: "ab".repeat(32),
            birthday: 4_408_922,
            sealing: "amd-sev-snp-derived-key".into(),
            sealing_root_key: "vcek".into(),
            sealing_guest_fields: "guest_policy,measurement".into(),
            guest_policy: "0x0000000000030000".into(),
            tcb_version: "bootloader=1 tee=2 snp=3 microcode=4".into(),
            rng: "rdseed".into(),
            attestation_file: "keys/zns_attestation.bin".into(),
            attestation_hash_blake2b256:
                "6dd83b43bfc3b3542aad908a2b607f2be449c57b9bd284eee73ed77726dd9bfa".into(),
            report_data_hash_blake2b256:
                "0eb923b0cbd24df54401d998531feead35a47a99f4deed205de4af81120f9761".into(),
            measurement: "7a".repeat(48),
            attestation_sig_algo: "ecdsa-p384-sha384".into(),
            migration: "none".into(),
            signer_socket: "none".into(),
        };
        assert_eq!(record.to_toml(), KEYGEN_MANIFEST);
    }

    #[test]
    fn custody_reads_out_of_the_record() {
        assert_eq!(
            Custody::read(KEYGEN_MANIFEST).unwrap(),
            Custody {
                network: "mainnet".into(),
                seed_fingerprint:
                    "zip32seedfp1y4g3culaawgkav3nuhhdt5rnxv0vxncv2xc5aen20sgpvds4zevql4zs7n".into(),
            }
        );
    }

    #[test]
    fn read_refuses_what_boot_refuses() {
        assert_eq!(
            Custody::read("seed_fingerprint = \"x\"\n"),
            Err(CustodyError::NoNetwork)
        );
        assert_eq!(
            Custody::read("network = \"testnet\"\n"),
            Err(CustodyError::NoSeedFingerprint)
        );
        assert!(matches!(
            Custody::read("not toml ="),
            Err(CustodyError::Invalid(_))
        ));
    }

    #[test]
    fn the_path_is_the_file_in_keys() {
        assert_eq!(PATH, format!("keys/{FILE}"));
    }
}
