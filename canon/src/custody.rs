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
