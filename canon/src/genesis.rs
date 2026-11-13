//! Authenticated statement of the finished genesis ceremony.
//!
//! The capsule attestation binds only the seed fingerprint and the capsule
//! hash. This module binds the rest of the genesis state once the anchor
//! transaction has a confirmed birthday.
//! Ceremony orchestration stays in `zns-keygen`; this is the canonical record.

use serde::Deserialize;
use thiserror::Error;

use crate::attestation::REPORT_DATA_LEN;

/// Domain separation for [`genesis_report_data`].
pub const GENESIS_DOMAIN: &[u8] = b"ZNS_GENESIS_V1";

/// Fixed layout of [`canonical_encoding`]:
/// version (4) || network (1) || fingerprint (32) || capsule hash (32)
/// || anchor txid (32) || birthday (4).
pub const GENESIS_ENCODING_LEN: usize = 4 + 1 + 32 + 32 + 32 + 4;

/// Which Zcash network the genesis anchor was mined on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NetworkId {
    Mainnet = 1,
    Testnet = 2,
}

/// The genesis facts a later guest must recognize before it adopts the seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisRecord {
    pub version: u32,
    pub network: NetworkId,
    pub seed_fingerprint: [u8; 32],
    pub capsule_hash: [u8; 32],
    pub anchor_txid: [u8; 32],
    pub birthday: u32,
}

/// Little-endian fixed fields. No length prefixes and no omitted values.
pub fn canonical_encoding(record: &GenesisRecord) -> [u8; GENESIS_ENCODING_LEN] {
    let mut out = [0u8; GENESIS_ENCODING_LEN];
    let mut offset = 0;
    write_bytes(&mut out, &mut offset, &record.version.to_le_bytes());
    write_bytes(&mut out, &mut offset, &[record.network as u8]);
    write_bytes(&mut out, &mut offset, &record.seed_fingerprint);
    write_bytes(&mut out, &mut offset, &record.capsule_hash);
    write_bytes(&mut out, &mut offset, &record.anchor_txid);
    write_bytes(&mut out, &mut offset, &record.birthday.to_le_bytes());
    debug_assert_eq!(offset, GENESIS_ENCODING_LEN);
    out
}

/// `BLAKE2b-512(b"ZNS_GENESIS_V1" || canonical_encoding(record))`.
///
/// The result is the 64-byte `report_data` for a second SNP attestation,
/// requested after the anchor's birthday is confirmed.
pub fn genesis_report_data(record: &GenesisRecord) -> [u8; REPORT_DATA_LEN] {
    let encoding = canonical_encoding(record);
    let mut input = Vec::with_capacity(GENESIS_DOMAIN.len() + encoding.len());
    input.extend_from_slice(GENESIS_DOMAIN);
    input.extend_from_slice(&encoding);
    crate::blake2b::<REPORT_DATA_LEN>(&input)
}

fn write_bytes(out: &mut [u8], offset: &mut usize, bytes: &[u8]) {
    let end = *offset + bytes.len();
    out[*offset..end].copy_from_slice(bytes);
    *offset = end;
}

/// Why a manifest's anchor fields were refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnchorError {
    #[error("is invalid: {0}")]
    Invalid(String),
    #[error("has no anchor txid")]
    NoAnchorTxid,
    #[error("txid is not hex")]
    TxidNotHex,
    #[error("txid is not 32 bytes")]
    TxidLength,
    #[error("has no birthday")]
    NoBirthday,
}

/// Where the Registry starts, as the custody manifest records it: the
/// anchor transaction and the height it was mined at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// Display order, as the file writes it: `Transaction::txid`'s
    /// `Display`.
    pub txid: [u8; 32],
    pub birthday: u32,
}

impl Anchor {
    /// Reads `anchor_txid` and `birthday` out of a manifest's text. Other
    /// fields are ignored.
    pub fn read(text: &str) -> Result<Self, AnchorError> {
        #[derive(Deserialize)]
        struct Raw {
            anchor_txid: Option<String>,
            birthday: Option<u32>,
        }
        let raw: Raw =
            toml::from_str(text).map_err(|error| AnchorError::Invalid(error.to_string()))?;
        let txid = raw
            .anchor_txid
            .filter(|txid| !txid.trim().is_empty())
            .ok_or(AnchorError::NoAnchorTxid)?;
        let birthday = raw.birthday.ok_or(AnchorError::NoBirthday)?;
        let txid = hex::decode(txid.trim())
            .map_err(|_| AnchorError::TxidNotHex)?
            .try_into()
            .map_err(|_| AnchorError::TxidLength)?;
        Ok(Self { txid, birthday })
    }

    /// `text` with `anchor_txid` and `birthday` set to this anchor. Every
    /// other byte is kept as written.
    pub fn rewrite(&self, text: &str) -> Result<String, AnchorError> {
        let mut document: toml_edit::DocumentMut = text
            .parse()
            .map_err(|error: toml_edit::TomlError| AnchorError::Invalid(error.to_string()))?;
        document["anchor_txid"] = toml_edit::value(hex::encode(self.txid));
        document["birthday"] = toml_edit::value(i64::from(self.birthday));
        Ok(document.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GenesisRecord {
        GenesisRecord {
            version: 1,
            network: NetworkId::Testnet,
            seed_fingerprint: [0x11; 32],
            capsule_hash: [0x22; 32],
            anchor_txid: [0x33; 32],
            birthday: 4408922,
        }
    }

    #[test]
    fn encoding_lays_out_the_fixed_fields() {
        let bytes = canonical_encoding(&sample());
        assert_eq!(&bytes[0..4], &1u32.to_le_bytes());
        assert_eq!(bytes[4], NetworkId::Testnet as u8);
        assert_eq!(&bytes[5..37], &[0x11; 32]);
        assert_eq!(&bytes[37..69], &[0x22; 32]);
        assert_eq!(&bytes[69..101], &[0x33; 32]);
        assert_eq!(&bytes[101..105], &4408922u32.to_le_bytes());
        assert_eq!(bytes.len(), GENESIS_ENCODING_LEN);
    }

    #[test]
    fn report_data_covers_the_domain_and_changes_with_birthday() {
        let record = sample();
        let bound = genesis_report_data(&record);
        let encoding = canonical_encoding(&record);
        assert_ne!(bound, crate::blake2b::<REPORT_DATA_LEN>(&encoding));

        let mut later = record;
        later.birthday += 1;
        assert_ne!(genesis_report_data(&later), bound);
    }

    #[test]
    fn rewrite_changes_only_the_anchor_lines() {
        let manifest = "seed_fingerprint = \"zip32seedfp1x\"
capsule_hash_blake2b256 = \"4444\"
anchor_txid = \"abababababababababababababababababababababababababababababababab\"
birthday = 4408922
measurement = \"7a7a\"
";
        let moved = Anchor {
            txid: [0xff; 32],
            birthday: 3_500_000,
        };
        let rewritten = moved.rewrite(manifest).unwrap();
        assert_eq!(manifest.lines().count(), rewritten.lines().count());
        let changed: Vec<_> = manifest
            .lines()
            .zip(rewritten.lines())
            .filter(|(before, after)| before != after)
            .collect();
        assert_eq!(
            changed,
            vec![
                (
                    "anchor_txid = \"abababababababababababababababababababababababababababababababab\"",
                    "anchor_txid = \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"",
                ),
                ("birthday = 4408922", "birthday = 3500000"),
            ]
        );
        assert_eq!(Anchor::read(&rewritten).unwrap(), moved);
    }
}
