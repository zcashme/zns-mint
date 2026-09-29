//! The pre-sale protected-names table, cached in memory.
//!
//! `zn_names` is read once at boot and re-read once per MTP day in
//! the tip pass; claims consult the cache synchronously — Supabase
//! is never on a claim's path. Every row is protected; `expires_at`
//! (`timestamptz`, nullable) is either a lift moment, judged against
//! the current MTP per claim, or forever. A missing row, or a lift
//! moment the MTP has reached, is unprotected. The six-digit code is not
//! stored in the table: it is derived in the TEE from a root key
//! (`Tee::derive_sealing_key`) and the claim name, matching the
//! access-code-v1 HMAC construction. Redemption is the name live in
//! the registry; the mint never writes Supabase.

use std::collections::BTreeMap;
use std::time::Duration;

use hmac::{Hmac, Mac};
use http::Uri;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Deserializer};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, Timestamp};
use zeroize::{Zeroize, Zeroizing};

use crate::mint::Name;

/// Context for [`crate::tee::Tee::derive_sealing_key`]: the access-code
/// root private key (32 bytes). Distinct from the capsule sealing context.
pub const ACCESS_CODE_KEY_CONTEXT: &[u8] = b"ZNS/access-code/root/v1";

/// Supabase project HTTP origin. PostgREST only.
const PRESALE_HOST: &str = "https://cclrkfymckyjfufvqedr.supabase.co";

/// Protected-name collection.
const PRESALE_TABLE: &str = "zn_names";

/// Public Supabase publishable key (`apikey` for PostgREST).
const PRESALE_PUBLISHABLE_KEY: &str = "sb_publishable_eRyX0Z5CY3bHm11iCFoZRA_-u2WgStF";

const FETCH_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Rows per request — four requests per thousand rows. Worst-case
/// valid rows (~137 bytes: a 63-byte name plus a 35-character RFC
/// 3339 timestamp) keep a page at ~34 KB, half of `MAX_BODY_BYTES`.
const PAGE_ROWS: usize = 250;

/// Page ceiling: a read past this many full pages (~25,000 names)
/// is refused — a pathological table keeps yesterday's rows, loudly.
const MAX_PAGES: usize = 100;

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>;
type HmacSha256 = Hmac<Sha256>;

fn https_client() -> HttpsClient {
    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(connector)
}

fn presale_rest_url() -> String {
    format!("{PRESALE_HOST}/rest/v1/{PRESALE_TABLE}")
}

/// A six-digit protected-name access code (same wire shape as an OTP).
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct AccessCode(u32);

impl std::fmt::Debug for AccessCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccessCode(REDACTED)")
    }
}

impl AccessCode {
    /// Derive from the purpose key and name (UTF-8 bytes exactly as given).
    ///
    /// `digest = HMAC-SHA256(access_code_key, name)`; value is
    /// `u32_be(digest[0..4]) mod 1_000_000`.
    pub fn derive(access_code_key: &[u8], name: &str) -> Self {
        let mut mac = HmacSha256::new_from_slice(access_code_key)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(name.as_bytes());
        let digest = mac.finalize().into_bytes();
        let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        Self(n % 1_000_000)
    }

    /// The six ASCII digits.
    pub fn digits(&self) -> [u8; 6] {
        let mut digits = [0u8; 6];
        let mut n = self.0;
        for i in (0..6).rev() {
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        digits
    }

    /// Parses six ASCII digits.
    pub fn from_digits(digits: &[u8; 6]) -> Option<Self> {
        if !digits.iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
        std::str::from_utf8(digits)
            .ok()?
            .parse::<u32>()
            .ok()
            .map(Self)
    }

    /// Parses exactly six ASCII decimal digits from a memo field.
    pub fn parse(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.len() != 6 {
            return None;
        }
        Self::from_digits(bytes.try_into().ok()?)
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }

    /// Digits as a `String`; test-only.
    #[cfg(test)]
    pub fn expose_for_test(&self) -> [u8; 6] {
        self.digits()
    }
}

/// A name's protection status. `Unprotected` is never stored — it
/// is the flattened absence, produced by [`ProtectedNames::get`]. A
/// finite row stays `WithExpiry` whether five minutes or five years
/// remain; the lift moment is judged against the current MTP per
/// claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectionStatus {
    /// Returned for an absent name; never stored.
    Unprotected,
    /// Protection lifts when the MTP reaches the timestamp.
    WithExpiry(Timestamp),
    /// Protection never lifts.
    Forever,
}

/// The claim-lane verdict.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Proceed to payment and authorize.
    Allow,
    /// Dead: wrong or missing code, or the name already exists (redeemed).
    Deny,
}

/// Derive the purpose-specific access-code key from the TEE root.
///
/// `HMAC-SHA256(key = private_key, data = "access-code-v1")`.
pub fn derive_access_code_key(private_key: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut k =
        HmacSha256::new_from_slice(private_key).expect("HMAC-SHA256 accepts any key length");
    k.update(b"access-code-v1");
    let out = k.finalize().into_bytes();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&out);
    key
}

/// A row from `zn_names`. `normalized_name` must parse as a [`Name`];
/// `expires_at` must be RFC 3339 or null. Other columns are ignored
/// by serde's default field handling.
#[derive(Deserialize)]
struct ProtectedRow {
    normalized_name: String,
    #[serde(default, deserialize_with = "deserialize_optional_timestamp")]
    expires_at: Option<Timestamp>,
}

/// Deserialize `timestamptz` in the RFC 3339 shape PostgREST returns
/// (e.g. `"2027-01-01T00:00:00+00:00"`). `null` → `None`; any string
/// that does not parse as RFC 3339 fails the deserializer, which
/// fails the whole read.
fn deserialize_optional_timestamp<'de, D>(deserializer: D) -> Result<Option<Timestamp>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: Option<String> = Option::deserialize(deserializer)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let dt = OffsetDateTime::parse(&raw, &Rfc3339).map_err(serde::de::Error::custom)?;
    let ts = Timestamp::from_seconds(dt.unix_timestamp()).map_err(serde::de::Error::custom)?;
    Ok(Some(ts))
}

/// The protected-names table: name → protection status. A name
/// absent from the map is unprotected. Pure data; [`fetch`] and
/// [`ProtectedNames::refresh`] are the only writers.
#[derive(Clone, Debug)]
pub struct ProtectedNames(BTreeMap<Name, ProtectionStatus>);

impl ProtectedNames {
    /// The name's status; `Unprotected` when absent.
    pub fn get(&self, name: &Name) -> ProtectionStatus {
        self.0
            .get(name)
            .copied()
            .unwrap_or(ProtectionStatus::Unprotected)
    }

    /// Re-reads the table; keeps the current rows on a failed read.
    pub async fn refresh(&mut self) {
        if let Some(fresh) = fetch().await {
            *self = fresh;
        }
    }
}

/// Reads the whole table, `PAGE_ROWS` at a time, stopping on a short
/// page. Any failure rejects the whole read (`None`) — a caller
/// keeps what it has.
pub async fn fetch() -> Option<ProtectedNames> {
    let client = https_client();
    let mut rows = BTreeMap::new();
    let mut offset = 0;
    loop {
        let page = fetch_page(&client, offset).await?;
        let short = page.len() < PAGE_ROWS;
        absorb(page, &mut rows)?;
        if short {
            return Some(ProtectedNames(rows));
        }
        offset += PAGE_ROWS;
        if offset > PAGE_ROWS * MAX_PAGES {
            tracing::warn!("pre-sale fetch exceeded the page ceiling");
            return None;
        }
    }
}

/// One page of rows, ordered by name so pages neither repeat nor
/// skip. `None` on any transport, timeout, status, size, or parse
/// failure; each is warned here. One end-to-end timeout covers the
/// request and the body.
async fn fetch_page(client: &HttpsClient, offset: usize) -> Option<Vec<ProtectedRow>> {
    let url = format!(
        "{}?select=normalized_name,expires_at&order=normalized_name.asc&limit={PAGE_ROWS}&offset={offset}",
        presale_rest_url(),
    );
    let uri: Uri = url.parse().ok()?;
    let request = Request::builder()
        .uri(uri)
        .header("accept", "application/json")
        .header("apikey", PRESALE_PUBLISHABLE_KEY)
        .body(Empty::<Bytes>::default())
        .ok()?;
    let page = tokio::time::timeout(FETCH_TIMEOUT, async {
        let response = client.request(request).await.ok()?;
        let status = response.status();
        if !status.is_success() {
            tracing::warn!(%status, "pre-sale fetch: non-success status");
            return None;
        }
        let body = Limited::new(response.into_body(), MAX_BODY_BYTES)
            .collect()
            .await
            .ok()?
            .to_bytes();
        match serde_json::from_slice(&body) {
            Ok(rows) => Some(rows),
            Err(error) => {
                tracing::warn!(?error, "pre-sale fetch: json parse failed");
                None
            }
        }
    })
    .await;
    match page {
        Ok(page) => page,
        Err(_) => {
            tracing::warn!("pre-sale fetch: timed out");
            None
        }
    }
}

/// Validates rows into the map. One bad row — a `normalized_name`
/// that is not a lawful [`Name`], or a duplicate — rejects the whole
/// read: an existing protection can freeze, never silently drop.
fn absorb(rows: Vec<ProtectedRow>, map: &mut BTreeMap<Name, ProtectionStatus>) -> Option<()> {
    for row in rows {
        let name = Name::parse(&row.normalized_name)?;
        let status = match row.expires_at {
            Some(ts) => ProtectionStatus::WithExpiry(ts),
            None => ProtectionStatus::Forever,
        };
        if map.insert(name, status).is_some() {
            tracing::warn!(
                name = %row.normalized_name,
                "pre-sale fetch: duplicate normalized_name"
            );
            return None;
        }
    }
    Some(())
}

/// Zeroizing holder for the boot-derived access-code key.
#[derive(Clone)]
pub struct AccessCodeDerivationKey(Zeroizing<[u8; 32]>);

impl AccessCodeDerivationKey {
    /// From a TEE root private key (`ACCESS_CODE_KEY_CONTEXT`).
    pub fn from_private_key(private_key: &[u8; 32]) -> Self {
        Self(derive_access_code_key(private_key))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The six-digit code a protected `name` must present.
    pub fn code_for(&self, name: &Name) -> AccessCode {
        AccessCode::derive(self.0.as_ref(), name.as_str())
    }

    /// The pre-sale gate. Unprotected names pass; protected names
    /// must present this key's code for `name`. A name already live
    /// is refused by the Registry's own authorization — redemption —
    /// not here.
    pub fn check_access(
        &self,
        status: ProtectionStatus,
        mtp: Timestamp,
        name: &Name,
        offered: Option<&AccessCode>,
    ) -> Decision {
        let protected = match status {
            ProtectionStatus::Unprotected => false,
            ProtectionStatus::Forever => true,
            ProtectionStatus::WithExpiry(ts) => mtp < ts,
        };
        if !protected {
            return Decision::Allow;
        }
        match offered {
            Some(offered) if self.code_for(name).ct_eq(offered) => Decision::Allow,
            _ => Decision::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec test vector private key.
    fn vector_private_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    fn ts(secs: i64) -> Timestamp {
        Timestamp::from_seconds(secs).unwrap()
    }

    fn gate() -> AccessCodeDerivationKey {
        AccessCodeDerivationKey::from_private_key(&vector_private_key())
    }

    fn alice() -> Name {
        Name::parse("alice").unwrap()
    }

    fn row_with(name: &str, expires_at: Option<Timestamp>) -> ProtectedRow {
        ProtectedRow {
            normalized_name: name.to_string(),
            expires_at,
        }
    }

    #[test]
    fn reference_vector_alice_bob() {
        let root = vector_private_key();
        let key = derive_access_code_key(&root);
        assert_eq!(
            hex::encode(*key),
            "5e2db6040cd32d2486675a3b3d60b9d4d96e9c8d4a5f862e0dfd7bd6a3f57b91"
        );
        assert_eq!(
            AccessCode::derive(key.as_ref(), "alice").expose_for_test(),
            *b"352582"
        );
        assert_eq!(
            AccessCode::derive(key.as_ref(), "bob").expose_for_test(),
            *b"131624"
        );
        assert_eq!(
            AccessCode::derive(key.as_ref(), "alice").expose_for_test(),
            *b"352582"
        );
    }

    #[test]
    fn unprotected_names_need_no_code() {
        assert_eq!(
            gate().check_access(
                ProtectionStatus::Unprotected,
                ts(1_700_000_000),
                &alice(),
                None,
            ),
            Decision::Allow
        );
    }

    /// The audit-critical case: a lift moment the MTP has reached is
    /// unprotected — judged per claim, never stored, so it lifts exactly
    /// on schedule without waiting for a refresh.
    #[test]
    fn expired_protection_is_unprotected() {
        let expired = ProtectionStatus::WithExpiry(ts(1_600_000_000));
        assert_eq!(
            gate().check_access(expired, ts(1_700_000_000), &alice(), None),
            Decision::Allow
        );
    }

    /// Exact-second boundary: `mtp == expires_at` means the lift
    /// moment has been reached; the row is unprotected.
    #[test]
    fn expiry_boundary_is_inclusive_unprotected() {
        let now = ts(1_700_000_000);
        let status = ProtectionStatus::WithExpiry(now);
        assert_eq!(
            gate().check_access(status, now, &alice(), None),
            Decision::Allow
        );
    }

    #[test]
    fn protected_with_expiry_requires_the_matching_code() {
        let expected = gate().code_for(&alice());
        let wrong = AccessCode::parse("999999").unwrap();
        let status = ProtectionStatus::WithExpiry(ts(2_000_000_000));

        assert_eq!(
            gate().check_access(status, ts(1_700_000_000), &alice(), Some(&expected)),
            Decision::Allow
        );
        assert_eq!(
            gate().check_access(status, ts(1_700_000_000), &alice(), Some(&wrong)),
            Decision::Deny
        );
        assert_eq!(
            gate().check_access(status, ts(1_700_000_000), &alice(), None),
            Decision::Deny
        );
    }

    #[test]
    fn protected_forever_requires_the_matching_code() {
        let expected = gate().code_for(&alice());
        let wrong = AccessCode::parse("999999").unwrap();
        let status = ProtectionStatus::Forever;

        assert_eq!(
            gate().check_access(status, ts(1_700_000_000), &alice(), Some(&expected)),
            Decision::Allow
        );
        assert_eq!(
            gate().check_access(status, ts(1_700_000_000), &alice(), Some(&wrong)),
            Decision::Deny
        );
        assert_eq!(
            gate().check_access(status, ts(1_700_000_000), &alice(), None),
            Decision::Deny
        );
    }

    #[test]
    fn code_for_matches_the_vector() {
        assert_eq!(gate().code_for(&alice()).expose_for_test(), *b"352582");
    }

    #[test]
    fn table_is_zn_names() {
        assert_eq!(PRESALE_TABLE, "zn_names");
        assert!(!PRESALE_PUBLISHABLE_KEY.is_empty());
    }

    #[test]
    fn absorb_builds_the_map() {
        let mut map = BTreeMap::new();
        let rows = vec![
            row_with("alice", Some(ts(2_000_000_000))),
            row_with("bob", None),
        ];
        assert_eq!(absorb(rows, &mut map), Some(()));
        let names = ProtectedNames(map);
        assert_eq!(
            names.get(&Name::parse("alice").unwrap()),
            ProtectionStatus::WithExpiry(ts(2_000_000_000))
        );
        assert_eq!(
            names.get(&Name::parse("bob").unwrap()),
            ProtectionStatus::Forever
        );
        assert_eq!(
            names.get(&Name::parse("carol").unwrap()),
            ProtectionStatus::Unprotected
        );
    }

    /// An expired row is stored as `WithExpiry` all the same — the
    /// lift moment is data, not a state.
    #[test]
    fn absorb_keeps_expired_rows() {
        let mut map = BTreeMap::new();
        let rows = vec![row_with("alice", Some(ts(1_600_000_000)))];
        assert_eq!(absorb(rows, &mut map), Some(()));
        assert_eq!(
            map.get(&Name::parse("alice").unwrap()),
            Some(&ProtectionStatus::WithExpiry(ts(1_600_000_000)))
        );
    }

    #[test]
    fn absorb_rejects_unlawful_names() {
        let mut map = BTreeMap::new();
        let rows = vec![row_with("Not-A-Name!", None)];
        assert_eq!(absorb(rows, &mut map), None);
        assert!(map.is_empty());
    }

    #[test]
    fn absorb_rejects_duplicates() {
        let mut map = BTreeMap::new();
        let rows = vec![row_with("alice", None), row_with("alice", None)];
        assert_eq!(absorb(rows, &mut map), None);
    }

    /// Extra columns Supabase returns (`id`, `created_at`, `source`,
    /// `dupe`, and a `status` field the old schema carried) do not
    /// prevent decoding — serde ignores unknown fields, so schema
    /// evolution on unused columns is safe.
    #[test]
    fn row_decode_ignores_unused_columns() {
        let json = r#"[{
            "id": "00000000-0000-0000-0000-000000000000",
            "normalized_name": "alice",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2027-06-15T12:34:56+00:00",
            "source": "founder",
            "dupe": false,
            "status": "protected"
        }]"#;
        let rows: Vec<ProtectedRow> = serde_json::from_slice(json.as_bytes()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].normalized_name, "alice");
        // 2027-06-15T12:34:56 UTC = 1_813_062_896 seconds since the Unix epoch.
        assert_eq!(rows[0].expires_at, Some(ts(1_813_062_896)));
    }

    #[test]
    fn row_decode_null_expires_at() {
        let json = r#"[{"normalized_name": "alice", "expires_at": null}]"#;
        let rows: Vec<ProtectedRow> = serde_json::from_slice(json.as_bytes()).unwrap();
        assert_eq!(rows[0].expires_at, None);
    }

    /// A malformed `expires_at` string must fail the deserializer,
    /// which fails the whole read.
    #[test]
    fn row_decode_bad_timestamp_errors() {
        let json = r#"[{"normalized_name": "alice", "expires_at": "not-a-timestamp"}]"#;
        let rows: Result<Vec<ProtectedRow>, _> = serde_json::from_slice(json.as_bytes());
        assert!(rows.is_err(), "malformed timestamp must not deserialize");
    }
}
