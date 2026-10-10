//! The pre-sale protected-names table, cached in memory: read once
//! at boot, refreshed once per MTP day, judged per claim against the
//! current MTP — Supabase is never on a claim's path. A missing row,
//! or a reached lift moment, is unprotected. Codes are derived in
//! the TEE (`access-code-v1`); the mint never writes Supabase.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::time::Duration;

use hmac::{Hmac, Mac};
use http::header::CONTENT_RANGE;
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
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, Timestamp};
use zeroize::{Zeroize, Zeroizing};

use crate::mint::Name;

/// TEE sealing context for the access-code root key.
pub const ACCESS_CODE_KEY_CONTEXT: &[u8] = b"ZNS/access-code/root/v1";

/// Supabase project HTTP origin. PostgREST only.
const PRESALE_HOST: &str = "https://cclrkfymckyjfufvqedr.supabase.co";

/// Protected-name collection.
const PRESALE_TABLE: &str = "zn_names";

/// Public Supabase publishable key (`apikey` for PostgREST).
const PRESALE_PUBLISHABLE_KEY: &str = "sb_publishable_eRyX0Z5CY3bHm11iCFoZRA_-u2WgStF";

const FETCH_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Rows per page — worst case ~34 KB, half of `MAX_BODY_BYTES`.
const PAGE_ROWS: usize = 250;

/// Page ceiling (~25,000 names); over it, the read is refused loudly.
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
    /// Parses exactly six ASCII digits.
    pub fn parse(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.len() != 6 || !bytes.iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
        std::str::from_utf8(bytes)
            .ok()?
            .parse::<u32>()
            .ok()
            .map(Self)
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }

    /// The six ASCII digits; test-only.
    #[cfg(test)]
    pub fn expose_for_test(&self) -> [u8; 6] {
        let mut digits = [0u8; 6];
        let mut n = self.0;
        for i in (0..6).rev() {
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        digits
    }
}

/// A name's protection. Absence is `Unprotected`; a lift moment is
/// judged against the current MTP per claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectionStatus {
    /// Never stored — the flattened absence.
    Unprotected,
    /// Protection lifts at this timestamp.
    WithExpiry(Timestamp),
    /// Protection never lifts.
    Forever,
}

/// A `zn_names` row: `id` keys the cursor, `name` must parse as a
/// [`Name`], `expiry_at` null means forever.
#[derive(Deserialize)]
pub struct ProtectedRow {
    pub id: String,
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_optional_timestamp")]
    pub expiry_at: Option<Timestamp>,
}

/// PostgREST `timestamptz` (RFC 3339); `null` → `None`, anything
/// else fails the read.
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

/// name → protection; absent is unprotected. Pure data —
/// [`ProtectedNames::from_rows`] is the only writer.
#[derive(Clone, Debug)]
pub struct ProtectedNames(BTreeMap<Name, ProtectionStatus>);

impl ProtectedNames {
    /// The stored fact — `Unprotected` for absent names; never `None`.
    pub fn status(&self, name: &Name) -> ProtectionStatus {
        self.0
            .get(name)
            .copied()
            .unwrap_or(ProtectionStatus::Unprotected)
    }

    /// The judged question: protected at this MTP? Expiry is never
    /// stored, so protection lifts exactly on schedule.
    pub fn is_protected(&self, name: &Name, mtp: Timestamp) -> bool {
        match self.status(name) {
            ProtectionStatus::Unprotected => false,
            ProtectionStatus::Forever => true,
            ProtectionStatus::WithExpiry(ts) => mtp < ts,
        }
    }

    /// Rows in, new table out: re-purchases coalesce to the
    /// strongest term (`Forever` over any expiry, the later expiry
    /// wins). All-or-nothing — one corrupt row fails the batch with
    /// [`FetchError::CorruptRow`], logged where it is seen.
    pub fn from_rows(
        self,
        rows: impl IntoIterator<Item = ProtectedRow>,
    ) -> Result<Self, FetchError> {
        let mut map = self.0;
        for row in rows {
            let Some(name) = Name::parse(&row.name) else {
                tracing::warn!(
                    name = %row.name,
                    "pre-sale row is not a lawful name; refusing the read"
                );
                return Err(FetchError::CorruptRow);
            };
            let status = match row.expiry_at {
                Some(ts) => ProtectionStatus::WithExpiry(ts),
                None => ProtectionStatus::Forever,
            };
            match map.entry(name) {
                Entry::Vacant(entry) => {
                    entry.insert(status);
                }
                Entry::Occupied(mut entry) => {
                    let strongest = match (*entry.get(), status) {
                        (ProtectionStatus::Forever, _) | (_, ProtectionStatus::Forever) => {
                            ProtectionStatus::Forever
                        }
                        (ProtectionStatus::WithExpiry(have), ProtectionStatus::WithExpiry(got)) => {
                            ProtectionStatus::WithExpiry(have.max(got))
                        }
                        (ProtectionStatus::Unprotected, _) | (_, ProtectionStatus::Unprotected) => {
                            unreachable!("Unprotected is never stored")
                        }
                    };
                    entry.insert(strongest);
                }
            };
        }
        Ok(Self(map))
    }
}

/// Why a pre-sale table read failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FetchError {
    /// The read did not complete; a retry may succeed.
    #[error("read failed")]
    Unavailable,
    /// The read finished but its completeness is unproven — count
    /// missing or mismatched, or over the page ceiling.
    #[error("read could not be confirmed complete")]
    Unconfirmed,
    /// A row's `name` is not a lawful [`Name`]; retries fail until
    /// the table is fixed.
    #[error("row is not a lawful name")]
    CorruptRow,
}

/// Reads the whole table, `PAGE_ROWS` at a time, keyset-paginated
/// by `(name, id)`, installing only when every counted row landed.
/// Over `MAX_PAGES` full pages, or any failure: [`FetchError`] —
/// the caller keeps what it has.
pub async fn fetch() -> Result<ProtectedNames, FetchError> {
    let client = https_client();
    let mut table = ProtectedNames(BTreeMap::new());
    let mut read = 0usize;
    let mut after: Option<(String, String)> = None;
    let mut total: Option<usize> = None;
    let mut pages = 0;
    loop {
        let want_total = total.is_none();
        let (page, counted) = fetch_page(
            &client,
            after
                .as_ref()
                .map(|(name, id)| (name.as_str(), id.as_str())),
            want_total,
        )
        .await
        .ok_or(FetchError::Unavailable)?;
        pages += 1;
        if pages > MAX_PAGES && !page.is_empty() {
            tracing::warn!("pre-sale fetch exceeded the page ceiling");
            return Err(FetchError::Unconfirmed);
        }
        total = total.or(counted);
        let short = page.len() < PAGE_ROWS;
        let last = page.last().map(|row| (row.name.clone(), row.id.clone()));
        read += page.len();
        table = table.from_rows(page)?;
        if short {
            return match total {
                Some(total) if total == read => {
                    tracing::info!(rows = read, "pre-sale fetch: table loaded");
                    Ok(table)
                }
                Some(total) => {
                    tracing::warn!(
                        counted = total,
                        read,
                        "pre-sale fetch did not install every counted row"
                    );
                    Err(FetchError::Unconfirmed)
                }
                None => {
                    tracing::warn!("pre-sale fetch: row count missing");
                    Err(FetchError::Unconfirmed)
                }
            };
        }
        after = last;
    }
}

/// One page after `after`, with the server's exact row count when
/// `want_total`. `None` on any failure, each warned here. One
/// end-to-end timeout covers the request and the body.
async fn fetch_page(
    client: &HttpsClient,
    after: Option<(&str, &str)>,
    want_total: bool,
) -> Option<(Vec<ProtectedRow>, Option<usize>)> {
    let filter = keyset_filter(after);
    let url = format!(
        "{}?select=id,name,expiry_at&order=name.asc,id.asc&limit={PAGE_ROWS}{filter}",
        presale_rest_url(),
    );
    let uri: Uri = url.parse().ok()?;
    let mut builder = Request::builder()
        .uri(uri)
        .header("accept", "application/json")
        .header("apikey", PRESALE_PUBLISHABLE_KEY);
    if want_total {
        builder = builder.header("prefer", "count=exact");
    }
    let request = builder.body(Empty::<Bytes>::default()).ok()?;
    let page = tokio::time::timeout(FETCH_TIMEOUT, async {
        let response = client.request(request).await.ok()?;
        let status = response.status();
        if !status.is_success() {
            tracing::warn!(%status, "pre-sale fetch: non-success status");
            return None;
        }
        let total = response
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.rsplit('/').next())
            .and_then(|value| value.parse::<usize>().ok());
        let body = Limited::new(response.into_body(), MAX_BODY_BYTES)
            .collect()
            .await
            .ok()?
            .to_bytes();
        match serde_json::from_slice(&body) {
            Ok(rows) => Some((rows, total)),
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

/// Rows strictly after `(name, id)`; `[a-z0-9]` names and UUID
/// ids need no escaping.
fn keyset_filter(after: Option<(&str, &str)>) -> String {
    match after {
        None => String::new(),
        Some((name, id)) => {
            format!("&or=(name.gt.{name},and(name.eq.{name},id.gt.{id}))")
        }
    }
}

/// Zeroizing holder for the boot-derived access-code key.
#[derive(Clone)]
pub struct AccessCodeDerivationKey(Zeroizing<[u8; 32]>);

impl AccessCodeDerivationKey {
    /// From a TEE root private key: the purpose key
    /// `HMAC-SHA256(key = root, data = "access-code-v1")`.
    pub fn from_private_key(private_key: &[u8; 32]) -> Self {
        let mut mac =
            HmacSha256::new_from_slice(private_key).expect("HMAC-SHA256 accepts any key length");
        mac.update(b"access-code-v1");
        let out = mac.finalize().into_bytes();
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&out);
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The six-digit code `name` must present:
    /// `u32_be(HMAC-SHA256(key, name)[0..4]) mod 1_000_000`.
    pub fn derive(&self, name: &Name) -> AccessCode {
        let mut mac = HmacSha256::new_from_slice(self.0.as_ref())
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(name.as_str().as_bytes());
        let digest = mac.finalize().into_bytes();
        let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        AccessCode(n % 1_000_000)
    }

    /// Does `offered` match the code for `name`? Missing never
    /// matches.
    pub fn accepts(&self, name: &Name, offered: Option<&AccessCode>) -> bool {
        match offered {
            Some(offered) => self.derive(name).ct_eq(offered),
            None => false,
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

    fn row_with(name: &str, expiry_at: Option<Timestamp>) -> ProtectedRow {
        ProtectedRow {
            id: format!("id-{name}"),
            name: name.to_string(),
            expiry_at,
        }
    }

    #[test]
    fn reference_vector_alice_bob() {
        let gate = AccessCodeDerivationKey::from_private_key(&vector_private_key());
        assert_eq!(
            hex::encode(gate.as_bytes()),
            "5e2db6040cd32d2486675a3b3d60b9d4d96e9c8d4a5f862e0dfd7bd6a3f57b91"
        );
        assert_eq!(gate.derive(&alice()).expose_for_test(), *b"352582");
        assert_eq!(
            gate.derive(&Name::parse("bob").unwrap()).expose_for_test(),
            *b"131624"
        );
    }

    fn table_of(rows: &[(&str, ProtectionStatus)]) -> ProtectedNames {
        let mut map = BTreeMap::new();
        for (name, status) in rows {
            map.insert(Name::parse(name).unwrap(), *status);
        }
        ProtectedNames(map)
    }

    #[test]
    fn forever_and_a_future_expiry_are_protected() {
        let table = table_of(&[
            ("alice", ProtectionStatus::Forever),
            ("bob", ProtectionStatus::WithExpiry(ts(2_000_000_000))),
        ]);
        assert!(table.is_protected(&alice(), ts(1_700_000_000)));
        assert!(table.is_protected(&Name::parse("bob").unwrap(), ts(1_700_000_000)));
    }

    /// The audit-critical case: a lift moment the MTP has reached is
    /// unprotected — judged per claim, never stored, so it lifts
    /// exactly on schedule without waiting for a refresh.
    #[test]
    fn expired_protection_is_unprotected() {
        let table = table_of(&[("alice", ProtectionStatus::WithExpiry(ts(1_600_000_000)))]);
        assert!(!table.is_protected(&alice(), ts(1_700_000_000)));
    }

    /// Exact-second boundary: `mtp == expiry_at` means the lift
    /// moment has been reached; the row is unprotected.
    #[test]
    fn expiry_boundary_is_inclusive_unprotected() {
        let now = ts(1_700_000_000);
        let table = table_of(&[("alice", ProtectionStatus::WithExpiry(now))]);
        assert!(!table.is_protected(&alice(), now));
    }

    #[test]
    fn an_absent_name_is_unprotected() {
        let table = table_of(&[]);
        assert!(!table.is_protected(&alice(), ts(1_700_000_000)));
    }

    #[test]
    fn the_matching_code_is_accepted() {
        let expected = gate().derive(&alice());
        assert!(gate().accepts(&alice(), Some(&expected)));
    }

    #[test]
    fn a_wrong_or_missing_code_is_refused() {
        let wrong = AccessCode::parse("999999").unwrap();
        assert!(!gate().accepts(&alice(), Some(&wrong)));
        assert!(!gate().accepts(&alice(), None));
    }

    #[test]
    fn derive_matches_the_vector() {
        assert_eq!(gate().derive(&alice()).expose_for_test(), *b"352582");
    }

    #[test]
    fn table_is_zn_names() {
        assert_eq!(PRESALE_TABLE, "zn_names");
        assert!(!PRESALE_PUBLISHABLE_KEY.is_empty());
    }

    /// Builds a table from rows through the public door, seeded empty.
    fn from_rows(rows: Vec<ProtectedRow>) -> Result<ProtectedNames, FetchError> {
        ProtectedNames(BTreeMap::new()).from_rows(rows)
    }

    #[test]
    fn from_rows_builds_the_map() {
        let names = from_rows(vec![
            row_with("alice", Some(ts(2_000_000_000))),
            row_with("bob", None),
        ])
        .unwrap();
        assert_eq!(
            names.status(&Name::parse("alice").unwrap()),
            ProtectionStatus::WithExpiry(ts(2_000_000_000))
        );
        assert_eq!(
            names.status(&Name::parse("bob").unwrap()),
            ProtectionStatus::Forever
        );
        assert_eq!(
            names.status(&Name::parse("carol").unwrap()),
            ProtectionStatus::Unprotected
        );
    }

    /// An expired row is stored as `WithExpiry` all the same — the
    /// lift moment is data, not a state.
    #[test]
    fn from_rows_keeps_expired_rows() {
        let table = from_rows(vec![row_with("alice", Some(ts(1_600_000_000)))]).unwrap();
        assert_eq!(
            table.status(&Name::parse("alice").unwrap()),
            ProtectionStatus::WithExpiry(ts(1_600_000_000))
        );
    }

    #[test]
    fn from_rows_rejects_corrupt_rows() {
        let rows = vec![row_with("Not-A-Name!", None)];
        assert!(matches!(from_rows(rows), Err(FetchError::CorruptRow)));
    }

    /// A duplicate row is a re-purchase: the name's rows coalesce
    /// to the strongest bought term.
    #[test]
    fn from_rows_coalesces_identical_rows() {
        let table = from_rows(vec![row_with("alice", None), row_with("alice", None)]).unwrap();
        assert_eq!(table.status(&alice()), ProtectionStatus::Forever);
    }

    /// Two dated terms cover the name to the later lift moment.
    #[test]
    fn from_rows_coalesces_expiries_to_the_latest() {
        let table = from_rows(vec![
            row_with("alice", Some(ts(2_000_000_000))),
            row_with("alice", Some(ts(1_900_000_000))),
        ])
        .unwrap();
        assert_eq!(
            table.status(&alice()),
            ProtectionStatus::WithExpiry(ts(2_000_000_000))
        );
    }

    /// Forever covers any expiry, in either row order.
    #[test]
    fn from_rows_coalesces_forever_over_an_expiry() {
        for rows in [
            vec![
                row_with("alice", Some(ts(2_000_000_000))),
                row_with("alice", None),
            ],
            vec![
                row_with("alice", None),
                row_with("alice", Some(ts(2_000_000_000))),
            ],
        ] {
            let table = from_rows(rows).unwrap();
            assert_eq!(table.status(&alice()), ProtectionStatus::Forever);
        }
    }

    /// The reported live shape: `9` and `tom` each hold an expiry
    /// plus Forever among their re-purchases.
    #[test]
    fn from_rows_coalesces_the_reported_table_shape() {
        let table = from_rows(vec![
            row_with("9", Some(ts(1_795_898_400))),
            row_with("9", None),
            row_with("9", None),
            row_with("9", None),
            row_with("9", None),
            row_with("tom", Some(ts(1_800_563_400))),
            row_with("tom", None),
            row_with("alice", Some(ts(2_000_000_000))),
        ])
        .unwrap();
        assert_eq!(
            table.status(&Name::parse("9").unwrap()),
            ProtectionStatus::Forever
        );
        assert_eq!(
            table.status(&Name::parse("tom").unwrap()),
            ProtectionStatus::Forever
        );
        assert_eq!(
            table.status(&Name::parse("alice").unwrap()),
            ProtectionStatus::WithExpiry(ts(2_000_000_000))
        );
    }

    /// Columns Supabase may return beyond the three the mint reads
    /// (`id`, `name`, `expiry_at`) do not prevent decoding — serde
    /// ignores unknown fields, so schema evolution on unused columns
    /// is safe.
    #[test]
    fn row_decode_ignores_unused_columns() {
        let json = r#"[{
            "id": "00000000-0000-0000-0000-000000000000",
            "name": "alice",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expiry_at": "2027-06-15T12:34:56+00:00",
            "source": "founder"
        }]"#;
        let rows: Vec<ProtectedRow> = serde_json::from_slice(json.as_bytes()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "alice");
        // 2027-06-15T12:34:56 UTC = 1_813_062_896 seconds since the Unix epoch.
        assert_eq!(rows[0].expiry_at, Some(ts(1_813_062_896)));
    }

    #[test]
    fn row_decode_null_expiry_at() {
        let json = r#"[{"id": "0", "name": "alice", "expiry_at": null}]"#;
        let rows: Vec<ProtectedRow> = serde_json::from_slice(json.as_bytes()).unwrap();
        assert_eq!(rows[0].expiry_at, None);
    }

    /// A malformed `expiry_at` string must fail the deserializer,
    /// which fails the whole read.
    #[test]
    fn row_decode_bad_timestamp_errors() {
        let json = r#"[{"id": "0", "name": "alice", "expiry_at": "not-a-timestamp"}]"#;
        let rows: Result<Vec<ProtectedRow>, _> = serde_json::from_slice(json.as_bytes());
        assert!(rows.is_err(), "malformed timestamp must not deserialize");
    }

    /// The cursor filter is the pagination contract: strictly after
    /// `(name, id)`, in either dimension.
    #[test]
    fn keyset_filter_continues_strictly_after() {
        assert_eq!(keyset_filter(None), "");
        assert_eq!(
            keyset_filter(Some(("9", "abc"))),
            "&or=(name.gt.9,and(name.eq.9,id.gt.abc))"
        );
    }
}
