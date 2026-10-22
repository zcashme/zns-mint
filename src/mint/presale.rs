//! The pre-sale protected-names table, cached in memory: read at
//! boot and again on every tip pass before the deciding pass, judged
//! per claim against the current MTP. A failed read keeps the last
//! table. A missing row, or a reached lift moment, is unprotected. Codes are derived in
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
use zns_canon::access_code::purpose_key;

/// Supabase project HTTP origin. PostgREST only.
const PRESALE_HOST: &str = "https://cclrkfymckyjfufvqedr.supabase.co";

/// Protected-name collection.
const PRESALE_TABLE: &str = "zn_names";

/// Public Supabase publishable key (`apikey` for PostgREST).
const PRESALE_PUBLISHABLE_KEY: &str = "sb_publishable_eRyX0Z5CY3bHm11iCFoZRA_-u2WgStF";

/// One end-to-end bound on the whole read, request and body.
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// The whole table in one body: ~214 KB at 2,559 rows; the cap holds
/// ~30,000 worst-case rows (~137 B each). Over it, the read is refused.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// How long an idle connection stays pooled: past one tip pass
/// (~75 s), so consecutive reads share a connection.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

pub type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>;
type HmacSha256 = Hmac<Sha256>;

/// The one client every read goes through, built at boot. A closed
/// connection is replaced on the next request; a read that times out
/// drops its connection, so the next read opens a fresh one.
pub fn https_client() -> HttpsClient {
    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        .build(connector)
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

/// A `zn_names` row: `name` must parse as a [`Name`], `expiry_at`
/// null means forever.
#[derive(Deserialize)]
pub struct ProtectedRow {
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
    /// missing or mismatched.
    #[error("read could not be confirmed complete")]
    Unconfirmed,
    /// A row's `name` is not a lawful [`Name`]; retries fail until
    /// the table is fixed.
    #[error("row is not a lawful name")]
    CorruptRow,
}

/// Reads the whole table in one request, installing only when every
/// counted row landed. Any failure: [`FetchError`] — the caller keeps
/// what it has.
pub async fn fetch(client: &HttpsClient) -> Result<ProtectedNames, FetchError> {
    let (rows, total) = fetch_rows(client).await.ok_or(FetchError::Unavailable)?;
    complete(rows, total)
}

/// Rows in, table out, only when the server's exact count matches the
/// rows read: past the project's Max Rows, PostgREST truncates the
/// reply silently.
fn complete(rows: Vec<ProtectedRow>, total: Option<usize>) -> Result<ProtectedNames, FetchError> {
    let read = rows.len();
    match total {
        Some(total) if total == read => {
            let table = ProtectedNames(BTreeMap::new()).from_rows(rows)?;
            tracing::debug!(rows = read, "pre-sale fetch: table loaded");
            Ok(table)
        }
        Some(total) => {
            tracing::warn!(
                counted = total,
                read,
                "pre-sale fetch did not return every counted row"
            );
            Err(FetchError::Unconfirmed)
        }
        None => {
            tracing::warn!("pre-sale fetch: row count missing");
            Err(FetchError::Unconfirmed)
        }
    }
}

/// Every row, with the server's exact row count. `None` on any
/// failure, each warned here. One end-to-end timeout covers the
/// request and the body.
async fn fetch_rows(client: &HttpsClient) -> Option<(Vec<ProtectedRow>, Option<usize>)> {
    let url = format!("{}?select=name,expiry_at", presale_rest_url());
    let uri: Uri = url.parse().ok()?;
    let request = Request::builder()
        .uri(uri)
        .header("accept", "application/json")
        .header("apikey", PRESALE_PUBLISHABLE_KEY)
        .header("prefer", "count=exact")
        .body(Empty::<Bytes>::default())
        .ok()?;
    let read = tokio::time::timeout(FETCH_TIMEOUT, async {
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
        let body = match Limited::new(response.into_body(), MAX_BODY_BYTES)
            .collect()
            .await
        {
            Ok(body) => body.to_bytes(),
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "pre-sale fetch: body unreadable or over the size cap"
                );
                return None;
            }
        };
        match serde_json::from_slice(&body) {
            Ok(rows) => Some((rows, total)),
            Err(error) => {
                tracing::warn!(?error, "pre-sale fetch: json parse failed");
                None
            }
        }
    })
    .await;
    match read {
        Ok(read) => read,
        Err(_) => {
            tracing::warn!("pre-sale fetch: timed out");
            None
        }
    }
}

/// Zeroizing holder for the boot-derived access-code key.
#[derive(Clone)]
pub struct AccessCodeDerivationKey(Zeroizing<[u8; 32]>);

impl AccessCodeDerivationKey {
    /// From the unsealed ceremony seed, via `zns_canon::access_code`:
    /// the seed-derived X25519 scalar agrees with the issuer's public
    /// key; this is that shared secret's purpose key.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(purpose_key(seed))
    }

    /// The purpose key of a shared secret (or a test-vector key):
    /// `HMAC-SHA256(key, "access-code-v1")`.
    pub fn from_private_key(private_key: &[u8; 32]) -> Self {
        let mut mac =
            HmacSha256::new_from_slice(private_key).expect("HMAC-SHA256 accepts any key length");
        mac.update(b"access-code-v1");
        let mut out = mac.finalize().into_bytes();
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&out);
        out.zeroize();
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
        assert_eq!(gate.derive(&alice()).digits(), *b"352582");
        assert_eq!(
            gate.derive(&Name::parse("bob").unwrap()).digits(),
            *b"131624"
        );
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [0x33u8; 32];
        let name = Name::parse("alice").unwrap();
        assert_eq!(
            AccessCodeDerivationKey::from_seed(&seed)
                .derive(&name)
                .digits(),
            AccessCodeDerivationKey::from_seed(&seed)
                .derive(&name)
                .digits()
        );
    }

    /// Known-answer vector generated independently of this crate
    /// (Python: HMAC-SHA256 seed scalar, X25519 against the issuer
    /// public key, purpose step, "alice"). Catches a wrong issuer key
    /// or a divergent derivation that self-consistent tests would miss.
    #[test]
    fn issuer_known_answer_vector() {
        let key = AccessCodeDerivationKey::from_seed(&[0x22u8; 32]);
        assert_eq!(
            hex::encode(key.as_bytes()),
            "bcd2c0e1ffa22fdd3756b5ec81a4b7c2d252c14251a44552aea3324d5d41d3f0"
        );
        assert_eq!(key.derive(&alice()).digits(), *b"549703");
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
        assert_eq!(gate().derive(&alice()).digits(), *b"352582");
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

    /// Columns Supabase may return beyond the two the mint reads
    /// (`name`, `expiry_at`) do not prevent decoding — serde
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

    /// The read installs only when every counted row arrived.
    #[test]
    fn complete_installs_when_the_count_matches() {
        let table = complete(vec![row_with("alice", None)], Some(1)).unwrap();
        assert_eq!(table.status(&alice()), ProtectionStatus::Forever);
    }

    /// A reply cut short by the server's Max Rows is refused, never
    /// installed as a smaller table.
    #[test]
    fn complete_refuses_a_truncated_read() {
        let rows = vec![row_with("alice", None)];
        assert!(matches!(
            complete(rows, Some(2)),
            Err(FetchError::Unconfirmed)
        ));
    }

    #[test]
    fn complete_refuses_a_missing_count() {
        let rows = vec![row_with("alice", None)];
        assert!(matches!(complete(rows, None), Err(FetchError::Unconfirmed)));
    }
}
