//! The pre-sale protected-names table, cached in memory and read on
//! every tip pass. Claims are judged against the current MTP; a
//! failed read keeps the last table. Codes are derived in the TEE.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::header::CONTENT_RANGE;
use hyper::{Request, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use serde::{Deserialize, Deserializer};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, Timestamp};
use tokio::task::JoinHandle;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::mint::Name;
use zns_canon::access_code::purpose_key;

/// Supabase project HTTP origin. PostgREST only.
const PRESALE_HOST: &str = "https://cclrkfymckyjfufvqedr.supabase.co";

/// Protected-name collection.
const PRESALE_TABLE: &str = "zn_names";

/// Public Supabase publishable key (`apikey` for PostgREST).
const PRESALE_PUBLISHABLE_KEY: &str = "sb_publishable_eRyX0Z5CY3bHm11iCFoZRA_-u2WgStF";

/// Bounds the whole read, request and body.
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// Whole-table body cap; over it, the read is refused.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Keeps the connection pooled across tip passes.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>;
type HmacSha256 = Hmac<Sha256>;

/// The one client every read goes through, built at boot.
pub(crate) fn https_client() -> HttpsClient {
    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();
    // The idle timeout never fires without a timer: nothing wakes the
    // pool to evict the connection.
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        .pool_timer(TokioTimer::new())
        .build(connector)
}

fn presale_rest_url() -> String {
    format!("{PRESALE_HOST}/rest/v1/{PRESALE_TABLE}")
}

/// A six-digit protected-name access code (same wire shape as an OTP).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
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
    /// wins). A name that does not parse is skipped and warned;
    /// the other rows still install.
    pub fn from_rows(self, rows: impl IntoIterator<Item = ProtectedRow>) -> Self {
        let mut map = self.0;
        for row in rows {
            let Some(name) = Name::parse(&row.name) else {
                tracing::warn!(
                    name = %row.name,
                    "pre-sale name does not parse; skipping it"
                );
                continue;
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
        Self(map)
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
}

/// Reads the whole table; installs only when every counted row landed.
pub async fn fetch(client: &HttpsClient) -> Result<ProtectedNames, FetchError> {
    let (rows, landed, total) = fetch_rows(client).await.ok_or(FetchError::Unavailable)?;
    complete(rows, landed, total)
}

/// A table read running in the background, started before the tip
/// pass needs it. Dropping it before `install` cancels the read.
pub struct PendingRead(JoinHandle<Result<ProtectedNames, FetchError>>);

impl PendingRead {
    pub fn start(client: &HttpsClient) -> Self {
        let client = client.clone();
        Self(tokio::spawn(async move { fetch(&client).await }))
    }

    /// Waits out the read into `names`; a failed read keeps the last table.
    pub async fn install(mut self, names: &mut ProtectedNames) {
        match (&mut self.0)
            .await
            .expect("FATAL: pre-sale read task panicked")
        {
            Ok(fresh) => *names = fresh,
            Err(error) => tracing::warn!(%error, "pre-sale read failed; the last table stands"),
        }
    }
}

impl Drop for PendingRead {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Installs only when the exact count matches the rows that landed.
/// A row skipped while decoding still counts as landed.
fn complete(
    rows: Vec<ProtectedRow>,
    landed: usize,
    total: Option<usize>,
) -> Result<ProtectedNames, FetchError> {
    match total {
        Some(total) if total == landed => {
            let table = ProtectedNames(BTreeMap::new()).from_rows(rows);
            tracing::debug!(rows = landed, "pre-sale fetch: table loaded");
            Ok(table)
        }
        Some(total) => {
            tracing::warn!(
                counted = total,
                read = landed,
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

/// A JSON array of rows. An element that does not decode is skipped
/// and warned, and still counts as landed. A body that is not an
/// array fails the read.
fn decode_rows(body: &[u8]) -> Result<(Vec<ProtectedRow>, usize), serde_json::Error> {
    let values: Vec<serde_json::Value> = serde_json::from_slice(body)?;
    let landed = values.len();
    let mut rows = Vec::with_capacity(landed);
    for value in values {
        match serde_json::from_value(value) {
            Ok(row) => rows.push(row),
            Err(error) => tracing::warn!(%error, "pre-sale row did not decode; skipping it"),
        }
    }
    Ok((rows, landed))
}

/// Every row and the exact count; `None` on any failure, each warned.
async fn fetch_rows(client: &HttpsClient) -> Option<(Vec<ProtectedRow>, usize, Option<usize>)> {
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
        let body = Limited::new(response.into_body(), MAX_BODY_BYTES)
            .collect()
            .await
            .inspect_err(|error| {
                tracing::warn!(
                    ?error,
                    "pre-sale fetch: body unreadable or over the size cap"
                )
            })
            .ok()?
            .to_bytes();
        match decode_rows(&body) {
            Ok((rows, landed)) => Some((rows, landed, total)),
            Err(error) => {
                tracing::warn!(%error, "pre-sale fetch: json parse failed");
                None
            }
        }
    })
    .await;
    read.unwrap_or_else(|_| {
        tracing::warn!("pre-sale fetch: timed out");
        None
    })
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
    use zns_canon::access_code::purpose;

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
        AccessCodeDerivationKey(purpose(&vector_private_key()))
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
        let gate = gate();
        assert_eq!(
            hex::encode(*gate.0),
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
            hex::encode(*key.0),
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
    fn from_rows(rows: Vec<ProtectedRow>) -> ProtectedNames {
        ProtectedNames(BTreeMap::new()).from_rows(rows)
    }

    /// An expired row is stored as `WithExpiry` all the same — the
    /// lift moment is data, not a state.
    #[test]
    fn from_rows_keeps_expired_rows() {
        let table = from_rows(vec![row_with("alice", Some(ts(1_600_000_000)))]);
        assert_eq!(
            table.status(&Name::parse("alice").unwrap()),
            ProtectionStatus::WithExpiry(ts(1_600_000_000))
        );
    }

    /// A name that does not parse is skipped. The other rows install.
    #[test]
    fn from_rows_skips_a_name_that_does_not_parse() {
        let table = from_rows(vec![row_with("Not-A-Name!", None), row_with("alice", None)]);
        assert_eq!(table.0.len(), 1);
        assert_eq!(table.status(&alice()), ProtectionStatus::Forever);
    }

    /// A duplicate row is a re-purchase: the name's rows coalesce
    /// to the strongest bought term.
    #[test]
    fn from_rows_coalesces_identical_rows() {
        let table = from_rows(vec![row_with("alice", None), row_with("alice", None)]);
        assert_eq!(table.status(&alice()), ProtectionStatus::Forever);
    }

    /// Two dated terms cover the name to the later lift moment.
    #[test]
    fn from_rows_coalesces_expiries_to_the_latest() {
        let table = from_rows(vec![
            row_with("alice", Some(ts(2_000_000_000))),
            row_with("alice", Some(ts(1_900_000_000))),
        ]);
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
            let table = from_rows(rows);
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
        ]);
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

    /// A malformed `expiry_at` skips that row. The other rows
    /// decode, and the skipped row still counts as landed.
    #[test]
    fn decode_rows_skips_a_bad_timestamp() {
        let json = r#"[
            {"name": "alice", "expiry_at": "not-a-timestamp"},
            {"name": "bob", "expiry_at": null}
        ]"#;
        let (rows, landed) = decode_rows(json.as_bytes()).unwrap();
        assert_eq!(landed, 2);
        let table = complete(rows, landed, Some(landed)).unwrap();
        assert_eq!(
            table.status(&Name::parse("bob").unwrap()),
            ProtectionStatus::Forever
        );
        assert_eq!(table.status(&alice()), ProtectionStatus::Unprotected);
    }

    /// A body that is not a JSON array fails the read.
    #[test]
    fn decode_rows_rejects_a_non_array() {
        assert!(decode_rows(br#"{"name":"alice"}"#).is_err());
    }

    /// The read installs only when every counted row arrived.
    #[test]
    fn complete_installs_when_the_count_matches() {
        let table = complete(vec![row_with("alice", None)], 1, Some(1)).unwrap();
        assert_eq!(table.status(&alice()), ProtectionStatus::Forever);
    }

    /// A reply cut short by Max Rows is refused, not installed.
    #[test]
    fn complete_refuses_a_truncated_read() {
        let rows = vec![row_with("alice", None)];
        assert!(matches!(
            complete(rows, 1, Some(2)),
            Err(FetchError::Unconfirmed)
        ));
    }

    #[test]
    fn complete_refuses_a_missing_count() {
        let rows = vec![row_with("alice", None)];
        assert!(matches!(
            complete(rows, 1, None),
            Err(FetchError::Unconfirmed)
        ));
    }

    /// A skipped row counts toward the server total, and the reply installs.
    #[test]
    fn complete_counts_a_skipped_row_as_landed() {
        let table = complete(vec![row_with("alice", None)], 2, Some(2)).unwrap();
        assert_eq!(table.status(&alice()), ProtectionStatus::Forever);
    }

    /// `install` takes the table the read returned. A name only the
    /// previous table held is gone.
    #[tokio::test]
    async fn install_replaces_the_table() {
        let mut names = table_of(&[("alice", ProtectionStatus::Forever)]);
        let fresh = table_of(&[("bob", ProtectionStatus::Forever)]);
        let pending = PendingRead(tokio::spawn(async move { Ok(fresh) }));
        pending.install(&mut names).await;
        assert_eq!(names.status(&alice()), ProtectionStatus::Unprotected);
        assert_eq!(
            names.status(&Name::parse("bob").unwrap()),
            ProtectionStatus::Forever
        );
    }

    /// A failed read is not installed. The protections already held stand.
    #[tokio::test]
    async fn a_failed_read_keeps_the_table() {
        let mut names = table_of(&[("alice", ProtectionStatus::Forever)]);
        let pending = PendingRead(tokio::spawn(async { Err(FetchError::Unavailable) }));
        pending.install(&mut names).await;
        assert_eq!(names.status(&alice()), ProtectionStatus::Forever);
    }

    /// A read dropped before `install` is cancelled, even after it has started.
    #[tokio::test]
    async fn dropping_an_unfinished_read_cancels_it() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let pending = PendingRead(tokio::spawn(async move {
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
            let _ = finished_tx.send(());
            Err(FetchError::Unavailable)
        }));
        started_rx.await.unwrap();
        drop(pending);
        let finished = tokio::time::timeout(std::time::Duration::from_secs(1), finished_rx).await;
        assert!(matches!(finished, Ok(Err(_))));
    }
}
