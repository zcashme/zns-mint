//! The pre-sale protected-names table, cached in memory.
//!
//! `zn_names` is read once at boot and re-read once per MTP day by
//! a background fetch whose result installs on completion; claims
//! consult the cache synchronously — Supabase is never on a claim's
//! path. Every row is protected; `expiry_at`
//! (`timestamptz`, nullable) is either a lift moment, judged against
//! the current MTP per claim, or forever. A missing row, or a lift
//! moment the MTP has reached, is unprotected. The six-digit code is not
//! stored in the table: it is derived in the TEE from a root key
//! (`Tee::derive_sealing_key`) and the claim name, matching the
//! access-code-v1 HMAC construction. Redemption is the name live in
//! the registry; the mint never writes Supabase.

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
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, Timestamp};
use zeroize::{Zeroize, Zeroizing};

use crate::mint::Name;

/// Context for [`zns_canon::sealing::Tee::derive_sealing_key`]: the access-code
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

/// Page ceiling: a read needing more than this many full pages
/// (~25,000 names) is refused — a pathological table keeps
/// yesterday's rows, loudly.
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
    /// Parses exactly six ASCII decimal digits from a memo field.
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

/// A name's protection status. `Unprotected` is never stored — it
/// is the flattened absence `ProtectedNames::get` returns. A
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

/// A row from `zn_names`: `id` keys the cursor, `name` must parse
/// as a [`Name`], `expiry_at` is RFC 3339 or null (forever). Other
/// columns are ignored.
#[derive(Deserialize)]
struct ProtectedRow {
    id: String,
    name: String,
    #[serde(default, deserialize_with = "deserialize_optional_timestamp")]
    expiry_at: Option<Timestamp>,
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
/// absent from the map is unprotected. Pure data; [`fetch`] is the
/// only writer.
#[derive(Clone, Debug)]
pub struct ProtectedNames(BTreeMap<Name, ProtectionStatus>);

impl ProtectedNames {
    /// The name's [`ProtectionStatus`] — `Unprotected` when the table
    /// doesn't know the name. Total by design: absence is a status,
    /// not a lookup failure, so this never returns `Option`.
    pub fn status(&self, name: &Name) -> ProtectionStatus {
        self.0
            .get(name)
            .copied()
            .unwrap_or(ProtectionStatus::Unprotected)
    }

    /// Is the name protected at this MTP? Expiry is judged now,
    /// never stored — protection lifts exactly on schedule. The
    /// judged question; [`ProtectedNames::status`] is the stored fact.
    pub fn is_protected(&self, name: &Name, mtp: Timestamp) -> bool {
        match self.status(name) {
            ProtectionStatus::Unprotected => false,
            ProtectionStatus::Forever => true,
            ProtectionStatus::WithExpiry(ts) => mtp < ts,
        }
    }
}

/// Reads the whole table, `PAGE_ROWS` at a time, keyset-paginated
/// by the unique `(name, id)`: inserts and deletes cannot shift
/// the window, and no row can be skipped or repeated. The first
/// page carries the server's exact row count; the read installs
/// only when every counted row landed — duplicates coalesce
/// wherever their pages arrive. Stops on a short page; refuses a
/// read needing more than `MAX_PAGES` full pages. Any failure
/// rejects the whole read (`None`) — a caller keeps what it has.
pub async fn fetch() -> Option<ProtectedNames> {
    let client = https_client();
    let mut rows = BTreeMap::new();
    let mut read = 0usize;
    let mut coalesced = 0usize;
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
        .await?;
        pages += 1;
        if pages > MAX_PAGES && !page.is_empty() {
            tracing::warn!("pre-sale fetch exceeded the page ceiling");
            return None;
        }
        total = total.or(counted);
        let short = page.len() < PAGE_ROWS;
        let last = page.last().map(|row| (row.name.clone(), row.id.clone()));
        let before = rows.len();
        let page_len = page.len();
        read += page_len;
        absorb(page, &mut rows)?;
        coalesced += page_len - (rows.len() - before);
        if short {
            return match total {
                Some(total) if total == read => {
                    tracing::info!(
                        names = rows.len(),
                        rows = read,
                        coalesced,
                        "pre-sale fetch: table loaded"
                    );
                    Some(ProtectedNames(rows))
                }
                Some(total) => {
                    tracing::warn!(
                        counted = total,
                        read,
                        installed = rows.len(),
                        "pre-sale fetch did not install every counted row"
                    );
                    None
                }
                None => {
                    tracing::warn!("pre-sale fetch: row count missing");
                    None
                }
            };
        }
        after = last;
    }
}

/// One page of rows after `after` (the previous page's last
/// `(name, id)`), ordered by `(name, id)`, with the server's exact
/// row count when `want_total`. `None` on any transport, timeout,
/// status, size, or parse failure; each is warned here. One
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

/// The filter for rows strictly after `(name, id)`: every later
/// name, or the same name with a later id. Names are `[a-z0-9]`
/// and ids UUID text, so no value needs escaping.
fn keyset_filter(after: Option<(&str, &str)>) -> String {
    match after {
        None => String::new(),
        Some((name, id)) => {
            format!("&or=(name.gt.{name},and(name.eq.{name},id.gt.{id}))")
        }
    }
}

/// Validates rows into the map, coalescing a re-purchase into the
/// strongest bought term: `Forever` over any expiry, the later
/// expiry over the earlier. An unlawful `name` rejects the whole
/// read — corruption, not a purchase; nothing paid-for is dropped.
fn absorb(rows: Vec<ProtectedRow>, map: &mut BTreeMap<Name, ProtectionStatus>) -> Option<()> {
    for row in rows {
        let name = Name::parse(&row.name)?;
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
    Some(())
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

    /// Derive the six-digit code a protected `name` must present.
    ///
    /// `digest = HMAC-SHA256(purpose_key, name)`; value is
    /// `u32_be(digest[0..4]) mod 1_000_000`.
    pub fn derive(&self, name: &Name) -> AccessCode {
        let mut mac = HmacSha256::new_from_slice(self.0.as_ref())
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(name.as_str().as_bytes());
        let digest = mac.finalize().into_bytes();
        let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        AccessCode(n % 1_000_000)
    }

    /// Does the offered code match this key's code for `name`?
    /// A missing code never matches.
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

    #[test]
    fn absorb_builds_the_map() {
        let mut map = BTreeMap::new();
        let rows = vec![
            row_with("alice", Some(ts(2_000_000_000))),
            row_with("bob", None),
        ];
        absorb(rows, &mut map).unwrap();
        let names = ProtectedNames(map);
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
    fn absorb_keeps_expired_rows() {
        let mut map = BTreeMap::new();
        let rows = vec![row_with("alice", Some(ts(1_600_000_000)))];
        absorb(rows, &mut map).unwrap();
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

    /// A duplicate row is a re-purchase: the name's rows coalesce
    /// to the strongest bought term.
    #[test]
    fn absorb_coalesces_identical_rows() {
        let mut map = BTreeMap::new();
        let rows = vec![row_with("alice", None), row_with("alice", None)];
        absorb(rows, &mut map).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.get(&Name::parse("alice").unwrap()),
            Some(&ProtectionStatus::Forever)
        );
    }

    /// Two dated terms cover the name to the later lift moment.
    #[test]
    fn absorb_coalesces_expiries_to_the_latest() {
        let mut map = BTreeMap::new();
        let rows = vec![
            row_with("alice", Some(ts(2_000_000_000))),
            row_with("alice", Some(ts(1_900_000_000))),
        ];
        absorb(rows, &mut map).unwrap();
        assert_eq!(
            map.get(&Name::parse("alice").unwrap()),
            Some(&ProtectionStatus::WithExpiry(ts(2_000_000_000)))
        );
    }

    /// Forever covers any expiry, in either row order.
    #[test]
    fn absorb_coalesces_forever_over_an_expiry() {
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
            let mut map = BTreeMap::new();
            absorb(rows, &mut map).unwrap();
            assert_eq!(
                map.get(&Name::parse("alice").unwrap()),
                Some(&ProtectionStatus::Forever)
            );
        }
    }

    /// The reported live shape: `9` and `tom` each hold an expiry
    /// plus Forever among their re-purchases.
    #[test]
    fn absorb_coalesces_the_reported_table_shape() {
        let mut map = BTreeMap::new();
        let rows = vec![
            row_with("9", Some(ts(1_795_898_400))),
            row_with("9", None),
            row_with("9", None),
            row_with("9", None),
            row_with("9", None),
            row_with("tom", Some(ts(1_800_563_400))),
            row_with("tom", None),
            row_with("alice", Some(ts(2_000_000_000))),
        ];
        absorb(rows, &mut map).unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.get(&Name::parse("9").unwrap()),
            Some(&ProtectionStatus::Forever)
        );
        assert_eq!(
            map.get(&Name::parse("tom").unwrap()),
            Some(&ProtectionStatus::Forever)
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
