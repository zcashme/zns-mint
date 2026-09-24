//! Pre-sale access codes for early claims of protected names.
//!
//! The mint looks up each claim name in Supabase `zn_protected_names`
//! (read-only). An absent row means the name is open. Every row in the
//! table is protected; its `expires_at` (`timestamptz`, nullable) chooses
//! between finite protection and forever protection. A row whose
//! `expires_at` is at or before the current MTP is treated as open —
//! the protection has expired. The six-digit code is not stored in the
//! table: it is derived in the TEE from a root key
//! (`Tee::derive_sealing_key`) and the claim name, matching the
//! access-code-v1 HMAC construction. Redemption is the name live in the
//! registry; the mint never writes Supabase.

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
const PRESALE_TABLE: &str = "zn_protected_names";

/// Public Supabase publishable key (`apikey` for PostgREST).
const PRESALE_PUBLISHABLE_KEY: &str = "sb_publishable_eRyX0Z5CY3bHm11iCFoZRA_-u2WgStF";

const FETCH_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_BODY_BYTES: usize = 64 * 1024;

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

/// Outcome of one read-only pre-sale lookup for a claim name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Name is not in the protected table, or its row's protection has
    /// already expired at the current MTP. The ordinary claim path
    /// applies.
    Open,
    /// Name is in the table with an `expires_at` in the future; the
    /// offered memo code must match the TEE derive. The wrapped
    /// timestamp is the moment protection lifts, kept for observability.
    ProtectedWithExpiry(Timestamp),
    /// Name is in the table with a null `expires_at`; the offered memo
    /// code must match the TEE derive. Protection does not lift.
    ProtectedForever,
}

/// Why a pre-sale lookup could not be classified. The variant is the
/// only distinction callers branch on — retry vs give up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupError {
    /// Transport, timeout, or 5xx. Queue entry retried next tip.
    Transient,
    /// Non-429 4xx, non-JSON body, unparsable `expires_at`, or multi-row
    /// for one `normalized_name`. Retrying observes the same state; the
    /// claim is dropped.
    Terminal,
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient => f.write_str("pre-sale lookup transient failure"),
            Self::Terminal => f.write_str("pre-sale lookup terminal failure"),
        }
    }
}

impl std::error::Error for LookupError {}

/// Claim-lane decision after the lookup.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Proceed to payment and authorize.
    Allow,
    /// Dead: wrong or missing code, or the name already exists (redeemed).
    Deny,
    /// Keep the queue entry; try again on the next tip.
    Retry,
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

/// Pure gate. For every protected variant, recomputes the code from
/// `access_code_key` and the claim `name` (must be the same bytes the
/// issuer used — the memo's normalized ZNS name). A transient lookup
/// error keeps the queue entry alive with [`Decision::Retry`]; a
/// terminal lookup error frees the slot with [`Decision::Deny`] so a
/// permanently broken row does not tie up the queue forever.
pub fn decide(
    lookup: Result<Lookup, LookupError>,
    offered: Option<&AccessCode>,
    name_live: bool,
    access_code_key: &[u8],
    name: &str,
) -> Decision {
    let lookup = match lookup {
        Ok(lookup) => lookup,
        Err(LookupError::Transient) => return Decision::Retry,
        Err(LookupError::Terminal) => return Decision::Deny,
    };
    match lookup {
        Lookup::Open => Decision::Allow,
        Lookup::ProtectedWithExpiry(_) | Lookup::ProtectedForever => {
            if name_live {
                return Decision::Deny;
            }
            let expected = AccessCode::derive(access_code_key, name);
            match offered {
                Some(offered) if expected.ct_eq(offered) => Decision::Allow,
                _ => Decision::Deny,
            }
        }
    }
}

/// A row from `zn_protected_names`. Only `expires_at` matters here —
/// every row is protected by construction, and the other columns
/// (`id`, `normalized_name`, `created_at`, `source`, `dupe`) are ignored
/// by serde's default field handling.
#[derive(Deserialize)]
struct ProtectedRow {
    #[serde(default, deserialize_with = "deserialize_optional_timestamp")]
    expires_at: Option<Timestamp>,
}

/// Deserialize `timestamptz` in the RFC 3339 shape PostgREST returns
/// (e.g. `"2027-01-01T00:00:00+00:00"`). `null` → `None`; any string
/// that does not parse as RFC 3339 fails the deserializer, which
/// bubbles up as [`LookupError::Terminal`] via `serde_json` — the row
/// data is structurally broken, retrying will observe the same bytes.
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

/// Classifies pre-sale rows into a [`Lookup`] outcome relative to `mtp`.
///
/// - `[]` (absence): [`Lookup::Open`] — the name is not in the table.
/// - `[row]` with null `expires_at`: [`Lookup::ProtectedForever`].
/// - `[row]` with `expires_at > mtp`: [`Lookup::ProtectedWithExpiry`].
/// - `[row]` with `expires_at <= mtp`: [`Lookup::Open`] — protection
///   has expired.
/// - Multiple rows for one `normalized_name` violates the schema's
///   uniqueness; returned as [`LookupError::Terminal`] with a `warn`
///   log. Retrying will observe the same duplicate rows.
fn classify(rows: &[ProtectedRow], name: &Name, mtp: Timestamp) -> Result<Lookup, LookupError> {
    match rows {
        [] => Ok(Lookup::Open),
        [row] => match row.expires_at {
            None => Ok(Lookup::ProtectedForever),
            Some(expires_at) if mtp >= expires_at => Ok(Lookup::Open),
            Some(expires_at) => Ok(Lookup::ProtectedWithExpiry(expires_at)),
        },
        _ => {
            tracing::warn!(
                name = %name.as_str(),
                rows = rows.len(),
                "pre-sale returned multiple rows for one normalized name"
            );
            Err(LookupError::Terminal)
        }
    }
}

/// Read-only lookup by `normalized_name`. The code is TEE-derived.
///
/// `mtp` is the current canonical-chain MTP; used to decide whether a
/// row's `expires_at` still gates the claim.
///
/// Error kind reflects retry semantics: transport, timeout, 429, and
/// 5xx are [`LookupError::Transient`]; any other 4xx, a malformed body,
/// or a malformed `expires_at` are [`LookupError::Terminal`].
pub async fn lookup_name(name: &Name, mtp: Timestamp) -> Result<Lookup, LookupError> {
    let url = format!(
        "{}?normalized_name=eq.{}&select=expires_at",
        presale_rest_url(),
        name.as_str()
    );
    // URL parse and request build only fail on a code bug given a
    // static base and a validated `Name`. Terminal: retrying will
    // reproduce the same programmer error.
    let uri: Uri = match url.parse() {
        Ok(uri) => uri,
        Err(error) => {
            tracing::warn!(?error, name = %name.as_str(), "pre-sale lookup: invalid URL");
            return Err(LookupError::Terminal);
        }
    };
    let mut builder = Request::builder()
        .uri(uri)
        .header("accept", "application/json");
    if !PRESALE_PUBLISHABLE_KEY.is_empty() {
        builder = builder.header("apikey", PRESALE_PUBLISHABLE_KEY);
    }
    let request = match builder.body(Empty::<Bytes>::default()) {
        Ok(request) => request,
        Err(error) => {
            tracing::warn!(?error, name = %name.as_str(), "pre-sale lookup: request build failed");
            return Err(LookupError::Terminal);
        }
    };

    let client = https_client();
    let response = match tokio::time::timeout(FETCH_TIMEOUT, client.request(request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            tracing::warn!(?error, name = %name.as_str(), "pre-sale lookup: http transport failed");
            return Err(LookupError::Transient);
        }
        Err(_) => {
            tracing::warn!(name = %name.as_str(), "pre-sale lookup: timed out");
            return Err(LookupError::Transient);
        }
    };
    let status = response.status();
    if !status.is_success() {
        // 5xx (and any non-standard non-4xx) is Transient — Supabase
        // may recover on its own. 4xx is a caller-side or config
        // problem (auth revoked, table missing, filter rejected) that
        // won't change without operator action.
        // 429 is a rate limit: the row has not been classified. 5xx may
        // clear on its own. Other 4xx is auth, schema, or a missing table.
        let kind = if status.as_u16() == 429 || status.is_server_error() {
            LookupError::Transient
        } else {
            LookupError::Terminal
        };
        tracing::warn!(
            status = %status,
            name = %name.as_str(),
            ?kind,
            "pre-sale lookup: non-success HTTP status"
        );
        return Err(kind);
    }
    // Body read failures are transport-shaped (mid-stream reset, or a
    // response exceeding MAX_BODY_BYTES). Transient so a truncated
    // fetch does not sink a paid claim.
    let body = match Limited::new(response.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            tracing::warn!(?error, name = %name.as_str(), "pre-sale lookup: body read failed");
            return Err(LookupError::Transient);
        }
    };
    // JSON parse failure covers both a malformed body and a row whose
    // `expires_at` is not RFC 3339. Both mean the bytes on the wire
    // will not become valid without operator action: Terminal.
    let rows: Vec<ProtectedRow> = match serde_json::from_slice(&body) {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(?error, name = %name.as_str(), "pre-sale lookup: json parse failed");
            return Err(LookupError::Terminal);
        }
    };
    classify(&rows, name, mtp)
}

/// Zeroizing holder for the boot-derived access-code key.
#[derive(Clone)]
pub struct AccessCodeKey(Zeroizing<[u8; 32]>);

impl AccessCodeKey {
    /// From a TEE root private key (`ACCESS_CODE_KEY_CONTEXT`).
    pub fn from_private_key(private_key: &[u8; 32]) -> Self {
        Self(derive_access_code_key(private_key))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
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

    fn row_with(expires_at: Option<Timestamp>) -> ProtectedRow {
        ProtectedRow { expires_at }
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
    fn open_names_need_no_code() {
        let key = derive_access_code_key(&vector_private_key());
        assert_eq!(
            decide(Ok(Lookup::Open), None, false, key.as_ref(), "alice"),
            Decision::Allow
        );
    }

    #[test]
    fn protected_with_expiry_requires_the_matching_code() {
        let key = derive_access_code_key(&vector_private_key());
        let expected = AccessCode::derive(key.as_ref(), "alice");
        let wrong = AccessCode::parse("999999").unwrap();
        let lookup = || Ok(Lookup::ProtectedWithExpiry(ts(2_000_000_000)));

        assert_eq!(
            decide(lookup(), Some(&expected), false, key.as_ref(), "alice"),
            Decision::Allow
        );
        assert_eq!(
            decide(lookup(), Some(&wrong), false, key.as_ref(), "alice"),
            Decision::Deny
        );
        assert_eq!(
            decide(lookup(), None, false, key.as_ref(), "alice"),
            Decision::Deny
        );
    }

    #[test]
    fn protected_forever_requires_the_matching_code() {
        let key = derive_access_code_key(&vector_private_key());
        let expected = AccessCode::derive(key.as_ref(), "alice");
        let wrong = AccessCode::parse("999999").unwrap();
        let lookup = || Ok(Lookup::ProtectedForever);

        assert_eq!(
            decide(lookup(), Some(&expected), false, key.as_ref(), "alice"),
            Decision::Allow
        );
        assert_eq!(
            decide(lookup(), Some(&wrong), false, key.as_ref(), "alice"),
            Decision::Deny
        );
        assert_eq!(
            decide(lookup(), None, false, key.as_ref(), "alice"),
            Decision::Deny
        );
    }

    #[test]
    fn live_name_redeems_the_code() {
        let key = derive_access_code_key(&vector_private_key());
        let expected = AccessCode::derive(key.as_ref(), "alice");
        for lookup in [
            Lookup::ProtectedWithExpiry(ts(2_000_000_000)),
            Lookup::ProtectedForever,
        ] {
            assert_eq!(
                decide(Ok(lookup), Some(&expected), true, key.as_ref(), "alice"),
                Decision::Deny
            );
        }
    }

    #[test]
    fn transient_error_retries() {
        let key = derive_access_code_key(&vector_private_key());
        let offered = AccessCode::parse("352582").unwrap();
        assert_eq!(
            decide(
                Err(LookupError::Transient),
                Some(&offered),
                false,
                key.as_ref(),
                "alice",
            ),
            Decision::Retry
        );
    }

    /// A permanent lookup failure must
    /// free the queue slot rather than retry forever. Payment stays in
    /// Treasury; no on-chain effect. The claim is dropped.
    #[test]
    fn terminal_error_denies() {
        let key = derive_access_code_key(&vector_private_key());
        let offered = AccessCode::parse("352582").unwrap();
        assert_eq!(
            decide(
                Err(LookupError::Terminal),
                Some(&offered),
                false,
                key.as_ref(),
                "alice",
            ),
            Decision::Deny
        );
    }

    #[test]
    fn table_is_zn_protected_names() {
        assert_eq!(PRESALE_TABLE, "zn_protected_names");
        assert!(!PRESALE_PUBLISHABLE_KEY.is_empty());
    }

    #[test]
    fn absent_row_is_open() {
        let name = Name::parse("alice").unwrap();
        assert_eq!(classify(&[], &name, ts(1_700_000_000)), Ok(Lookup::Open));
    }

    #[test]
    fn null_expiry_is_forever() {
        let name = Name::parse("alice").unwrap();
        let rows = [row_with(None)];
        assert_eq!(
            classify(&rows, &name, ts(1_700_000_000)),
            Ok(Lookup::ProtectedForever)
        );
    }

    #[test]
    fn future_expiry_is_protected() {
        let name = Name::parse("alice").unwrap();
        let expiry = ts(2_000_000_000);
        let rows = [row_with(Some(expiry))];
        assert_eq!(
            classify(&rows, &name, ts(1_700_000_000)),
            Ok(Lookup::ProtectedWithExpiry(expiry))
        );
    }

    /// The audit-critical case: protection whose deadline has passed
    /// must not gate the claim. The row still exists but its clock ran
    /// out, so it flattens to `Open` for `decide`.
    #[test]
    fn past_expiry_becomes_open() {
        let name = Name::parse("alice").unwrap();
        let rows = [row_with(Some(ts(1_600_000_000)))];
        assert_eq!(classify(&rows, &name, ts(1_700_000_000)), Ok(Lookup::Open));
    }

    /// Exact-second boundary: `mtp == expires_at` means the deadline
    /// has been reached; the row is open.
    #[test]
    fn expiry_boundary_is_inclusive_open() {
        let name = Name::parse("alice").unwrap();
        let now = ts(1_700_000_000);
        let rows = [row_with(Some(now))];
        assert_eq!(classify(&rows, &name, now), Ok(Lookup::Open));
    }

    /// A schema anomaly for one name is Terminal — the duplicate rows
    /// will still be there on the next tip. Retrying only wastes a
    /// fetch; denying frees the queue slot.
    #[test]
    fn multiple_rows_are_terminal() {
        let name = Name::parse("alice").unwrap();
        let rows = [row_with(None), row_with(None)];
        assert_eq!(
            classify(&rows, &name, ts(1_700_000_000)),
            Err(LookupError::Terminal)
        );
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
        // 2027-06-15T12:34:56 UTC = 1_813_062_896 seconds since the Unix epoch.
        assert_eq!(rows[0].expires_at, Some(ts(1_813_062_896)));
    }

    #[test]
    fn row_decode_null_expires_at() {
        let json = r#"[{"expires_at": null}]"#;
        let rows: Vec<ProtectedRow> = serde_json::from_slice(json.as_bytes()).unwrap();
        assert_eq!(rows[0].expires_at, None);
    }

    /// A malformed `expires_at` string must fail the deserializer,
    /// which bubbles up through `serde_json::from_slice` in
    /// `lookup_name` and yields `LookupBadRequest`.
    #[test]
    fn row_decode_bad_timestamp_errors() {
        let json = r#"[{"expires_at": "not-a-timestamp"}]"#;
        let rows: Result<Vec<ProtectedRow>, _> = serde_json::from_slice(json.as_bytes());
        assert!(rows.is_err(), "malformed timestamp must not deserialize");
    }
}
