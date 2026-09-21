//! Pre-sale access codes for early claims of protected names.
//!
//! During the early-access window the mint looks up each claim name in
//! Supabase `zn_protected_names` (read-only). A `status = protected` row
//! requires the leading memo code; an absent row is open. The six-digit
//! code is not stored in the table: it is derived in the TEE from a
//! root key (`Tee::derive_sealing_key`) and the claim name, matching the
//! access-code-v1 HMAC construction. At general availability codes die
//! worthless. Redemption is the name live in the registry; the mint
//! never writes Supabase.

use std::time::Duration;

use hmac::{Hmac, Mac};
use http::Uri;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::mint::Name;

/// Day-clock day (MTP days since the mint birthday) on which protected
/// names open to the public and unredeemed codes die.
pub const GENERAL_AVAILABILITY_DAY: i64 = 90;

/// Context for [`crate::tee::Tee::derive_sealing_key`]: the access-code
/// root private key (32 bytes). Distinct from the capsule sealing context.
pub const ACCESS_CODE_KEY_CONTEXT: &[u8] = b"ZNS/access-code/root/v1";

/// Supabase project HTTP origin. PostgREST only.
const PRESALE_HOST: &str = "https://cclrkfymckyjfufvqedr.supabase.co";

/// Protected-name collection.
const PRESALE_TABLE: &str = "zn_protected_names";

/// Public Supabase publishable key (`apikey` for PostgREST).
const PRESALE_PUBLISHABLE_KEY: &str = "sb_publishable_eRyX0Z5CY3bHm11iCFoZRA_-u2WgStF";

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
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
    /// Transport or table unavailability — the request-queue entry waits.
    Unavailable,
    /// Name is not a protected row; the ordinary claim path applies.
    Open,
    /// Name is protected; the offered memo code must match the TEE derive.
    Protected,
}

/// Claim-lane decision after the day clock and the lookup.
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

/// Pure gate. For [`Lookup::Protected`], recomputes the code from
/// `access_code_key` and the claim `name` (must be the same bytes the
/// issuer used — the memo's normalized ZNS name).
pub fn decide(
    today: i64,
    lookup: Lookup,
    offered: Option<&AccessCode>,
    name_live: bool,
    access_code_key: &[u8],
    name: &str,
) -> Decision {
    if today >= GENERAL_AVAILABILITY_DAY {
        return Decision::Allow;
    }
    match lookup {
        Lookup::Unavailable => Decision::Retry,
        Lookup::Open => Decision::Allow,
        Lookup::Protected => {
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

#[derive(Deserialize)]
struct ProtectedRow {
    status: String,
}

/// Read-only lookup by `normalized_name`. The code is TEE-derived.
pub async fn lookup_name(name: &Name) -> Lookup {
    let url = format!(
        "{}?normalized_name=eq.{}&select=status",
        presale_rest_url(),
        name.as_str()
    );
    let uri: Uri = match url.parse() {
        Ok(uri) => uri,
        Err(_) => return Lookup::Unavailable,
    };
    let mut builder = Request::builder()
        .uri(uri)
        .header("accept", "application/json");
    if !PRESALE_PUBLISHABLE_KEY.is_empty() {
        builder = builder.header("apikey", PRESALE_PUBLISHABLE_KEY);
    }
    let request = match builder.body(Empty::<Bytes>::default()) {
        Ok(request) => request,
        Err(_) => return Lookup::Unavailable,
    };

    let client = https_client();
    let response = match tokio::time::timeout(FETCH_TIMEOUT, client.request(request)).await {
        Ok(Ok(response)) => response,
        _ => return Lookup::Unavailable,
    };
    if !response.status().is_success() {
        return Lookup::Unavailable;
    }
    let body = match Limited::new(response.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Lookup::Unavailable,
    };
    let rows: Vec<ProtectedRow> = match serde_json::from_slice(&body) {
        Ok(rows) => rows,
        Err(_) => return Lookup::Unavailable,
    };
    match rows.as_slice() {
        [] => Lookup::Open,
        [row] if row.status == "protected" => Lookup::Protected,
        [_] => Lookup::Open,
        _ => Lookup::Unavailable,
    }
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
    fn after_ga_codes_are_worthless() {
        let key = derive_access_code_key(&vector_private_key());
        assert_eq!(
            decide(
                GENERAL_AVAILABILITY_DAY,
                Lookup::Protected,
                None,
                false,
                key.as_ref(),
                "alice"
            ),
            Decision::Allow
        );
    }

    #[test]
    fn open_names_need_no_code_before_ga() {
        let key = derive_access_code_key(&vector_private_key());
        assert_eq!(
            decide(0, Lookup::Open, None, false, key.as_ref(), "alice"),
            Decision::Allow
        );
    }

    #[test]
    fn protected_names_require_the_matching_code() {
        let key = derive_access_code_key(&vector_private_key());
        let expected = AccessCode::derive(key.as_ref(), "alice");
        assert_eq!(
            decide(
                0,
                Lookup::Protected,
                Some(&expected),
                false,
                key.as_ref(),
                "alice"
            ),
            Decision::Allow
        );
        let wrong = AccessCode::parse("999999").unwrap();
        assert_eq!(
            decide(
                0,
                Lookup::Protected,
                Some(&wrong),
                false,
                key.as_ref(),
                "alice"
            ),
            Decision::Deny
        );
        assert_eq!(
            decide(0, Lookup::Protected, None, false, key.as_ref(), "alice"),
            Decision::Deny
        );
    }

    #[test]
    fn live_name_redeems_the_code() {
        let key = derive_access_code_key(&vector_private_key());
        let expected = AccessCode::derive(key.as_ref(), "alice");
        assert_eq!(
            decide(
                0,
                Lookup::Protected,
                Some(&expected),
                true,
                key.as_ref(),
                "alice"
            ),
            Decision::Deny
        );
    }

    #[test]
    fn unavailability_retries() {
        let key = derive_access_code_key(&vector_private_key());
        let offered = AccessCode::parse("352582").unwrap();
        assert_eq!(
            decide(
                0,
                Lookup::Unavailable,
                Some(&offered),
                false,
                key.as_ref(),
                "alice"
            ),
            Decision::Retry
        );
    }

    #[test]
    fn table_is_zn_protected_names() {
        assert_eq!(PRESALE_TABLE, "zn_protected_names");
        assert!(!PRESALE_PUBLISHABLE_KEY.is_empty());
    }
}
