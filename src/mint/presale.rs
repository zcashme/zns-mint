//! Pre-sale access codes for early claims of protected names.
//!
//! During the early-access window the mint looks up each claim's name in
//! the external Supabase pre-sale table (read-only). A protected name
//! requires the matching leading memo code; an open name does not. At
//! general availability the window closes on a day-clock day and codes
//! die worthless — claims proceed without the table. Redemption is
//! derived from the name already existing in the registry; the mint
//! never writes back to Supabase.

use std::time::Duration;

use http::Uri;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;

use crate::mint::Name;

/// Day-clock day (MTP days since the mint birthday) on which protected
/// names open to the public and unredeemed codes die. Fixed at deploy;
/// the window is open while `today < GENERAL_AVAILABILITY_DAY`.
pub const GENERAL_AVAILABILITY_DAY: i64 = 90;

/// TODO: wire the PostgREST collection URL. Empty disables the lookup
/// and treats every name as open.
const PRESALE_REST_URL: &str = "";

/// TODO: wire the Supabase anon key for the read-only RLS policy. Empty
/// with a wired URL fails closed as [`Lookup::Unavailable`].
const PRESALE_ANON_KEY: &str = "";

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BODY_BYTES: usize = 64 * 1024;

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>;

fn https_client() -> HttpsClient {
    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(connector)
}

/// Outcome of one read-only pre-sale lookup for a claim name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Transport or table unavailability — the request-queue entry waits.
    Unavailable,
    /// Name is not in the pre-sale table; the ordinary claim path applies.
    Open,
    /// Name is protected; `code` is the issued access code.
    Protected { code: String },
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

/// Pure gate: day clock, lookup, offered code, and whether the name is
/// already live in the registry. Never contacts the network.
pub fn decide(today: i64, lookup: Lookup, offered: Option<&str>, name_live: bool) -> Decision {
    // After GA every code is worthless; protected names are public.
    if today >= GENERAL_AVAILABILITY_DAY {
        return Decision::Allow;
    }
    match lookup {
        Lookup::Unavailable => Decision::Retry,
        Lookup::Open => Decision::Allow,
        Lookup::Protected { code } => {
            // Redemption is the name existing — never a write to the table.
            if name_live {
                return Decision::Deny;
            }
            match offered {
                Some(c) if c == code => Decision::Allow,
                _ => Decision::Deny,
            }
        }
    }
}

#[derive(Deserialize)]
struct PresaleRow {
    code: String,
}

/// Read-only per-claim lookup. Names are `a-z` / `0-9` only, so the
/// query string needs no percent-encoding.
pub async fn lookup_name(name: &Name) -> Lookup {
    if PRESALE_REST_URL.is_empty() {
        return Lookup::Open;
    }
    if PRESALE_ANON_KEY.is_empty() {
        return Lookup::Unavailable;
    }

    let url = format!("{}?name=eq.{}&select=code", PRESALE_REST_URL, name.as_str());
    let uri: Uri = match url.parse() {
        Ok(uri) => uri,
        Err(_) => return Lookup::Unavailable,
    };
    let request = match Request::builder()
        .uri(uri)
        .header("accept", "application/json")
        .header("apikey", PRESALE_ANON_KEY)
        .header("authorization", format!("Bearer {PRESALE_ANON_KEY}"))
        .body(Empty::<Bytes>::default())
    {
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
    let rows: Vec<PresaleRow> = match serde_json::from_slice(&body) {
        Ok(rows) => rows,
        Err(_) => return Lookup::Unavailable,
    };
    match rows.as_slice() {
        [] => Lookup::Open,
        [row] if !row.code.is_empty() => Lookup::Protected {
            code: row.code.clone(),
        },
        _ => Lookup::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn after_ga_codes_are_worthless() {
        assert_eq!(
            decide(
                GENERAL_AVAILABILITY_DAY,
                Lookup::Protected {
                    code: "a1b2c3d4e5f6g7h8".into()
                },
                None,
                false
            ),
            Decision::Allow
        );
        assert_eq!(
            decide(
                GENERAL_AVAILABILITY_DAY + 1,
                Lookup::Protected {
                    code: "a1b2c3d4e5f6g7h8".into()
                },
                Some("zzzzzzzzzzzzzzzz"),
                false
            ),
            Decision::Allow
        );
    }

    #[test]
    fn open_names_need_no_code_before_ga() {
        assert_eq!(decide(0, Lookup::Open, None, false), Decision::Allow);
    }

    #[test]
    fn protected_names_require_the_matching_code() {
        let protected = Lookup::Protected {
            code: "a1b2c3d4e5f6g7h8".into(),
        };
        assert_eq!(
            decide(0, protected.clone(), Some("a1b2c3d4e5f6g7h8"), false),
            Decision::Allow
        );
        assert_eq!(
            decide(0, protected.clone(), Some("zzzzzzzzzzzzzzzz"), false),
            Decision::Deny
        );
        assert_eq!(decide(0, protected, None, false), Decision::Deny);
    }

    #[test]
    fn live_name_redeems_the_code() {
        assert_eq!(
            decide(
                0,
                Lookup::Protected {
                    code: "a1b2c3d4e5f6g7h8".into()
                },
                Some("a1b2c3d4e5f6g7h8"),
                true
            ),
            Decision::Deny
        );
    }

    #[test]
    fn unavailability_retries() {
        assert_eq!(
            decide(0, Lookup::Unavailable, Some("a1b2c3d4e5f6g7h8"), false),
            Decision::Retry
        );
    }

    #[test]
    fn empty_rest_url_is_open() {
        assert!(PRESALE_REST_URL.is_empty());
    }
}
