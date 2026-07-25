//! Treasury memo parsing and classification.

use core::fmt;

pub use crate::mint::Action;

/// Why a memo failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoError {
    /// Zcash memos are exactly 512 bytes.
    InvalidLength,
    /// Not a ZNS memo at all (no `ZNS:` prefix, or not UTF-8).
    NotZns,
    /// A `ZNS:` memo with an unknown verb.
    UnknownVerb,
    /// Wrong number of `:`-separated fields for the verb.
    FieldCount,
    /// The name violates the DNS-label rule.
    InvalidName,
    /// A required unified-address argument is empty.
    EmptyArg,
    /// `otp` is not exactly 32 lowercase hex chars.
    InvalidOtp,
}

/// A parsed, typed request memo sent by a user to the Treasury.
#[derive(Clone, PartialEq, Eq)]
pub enum RequestMemo {
    /// A claim request: `ZNS:claim:<name>:<ua>`
    Claim { name: String, ua: String },
    /// An update request: `ZNS:update:<name>:<ua>[:<otp>]`
    Update {
        name: String,
        ua: String,
        otp: Option<[u8; 16]>,
    },
    /// A release request: `ZNS:release:<name>:<ua>[:<otp>]`
    Release {
        name: String,
        ua: String,
        otp: Option<[u8; 16]>,
    },
}

impl fmt::Debug for RequestMemo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestMemo(<redacted>)")
    }
}

impl RequestMemo {
    /// Returns the action type for this request.
    pub fn action(&self) -> Action {
        match self {
            RequestMemo::Claim { .. } => Action::Claim,
            RequestMemo::Update { .. } => Action::Update,
            RequestMemo::Release { .. } => Action::Release,
        }
    }

    /// Returns a short, metrics-safe string for the action.
    pub fn action_str(&self) -> &'static str {
        match self {
            RequestMemo::Claim { .. } => "claim",
            RequestMemo::Update { .. } => "update",
            RequestMemo::Release { .. } => "release",
        }
    }

    /// Returns the parsed canonical name for this request.
    pub fn name(&self) -> &str {
        match self {
            RequestMemo::Claim { name, .. } => name,
            RequestMemo::Update { name, .. } => name,
            RequestMemo::Release { name, .. } => name,
        }
    }

    /// Returns the parsed unified address for this request.
    pub fn ua(&self) -> &str {
        match self {
            RequestMemo::Claim { ua, .. } => ua,
            RequestMemo::Update { ua, .. } => ua,
            RequestMemo::Release { ua, .. } => ua,
        }
    }

    /// Parses a raw 512-byte request memo using strict grammar rules.
    pub fn parse(raw: &[u8]) -> Result<Self, MemoError> {
        if raw.len() != 512 {
            return Err(MemoError::InvalidLength);
        }
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        if raw[end..].iter().any(|b| *b != 0) {
            return Err(MemoError::FieldCount);
        }
        let text = core::str::from_utf8(&raw[..end]).map_err(|_| MemoError::NotZns)?;

        let mut fields = text.split(':');
        if fields.next() != Some("ZNS") {
            return Err(MemoError::NotZns);
        }
        let verb = fields.next().ok_or(MemoError::FieldCount)?;
        let name = fields.next().ok_or(MemoError::FieldCount)?;
        crate::mint::Name::parse(name).ok_or(MemoError::InvalidName)?;

        let ua = fields.next().ok_or(MemoError::FieldCount)?;
        if ua.is_empty() {
            return Err(MemoError::EmptyArg);
        }

        let otp_str = fields.next();
        if fields.next().is_some() {
            return Err(MemoError::FieldCount);
        }

        match verb {
            "claim" => {
                if otp_str.is_some() {
                    return Err(MemoError::FieldCount);
                }
                Ok(RequestMemo::Claim {
                    name: name.to_string(),
                    ua: ua.to_string(),
                })
            }
            "update" => {
                let otp = match otp_str {
                    Some(s) => Some(decode_otp(s)?),
                    None => None,
                };
                Ok(RequestMemo::Update {
                    name: name.to_string(),
                    ua: ua.to_string(),
                    otp,
                })
            }
            "release" => {
                let otp = match otp_str {
                    Some(s) => Some(decode_otp(s)?),
                    None => None,
                };
                Ok(RequestMemo::Release {
                    name: name.to_string(),
                    ua: ua.to_string(),
                    otp,
                })
            }
            _ => Err(MemoError::UnknownVerb),
        }
    }
}

/// Decode an `otp` field: exactly 32 lowercase hex chars.
fn decode_otp(s: &str) -> Result<[u8; 16], MemoError> {
    let bytes = s.as_bytes();
    if bytes.len() != 32 {
        return Err(MemoError::InvalidOtp);
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(MemoError::InvalidOtp),
    };
    let mut out = [0u8; 16];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn padded(s: &str) -> [u8; 512] {
        let mut m = [0u8; 512];
        m[..s.len()].copy_from_slice(s.as_bytes());
        m
    }

    #[test]
    fn request_parsers_reject_prev_rcm() {
        // A user request must not contain the 5th field (prev_rcm is for minted Name Notes)
        let m = "ZNS:claim:alice:u1xxx:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert_eq!(RequestMemo::parse(&padded(m)), Err(MemoError::FieldCount));
    }

    #[test]
    fn accepts_exactly_the_five_request_forms() {
        let otp_hex = "00112233445566778899aabbccddeeff";
        let mut otp = [0u8; 16];
        hex::decode_to_slice(otp_hex, &mut otp).unwrap();

        assert_eq!(
            RequestMemo::parse(&padded("ZNS:claim:alice:u1owner")),
            Ok(RequestMemo::Claim {
                name: "alice".into(),
                ua: "u1owner".into(),
            })
        );
        assert_eq!(
            RequestMemo::parse(&padded("ZNS:update:alice:u1new")),
            Ok(RequestMemo::Update {
                name: "alice".into(),
                ua: "u1new".into(),
                otp: None,
            })
        );
        assert_eq!(
            RequestMemo::parse(&padded(&format!("ZNS:update:alice:u1new:{otp_hex}"))),
            Ok(RequestMemo::Update {
                name: "alice".into(),
                ua: "u1new".into(),
                otp: Some(otp),
            })
        );
        assert_eq!(
            RequestMemo::parse(&padded("ZNS:release:alice:u1owner")),
            Ok(RequestMemo::Release {
                name: "alice".into(),
                ua: "u1owner".into(),
                otp: None,
            })
        );
        assert_eq!(
            RequestMemo::parse(&padded(&format!("ZNS:release:alice:u1owner:{otp_hex}"))),
            Ok(RequestMemo::Release {
                name: "alice".into(),
                ua: "u1owner".into(),
                otp: Some(otp),
            })
        );
    }

    #[test]
    fn rejects_unapproved_request_fields() {
        for text in [
            "ZNS:v1:claim:alice:u1owner",
            "ZNS:claim:main:alice:u1owner",
            "ZNS:claim:alice:u1owner:nonce",
            "ZNS:claim:alice:u1owner:challenge_id",
            "ZNS:update:alice:u1new:00112233445566778899aabbccddeeff:nonce",
            "ZNS:release:alice:u1owner:00112233445566778899aabbccddeeff:challenge_id",
        ] {
            assert!(
                RequestMemo::parse(&padded(text)).is_err(),
                "accepted {text}"
            );
        }
    }








}
