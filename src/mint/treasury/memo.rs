//! Treasury memo parsing and classification.

use core::fmt;

use crate::mint::Action;

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
    /// `otp` is not exactly six ASCII decimal digits.
    InvalidOtp,
}

/// A parsed, typed request memo sent by a user to the Treasury.
#[derive(Clone)]
pub enum RequestMemo {
    /// A claim request: `ZNS:claim:<name>:<ua>`
    Claim { name: String, ua: String },
    /// An update request: `ZNS:update:<name>:<ua>[:<otp>]`
    Update {
        name: String,
        ua: String,
        otp: Option<[u8; 6]>,
    },
    /// A release request: `ZNS:release:<name>:<ua>[:<otp>]`
    Release {
        name: String,
        ua: String,
        otp: Option<[u8; 6]>,
    },
}

impl PartialEq for RequestMemo {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        match (self, other) {
            (
                Self::Claim { name: l_name, ua: l_ua },
                Self::Claim { name: r_name, ua: r_ua },
            ) => l_name == r_name && l_ua == r_ua,
            (
                Self::Update { name: l_name, ua: l_ua, otp: l_otp },
                Self::Update { name: r_name, ua: r_ua, otp: r_otp },
            ) => {
                if l_name != r_name || l_ua != r_ua {
                    return false;
                }
                match (l_otp, r_otp) {
                    (Some(l), Some(r)) => bool::from(l.ct_eq(r)),
                    (None, None) => true,
                    _ => false,
                }
            }
            (
                Self::Release { name: l_name, ua: l_ua, otp: l_otp },
                Self::Release { name: r_name, ua: r_ua, otp: r_otp },
            ) => {
                if l_name != r_name || l_ua != r_ua {
                    return false;
                }
                match (l_otp, r_otp) {
                    (Some(l), Some(r)) => bool::from(l.ct_eq(r)),
                    (None, None) => true,
                    _ => false,
                }
            }
            _ => false,
        }
    }
}
impl Eq for RequestMemo {}

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

/// Decode an `otp` field: exactly six ASCII decimal digits.
fn decode_otp(s: &str) -> Result<[u8; 6], MemoError> {
    let bytes = s.as_bytes();
    if bytes.len() != 6 {
        return Err(MemoError::InvalidOtp);
    }
    let mut out = [0u8; 6];
    for (i, &b) in bytes.iter().enumerate() {
        if !b.is_ascii_digit() {
            return Err(MemoError::InvalidOtp);
        }
        out[i] = b;
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
    fn accepts_exactly_the_five_request_forms() {
        let otp = "004206";

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
            RequestMemo::parse(&padded(&format!("ZNS:update:alice:u1new:{otp}"))),
            Ok(RequestMemo::Update {
                name: "alice".into(),
                ua: "u1new".into(),
                otp: Some(*b"004206"),
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
            RequestMemo::parse(&padded(&format!("ZNS:release:alice:u1owner:{otp}"))),
            Ok(RequestMemo::Release {
                name: "alice".into(),
                ua: "u1owner".into(),
                otp: Some(*b"004206"),
            })
        );
    }










}
