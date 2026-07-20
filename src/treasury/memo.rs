//! Treasury memo parsing and classification.

pub use crate::mint::Action;

/// Why a memo failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoError {
    /// Not a ZNS memo at all (no `ZNS:` prefix, or not UTF-8).
    NotZns,
    /// A `ZNS:` memo with an unknown verb.
    UnknownVerb,
    /// Wrong number of `:`-separated fields for the verb.
    FieldCount,
    /// The name violates the DNS-label rule.
    InvalidName,
    /// A required argument (`ua` or `nonce`) is empty.
    EmptyArg,
    /// `otp` is not exactly 32 lowercase hex chars.
    InvalidOtp,
}

/// A parsed, typed request memo sent by a user to the Treasury.
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl RequestMemo {
    /// Returns the action type for this request.
    pub fn action(&self) -> Action {
        match self {
            RequestMemo::Claim { .. } => Action::Claim,
            RequestMemo::Update { .. } => Action::Update,
            RequestMemo::Release { .. } => Action::Release,
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

    /// Parses a raw 512-byte request memo using strict grammar rules.
    pub fn parse(raw: &[u8]) -> Result<Self, MemoError> {
        let end = raw.iter().rposition(|b| *b != 0).map_or(0, |p| p + 1);
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
    fn parses_otp_field() {
        let hex = "00112233445566778899aabbccddeeff";
        let m = format!("ZNS:update:alice:u1new:{hex}");
        let mut otp = [0u8; 16];
        hex::decode_to_slice(hex, &mut otp).unwrap();
        assert_eq!(
            RequestMemo::parse(&padded(&m)),
            Ok(RequestMemo::Update {
                name: "alice".into(),
                ua: "u1new".into(),
                otp: Some(otp)
            })
        );
    }

    #[test]
    fn strict_field_counts_and_validation() {
        assert_eq!(
            RequestMemo::parse(&padded("ZNS:claim:alice")),
            Err(MemoError::FieldCount)
        );
        assert_eq!(
            RequestMemo::parse(&padded("ZNS:claim:alice:")),
            Err(MemoError::EmptyArg)
        );
        assert_eq!(
            RequestMemo::parse(&padded("ZNS:settle:alice:u1x")),
            Err(MemoError::UnknownVerb)
        );

        // Invalid names
        assert_eq!(
            RequestMemo::parse(&padded("ZNS:claim:Alice:u1x")),
            Err(MemoError::InvalidName)
        );
        assert_eq!(
            RequestMemo::parse(&padded("ZNS:claim:-alice:u1x")),
            Err(MemoError::InvalidName)
        );
    }

    #[test]
    fn non_zns_memos_are_not_zns() {
        assert_eq!(
            RequestMemo::parse(&padded("just a payment note")),
            Err(MemoError::NotZns)
        );
        assert_eq!(
            RequestMemo::parse(&padded("ZEC:claim:alice:u1")),
            Err(MemoError::NotZns)
        );
    }
}
