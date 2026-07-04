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
        validate_name(name)?;

        let ua = fields.next().ok_or(MemoError::FieldCount)?;
        if ua.is_empty() {
            return Err(MemoError::EmptyArg);
        }

        let otp_str = fields.next();
        if fields.next().is_some() {
            return Err(MemoError::FieldCount);
        }

        let otp = match otp_str {
            Some(s) => Some(decode_otp(s)?),
            None => None,
        };

        match verb {
            "claim" => {
                if otp.is_some() {
                    return Err(MemoError::FieldCount);
                }
                Ok(RequestMemo::Claim {
                    name: name.to_string(),
                    ua: ua.to_string(),
                })
            }
            "update" => Ok(RequestMemo::Update {
                name: name.to_string(),
                ua: ua.to_string(),
                otp,
            }),
            "release" => Ok(RequestMemo::Release {
                name: name.to_string(),
                ua: ua.to_string(),
                otp,
            }),
            _ => Err(MemoError::UnknownVerb),
        }
    }
}

/// Validate a ZNS name: 1 to 63 bytes of `a-z 0-9 -`, with no
/// leading or trailing hyphen (the DNS-label rule).
fn validate_name(name: &str) -> Result<(), MemoError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return Err(MemoError::InvalidName);
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return Err(MemoError::InvalidName);
    }
    if !bytes
        .iter()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(MemoError::InvalidName);
    }
    Ok(())
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
