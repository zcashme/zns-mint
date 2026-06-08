//! ZNS memo parser.
//!
//! Parses the canonical ZNS memo grammar from DESIGN.md §6:
//!
//! ```text
//! "ZNS:claim:alice:u1abcdef..."     → ParsedMemo::Action { action: Claim,   name, ua }
//! "ZNS:update:alice:u1newaddr..."   → ParsedMemo::Action { action: Update,  name, ua }
//! "ZNS:release:alice"               → ParsedMemo::Action { action: Release, name, ua: "" }
//! "ZNS:confirm:alice:<nonce>"       → ParsedMemo::Confirm { name, nonce }
//! ```

use crate::action::Action;
use crate::error::RegistryError;

/// A fully-parsed ZNS memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedMemo {
    /// A lifecycle action (claim / update / release).
    Action {
        action: Action,
        name: String,
        ua: String,
    },
    /// A confirm note — carries the OTP nonce for UPDATE / RELEASE auth.
    Confirm { name: String, nonce: String },
}

impl ParsedMemo {
    /// Convenience accessor — returns the name string regardless of variant.
    pub fn name(&self) -> &str {
        match self {
            ParsedMemo::Action { name, .. } | ParsedMemo::Confirm { name, .. } => name,
        }
    }
}

/// Parse raw memo bytes into a [`ParsedMemo`].
///
/// The memo may be zero-padded at the end (as per ZIP 302); trailing zero
/// bytes are stripped before parsing.
pub fn parse_memo(raw: &[u8]) -> Result<ParsedMemo, RegistryError> {
    // Strip trailing NUL padding (ZIP 302 §3).
    let trimmed = strip_trailing_zeros(raw);
    let text = std::str::from_utf8(trimmed)
        .map_err(|_| RegistryError::InvalidMemo("non-UTF-8 bytes".into()))?;
    parse_memo_str(text)
}

fn strip_trailing_zeros(b: &[u8]) -> &[u8] {
    let last_non_zero = b.iter().rposition(|&c| c != 0).map(|i| i + 1).unwrap_or(0);
    &b[..last_non_zero]
}

fn parse_memo_str(text: &str) -> Result<ParsedMemo, RegistryError> {
    let parts: Vec<&str> = text.splitn(5, ':').collect();

    if parts.is_empty() || parts[0] != "ZNS" {
        return Err(RegistryError::InvalidMemo(
            "does not start with 'ZNS:'".into(),
        ));
    }

    if parts.len() < 3 {
        return Err(RegistryError::InvalidMemo(
            "too few colon-separated fields".into(),
        ));
    }

    let verb = parts[1];
    let name = parts[2].to_owned();

    validate_name(&name)?;

    match verb {
        "claim" | "update" => {
            let ua = parts.get(3).copied().unwrap_or("").to_owned();
            let action = if verb == "claim" {
                Action::Claim
            } else {
                Action::Update
            };
            Ok(ParsedMemo::Action { action, name, ua })
        }
        "release" => {
            // UA field is optional and empty by convention.
            let ua = parts.get(3).copied().unwrap_or("").to_owned();
            Ok(ParsedMemo::Action {
                action: Action::Release,
                name,
                ua,
            })
        }
        "confirm" => {
            let nonce = parts.get(3).copied().unwrap_or("").to_owned();
            if nonce.is_empty() {
                return Err(RegistryError::InvalidMemo("confirm: missing nonce".into()));
            }
            Ok(ParsedMemo::Confirm { name, nonce })
        }
        other => Err(RegistryError::InvalidMemo(format!(
            "unknown verb '{other}'"
        ))),
    }
}

/// Validate a ZNS name: non-empty, ≤ 63 bytes, ASCII lowercase alphanumeric
/// plus hyphens (no leading/trailing hyphen).
fn validate_name(name: &str) -> Result<(), RegistryError> {
    if name.is_empty() {
        return Err(RegistryError::InvalidName(
            name.into(),
            "empty name".into(),
        ));
    }
    if name.len() > 63 {
        return Err(RegistryError::InvalidName(
            name.into(),
            "exceeds 63-byte limit".into(),
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(RegistryError::InvalidName(
            name.into(),
            "leading or trailing hyphen".into(),
        ));
    }
    for c in name.chars() {
        if !matches!(c, 'a'..='z' | '0'..='9' | '-') {
            return Err(RegistryError::InvalidName(
                name.into(),
                format!("invalid character '{c}'"),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Outbound memos (registry → owner)
// ---------------------------------------------------------------------------

/// The verb the registry uses to relay an OTP nonce to a name's current owner
/// for UPDATE / RELEASE. The owner echoes it back as `ZNS:confirm:<name>:<nonce>`
/// (see [`ParsedMemo::Confirm`]). This closes the auth loop: without sending
/// this memo the owner never learns the nonce and can never confirm.
pub const CHALLENGE_VERB: &str = "challenge";

/// The fixed ZIP-302 memo size, in bytes.
pub const MEMO_SIZE: usize = 512;

/// Build the outbound OTP challenge memo: `ZNS:challenge:<name>:<nonce>`.
pub fn encode_challenge(name: &str, nonce: &str) -> String {
    format!("ZNS:{CHALLENGE_VERB}:{name}:{nonce}")
}

/// Encode memo `text` into a fixed [`MEMO_SIZE`]-byte, zero-padded ZIP-302 memo.
///
/// Returns [`RegistryError::InvalidMemo`] if the text does not fit.
pub fn encode_memo_bytes(text: &str) -> Result<[u8; MEMO_SIZE], RegistryError> {
    let bytes = text.as_bytes();
    if bytes.len() > MEMO_SIZE {
        return Err(RegistryError::InvalidMemo(format!(
            "memo too long: {} bytes (max {MEMO_SIZE})",
            bytes.len()
        )));
    }
    let mut memo = [0u8; MEMO_SIZE];
    memo[..bytes.len()].copy_from_slice(bytes);
    Ok(memo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_roundtrips_through_padding() {
        let text = encode_challenge("alice", "deadbeef");
        assert_eq!(text, "ZNS:challenge:alice:deadbeef");
        let memo = encode_memo_bytes(&text).unwrap();
        // Parsing the zero-padded form recovers the original string.
        let trimmed = strip_trailing_zeros(&memo);
        assert_eq!(std::str::from_utf8(trimmed).unwrap(), text);
    }

    #[test]
    fn claim() {
        let m = parse_memo_str("ZNS:claim:alice:u1abcdef").unwrap();
        assert_eq!(
            m,
            ParsedMemo::Action {
                action: Action::Claim,
                name: "alice".into(),
                ua: "u1abcdef".into()
            }
        );
    }

    #[test]
    fn update() {
        let m = parse_memo_str("ZNS:update:alice:u1other").unwrap();
        assert_eq!(
            m,
            ParsedMemo::Action {
                action: Action::Update,
                name: "alice".into(),
                ua: "u1other".into()
            }
        );
    }

    #[test]
    fn release() {
        let m = parse_memo_str("ZNS:release:alice").unwrap();
        assert_eq!(
            m,
            ParsedMemo::Action {
                action: Action::Release,
                name: "alice".into(),
                ua: "".into()
            }
        );
    }

    #[test]
    fn confirm() {
        let m = parse_memo_str("ZNS:confirm:alice:abc123").unwrap();
        assert_eq!(
            m,
            ParsedMemo::Confirm {
                name: "alice".into(),
                nonce: "abc123".into()
            }
        );
    }

    #[test]
    fn bad_prefix() {
        assert!(parse_memo_str("ZEC:claim:alice:u1").is_err());
    }

    #[test]
    fn trailing_zeros_stripped() {
        let mut raw = b"ZNS:claim:alice:u1x".to_vec();
        raw.resize(512, 0);
        let m = parse_memo(&raw).unwrap();
        assert!(matches!(m, ParsedMemo::Action { action: Action::Claim, .. }));
    }
}
