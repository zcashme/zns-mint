//! ZNS memo parser — the registry's independent implementation of the
//! canonical grammar.
//!
//! Like the `(ψ, rcm)` derivation (see `crate::action`), this deliberately
//! does not depend on `zns-verify`'s parser: producer and consumer keep
//! separate implementations of the spec so a bug in one is caught by the
//! other. The *semantics* must be byte-identical — the grammar is **strict**
//! (exact field counts; extra or empty fields reject; DNS-label names), and
//! the divergence tests below mirror the kernel's.
//!
//! ```text
//! "ZNS:claim:alice:u1abc…"           → Action { Claim,   name, ua, prev_rcm: None }
//! "ZNS:update:alice:u1new…"          → Action { Update,  name, ua, prev_rcm: None }
//! "ZNS:release:alice"                → Action { Release, name, "", prev_rcm: None }
//! "ZNS:claim:alice:u1abc…:<hex64>"   → Action { …, prev_rcm: Some(…) }  (Name Note form)
//! "ZNS:release:alice::<hex64>"       → Action { …, prev_rcm: Some(…) }  (ua positional)
//! "ZNS:challenge:alice:<nonce>"      → Challenge { name, nonce }
//! "ZNS:confirm:alice:<nonce>"        → Confirm { name, nonce }
//! ```
//!
//! A memo carrying `prev_rcm` is the **registry's own** Name Note canonical
//! form (DESIGN.md §6) — never a user request. The daemon skips those on
//! rescan instead of treating them as actions to mint.

use crate::action::Action;
use crate::error::MemoError;

/// A fully-parsed ZNS memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedMemo {
    /// A lifecycle action (claim / update / release). `prev_rcm` is present
    /// exactly in the Name Note canonical form (registry-authored).
    Action {
        action: Action,
        name: String,
        ua: String,
        prev_rcm: Option<[u8; 32]>,
    },
    /// The registry's outbound OTP challenge (`ZNS:challenge:<name>:<nonce>`).
    Challenge { name: String, nonce: String },
    /// A confirm note — carries the OTP nonce for UPDATE / RELEASE auth.
    Confirm { name: String, nonce: String },
}

impl ParsedMemo {
    /// Convenience accessor — returns the name string regardless of variant.
    pub fn name(&self) -> &str {
        match self {
            ParsedMemo::Action { name, .. }
            | ParsedMemo::Challenge { name, .. }
            | ParsedMemo::Confirm { name, .. } => name,
        }
    }
}

/// Parse raw memo bytes into a [`ParsedMemo`].
///
/// The memo may be zero-padded at the end (as per ZIP 302); trailing zero
/// bytes are stripped before parsing.
pub fn parse_memo(raw: &[u8]) -> Result<ParsedMemo, MemoError> {
    // Strip trailing NUL padding (ZIP 302 §3).
    let trimmed = strip_trailing_zeros(raw);
    let text = std::str::from_utf8(trimmed)
        .map_err(|_| MemoError::InvalidMemo("non-UTF-8 bytes".into()))?;
    parse_memo_str(text)
}

fn strip_trailing_zeros(b: &[u8]) -> &[u8] {
    let last_non_zero = b.iter().rposition(|&c| c != 0).map(|i| i + 1).unwrap_or(0);
    &b[..last_non_zero]
}

fn parse_memo_str(text: &str) -> Result<ParsedMemo, MemoError> {
    // `split` (never `splitn`): strictness is load-bearing — a lenient parser
    // that absorbs or ignores trailing fields would read a different `ua`
    // from the same memo than the verification kernel does.
    let parts: Vec<&str> = text.split(':').collect();

    if parts[0] != "ZNS" {
        return Err(MemoError::InvalidMemo("does not start with 'ZNS:'".into()));
    }
    if parts.len() < 3 || parts.len() > 5 {
        return Err(MemoError::InvalidMemo(format!(
            "wrong field count: {}",
            parts.len()
        )));
    }

    let verb = parts[1];
    let name = parts[2].to_owned();
    validate_name(&name)?;

    // A fifth field is always the Name Note form's prev_rcm witness.
    let prev_rcm = parts.get(4).map(|s| decode_prev_rcm(s)).transpose()?;
    let arg = |what: &str| -> Result<String, MemoError> {
        match parts.get(3) {
            Some(&"") | None => Err(MemoError::InvalidMemo(format!("missing {what}"))),
            Some(a) => Ok((*a).to_owned()),
        }
    };

    match verb {
        "claim" | "update" => {
            let action = if verb == "claim" {
                Action::Claim
            } else {
                Action::Update
            };
            Ok(ParsedMemo::Action {
                action,
                name,
                ua: arg("ua")?,
                prev_rcm,
            })
        }
        "release" => match (parts.len(), prev_rcm) {
            // Request form: exactly three fields.
            (3, None) => Ok(ParsedMemo::Action {
                action: Action::Release,
                name,
                ua: String::new(),
                prev_rcm: None,
            }),
            // Name Note form: positional empty ua, then the witness.
            (5, Some(_)) if parts[3].is_empty() => Ok(ParsedMemo::Action {
                action: Action::Release,
                name,
                ua: String::new(),
                prev_rcm,
            }),
            _ => Err(MemoError::InvalidMemo("release: wrong field count".into())),
        },
        "challenge" if prev_rcm.is_none() => Ok(ParsedMemo::Challenge {
            name,
            nonce: arg("nonce")?,
        }),
        "confirm" if prev_rcm.is_none() => Ok(ParsedMemo::Confirm {
            name,
            nonce: arg("nonce")?,
        }),
        "challenge" | "confirm" => {
            Err(MemoError::InvalidMemo(format!("{verb}: wrong field count")))
        }
        other => Err(MemoError::InvalidMemo(format!("unknown verb '{other}'"))),
    }
}

/// Decode a `prev_rcm` field: exactly 64 lowercase hex chars.
fn decode_prev_rcm(s: &str) -> Result<[u8; 32], MemoError> {
    let bad = || MemoError::InvalidMemo("prev_rcm: not 64 lowercase hex chars".into());
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(bad());
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(bad()),
    };
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

/// Validate a ZNS name: non-empty, ≤ 63 bytes, ASCII lowercase alphanumeric
/// plus hyphens (no leading/trailing hyphen) — the DNS-label rule, byte-
/// identical to the kernel's (`zns_verify::memo::validate_name`).
///
/// This is the **authoritative producer-side validator**: the signer's policy
/// gate delegates here, so the parser and the gate can never disagree about
/// which names exist.
pub fn validate_name(name: &str) -> Result<(), MemoError> {
    if name.is_empty() {
        return Err(MemoError::InvalidName(name.into(), "empty name".into()));
    }
    if name.len() > 63 {
        return Err(MemoError::InvalidName(
            name.into(),
            "exceeds 63-byte limit".into(),
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(MemoError::InvalidName(
            name.into(),
            "leading or trailing hyphen".into(),
        ));
    }
    for c in name.chars() {
        if !matches!(c, 'a'..='z' | '0'..='9' | '-') {
            return Err(MemoError::InvalidName(
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

/// Build the canonical memo the registry writes into a Name Note it mints:
/// `ZNS:<verb>:<name>:<ua>:<prev_rcm_hex>` (DESIGN.md §6), zero-padded to
/// [`MEMO_SIZE`]. RELEASE keeps `ua` positional and explicitly empty, so
/// `prev_rcm` never shifts columns.
///
/// The disclosed `prev_rcm` is the chain-link *witness*: the commitment
/// already binds it as a hash input, so publishing it lets any scanner verify
/// this single note's binding standalone — no reconstructed chain required.
/// That is what makes the wallet tail-scan backstop and single-note fraud
/// proofs work against a withholding resolver (DESIGN.md §19.4, §12).
pub fn encode_name_note(
    action: Action,
    name: &str,
    ua: &str,
    prev_rcm: &[u8; 32],
) -> Result<[u8; MEMO_SIZE], MemoError> {
    validate_name(name)?;
    // Unreachable from the inbound parser (it can't produce a ua containing
    // the field separator), but this is the canonical memo — keep the
    // invariant local rather than inherited.
    if ua.contains(':') {
        return Err(MemoError::InvalidMemo(
            "ua contains the field separator ':'".into(),
        ));
    }
    let verb = match action {
        Action::Claim => "claim",
        Action::Update => "update",
        Action::Release => "release",
    };
    let hex: String = prev_rcm.iter().map(|b| format!("{b:02x}")).collect();
    encode_memo_bytes(&format!("ZNS:{verb}:{name}:{ua}:{hex}"))
}

/// Encode memo `text` into a fixed [`MEMO_SIZE`]-byte, zero-padded ZIP-302 memo.
///
/// Returns [`MemoError::InvalidMemo`] if the text does not fit.
pub fn encode_memo_bytes(text: &str) -> Result<[u8; MEMO_SIZE], MemoError> {
    let bytes = text.as_bytes();
    if bytes.len() > MEMO_SIZE {
        return Err(MemoError::InvalidMemo(format!(
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
    fn name_note_memo_is_canonical() {
        let memo = encode_name_note(Action::Claim, "alice", "u1xxx", &[0u8; 32]).unwrap();
        let text = std::str::from_utf8(strip_trailing_zeros(&memo)).unwrap();
        assert_eq!(
            text,
            "ZNS:claim:alice:u1xxx:0000000000000000000000000000000000000000000000000000000000000000"
        );
        // RELEASE keeps the ua column, explicitly empty.
        let memo = encode_name_note(Action::Release, "alice", "", &[0xa5u8; 32]).unwrap();
        let text = std::str::from_utf8(strip_trailing_zeros(&memo)).unwrap();
        assert_eq!(
            text,
            "ZNS:release:alice::a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"
        );
    }

    #[test]
    fn challenge_roundtrips_through_padding() {
        let text = encode_challenge("alice", "deadbeef");
        assert_eq!(text, "ZNS:challenge:alice:deadbeef");
        let memo = encode_memo_bytes(&text).unwrap();
        // Parsing the zero-padded form recovers the original string.
        let trimmed = strip_trailing_zeros(&memo);
        assert_eq!(std::str::from_utf8(trimmed).unwrap(), text);
    }

    fn action(a: Action, name: &str, ua: &str, prev_rcm: Option<[u8; 32]>) -> ParsedMemo {
        ParsedMemo::Action {
            action: a,
            name: name.into(),
            ua: ua.into(),
            prev_rcm,
        }
    }

    #[test]
    fn claim() {
        let m = parse_memo_str("ZNS:claim:alice:u1abcdef").unwrap();
        assert_eq!(m, action(Action::Claim, "alice", "u1abcdef", None));
    }

    #[test]
    fn update() {
        let m = parse_memo_str("ZNS:update:alice:u1other").unwrap();
        assert_eq!(m, action(Action::Update, "alice", "u1other", None));
    }

    #[test]
    fn release() {
        let m = parse_memo_str("ZNS:release:alice").unwrap();
        assert_eq!(m, action(Action::Release, "alice", "", None));
    }

    #[test]
    fn confirm_and_challenge() {
        let m = parse_memo_str("ZNS:confirm:alice:abc123").unwrap();
        assert_eq!(
            m,
            ParsedMemo::Confirm {
                name: "alice".into(),
                nonce: "abc123".into()
            }
        );
        let m = parse_memo_str("ZNS:challenge:alice:abc123").unwrap();
        assert_eq!(
            m,
            ParsedMemo::Challenge {
                name: "alice".into(),
                nonce: "abc123".into()
            }
        );
    }

    #[test]
    fn name_note_form_round_trips() {
        // The registry's own canonical memo parses back, witness intact —
        // the daemon uses `prev_rcm: Some(_)` to skip its own notes on rescan.
        let prev = [0xa5u8; 32];
        let memo = encode_name_note(Action::Update, "alice", "u1new", &prev).unwrap();
        let m = parse_memo(&memo).unwrap();
        assert_eq!(m, action(Action::Update, "alice", "u1new", Some(prev)));

        let memo = encode_name_note(Action::Release, "alice", "", &prev).unwrap();
        let m = parse_memo(&memo).unwrap();
        assert_eq!(m, action(Action::Release, "alice", "", Some(prev)));
    }

    #[test]
    fn bad_prefix() {
        assert!(parse_memo_str("ZEC:claim:alice:u1").is_err());
    }

    /// Mirrors the kernel parser's strictness tests (`zns_verify::memo`) —
    /// the two implementations are independent but must agree byte-for-byte.
    #[test]
    fn strict_field_counts_match_the_kernel() {
        // Trailing junk is never absorbed into `ua` nor silently ignored.
        assert!(parse_memo_str("ZNS:update:alice:u1x:extra").is_err());
        assert!(parse_memo_str("ZNS:release:alice:junk").is_err());
        assert!(parse_memo_str("ZNS:release:alice:").is_err());
        assert!(parse_memo_str("ZNS:claim:alice").is_err());
        assert!(parse_memo_str("ZNS:claim:alice:").is_err());
        assert!(parse_memo_str("ZNS:confirm:alice").is_err());
        assert!(parse_memo_str("ZNS:claim").is_err());
        assert!(parse_memo_str("ZNS:settle:alice:u1x").is_err());
        // The witness must be exactly 64 lowercase hex chars.
        assert!(parse_memo_str("ZNS:claim:alice:u1x:abcd").is_err());
        let upper = format!("ZNS:claim:alice:u1x:{}", "A".repeat(64));
        assert!(parse_memo_str(&upper).is_err());
        // Auth verbs never take a fifth field.
        let extra = format!("ZNS:confirm:alice:nonce:{}", "a".repeat(64));
        assert!(parse_memo_str(&extra).is_err());
    }

    #[test]
    fn trailing_zeros_stripped() {
        let mut raw = b"ZNS:claim:alice:u1x".to_vec();
        raw.resize(512, 0);
        let m = parse_memo(&raw).unwrap();
        assert!(matches!(
            m,
            ParsedMemo::Action {
                action: Action::Claim,
                ..
            }
        ));
    }
}
