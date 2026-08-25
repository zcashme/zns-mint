//! Treasury request memo parsing.
//!
//! A request memo is what a user sends to the Treasury to request a ZNS
//! transition. The format is always `ZNS:<verb>:<name>:<ua>` — three
//! colon-separated fields after the `ZNS` prefix. The verb is one of
//! `claim`, `update`, or `release`. No other fields.
//!
//! OTPs are never carried in request memos. When a user wants to update or
//! release, the Mint generates an OTP and sends it via a relay memo
//! (`ZNS:otp:...`, handled by [`crate::mint::otp`]). The controller forwards
//! that relay memo back to the Treasury to authorize the transition.

use zcash_keys::address::UnifiedAddress;
use zcash_protocol::consensus::Parameters;

use crate::mint::{Action, Name};

/// Parses a 512-byte Treasury memo into typed request fields.
///
/// Returns `Some((Action, Name, UnifiedAddress))` on success — all validated
/// at parse time, no re-parsing needed downstream. The network parameter is
/// required to parse the unified address against the correct network type.
///
/// Returns `None` for anything that isn't a valid `ZNS:<verb>:<name>:<ua>`
/// request memo. The intake loop tries [`crate::mint::otp::decode_otp_relay_memo`]
/// next, and if that also returns `None`, marks the note as seen and skips.
///
/// Request memos are exactly `ZNS:<verb>:<name>:<ua>`. Any extra field
/// (including an OTP) is rejected. OTP transitions arrive via the relay memo
/// path, not the request memo.
pub fn parse_request<P: Parameters>(
    network: &P,
    raw: &[u8; 512],
) -> Option<(Action, Name, UnifiedAddress)> {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    if raw[end..].iter().any(|b| *b != 0) {
        return None;
    }
    let text = core::str::from_utf8(&raw[..end]).ok()?;

    let mut fields = text.split(':');
    if fields.next()? != "ZNS" {
        return None;
    }
    let verb = fields.next()?;
    let name_str = fields.next()?;
    let name = Name::parse(name_str)?;

    let ua_str = fields.next()?;
    if ua_str.is_empty() {
        return None;
    }

    // No fifth field — request memos are exactly four fields.
    if fields.next().is_some() {
        return None;
    }

    let ua = parse_ua(network, ua_str)?;

    let action = match verb {
        "claim" => Action::Claim,
        "update" => Action::Update,
        "release" => Action::Release,
        _ => return None,
    };

    Some((action, name, ua))
}

/// Parses a unified address string against the network.
fn parse_ua<P: Parameters>(network: &P, s: &str) -> Option<UnifiedAddress> {
    let zaddr: zcash_address::ZcashAddress = s.parse().ok()?;
    match zaddr.convert_if_network(network.network_type()).ok()? {
        zcash_keys::address::Address::Unified(ua) => Some(ua),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::MainNetwork;

    const TEST_UA: &str = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";

    fn padded(s: &str) -> [u8; 512] {
        let mut m = [0u8; 512];
        m[..s.len()].copy_from_slice(s.as_bytes());
        m
    }

    #[test]
    fn accepts_exactly_the_three_request_forms() {
        let network = MainNetwork;

        let (action, name, _) =
            parse_request(&network, &padded(&format!("ZNS:claim:alice:{TEST_UA}"))).unwrap();
        assert_eq!(action, Action::Claim);
        assert_eq!(name.as_str(), "alice");

        let (action, name, _) =
            parse_request(&network, &padded(&format!("ZNS:update:alice:{TEST_UA}"))).unwrap();
        assert_eq!(action, Action::Update);
        assert_eq!(name.as_str(), "alice");

        let (action, name, _) =
            parse_request(&network, &padded(&format!("ZNS:release:alice:{TEST_UA}"))).unwrap();
        assert_eq!(action, Action::Release);
        assert_eq!(name.as_str(), "alice");
    }

    #[test]
    fn rejects_extra_field() {
        let network = MainNetwork;
        assert!(parse_request(&network, &padded(&format!("ZNS:update:alice:{TEST_UA}:004206"))).is_none());
        assert!(parse_request(&network, &padded(&format!("ZNS:claim:alice:{TEST_UA}:extra"))).is_none());
    }

    #[test]
    fn rejects_unknown_verb() {
        let network = MainNetwork;
        assert!(parse_request(&network, &padded(&format!("ZNS:otp:alice:{TEST_UA}"))).is_none());
    }

    #[test]
    fn rejects_non_zns() {
        let network = MainNetwork;
        assert!(parse_request(&network, &padded("hello world")).is_none());
    }

    #[test]
    fn rejects_invalid_name() {
        let network = MainNetwork;
        assert!(parse_request(&network, &padded(&format!("ZNS:claim:INVALID:{TEST_UA}"))).is_none());
    }
}