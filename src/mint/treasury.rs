//! Treasury wallet view and Treasury policy for the mint.
//!
//! The Treasury is the user-facing account's agent (ZIP-32 account 0): it is
//! everything that account must do, and nothing more. Five responsibilities:
//!
//! 1. **Interpret intake** — claim payments and OTP relay requests arrive as
//!    Ironwood notes owned by the wallet; Treasury decodes their stored memos
//!    (`memo`) and classifies them. Treasury is keyless: it holds no keys and
//!    no notes of its own — not even viewing keys. Every fact it learns flows
//!    through a wallet projection, and every signing capability arrives as a
//!    borrowed argument.
//! 2. **Guarantee payment freshness** — a payment confirmed at or before the
//!    name's current tip is rejected; a payment cannot be reused after a
//!    release/reclaim boundary.
//! 3. **Participate in settlements** — the atomic claim (spend the payment
//!    note, retain the fixed price). OTP relay delivery is a mint-level
//!    concern ([`crate::mint::otp`]): an ordinary upstream-built Treasury
//!    payment to the current controller. Treasury never decides a name's
//!    lifecycle — that is the Registry's.
//! 4. **Deposit to the vault** — when the spendable balance exceeds
//!    the threshold, send the excess to the project vault's transparent
//!    address, retaining a fixed reserve.
//! 5. **Pay Name Note fees** — the Treasury funds the ZIP-317 fee for every
//!    Name Note transaction in a multi-authority bundle with the Registry.

use zcash_keys::address::UnifiedAddress;
use zcash_protocol::consensus::Parameters;

use crate::mint::{Action, Name};

/// Parses a 512-byte memo sent to the Treasury as a ZNS transition request.
///
/// A request memo is `ZNS:<verb>:<name>:<ua>`, where `verb` is `claim`,
/// `update`, or `release`. OTPs are delivered through the separate relay-memo
/// path; request memos never carry an OTP.
///
/// Returns `None` unless the memo's grammar, name, and Unified Address for
/// `network` are all valid. The intake loop then tries
/// [`crate::mint::otp::decode_otp_relay_memo`] for non-request memos.
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

    if fields.next().is_some() {
        return None;
    }

    let ua = match zcash_keys::address::Address::decode(network, ua_str)? {
        zcash_keys::address::Address::Unified(ua) => ua,
        _ => return None,
    };

    let action = match verb {
        "claim" => Action::Claim,
        "update" => Action::Update,
        "release" => Action::Release,
        _ => return None,
    };

    Some((action, name, ua))
}

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
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:update:alice:{TEST_UA}:004206"))
        )
        .is_none());
        assert!(parse_request(
            &network,
            &padded(&format!("ZNS:claim:alice:{TEST_UA}:extra"))
        )
        .is_none());
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
        assert!(
            parse_request(&network, &padded(&format!("ZNS:claim:INVALID:{TEST_UA}"))).is_none()
        );
    }
}
