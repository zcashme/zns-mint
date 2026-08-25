//! Transition authorization: validates requests against the name-chain state
//! and produces typed [`NameNoteRequest`]s for the transaction-assembly path.
//! The OTP challenges those requests authorize with live in
//! [`crate::mint::otp`].

use time::Timestamp;
use crate::mint::otp::OtpQueue;
use crate::mint::{Action, Expiry, Name, NameCommitment, UnifiedAddress};
use zcash_protocol::consensus::Parameters;
use crate::mint::registry::{Registry, Record};

// ---------------------------------------------------------------------------
// Transition requests
// ---------------------------------------------------------------------------

/// A requested Name Note transition, ready for the transaction-assembly path.
///
/// Produced by the authorization functions after verifying the policy (name
/// availability, valid OTP, chain rules). Represents the cryptographically
/// approved intent to originate or terminate a shielded note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameNoteRequest {
    Claim(ClaimRequest),
    Update(UpdateRequest),
    Release(ReleaseRequest),
}

impl NameNoteRequest {
    pub fn action(&self) -> Action {
        match self {
            Self::Claim(_) => Action::Claim,
            Self::Update(_) => Action::Update,
            Self::Release(_) => Action::Release,
        }
    }

    pub fn name(&self) -> &Name {
        match self {
            Self::Claim(b) => &b.name,
            Self::Update(b) => &b.name,
            Self::Release(b) => &b.name,
        }
    }
}

/// Request for a new name claim (no previous commitment exists).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRequest {
    pub name: Name,
    pub ua: UnifiedAddress,
    /// The committed expiration (§4.5.1). Until term-request plumbing
    /// exists in the intake path, claims register without fixed expiration.
    pub expires_at: Expiry,
}

/// Request to update an existing name (requires previous commitment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRequest {
    pub name: Name,
    pub new_ua: UnifiedAddress,
    /// The carried-forward expiration (§4.5.3: an ordinary update MUST NOT
    /// change the registration period). Extension requests arrive as terms
    /// elsewhere; this field holds the resulting value.
    pub expires_at: Expiry,
    pub prev_commitment: NameCommitment,
}

/// Request to release an existing name (requires previous commitment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseRequest {
    pub name: Name,
    pub prev_commitment: NameCommitment,
}

/// Reads the current record of the name chain for `name`.
pub fn current_record(registry: &Registry, name: &Name) -> Option<Record> {
    registry.record(name).cloned()
}

/// Authorizes a claim request, producing a [`NameNoteRequest`].
///
/// The Treasury layer must have already verified that the claim payment was
/// made. This function verifies that the name is available (either no record,
/// or record is `Release`).
pub fn authorize_claim(
    registry: &Registry,
    name: Name,
    ua: UnifiedAddress,
) -> Option<NameNoteRequest> {
    match current_record(registry, &name) {
        None => Some(NameNoteRequest::Claim(ClaimRequest { name, ua, expires_at: Expiry::Never })),
        Some(Record {
            action: Action::Release,
            ..
        }) => Some(NameNoteRequest::Claim(ClaimRequest { name, ua, expires_at: Expiry::Never })),
        Some(_) => None, // Name is already live
    }
}

/// Authorizes an update request, producing a [`NameNoteRequest`].
///
/// Verifies the name is live and consumes an OTP bound to its exact current
/// predecessor commitment.
pub fn authorize_update(
    registry: &Registry,
    otp_queue: &mut OtpQueue,
    mtp: Timestamp,
    name: Name,
    new_ua: UnifiedAddress,
    otp: &[u8; 6],
) -> Option<NameNoteRequest> {
    let record = current_record(registry, &name)?;
    if record.action == Action::Release {
        return None;
    }

    if !otp_queue.verify_and_burn(&name, Action::Update, &new_ua, otp, mtp) {
        return None;
    }

    Some(NameNoteRequest::Update(UpdateRequest {
        name,
        new_ua,
        expires_at: record.expires_at,
        prev_commitment: record.commitment,
    }))
}

/// Authorizes a release request, producing a [`NameNoteRequest`].
///
/// Verifies the name is live and consumes an OTP bound to its exact current
/// predecessor commitment.
pub fn authorize_release(
    registry: &Registry,
    otp_queue: &mut OtpQueue,
    mtp: Timestamp,
    name: Name,
    current_ua: UnifiedAddress,
    otp: &[u8; 6],
) -> Option<NameNoteRequest> {
    let record = current_record(registry, &name)?;
    if record.action == Action::Release {
        return None;
    }

    let Some(controller) = &record.ua else {
        return None; // released bindings have no controller
    };
    if controller != &current_ua {
        return None;
    }
    if !otp_queue.verify_and_burn(&name, Action::Release, &current_ua, otp, mtp) {
        return None;
    }

    Some(NameNoteRequest::Release(ReleaseRequest {
        name,
        prev_commitment: record.commitment,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::NameCommitment;
    use crate::mint::otp::{OtpCode, OtpQueue, OtpRequest, encode_otp_relay_memo};
    use time::{Duration, Timestamp};
    

    fn mock_registry() -> Registry {
        Registry::new()
    }

    fn dummy_commitment() -> NameCommitment {
        let mut b = [0u8; 32];
        b[0] = 1;
        NameCommitment::from_bytes(&b).unwrap()
    }

    fn mock_otp_queue() -> OtpQueue {
        OtpQueue::new()
    }

    fn mock_ua() -> UnifiedAddress {
        crate::mint::NameNote::parse_ua(&MAIN_NETWORK, TEST_UA).expect("vector UA")
    }

    const TEST_UA: &str = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";
    use zcash_protocol::consensus::MAIN_NETWORK;
    use zcash_protocol::consensus::BlockHeight;

    fn dummy_rho() -> orchard::note::Rho {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        orchard::note::Rho::from_bytes(&bytes).into_option().unwrap()
    }

    #[test]
    fn claim_fits_unseen_or_released_name() {
        let mut reg = mock_registry();
        let name = Name::parse("alice").unwrap();
        let ua = mock_ua();
        let height = BlockHeight::from_u32(100);

        // Unseen name is claimable
        let req = authorize_claim(&reg, name.clone(), ua.clone()).unwrap();
        assert_eq!(req.action(), Action::Claim);

        // Released name is claimable
        reg.set_record_for_test(name.clone(), Action::Release, None, crate::mint::Expiry::Never, dummy_commitment(), height, dummy_rho());
        let req2 = authorize_claim(&reg, name.clone(), ua.clone()).unwrap();
        assert_eq!(req2.action(), Action::Claim);

        // Live name is NOT claimable
        reg.set_record_for_test(name.clone(), Action::Claim, Some(ua.clone()), crate::mint::Expiry::Never, dummy_commitment(), height, dummy_rho());
        assert!(authorize_claim(&reg, name, ua).is_none());
    }

    #[test]
    fn update_release_need_live_record() {
        let mut reg = mock_registry();
        let mut otps = mock_otp_queue();
        let name = Name::parse("bob").unwrap();
        let ua = mock_ua();
        let now = Timestamp::now();

        let dummy_otp = *b"000000";
        // Unseen name cannot be updated/released
        assert!(authorize_update(
            &reg, &mut otps, now, name.clone(), ua.clone(), &dummy_otp
        ).is_none());
        assert!(authorize_release(
            &reg, &mut otps, now, name.clone(), ua.clone(), &dummy_otp
        ).is_none());

        // Released name cannot be updated/released
        reg.set_record_for_test(name.clone(), Action::Release, None, crate::mint::Expiry::Never, dummy_commitment(), BlockHeight::from_u32(100), dummy_rho());
        assert!(authorize_update(
            &reg, &mut otps, now, name.clone(), ua.clone(), &dummy_otp
        ).is_none());
        assert!(authorize_release(
            &reg, &mut otps, now, name.clone(), ua.clone(), &dummy_otp
        ).is_none());
    }

    #[test]
    fn update_extends_update_tip_with_valid_otp() {
        let mut reg = mock_registry();
        let mut otps = mock_otp_queue();
        let name = Name::parse("carol").unwrap();
        let ua = mock_ua();
        let now = Timestamp::now();

        reg.set_record_for_test(name.clone(), Action::Update, Some(ua.clone()), crate::mint::Expiry::Never, dummy_commitment(), BlockHeight::from_u32(100), dummy_rho());

        // Invalid OTP fails
        let mut bad_otp = *b"000000";
        bad_otp[0] = b'X';
        assert!(
            authorize_update(&reg, &mut otps, now, name.clone(), ua.clone(), &bad_otp).is_none()
        );

        // Issue real OTP and it succeeds
        let issued_otp = OtpCode::generate();
        let real_otp = issued_otp.expose_for_test();
        otps.push(OtpRequest {
            name: Name::parse("carol").unwrap(),
            action: Action::Update,
            ua: mock_ua(),
            code: OtpCode::for_test(real_otp),
            expires_at: now + Duration::seconds(crate::mint::otp::D_OTP),
        });
        let req = authorize_update(&reg, &mut otps, now, name.clone(), ua, &real_otp).unwrap();
        assert_eq!(req.action(), Action::Update);
    }

    #[test]
    fn relay_memo_is_not_a_request_memo() {
        // OTP relay memos use verb "otp", which is not a valid request verb.
        // treasury::memo::RequestMemo::parse must reject them.
        let name = Name::parse("alice").unwrap();
        let ua = mock_ua();
        let otp = OtpCode::for_test(*b"123456");

        let memo = encode_otp_relay_memo(&MAIN_NETWORK, &name, Action::Update, &ua, &otp).unwrap();
        let result = crate::mint::treasury::memo::RequestMemo::parse(&memo);
        assert!(
            result.is_err(),
            "relay memo must not parse as a request memo"
        );
    }
}

/// Validates a transition request (update or release with OTP), reserves the name,
/// authorizes the transition, and assembles the transaction.
/// Returns `None` if the request is invalid, the name is locked, or authorization fails.
#[allow(clippy::too_many_arguments)]
pub fn process_transition<P: Parameters>(
    network: &P,
    name: Name,
    action: Action,
    ua: UnifiedAddress,
    otp: &[u8; 6],
    record_commitment: NameCommitment,
    mtp: Timestamp,
    anchor_height: zcash_protocol::consensus::BlockHeight,
    target_height: zcash_protocol::consensus::BlockHeight,
    excluded: &std::collections::BTreeSet<crate::wallet::NoteLocator>,
    wallet: &mut crate::wallet::Wallet,
    registry: &Registry,
    registry_keys: &crate::key::RegistryKeys,
    mint: &mut crate::mint::MintState,
) -> Option<crate::mint::RequestOutcome> {
    use crate::mint::{SubmissionKind, RequestOutcome};

    if mint.is_name_locked(&name) {
        return None;
    }
    let name_binding = mint.name_binding(&name, Some(record_commitment));

    let req = match action {
        Action::Update => authorize_update(registry, &mut mint.otp_queue, mtp, name, ua, otp),
        Action::Release => authorize_release(registry, &mut mint.otp_queue, mtp, name, ua, otp),
        Action::Claim => unreachable!(),
    };

    match req {
        None => None,
        Some(r) => {
            let result = crate::mint::registry::transaction::execute_transition(
                network,
                wallet,
                registry,
                registry_keys,
                r,
                excluded,
                anchor_height,
                target_height,
            )
            .map(|(txid, hex, notes)| {
                let kind = match action {
                    Action::Update => SubmissionKind::Update,
                    Action::Release => SubmissionKind::Release,
                    _ => unreachable!(),
                };
                (kind, txid, hex, notes)
            });
            Some(RequestOutcome {
                result,
                name_binding: Some(name_binding),
                relay_otp: None,
            })
        }
    }
}
