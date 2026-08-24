//! Transition authorization: validates requests against the name-chain state
//! and produces typed [`NameNoteRequest`]s for the transaction-assembly path.

use crate::mint::{Action, Name, NameCommitment, UnifiedAddress};
use crate::registry::{Registry, Record};

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
}

/// Request to update an existing name (requires previous commitment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRequest {
    pub name: Name,
    pub new_ua: UnifiedAddress,
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
        None => Some(NameNoteRequest::Claim(ClaimRequest { name, ua })),
        Some(Record {
            action: Action::Release,
            ..
        }) => Some(NameNoteRequest::Claim(ClaimRequest { name, ua })),
        Some(_) => None, // Name is already live
    }
}

/// Authorizes an update request, producing a [`NameNoteRequest`].
///
/// Verifies the name is live and consumes an OTP bound to its exact current
/// predecessor commitment.
pub fn authorize_update(
    registry: &Registry,
    pending_otps: &mut crate::auth::PendingOtps,
    current_height: zcash_protocol::consensus::BlockHeight,
    name: Name,
    new_ua: UnifiedAddress,
    otp: &[u8; 16],
) -> Option<NameNoteRequest> {
    let record = current_record(registry, &name)?;
    if record.action == Action::Release {
        return None;
    }

    let key = crate::auth::ChallengeKey::new(
        name.clone(),
        Action::Update,
        new_ua.clone(),
        record.commitment,
    );
    if !pending_otps.verify(&key, otp, current_height) {
        return None;
    }

    Some(NameNoteRequest::Update(UpdateRequest {
        name,
        new_ua,
        prev_commitment: record.commitment,
    }))
}

/// Authorizes a release request, producing a [`NameNoteRequest`].
///
/// Verifies the name is live and consumes an OTP bound to its exact current
/// predecessor commitment.
pub fn authorize_release(
    registry: &Registry,
    pending_otps: &mut crate::auth::PendingOtps,
    current_height: zcash_protocol::consensus::BlockHeight,
    name: Name,
    current_ua: UnifiedAddress,
    otp: &[u8; 16],
) -> Option<NameNoteRequest> {
    let record = current_record(registry, &name)?;
    if record.action == Action::Release {
        return None;
    }

    let controller = &record.ua;
    if controller != &current_ua {
        return None;
    }
    let key = crate::auth::ChallengeKey::new(
        name.clone(),
        Action::Release,
        controller.clone(),
        record.commitment,
    );
    if !pending_otps.verify(&key, otp, current_height) {
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
    use zcash_protocol::consensus::BlockHeight;

    fn mock_registry() -> Registry {
        Registry::new()
    }

    fn dummy_commitment() -> NameCommitment {
        let mut b = [0u8; 32];
        b[0] = 1;
        NameCommitment::from_bytes(&b).unwrap()
    }

    fn mock_pending_otps() -> crate::auth::PendingOtps {
        crate::auth::PendingOtps::new()
    }

    fn dummy_rho() -> orchard::note::Rho {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        orchard::note::Rho::from_bytes(&bytes).into_option().unwrap()
    }

    #[test]
    fn claim_fits_unseen_or_released_name() {
        let mut reg = mock_registry();
        let name = Name::parse("alice").unwrap();
        let ua = UnifiedAddress::from_string("u1xxx".into());
        let height = BlockHeight::from_u32(100);

        // Unseen name is claimable
        let req = authorize_claim(&reg, name.clone(), ua.clone()).unwrap();
        assert_eq!(req.action(), Action::Claim);

        // Released name is claimable
        reg.set_record_for_test(name.clone(), Action::Release, UnifiedAddress::empty(), dummy_commitment(), height, dummy_rho());
        let req2 = authorize_claim(&reg, name.clone(), ua.clone()).unwrap();
        assert_eq!(req2.action(), Action::Claim);

        // Live name is NOT claimable
        reg.set_record_for_test(name.clone(), Action::Claim, ua.clone(), dummy_commitment(), height, dummy_rho());
        assert!(authorize_claim(&reg, name, ua).is_none());
    }

    #[test]
    fn update_release_need_live_record() {
        let mut reg = mock_registry();
        let mut otps = mock_pending_otps();
        let name = Name::parse("bob").unwrap();
        let ua = UnifiedAddress::from_string("u1new".into());
        let height = BlockHeight::from_u32(100);

        let dummy_otp = [0u8; 16];
        // Unseen name cannot be updated/released
        assert!(authorize_update(
            &reg,
            &mut otps,
            height,
            name.clone(),
            ua.clone(),
            &dummy_otp
        )
        .is_none());
        assert!(authorize_release(
            &reg,
            &mut otps,
            height,
            name.clone(),
            ua.clone(),
            &dummy_otp
        )
        .is_none());

        // Released name cannot be updated/released
        reg.set_record_for_test(name.clone(), Action::Release, UnifiedAddress::empty(), dummy_commitment(), height, dummy_rho());
        assert!(authorize_update(
            &reg,
            &mut otps,
            height,
            name.clone(),
            ua.clone(),
            &dummy_otp
        )
        .is_none());
        assert!(authorize_release(
            &reg,
            &mut otps,
            height,
            name.clone(),
            ua.clone(),
            &dummy_otp
        )
        .is_none());
    }

    #[test]
    fn update_extends_update_tip_with_valid_otp() {
        let mut reg = mock_registry();
        let mut otps = mock_pending_otps();
        let name = Name::parse("carol").unwrap();
        let ua = UnifiedAddress::from_string("u1new".into());
        let height = BlockHeight::from_u32(100);

        reg.set_record_for_test(name.clone(), Action::Update, ua.clone(), dummy_commitment(), height, dummy_rho());

        // Invalid OTP fails
        let mut bad_otp = [0u8; 16];
        bad_otp[0] = 0xFF;
        assert!(
            authorize_update(&reg, &mut otps, height, name.clone(), ua.clone(), &bad_otp).is_none()
        );

        // Issue real OTP and it succeeds
        let key = crate::auth::ChallengeKey::new(
            Name::parse("carol").unwrap(),
            Action::Update,
            UnifiedAddress::from_string("u1new".into()),
            dummy_commitment(),
        );
        let issued_otp = crate::auth::OtpCode::generate();
        let real_otp = issued_otp.expose_for_test();
        otps.record_issued(key, &issued_otp, height);
        let req = authorize_update(&reg, &mut otps, height, name.clone(), ua, &real_otp).unwrap();
        assert_eq!(req.action(), Action::Update);
    }
}

/// Validates a transition request (update or release with OTP), reserves the name,
/// authorizes the transition, and assembles the transaction.
/// Returns `None` if the request is invalid, the name is locked, or authorization fails.
#[allow(clippy::too_many_arguments)]
pub fn process_transition<P: zcash_protocol::consensus::Parameters>(
    network: &P,
    name: Name,
    action: Action,
    ua: UnifiedAddress,
    otp: &[u8; 16],
    record_commitment: NameCommitment,
    cursor_height: zcash_protocol::consensus::BlockHeight,
    target_height: zcash_protocol::consensus::BlockHeight,
    excluded: &std::collections::BTreeSet<crate::wallet::NoteLocator>,
    wallet: &mut crate::wallet::Wallet,
    registry: &Registry,
    registry_keys: &crate::key::RegistryKeys,
    ops: &mut crate::mint::OperationalState,
    seen_with_otp: &mut std::collections::BTreeSet<crate::auth::ChallengeKey>,
) -> Option<crate::mint::RequestOutcome> {
    use crate::auth::ChallengeKey;
    use crate::mint::{SubmissionKind, RequestOutcome};

    let key = ChallengeKey::new(name.clone(), action, ua.clone(), record_commitment);
    if seen_with_otp.contains(&key) {
        return None;
    }
    crate::metrics::inc_request_received(action.as_str());
    seen_with_otp.insert(key);

    let lock = ops.reserve_name(&name, Some(record_commitment))?;
    let name_binding = lock.binding();

    let req = match action {
        Action::Update => authorize_update(registry, &mut ops.pending_otps, cursor_height, name, ua, otp),
        Action::Release => authorize_release(registry, &mut ops.pending_otps, cursor_height, name, ua, otp),
        Action::Claim => unreachable!(),
    };

    match req {
        None => {
            crate::metrics::inc_request_invalid("authorization_failed");
            ops.release_name(&lock);
            None
        }
        Some(r) => {
            let result = crate::registry::transaction::execute_transition(
                network,
                wallet,
                registry,
                registry_keys,
                r,
                excluded,
                cursor_height,
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
                name_lock: Some(lock),
                name_binding: Some(name_binding),
                relay_challenge: None,
            })
        }
    }
}
