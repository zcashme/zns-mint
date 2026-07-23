//! Transition authorization: validates requests against the name-chain state
//! and produces typed [`NameNoteRequest`]s for the transaction-assembly path.

use crate::mint::{Action, Name, NameCommitment, UnifiedAddress};
use crate::registry::state::{Registry, Tip};

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

/// Reads the current tip of the name chain for `name`.
pub fn current_tip(registry: &Registry, name: &Name) -> Option<Tip> {
    registry.tip(name).cloned()
}

/// Authorizes a claim request, producing a [`NameNoteRequest`].
///
/// The Treasury layer must have already verified that the claim payment was
/// made. This function verifies that the name is available (either no tip, or
/// tip is `Release`).
pub fn authorize_claim(
    registry: &Registry,
    name: Name,
    ua: UnifiedAddress,
) -> Option<NameNoteRequest> {
    match current_tip(registry, &name) {
        None => Some(NameNoteRequest::Claim(ClaimRequest { name, ua })),
        Some(Tip {
            action: Action::Release,
            ..
        }) => Some(NameNoteRequest::Claim(ClaimRequest { name, ua })),
        Some(_) => None, // Name is already live
    }
}

/// Authorizes an update request, producing a [`NameNoteRequest`].
///
/// Verifies the name is live and calls `auth::verify_consume` to validate the
/// OTP (not yet wired).
pub fn authorize_update(
    registry: &Registry,
    pending_otps: &mut crate::auth::PendingOtps,
    current_height: zcash_protocol::consensus::BlockHeight,
    name: Name,
    new_ua: UnifiedAddress,
    otp: &[u8; 16],
) -> Option<NameNoteRequest> {
    let tip = current_tip(registry, &name)?;
    if tip.action == Action::Release {
        return None;
    }

    let key = crate::auth::ChallengeKey::new(name.clone(), Action::Update, new_ua.clone());
    if !pending_otps.verify(&key, otp, current_height) {
        return None;
    }

    Some(NameNoteRequest::Update(UpdateRequest {
        name,
        new_ua,
        prev_commitment: tip.commitment,
    }))
}

/// Authorizes a release request, producing a [`NameNoteRequest`].
///
/// Verifies the name is live and calls `auth::verify_consume` to validate the
/// OTP (not yet wired).
pub fn authorize_release(
    registry: &Registry,
    pending_otps: &mut crate::auth::PendingOtps,
    current_height: zcash_protocol::consensus::BlockHeight,
    name: Name,
    current_ua: UnifiedAddress,
    otp: &[u8; 16],
) -> Option<NameNoteRequest> {
    let tip = current_tip(registry, &name)?;
    if tip.action == Action::Release {
        return None;
    }

    let key = crate::auth::ChallengeKey::new(name.clone(), Action::Release, current_ua);
    if !pending_otps.verify(&key, otp, current_height) {
        return None;
    }

    Some(NameNoteRequest::Release(ReleaseRequest {
        name,
        prev_commitment: tip.commitment,
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
        reg.set_tip_for_test(name.clone(), Action::Release, dummy_commitment(), height);
        let req2 = authorize_claim(&reg, name.clone(), ua.clone()).unwrap();
        assert_eq!(req2.action(), Action::Claim);

        // Live name is NOT claimable
        reg.set_tip_for_test(name.clone(), Action::Claim, dummy_commitment(), height);
        assert!(authorize_claim(&reg, name, ua).is_none());
    }

    #[test]
    fn update_release_need_live_tip() {
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
        reg.set_tip_for_test(name.clone(), Action::Release, dummy_commitment(), height);
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

        reg.set_tip_for_test(name.clone(), Action::Update, dummy_commitment(), height);

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
        );
        let issued_otp = otps.issue(key, height);
        let real_otp = issued_otp.expose_for_test();
        let req = authorize_update(&reg, &mut otps, height, name.clone(), ua, &real_otp).unwrap();
        assert_eq!(req.action(), Action::Update);
    }
}
