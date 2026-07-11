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
    otp_store: &mut crate::auth::OtpStore,
    current_height: zcash_protocol::consensus::BlockHeight,
    name: Name,
    new_ua: UnifiedAddress,
    otp: &str,
) -> Option<NameNoteRequest> {
    let tip = current_tip(registry, &name)?;
    if tip.action == Action::Release {
        return None;
    }

    let key = crate::auth::OtpKey::new(&name.to_string(), Action::Update, &new_ua.to_string());
    if !otp_store.verify(&key, otp, current_height) {
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
    otp_store: &mut crate::auth::OtpStore,
    current_height: zcash_protocol::consensus::BlockHeight,
    name: Name,
    current_ua: UnifiedAddress,
    otp: &str,
) -> Option<NameNoteRequest> {
    let tip = current_tip(registry, &name)?;
    if tip.action == Action::Release {
        return None;
    }

    let key = crate::auth::OtpKey::new(&name.to_string(), Action::Release, &current_ua.to_string());
    if !otp_store.verify(&key, otp, current_height) {
        return None;
    }

    Some(NameNoteRequest::Release(ReleaseRequest {
        name,
        prev_commitment: tip.commitment,
    }))
}