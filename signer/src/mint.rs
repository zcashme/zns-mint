//! ZNS Name Note minting.
//!
//! Computes `(psi, rcm)` via [`crate::derive::zns_psi_rcm`], then constructs a
//! fully-proven Orchard bundle using the `zns-orchard` fork's `add_zns_output`
//! API.  The bundle is wrapped in a V5 [`Transaction`] and serialized to bytes
//! suitable for broadcast.
//!
//! # Proving key caching
//!
//! [`orchard::circuit::ProvingKey::build()`] is expensive (~1 s on first call).
//! A [`std::sync::OnceLock`] caches the result for the lifetime of the process.

use std::sync::OnceLock;

use blake2b_simd::Params;
use orchard::{
    builder::{Builder as OrchardBuilder, BundleType},
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope},
    tree::Anchor,
    value::NoteValue,
    Address,
};
use pasta_curves::{group::ff::PrimeField, pallas};
use rand::rngs::OsRng;
use zcash_primitives::transaction::{
    Authorized as TxAuthorized, Transaction, TransactionData, TxVersion,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::ZatBalance,
};
use zns_core::Action;

use crate::derive::zns_psi_rcm;
use crate::error::BuildError;

// ---------------------------------------------------------------------------
// Proving key cache
// ---------------------------------------------------------------------------

static PK_FIXED: OnceLock<ProvingKey> = OnceLock::new();
static PK_INSECURE: OnceLock<ProvingKey> = OnceLock::new();

/// Orchard circuit version for proofs authored under `branch_id`.
///
/// `branch_id` should come from [`BranchId::for_height`] at the spend/sweep tip.
/// Mirrors `zebra-consensus`'s `verifier_for` era split: NU5..=NU6.1 use the
/// historical insecure circuit; NU6.2+ use the fixed circuit.
pub(crate) fn orchard_circuit_version(branch_id: BranchId) -> OrchardCircuitVersion {
    use BranchId::*;
    match branch_id {
        Nu6_2 => OrchardCircuitVersion::FixedPostNu6_2,
        Nu5 | Nu6 | Nu6_1 => OrchardCircuitVersion::InsecurePreNu6_2,
        // Orchard did not exist before NU5; kept for an exhaustive match only.
        Sprout | Overwinter | Sapling | Blossom | Heartwood | Canopy => {
            OrchardCircuitVersion::InsecurePreNu6_2
        }

    }
}

/// The proving key for `version`, built once and cached.
pub(crate) fn proving_key_for(version: OrchardCircuitVersion) -> &'static ProvingKey {
    match version {
        OrchardCircuitVersion::FixedPostNu6_2 => PK_FIXED.get_or_init(ProvingKey::build),
        OrchardCircuitVersion::InsecurePreNu6_2 => {
            PK_INSECURE.get_or_init(|| ProvingKey::build_for_version(version))
        }
    }
}

static VK_FIXED: OnceLock<VerifyingKey> = OnceLock::new();
static VK_INSECURE: OnceLock<VerifyingKey> = OnceLock::new();
fn verifying_key_for(version: OrchardCircuitVersion) -> &'static VerifyingKey {
    match version {
        OrchardCircuitVersion::FixedPostNu6_2 => VK_FIXED.get_or_init(VerifyingKey::build),
        OrchardCircuitVersion::InsecurePreNu6_2 => {
            VK_INSECURE.get_or_init(|| VerifyingKey::build_for_version(version))
        }
    }
}

// ---------------------------------------------------------------------------
// Sighash helper — V5 shielded-only (no transparent, no sapling)
// ---------------------------------------------------------------------------

fn v5_shielded_sighash(
    branch_id: BranchId,
    lock_time: u32,
    expiry_height: u32,
    orchard_digest: &[u8; 32],
) -> [u8; 32] {
    let header_digest = {
        let mut h = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdHeadersHash")
            .to_state();
        h.update(&TxVersion::V5.header().to_le_bytes());
        h.update(&TxVersion::V5.version_group_id().to_le_bytes());
        let bid: u32 = branch_id.into();
        h.update(&bid.to_le_bytes());
        h.update(&lock_time.to_le_bytes());
        h.update(&expiry_height.to_le_bytes());
        h.finalize()
    };

    let transparent_digest = Params::new()
        .hash_length(32)
        .personal(b"ZTxIdTranspaHash")
        .to_state()
        .finalize();

    let sapling_digest = Params::new()
        .hash_length(32)
        .personal(b"ZTxIdSaplingHash")
        .to_state()
        .finalize();

    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(b"ZcashTxHash_");
    personal[12..].copy_from_slice(&u32::from(branch_id).to_le_bytes());

    let mut h = Params::new().hash_length(32).personal(&personal).to_state();
    h.update(header_digest.as_bytes());
    h.update(transparent_digest.as_bytes());
    h.update(sapling_digest.as_bytes());
    h.update(orchard_digest);

    let hash = h.finalize();
    let bytes: &[u8; 32] = hash.as_bytes().try_into().expect("blake2b 32-byte output");
    *bytes
}

// ---------------------------------------------------------------------------
// Transaction wrapper
// ---------------------------------------------------------------------------

fn orchard_bundle_to_tx_bytes(
    bundle: orchard::bundle::Bundle<orchard::bundle::Authorized, i64>,
    consensus_branch_id: BranchId,
    expiry_height: u32,
    sighash: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), BuildError> {
    let bundle_zat = bundle
        .try_map_value_balance::<ZatBalance, _, _>(|v: i64| ZatBalance::from_i64(v))
        .map_err(BuildError::value_balance)?;

    let tx_data: TransactionData<TxAuthorized> = TransactionData::from_parts(
        TxVersion::V5,
        consensus_branch_id,
        0,
        BlockHeight::from_u32(expiry_height),
        None,
        None,
        None,
        Some(bundle_zat),
    );

    let tx: Transaction = tx_data.freeze().map_err(BuildError::Serialize)?;

    let txid: [u8; 32] = *tx.txid().as_ref();

    if txid != *sighash {
        return Err(BuildError::SighashMismatch);
    }

    let mut bytes = Vec::new();
    tx.write(&mut bytes)?;

    Ok((bytes, txid))
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Parameters needed to mint a single Name Note.
pub struct MintParams<'a> {
    pub action: Action,
    pub name: &'a str,
    pub ua: &'a str,
    pub prev_rcm: [u8; 32],
    pub recipient: Address,
    pub registry_fvk: FullViewingKey,
    pub anchor: Anchor,
    pub branch_id: BranchId,
    pub expiry_height: u32,
}

/// The output of a successful OTP challenge relay.
#[derive(Debug)]
pub struct RelayResult {
    pub txid: [u8; 32],
    pub tx_bytes: Vec<u8>,
}

/// The output of a successful mint.
#[derive(Debug)]
pub struct MintResult {
    pub new_rcm: [u8; 32],
    pub new_psi: [u8; 32],
    pub cmx: [u8; 32],
    pub txid: [u8; 32],
    pub tx_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Core mint function
// ---------------------------------------------------------------------------

pub fn build_name_note(params: MintParams<'_>) -> Result<MintResult, BuildError> {
    let circuit_version = orchard_circuit_version(params.branch_id);
    let (psi, rcm) = zns_psi_rcm(
        params.action.as_bytes(),
        params.name.as_bytes(),
        params.ua.as_bytes(),
        &params.prev_rcm,
    );

    let new_rcm: [u8; 32] = rcm.to_repr();
    let new_psi: [u8; 32] = psi.to_repr();

    let ovk = Some(params.registry_fvk.to_ovk(Scope::External));
    let mut builder =
        OrchardBuilder::new_for_version(BundleType::DEFAULT, params.anchor, circuit_version);

    let memo =
        zns_core::memo::encode_name_note(params.action, params.name, params.ua, &params.prev_rcm)?;
    builder
        .add_zns_output(
            ovk,
            params.recipient,
            NoteValue::from_raw(0),
            memo,
            rcm,
            psi,
        )
        .map_err(BuildError::bundle)?;

    let mut rng = OsRng;

    let (unauthorized_bundle, meta) = builder
        .build::<i64>(&mut rng)
        .map_err(BuildError::bundle)?
        .ok_or(BuildError::EmptyBundle)?;
    let name_note_action = meta
        .output_action_index(0)
        .ok_or(BuildError::MissingNameNote)?;

    let orchard_digest: [u8; 32] = unauthorized_bundle.commitment().into();
    let sighash = v5_shielded_sighash(params.branch_id, 0, params.expiry_height, &orchard_digest);

    let proven_bundle = unauthorized_bundle
        .create_proof(proving_key_for(circuit_version), &mut rng)
        .map_err(BuildError::proof)?;

    let authorized_bundle = proven_bundle
        .apply_signatures(rng, sighash, &[])
        .map_err(BuildError::signature)?;

    let cmx: [u8; 32] = authorized_bundle.actions()[name_note_action]
        .cmx()
        .to_bytes();
    let (tx_bytes, txid) = orchard_bundle_to_tx_bytes(
        authorized_bundle,
        params.branch_id,
        params.expiry_height,
        &sighash,
    )?;

    Ok(MintResult {
        new_rcm,
        new_psi,
        cmx,
        txid,
        tx_bytes,
    })
}

// ---------------------------------------------------------------------------
// Funded mint
// ---------------------------------------------------------------------------

use orchard::keys::{SpendAuthorizingKey, SpendingKey};

use crate::policy::{FundingInput, MintPlan};

#[allow(clippy::too_many_arguments)]
pub fn build_funded_mint(
    registry_fvk: &FullViewingKey,
    spend_key: &SpendingKey,
    recipient: Address,
    funding: &FundingInput,
    plan: &MintPlan,
    branch_id: BranchId,
    expiry_height: u32,
) -> Result<MintResult, BuildError> {
    let circuit_version = orchard_circuit_version(branch_id);
    let (psi, rcm) = zns_psi_rcm(
        plan.action.as_bytes(),
        plan.name.as_bytes(),
        plan.ua.as_bytes(),
        &plan.prev_rcm,
    );
    let new_rcm: [u8; 32] = rcm.to_repr();
    let new_psi: [u8; 32] = psi.to_repr();

    let ovk = Some(registry_fvk.to_ovk(Scope::External));
    let mut builder =
        OrchardBuilder::new_for_version(BundleType::DEFAULT, funding.anchor, circuit_version);

    builder
        .add_spend(
            registry_fvk.clone(),
            funding.note,
            funding.merkle_path.clone(),
        )
        .map_err(BuildError::bundle)?;

    let memo = zns_core::memo::encode_name_note(plan.action, &plan.name, &plan.ua, &plan.prev_rcm)?;
    builder
        .add_zns_output(
            ovk.clone(),
            recipient,
            NoteValue::from_raw(0),
            memo,
            rcm,
            psi,
        )
        .map_err(BuildError::bundle)?;

    if plan.change_zat > 0 {
        builder
            .add_output(
                ovk,
                recipient,
                NoteValue::from_raw(plan.change_zat),
                [0u8; 512],
            )
            .map_err(BuildError::bundle)?;
    }

    let mut rng = OsRng;
    let (unauthorized, meta) = builder
        .build::<i64>(&mut rng)
        .map_err(BuildError::bundle)?
        .ok_or(BuildError::EmptyBundle)?;
    let name_note_action = meta
        .output_action_index(0)
        .ok_or(BuildError::MissingNameNote)?;

    let orchard_digest: [u8; 32] = unauthorized.commitment().into();
    let sighash = v5_shielded_sighash(branch_id, 0, expiry_height, &orchard_digest);

    let proven = unauthorized
        .create_proof(proving_key_for(circuit_version), &mut rng)
        .map_err(BuildError::proof)?;

    let ask = SpendAuthorizingKey::from(spend_key);
    let authorized = proven
        .apply_signatures(rng, sighash, &[ask])
        .map_err(BuildError::signature)?;

    authorized
        .verify_proof(verifying_key_for(circuit_version))
        .map_err(BuildError::verify)?;

    let cmx: [u8; 32] = authorized.actions()[name_note_action].cmx().to_bytes();
    let (tx_bytes, txid) =
        orchard_bundle_to_tx_bytes(authorized, branch_id, expiry_height, &sighash)?;

    let readback = Transaction::read(&tx_bytes[..], branch_id)?;
    readback
        .orchard_bundle()
        .ok_or(BuildError::MissingNameNote)?
        .verify_proof(verifying_key_for(circuit_version))
        .map_err(BuildError::verify)?;

    Ok(MintResult {
        new_rcm,
        new_psi,
        cmx,
        txid,
        tx_bytes,
    })
}

/// Build a sweep transaction to the cold address.
#[allow(clippy::too_many_arguments)]
pub fn build_sweep(
    registry_fvk: &FullViewingKey,
    spend_key: &SpendingKey,
    cold_addr: Address,
    funding: &FundingInput,
    amount_zat: u64,
    branch_id: BranchId,
    expiry_height: u32,
) -> Result<(Vec<u8>, [u8; 32]), BuildError> {
    let circuit_version = orchard_circuit_version(branch_id);
    let ovk = Some(registry_fvk.to_ovk(Scope::External));
    let mut builder =
        OrchardBuilder::new_for_version(BundleType::DEFAULT, funding.anchor, circuit_version);

    builder
        .add_spend(
            registry_fvk.clone(),
            funding.note,
            funding.merkle_path.clone(),
        )
        .map_err(BuildError::bundle)?;
    builder
        .add_output(ovk, cold_addr, NoteValue::from_raw(amount_zat), [0u8; 512])
        .map_err(BuildError::bundle)?;

    let mut rng = OsRng;
    let (unauthorized, _meta) = builder
        .build::<i64>(&mut rng)
        .map_err(BuildError::bundle)?
        .ok_or(BuildError::EmptyBundle)?;

    let orchard_digest: [u8; 32] = unauthorized.commitment().into();
    let sighash = v5_shielded_sighash(branch_id, 0, expiry_height, &orchard_digest);

    let proven = unauthorized
        .create_proof(proving_key_for(circuit_version), &mut rng)
        .map_err(BuildError::proof)?;
    let ask = SpendAuthorizingKey::from(spend_key);
    let authorized = proven
        .apply_signatures(rng, sighash, &[ask])
        .map_err(BuildError::signature)?;

    let (tx_bytes, txid) =
        orchard_bundle_to_tx_bytes(authorized, branch_id, expiry_height, &sighash)?;
    Ok((tx_bytes, txid))
}

/// Build a memo-send transaction (OTP challenge relay).
#[allow(clippy::too_many_arguments)]
pub fn build_memo_send(
    registry_fvk: &FullViewingKey,
    spend_key: &SpendingKey,
    recipient: Address,
    change_addr: Address,
    funding: &FundingInput,
    dust_zat: u64,
    change_zat: u64,
    memo: [u8; 512],
    branch_id: BranchId,
    expiry_height: u32,
) -> Result<RelayResult, BuildError> {
    let circuit_version = orchard_circuit_version(branch_id);
    let ovk = Some(registry_fvk.to_ovk(Scope::External));
    let mut builder =
        OrchardBuilder::new_for_version(BundleType::DEFAULT, funding.anchor, circuit_version);

    builder
        .add_spend(
            registry_fvk.clone(),
            funding.note,
            funding.merkle_path.clone(),
        )
        .map_err(BuildError::bundle)?;

    builder
        .add_output(ovk.clone(), recipient, NoteValue::from_raw(dust_zat), memo)
        .map_err(BuildError::bundle)?;

    if change_zat > 0 {
        builder
            .add_output(
                ovk,
                change_addr,
                NoteValue::from_raw(change_zat),
                [0u8; 512],
            )
            .map_err(BuildError::bundle)?;
    }

    let mut rng = OsRng;
    let (unauthorized, _meta) = builder
        .build::<i64>(&mut rng)
        .map_err(BuildError::bundle)?
        .ok_or(BuildError::EmptyBundle)?;

    let orchard_digest: [u8; 32] = unauthorized.commitment().into();
    let sighash = v5_shielded_sighash(branch_id, 0, expiry_height, &orchard_digest);

    let proven = unauthorized
        .create_proof(proving_key_for(circuit_version), &mut rng)
        .map_err(BuildError::proof)?;
    let ask = SpendAuthorizingKey::from(spend_key);
    let authorized = proven
        .apply_signatures(rng, sighash, &[ask])
        .map_err(BuildError::signature)?;

    let (tx_bytes, txid) =
        orchard_bundle_to_tx_bytes(authorized, branch_id, expiry_height, &sighash)?;
    Ok(RelayResult { tx_bytes, txid })
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

pub fn derive_psi_rcm(
    action: Action,
    name: &str,
    ua: &str,
    prev_rcm: &[u8; 32],
) -> (pallas::Base, pallas::Scalar) {
    zns_psi_rcm(action.as_bytes(), name.as_bytes(), ua.as_bytes(), prev_rcm)
}

pub use zns_core::ZERO_PREV_RCM as CLAIM_PREV_RCM;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::{FullViewingKey, SpendingKey};
    use zcash_protocol::consensus::BranchId;
    use zns_core::ZERO_PREV_RCM;

    fn make_fvk() -> FullViewingKey {
        let seed = [0x42u8; 32];
        let sk = SpendingKey::from_zip32_seed(&seed, 133, zip32::AccountId::ZERO).unwrap();
        FullViewingKey::from(&sk)
    }

    fn test_params<'a>(
        fvk: FullViewingKey,
        name: &'a str,
        ua: &'a str,
        prev_rcm: [u8; 32],
    ) -> MintParams<'a> {
        let recipient = fvk.address_at(0u32, Scope::External);
        MintParams {
            action: if prev_rcm == ZERO_PREV_RCM {
                Action::Claim
            } else {
                Action::Update
            },
            name,
            ua,
            prev_rcm,
            recipient,
            registry_fvk: fvk,
            anchor: Anchor::empty_tree(),
            branch_id: BranchId::Nu6,
            expiry_height: 0,
        }
    }

    #[test]
    fn testnet_post_nu6_2_uses_fixed_circuit() {
        use zcash_protocol::consensus::{BlockHeight, Network};

        let branch = BranchId::for_height(&Network::TestNetwork, BlockHeight::from_u32(4_069_676));
        assert_eq!(branch, BranchId::Nu6_2);
        assert_eq!(
            orchard_circuit_version(branch),
            OrchardCircuitVersion::FixedPostNu6_2
        );
    }

    #[test]
    fn testnet_pre_nu6_2_orchard_uses_insecure_circuit() {
        use zcash_protocol::consensus::{BlockHeight, Network};

        let branch = BranchId::for_height(&Network::TestNetwork, BlockHeight::from_u32(4_051_999));
        assert_eq!(branch, BranchId::Nu6_1);
        assert_eq!(
            orchard_circuit_version(branch),
            OrchardCircuitVersion::InsecurePreNu6_2
        );
    }

    #[test]
    fn build_name_note_claim() {
        let fvk = make_fvk();
        let result = build_name_note(test_params(fvk, "alice", "u1xxx", ZERO_PREV_RCM)).unwrap();
        assert_ne!(result.new_rcm, [0u8; 32]);
        assert_ne!(result.new_psi, [0u8; 32]);
        assert!(!result.tx_bytes.is_empty());
        assert_eq!(result.tx_bytes[0], 0x05, "expected V5 tx first byte");
    }

    #[test]
    fn chained_rcm_differs() {
        let fvk = make_fvk();
        let claim =
            build_name_note(test_params(fvk.clone(), "alice", "u1xxx", ZERO_PREV_RCM)).unwrap();
        let update = build_name_note(MintParams {
            action: Action::Update,
            name: "alice",
            ua: "u1new",
            prev_rcm: claim.new_rcm,
            recipient: fvk.address_at(0u32, Scope::External),
            registry_fvk: fvk,
            anchor: Anchor::empty_tree(),
            branch_id: BranchId::Nu6,
            expiry_height: 0,
        })
        .unwrap();
        assert_ne!(claim.new_rcm, update.new_rcm);
        assert_ne!(claim.tx_bytes, update.tx_bytes);
    }

    #[test]
    fn tx_bytes_start_with_v5_header() {
        let fvk = make_fvk();
        let result = build_name_note(test_params(fvk, "bob", "u1yyy", ZERO_PREV_RCM)).unwrap();
        assert_eq!(&result.tx_bytes[..4], &[0x05, 0x00, 0x00, 0x80]);
    }
}
