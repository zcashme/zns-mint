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
    circuit::{OrchardCircuitVersion, ProvingKey},
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
use zns_core::{Action, RegistryError};

use crate::derive::zns_psi_rcm;

// ---------------------------------------------------------------------------
// Proving key cache
// ---------------------------------------------------------------------------

// Orchard 0.14 ships two circuits with distinct verifying keys: the fixed
// post-NU6.2 circuit (`build()` default) and the historical pre-NU6.2 circuit.
// A chain validates with the VK for its active upgrade, so we must prove with
// the version matching the target chain (e.g. a NU6 regtest needs the insecure
// pre-NU6.2 key, or it rejects with "could not validate orchard proof").
static PK_FIXED: OnceLock<ProvingKey> = OnceLock::new();
static PK_INSECURE: OnceLock<ProvingKey> = OnceLock::new();

/// The proving key for `version`, built once and cached.
pub(crate) fn proving_key_for(version: OrchardCircuitVersion) -> &'static ProvingKey {
    match version {
        OrchardCircuitVersion::FixedPostNu6_2 => PK_FIXED.get_or_init(ProvingKey::build),
        OrchardCircuitVersion::InsecurePreNu6_2 => {
            PK_INSECURE.get_or_init(|| ProvingKey::build_for_version(version))
        }
    }
}

/// Default proving key (fixed post-NU6.2) — used by the funded/sweep paths.
fn proving_key() -> &'static ProvingKey {
    proving_key_for(OrchardCircuitVersion::FixedPostNu6_2)
}

// ---------------------------------------------------------------------------
// Sighash helper — V5 shielded-only (no transparent, no sapling)
// ---------------------------------------------------------------------------
//
// ZIP 244 defines the V5 signature digest as:
//   BLAKE2b-256(personal = "ZcashTxHash_" || branch_id_le32,
//     header_digest || transparent_digest || sapling_digest || orchard_digest)
//
// For a shielded-only transaction:
//   header_digest      = BLAKE2b-256("ZTxIdHeadersHash",
//                          version_header_le32 || version_group_id_le32 ||
//                          branch_id_le32 || lock_time_le32 || expiry_height_le32)
//   transparent_digest = BLAKE2b-256("ZTxIdTranspaHash")   [empty — no inputs]
//   sapling_digest     = BLAKE2b-256("ZcTxSaplinHash")     [empty — no spends/outputs]
//   orchard_digest     = bundle.commitment().0             [already computed]
//
// This matches the private `to_hash` + `hash_header_txid_data` + `hash_transparent_txid_data`
// functions in zcash_primitives::transaction::txid, which are not public.

fn v5_shielded_sighash(
    branch_id: BranchId,
    lock_time: u32,
    expiry_height: u32,
    orchard_digest: &[u8; 32],
) -> [u8; 32] {
    // 1. Header digest  ("ZTxIdHeadersHash")
    let header_digest = {
        let mut h = Params::new()
            .hash_length(32)
            .personal(b"ZTxIdHeadersHash")
            .to_state();
        // header (version | overwintered bit)
        h.update(&TxVersion::V5.header().to_le_bytes());
        // version group id
        h.update(&TxVersion::V5.version_group_id().to_le_bytes());
        // consensus branch id
        let bid: u32 = branch_id.into();
        h.update(&bid.to_le_bytes());
        // lock_time
        h.update(&lock_time.to_le_bytes());
        // expiry_height
        h.update(&expiry_height.to_le_bytes());
        h.finalize()
    };

    // 2. Transparent digest — empty bundle ("ZTxIdTranspaHash")
    let transparent_digest = Params::new()
        .hash_length(32)
        .personal(b"ZTxIdTranspaHash")
        .to_state()
        .finalize();

    // 3. Sapling digest — empty bundle ("ZcTxSaplinHash")
    let sapling_digest = Params::new()
        .hash_length(32)
        .personal(b"ZcTxSaplinHash\0\0")
        .to_state()
        .finalize();

    // 4. Combine into the tx hash / sighash ("ZcashTxHash_" || branch_id_le32)
    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(b"ZcashTxHash_");
    personal[12..].copy_from_slice(&u32::from(branch_id).to_le_bytes());

    let mut h = Params::new()
        .hash_length(32)
        .personal(&personal)
        .to_state();
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

/// Wrap an `orchard::bundle::Bundle<Authorized, i64>` in a V5 transaction and
/// return the serialized bytes plus the ZIP-244 txid (the canonical on-chain
/// identifier, stored in the minted-action log).
fn orchard_bundle_to_tx_bytes(
    bundle: orchard::bundle::Bundle<orchard::bundle::Authorized, i64>,
    consensus_branch_id: BranchId,
    expiry_height: u32,
) -> Result<(Vec<u8>, [u8; 32]), RegistryError> {
    // Convert value_balance: i64 → ZatBalance (required by zcash_primitives serializer).
    let bundle_zat = bundle
        .try_map_value_balance::<ZatBalance, _, _>(|v: i64| ZatBalance::from_i64(v))
        .map_err(|e| RegistryError::Build(format!("value_balance out of range: {e:?}")))?;

    // Wrap in TransactionData (no transparent, no sprout, no sapling).
    let tx_data: TransactionData<TxAuthorized> = TransactionData::from_parts(
        TxVersion::V5,
        consensus_branch_id,
        0, // lock_time
        BlockHeight::from_u32(expiry_height),
        None, // transparent_bundle
        None, // sprout_bundle
        None, // sapling_bundle
        Some(bundle_zat),
    );

    // Freeze computes the txid via the ZIP-244 digest and returns a Transaction.
    let tx: Transaction = tx_data
        .freeze()
        .map_err(|e| RegistryError::Build(format!("freeze: {e}")))?;

    // The ZIP-244 txid is fixed once the tx is frozen.
    let txid: [u8; 32] = *tx.txid().as_ref();

    // Serialize using the Transaction::write() entry point.
    let mut bytes = Vec::new();
    tx.write(&mut bytes)
        .map_err(|e| RegistryError::Build(format!("serialize: {e}")))?;

    Ok((bytes, txid))
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Parameters needed to mint a single Name Note.
pub struct MintParams<'a> {
    /// The ZNS lifecycle action being performed.
    pub action: Action,
    /// The human-readable name being claimed/updated/released.
    pub name: &'a str,
    /// The Unified Address being bound to the name (empty for Release).
    pub ua: &'a str,
    /// The `rcm` of the previous Name Note in this name's chain.
    /// Use [`CLAIM_PREV_RCM`] for the initial CLAIM.
    pub prev_rcm: [u8; 32],
    /// The address that will receive the Name Note (registry self-address).
    pub recipient: Address,
    /// Full Viewing Key of the registry — used to derive the OVK.
    pub registry_fvk: FullViewingKey,
    /// Orchard Merkle anchor to use.  For value-0 notes an empty-tree anchor
    /// is sufficient (the circuit allows `v_old = 0 OR root = anchor`).
    pub anchor: Anchor,
    /// Consensus branch ID to embed in the transaction.
    ///
    /// Use `BranchId::Nu6` for current mainnet (activated at height 2_726_400)
    /// or `BranchId::Nu6_1` (activated at height 3_536_500 on mainnet).
    /// Defaults to `BranchId::Nu6` when the caller uses [`build_name_note`].
    pub branch_id: BranchId,
    /// Block height at which the transaction expires.  Set to 0 for no expiry.
    pub expiry_height: u32,
    /// Which Orchard circuit to prove against — must match the target chain's
    /// active upgrade (NU6 → `InsecurePreNu6_2`; NU6.2+ → `FixedPostNu6_2`).
    pub circuit_version: OrchardCircuitVersion,
}

/// The output of a successful mint: the derived cryptographic parameters and
/// a serialized V5 Orchard-only transaction ready for broadcast.
#[derive(Debug)]
pub struct MintResult {
    /// The new `rcm` — caller stores this as `tip_rcm` for future chaining.
    pub new_rcm: [u8; 32],
    /// The new `psi` — kept for diagnostic / test purposes.
    pub new_psi: [u8; 32],
    /// The Name Note's extracted note commitment (`cmx`) — the on-chain
    /// commitment recorded in the minted-action log.
    pub cmx: [u8; 32],
    /// The ZIP-244 txid of the broadcast transaction — the canonical identifier
    /// recorded in the minted-action log.
    pub txid: [u8; 32],
    /// Serialized V5 transaction bytes ready for broadcast via `sendrawtransaction`.
    pub tx_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Core mint function
// ---------------------------------------------------------------------------

/// Construct a ZNS Name Note, generate an Orchard proof, and return the
/// serialized transaction ready for broadcast.
///
/// This function is computationally expensive on the first call because
/// [`ProvingKey::build()`] must run.  Subsequent calls reuse the cached key.
pub fn build_name_note(params: MintParams<'_>) -> Result<MintResult, RegistryError> {
    // 1. Derive (psi, rcm) deterministically from the ZNS registration tuple.
    let (psi, rcm) = zns_psi_rcm(
        params.action.as_bytes(),
        params.name.as_bytes(),
        params.ua.as_bytes(),
        &params.prev_rcm,
    );

    // 2. Encode for storage.  `.to_repr()` is provided by the `PrimeField` trait.
    let new_rcm: [u8; 32] = rcm.to_repr();
    let new_psi: [u8; 32] = psi.to_repr();

    // 3. Build the Orchard action using the ZNS override path. The builder must
    //    carry the circuit version so its actions synthesize against the proving
    //    key we use below (a NU6 chain needs the insecure pre-NU6.2 circuit).
    let ovk = Some(params.registry_fvk.to_ovk(Scope::External));
    let mut builder =
        OrchardBuilder::new_for_version(BundleType::DEFAULT, params.anchor, params.circuit_version);

    builder
        .add_zns_output(
            ovk,
            params.recipient,
            NoteValue::from_raw(0),
            [0u8; 512],
            rcm,
            psi,
        )
        .map_err(|e| RegistryError::Build(format!("{e:?}")))?;

    let mut rng = OsRng;

    // 4. Build the unauthorized bundle.  `meta` maps our output index to its
    //    (shuffled) action index so we can recover the Name Note's `cmx`.
    let (unauthorized_bundle, meta) = builder
        .build::<i64>(&mut rng)
        .map_err(|e| RegistryError::Build(format!("build: {e:?}")))?
        .ok_or_else(|| RegistryError::Build("builder produced an empty bundle".into()))?;
    let name_note_action = meta
        .output_action_index(0)
        .ok_or_else(|| RegistryError::Build("Name Note output missing from bundle".into()))?;

    // 5. Compute the sighash BEFORE proving.
    //
    // The orchard_digest (bundle.commitment()) does not depend on the proof or
    // signatures — it only covers the action data (nullifiers, cmx, ciphertexts,
    // flags, value_balance, anchor).  This lets us compute the sighash from the
    // unauthorized bundle and feed it to apply_signatures.
    let orchard_digest: [u8; 32] = unauthorized_bundle.commitment().into();
    let sighash = v5_shielded_sighash(
        params.branch_id,
        0, // lock_time
        params.expiry_height,
        &orchard_digest,
    );

    // 6. Create the ZK proof under the circuit version the target chain expects.
    let proven_bundle = unauthorized_bundle
        .create_proof(proving_key_for(params.circuit_version), &mut rng)
        .map_err(|e| RegistryError::Build(format!("create_proof: {e:?}")))?;

    // 7. Apply signatures.  No spend authorizing keys are needed for a
    //    value-0 output-only bundle (no dummy spends require signing here).
    let authorized_bundle = proven_bundle
        .apply_signatures(&mut rng, sighash, &[])
        .map_err(|e| RegistryError::Build(format!("apply_signatures: {e:?}")))?;

    // 8. Recover the Name Note commitment, then serialize the transaction.
    let cmx: [u8; 32] = authorized_bundle.actions()[name_note_action]
        .cmx()
        .to_bytes();
    let (tx_bytes, txid) =
        orchard_bundle_to_tx_bytes(authorized_bundle, params.branch_id, params.expiry_height)?;

    Ok(MintResult {
        new_rcm,
        new_psi,
        cmx,
        txid,
        tx_bytes,
    })
}

// ---------------------------------------------------------------------------
// Funded mint — the production path (self-funds the fee from a treasury note)
// ---------------------------------------------------------------------------

use orchard::keys::{SpendAuthorizingKey, SpendingKey};

use crate::policy::{FundingInput, MintPlan};

/// Build a **self-funded** Name Note transaction: spend one treasury note to
/// cover the fee, emit the value-0 Name Note, and return the change to the
/// registry. Unlike [`build_name_note`], the funding spend is real, so it
/// requires a valid witness (`funding`) and a spend-auth signature (`spend_key`).
///
/// `recipient` is the registry self-address — the *only* place value lands
/// (Name Note + change). The caller is the policy-gated [`crate::sign::Signer`],
/// which authors `plan` and supplies `funding` from the WalletDb note-state.
pub fn build_funded_mint(
    registry_fvk: &FullViewingKey,
    spend_key: &SpendingKey,
    recipient: Address,
    funding: &FundingInput,
    plan: &MintPlan,
    branch_id: BranchId,
    expiry_height: u32,
) -> Result<MintResult, RegistryError> {
    // 1. Derive (psi, rcm) from the registration tuple — signer-authored, never
    //    host-supplied.
    let (psi, rcm) = zns_psi_rcm(
        plan.action.as_bytes(),
        plan.name.as_bytes(),
        plan.ua.as_bytes(),
        &plan.prev_rcm,
    );
    let new_rcm: [u8; 32] = rcm.to_repr();
    let new_psi: [u8; 32] = psi.to_repr();

    let ovk = Some(registry_fvk.to_ovk(Scope::External));
    let mut builder = OrchardBuilder::new(BundleType::DEFAULT, funding.anchor);

    // 2. Funding spend (pays the fee). Anchor must match the witness root.
    builder
        .add_spend(registry_fvk.clone(), funding.note.clone(), funding.merkle_path.clone())
        .map_err(|e| RegistryError::Build(format!("add_spend: {e:?}")))?;

    // 3. The Name Note (value 0) to the registry self-address.
    builder
        .add_zns_output(ovk.clone(), recipient, NoteValue::from_raw(0), [0u8; 512], rcm, psi)
        .map_err(|e| RegistryError::Build(format!("add_zns_output: {e:?}")))?;

    // 4. Change back to the registry. value_balance = funding − 0 − change = fee.
    if plan.change_zat > 0 {
        builder
            .add_output(ovk, recipient, NoteValue::from_raw(plan.change_zat), [0u8; 512])
            .map_err(|e| RegistryError::Build(format!("add_output(change): {e:?}")))?;
    }

    let mut rng = OsRng;
    let (unauthorized, meta) = builder
        .build::<i64>(&mut rng)
        .map_err(|e| RegistryError::Build(format!("build: {e:?}")))?
        .ok_or_else(|| RegistryError::Build("builder produced an empty bundle".into()))?;
    // The Name Note is output 0 (the funding spend is a spend, not an output).
    let name_note_action = meta
        .output_action_index(0)
        .ok_or_else(|| RegistryError::Build("Name Note output missing from bundle".into()))?;

    let orchard_digest: [u8; 32] = unauthorized.commitment().into();
    let sighash = v5_shielded_sighash(branch_id, 0, expiry_height, &orchard_digest);

    let proven = unauthorized
        .create_proof(proving_key(), &mut rng)
        .map_err(|e| RegistryError::Build(format!("create_proof: {e:?}")))?;

    // Real funding spend → needs a spend-auth signature from the registry key.
    let ask = SpendAuthorizingKey::from(spend_key);
    let authorized = proven
        .apply_signatures(&mut rng, sighash, &[ask])
        .map_err(|e| RegistryError::Build(format!("apply_signatures: {e:?}")))?;

    let cmx: [u8; 32] = authorized.actions()[name_note_action].cmx().to_bytes();
    let (tx_bytes, txid) = orchard_bundle_to_tx_bytes(authorized, branch_id, expiry_height)?;
    Ok(MintResult { new_rcm, new_psi, cmx, txid, tx_bytes })
}

/// Build a **sweep** transaction: spend one treasury note and move its value,
/// minus the fee, to the cold address. No Name Note, no change — the note is
/// swept wholesale (`amount_zat = funding.value − fee`), so `value_balance`
/// equals the fee. `cold_addr` is the policy constant; the caller is the
/// policy-gated [`crate::sign::Signer`].
pub fn build_sweep(
    registry_fvk: &FullViewingKey,
    spend_key: &SpendingKey,
    cold_addr: Address,
    funding: &FundingInput,
    amount_zat: u64,
    branch_id: BranchId,
    expiry_height: u32,
) -> Result<Vec<u8>, RegistryError> {
    let ovk = Some(registry_fvk.to_ovk(Scope::External));
    let mut builder = OrchardBuilder::new(BundleType::DEFAULT, funding.anchor);

    builder
        .add_spend(registry_fvk.clone(), funding.note.clone(), funding.merkle_path.clone())
        .map_err(|e| RegistryError::Build(format!("add_spend: {e:?}")))?;
    builder
        .add_output(ovk, cold_addr, NoteValue::from_raw(amount_zat), [0u8; 512])
        .map_err(|e| RegistryError::Build(format!("add_output(sweep): {e:?}")))?;

    let mut rng = OsRng;
    let (unauthorized, _meta) = builder
        .build::<i64>(&mut rng)
        .map_err(|e| RegistryError::Build(format!("build: {e:?}")))?
        .ok_or_else(|| RegistryError::Build("builder produced an empty bundle".into()))?;

    let orchard_digest: [u8; 32] = unauthorized.commitment().into();
    let sighash = v5_shielded_sighash(branch_id, 0, expiry_height, &orchard_digest);

    let proven = unauthorized
        .create_proof(proving_key(), &mut rng)
        .map_err(|e| RegistryError::Build(format!("create_proof: {e:?}")))?;
    let ask = SpendAuthorizingKey::from(spend_key);
    let authorized = proven
        .apply_signatures(&mut rng, sighash, &[ask])
        .map_err(|e| RegistryError::Build(format!("apply_signatures: {e:?}")))?;

    let (tx_bytes, _txid) = orchard_bundle_to_tx_bytes(authorized, branch_id, expiry_height)?;
    Ok(tx_bytes)
}

/// Build a **memo-send** transaction: spend one treasury note, deliver a small
/// dust output carrying `memo` to `recipient`, and return the change to the
/// registry. This is how the registry relays an OTP nonce to a name's current
/// owner (`ZNS:challenge:<name>:<nonce>`) so they can confirm an UPDATE/RELEASE.
///
/// No Name Note is minted — this is a pure value+memo carrier. `value_balance`
/// equals the fee (`funding.value − dust − change`). `change_addr` is the
/// registry self-address; the caller is the policy-gated [`crate::sign::Signer`].
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
) -> Result<Vec<u8>, RegistryError> {
    let ovk = Some(registry_fvk.to_ovk(Scope::External));
    let mut builder = OrchardBuilder::new(BundleType::DEFAULT, funding.anchor);

    // 1. Funding spend (covers dust + fee). Anchor must match the witness root.
    builder
        .add_spend(registry_fvk.clone(), funding.note.clone(), funding.merkle_path.clone())
        .map_err(|e| RegistryError::Build(format!("add_spend: {e:?}")))?;

    // 2. The dust output to the owner, carrying the challenge memo.
    builder
        .add_output(ovk.clone(), recipient, NoteValue::from_raw(dust_zat), memo)
        .map_err(|e| RegistryError::Build(format!("add_output(memo): {e:?}")))?;

    // 3. Change back to the registry.
    if change_zat > 0 {
        builder
            .add_output(ovk, change_addr, NoteValue::from_raw(change_zat), [0u8; 512])
            .map_err(|e| RegistryError::Build(format!("add_output(change): {e:?}")))?;
    }

    let mut rng = OsRng;
    let (unauthorized, _meta) = builder
        .build::<i64>(&mut rng)
        .map_err(|e| RegistryError::Build(format!("build: {e:?}")))?
        .ok_or_else(|| RegistryError::Build("builder produced an empty bundle".into()))?;

    let orchard_digest: [u8; 32] = unauthorized.commitment().into();
    let sighash = v5_shielded_sighash(branch_id, 0, expiry_height, &orchard_digest);

    let proven = unauthorized
        .create_proof(proving_key(), &mut rng)
        .map_err(|e| RegistryError::Build(format!("create_proof: {e:?}")))?;
    let ask = SpendAuthorizingKey::from(spend_key);
    let authorized = proven
        .apply_signatures(&mut rng, sighash, &[ask])
        .map_err(|e| RegistryError::Build(format!("apply_signatures: {e:?}")))?;

    let (tx_bytes, _txid) = orchard_bundle_to_tx_bytes(authorized, branch_id, expiry_height)?;
    Ok(tx_bytes)
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/// Derive the Orchard `(psi, rcm)` pair for a given registration event.
///
/// Thin public wrapper around [`zns_psi_rcm`] for use by callers that need
/// to verify an existing note without constructing a full bundle.
pub fn derive_psi_rcm(
    action: Action,
    name: &str,
    ua: &str,
    prev_rcm: &[u8; 32],
) -> (pallas::Base, pallas::Scalar) {
    zns_psi_rcm(action.as_bytes(), name.as_bytes(), ua.as_bytes(), prev_rcm)
}

/// The `prev_rcm` sentinel for the first action (CLAIM) in a name's chain.
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

    /// Deterministic FVK for tests — uses a fixed zip32 seed.
    fn make_fvk() -> FullViewingKey {
        let seed = [0x42u8; 32];
        let sk = SpendingKey::from_zip32_seed(&seed, 133, zip32::AccountId::ZERO).unwrap();
        FullViewingKey::from(&sk)
    }

    fn test_params<'a>(fvk: FullViewingKey, name: &'a str, ua: &'a str, prev_rcm: [u8; 32]) -> MintParams<'a> {
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
            circuit_version: OrchardCircuitVersion::InsecurePreNu6_2,
        }
    }

    #[test]
    fn build_name_note_claim() {
        let fvk = make_fvk();
        let result = build_name_note(test_params(fvk, "alice", "u1xxx", ZERO_PREV_RCM)).unwrap();

        assert_ne!(result.new_rcm, [0u8; 32]);
        assert_ne!(result.new_psi, [0u8; 32]);
        // A minimal V5 transaction is at least a few hundred bytes.
        assert!(!result.tx_bytes.is_empty());
        // V5 starts with the version header word 0x00000005 | 0x80000000 = 0x80000005 (LE).
        // zcash_primitives writes (version | overwintered_bit) then version_group_id.
        // The first byte of a V5 tx is 0x05.
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
            circuit_version: OrchardCircuitVersion::InsecurePreNu6_2,
        })
        .unwrap();

        assert_ne!(claim.new_rcm, update.new_rcm);
        assert_ne!(claim.tx_bytes, update.tx_bytes);
    }

    #[test]
    fn tx_bytes_start_with_v5_header() {
        let fvk = make_fvk();
        let result = build_name_note(test_params(fvk, "bob", "u1yyy", ZERO_PREV_RCM)).unwrap();
        // V5 version header: overwintered (bit 31) | version 5 => little-endian 0x80000005
        // Bytes: [0x05, 0x00, 0x00, 0x80]
        assert_eq!(&result.tx_bytes[..4], &[0x05, 0x00, 0x00, 0x80]);
    }
}
