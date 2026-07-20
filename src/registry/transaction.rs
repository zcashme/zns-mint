//! Transaction building: constructs an unproven Ironwood bundle from a
//! [`NameNoteRequest`], spending the previous Name Note (if update/release),
//! minting the new one, and self-funding the ZIP-317 fee.
//!
//! Name Notes live in the Ironwood pool (`BundleVersion::ironwood_v3`).
//! Both the Name Note and the fee-funding notes are Ironwood notes — the
//! Treasury funds the Registry via Ironwood, so a single Ironwood bundle
//! carries everything: ZNS spend, ZNS output, funding spends, and change.

use crate::mint::Action;
use crate::registry::authorize::NameNoteRequest;
use crate::registry::state::{Psi, Rcm, Registry};
use transparent::address::TransparentAddress;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

// ---------------------------------------------------------------------------
// Transparent output type
// ---------------------------------------------------------------------------

/// A transparent output for a v6 transaction (e.g. the cold-storage destination
/// of a Treasury auto-sweep). The Treasury UA omits the transparent receiver,
/// so transparent *inputs* are never needed — only outputs.
///
/// Carries a [`TransparentAddress`] (the upstream type) rather than raw script
/// bytes, so [`transparent::builder::TransparentBuilder::add_output`] can be
/// used directly — no `zcash_script` dependency needed.
#[derive(Clone, Debug)]
pub struct TransparentOutput {
    pub address: TransparentAddress,
    pub value: Zatoshis,
}

// ---------------------------------------------------------------------------
// Bundle construction
// ---------------------------------------------------------------------------

/// Assembles an unproven Ironwood bundle to execute a ZNS request.
///
/// Spends the previous Name Note (if update/release) via `add_zns_spend`,
/// mints the new Name Note via `add_zns_output`, and self-funds the ZIP-317
/// fee using the Registry's own Ironwood ZEC reserves.
///
/// The bundle's value balance is asserted to equal the computed fee before
/// returning — a misbalanced transaction must not reach the signing path.
#[allow(clippy::too_many_arguments)]
pub fn build_transaction(
    wallet: &mut crate::wallet::Wallet,
    registry: &Registry,
    orchard_spending_key: &orchard::keys::SpendingKey,
    request: NameNoteRequest,
    exclude: &[orchard::note::Rho],
    target_height: BlockHeight,
) -> Result<
    orchard::Bundle<
        orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>,
        zcash_protocol::value::ZatBalance,
    >,
    &'static str,
> {
    use orchard::builder::BundleType;
    use orchard::bundle::BundleVersion;
    use rand::rngs::OsRng;

    // 1. Get the Ironwood anchor at target_height
    let anchor = wallet
        .ironwood_anchor(target_height)
        .ok()
        .flatten()
        .ok_or("no ironwood anchor at target height")?;

    // 2. Initialize the Ironwood Builder
    let bundle_version = BundleVersion::ironwood_v3();
    let flags = bundle_version.default_flags();

    let mut builder =
        orchard::builder::Builder::new(BundleType::DEFAULT, bundle_version, flags, anchor.into())
            .map_err(|_| "failed to create builder")?;

    let fvk = orchard::keys::FullViewingKey::from(orchard_spending_key);
    let address = fvk.address_at(0u32, orchard::keys::Scope::External);
    let name = request.name();

    let (action, ua_str, prev_commitment) = match &request {
        NameNoteRequest::Claim(b) => (Action::Claim, b.ua.as_str(), None),
        NameNoteRequest::Update(b) => (Action::Update, b.new_ua.as_str(), Some(b.prev_commitment)),
        NameNoteRequest::Release(b) => (Action::Release, "", Some(b.prev_commitment)),
    };

    // 3. Spend previous Name Note if updating or releasing
    //
    // The previous Name Note is an Ironwood note — looked up via
    // `ironwood_notes_for` and witnessed via `ironwood_witness`.
    if action == Action::Update || action == Action::Release {
        let prev_note = wallet
            .ironwood_notes_for(crate::mint::REGISTRY_ACCOUNT)
            .find(|n| {
                if exclude.contains(&n.note.rho()) {
                    return false;
                }
                if let Some((n_name, _, _, _)) = crate::mint::decode_name_note(n.memo.as_array()) {
                    &n_name == name
                } else {
                    false
                }
            })
            .cloned()
            .ok_or("previous name note not found in wallet")?;

        let merkle_path = wallet
            .ironwood_witness(prev_note.position, target_height)
            .ok()
            .flatten()
            .ok_or("witness for previous note not found")?;

        let tip = registry.tip(name).ok_or("tip not found in registry")?;

        builder
            .add_zns_spend(
                fvk.clone(),
                prev_note.note,
                merkle_path.into(),
                tip.rcm.into_scalar(),
                tip.psi.into_base(),
            )
            .map_err(|_| "failed to add zns spend")?;
    }

    // 4. Create new ZNS output
    let (new_rcm, new_psi) = crate::mint::zns_psi_rcm(name, action, ua_str, prev_commitment);

    let rcm = Rcm::from_scalar(new_rcm);
    let psi = Psi::from_base(new_psi);

    let memo = crate::mint::encode_name_note(name, action, ua_str, prev_commitment)
        .ok_or("failed to encode name note memo")?;

    let value = orchard::value::NoteValue::from_raw(0);

    builder
        .add_zns_output(
            Some(fvk.to_ovk(orchard::keys::Scope::External)),
            address,
            value,
            memo,
            rcm.into_scalar(),
            psi.into_base(),
        )
        .map_err(|_| "failed to add zns output")?;

    // 5. Fee Funding — ZIP-317 iterative computation
    //
    // fee = MARGINAL_FEE * max(GRACE_ACTIONS, logical_actions)
    // where logical_actions = max(num_spends, num_outputs) for Ironwood-only.
    //
    // The fee is circular: it depends on the number of funding spends, which
    // depends on how much we need to fund, which depends on the fee. We resolve
    // this iteratively: each extra funding action adds exactly MARGINAL_FEE
    // (5_000 zatoshis) to the fee, so the loop converges in at most 2 steps
    // (any note worth spending has value >> 5_000).
    const MARGINAL_FEE: u64 = 5_000;
    const GRACE_ACTIONS: usize = 2;

    let committed_spends = builder.spends().len();
    let committed_outputs = builder.outputs().len();

    // Collect Ironwood funding notes sorted smallest-first (dust sweep).
    let mut funding_notes: Vec<_> = wallet
        .ironwood_notes_for(crate::mint::REGISTRY_ACCOUNT)
        .filter(|n| !exclude.contains(&n.note.rho()))
        .filter(|n| {
            crate::registry::liquidity::classify_registry_ironwood_note(n)
                == crate::registry::liquidity::RegistryNoteClass::Fee
        })
        .cloned()
        .collect();
    funding_notes.sort_by_key(|n| n.note.value().inner());

    let mut selected_count: usize = 0;
    let mut total_funded: u64 = 0;
    let mut fee: u64;

    loop {
        let num_spends = committed_spends + selected_count;
        let num_outputs = committed_outputs + 1; // +1 for change
        let logical_actions = std::cmp::max(num_spends, num_outputs);
        fee = MARGINAL_FEE * std::cmp::max(GRACE_ACTIONS, logical_actions) as u64;

        if total_funded >= fee {
            break;
        }

        if selected_count >= funding_notes.len() {
            return Err("insufficient funds in Registry account to pay transaction fee");
        }

        let note = &funding_notes[selected_count];
        total_funded += note.note.value().inner();
        selected_count += 1;
    }

    // Add the selected funding notes as standard Ironwood spends.
    for prev_note in funding_notes.iter().take(selected_count) {
        let merkle_path = wallet
            .ironwood_witness(prev_note.position, target_height)
            .ok()
            .flatten()
            .ok_or("witness for funding note not found")?;

        builder
            .add_spend(fvk.clone(), prev_note.note, merkle_path.into())
            .map_err(|_| "failed to add fee spend")?;
    }

    let change = total_funded - fee;
    if change > 0 {
        let change_address = fvk.address_at(0u32, orchard::keys::Scope::Internal);

        // ZIP-302 empty memo: 0xF6 followed by 511 zeros.
        let mut change_memo = [0u8; 512];
        change_memo[0] = 0xF6;

        builder
            .add_output(
                Some(fvk.to_ovk(orchard::keys::Scope::Internal)),
                change_address,
                orchard::value::NoteValue::from_raw(change),
                change_memo,
            )
            .map_err(|_| "failed to add change output")?;
    }

    // 6. Build and verify value balance
    let (bundle, _meta) = builder
        .build::<zcash_protocol::value::ZatBalance>(&mut OsRng)
        .map_err(|_| "failed to build transaction")?
        .ok_or("builder produced no bundle")?;

    // Assert the bundle's value balance equals the intended fee. The Ironwood
    // value balance is (sum of spend values) - (sum of output values). For a
    // correctly balanced transaction, this equals the fee the network will
    // charge. A mismatch means the transaction is misbalanced or the fee was
    // computed wrong — either way it must not be broadcast.
    let actual_fee: i64 = bundle.value_balance().into();
    assert_eq!(
        actual_fee, fee as i64,
        "bundle value balance {} != intended fee {} — transaction is misbalanced",
        actual_fee, fee,
    );

    // Note: the full cryptographic self-verification (proof + commitment) is
    // performed by `verify_proof` in `signing::assemble_and_sign_transaction`.
    // The ZNS payload (rcm, ψ) → cmx path cannot be independently recomputed
    // outside the orchard circuit (it requires the fork's Sinsemilla hash),
    // so `verify_proof` is the authoritative check.

    Ok(bundle)
}
