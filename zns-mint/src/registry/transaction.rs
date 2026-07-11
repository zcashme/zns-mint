//! Transaction building: constructs an unproven Orchard bundle from a
//! [`NameNoteRequest`], spending the previous Name Note (if update/release),
//! minting the new one, and self-funding the ZIP-317 fee.

use crate::mint::{Action, Name};
use crate::registry::authorize::NameNoteRequest;
use crate::registry::state::{Rcm, Psi, Registry};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

// ---------------------------------------------------------------------------
// Newtypes for transparent outputs
// ---------------------------------------------------------------------------

/// A Bitcoin/Zcash scriptPubKey — the output script that encodes the
/// spending conditions for a transparent output. Newtype over `Vec<u8>` to
/// distinguish a script from arbitrary bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptPubKey(Vec<u8>);

impl ScriptPubKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// A transparent output for a v5 transaction (e.g. the cold-storage destination
/// of a Treasury auto-sweep). The Treasury UA omits the transparent receiver,
/// so transparent *inputs* are never needed — only outputs.
#[derive(Clone, Debug)]
pub struct TransparentOutput {
    pub script_pubkey: ScriptPubKey,
    pub value: Zatoshis,
}

// ---------------------------------------------------------------------------
// Bundle construction
// ---------------------------------------------------------------------------

/// Assembles an unproven Orchard bundle to execute a ZNS request.
///
/// Spends the previous Name Note (if update/release) via `add_zns_spend`,
/// mints the new Name Note via `add_zns_output`, and self-funds the ZIP-317
/// fee using the Registry's own ZEC reserves.
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

    // 1. Get the latest anchor at target_height
    let anchor = wallet
        .orchard_anchor(target_height)
        .ok()
        .flatten()
        .ok_or("no orchard anchor at target height")?;

    // 2. Initialize the Builder
    let bundle_version = BundleVersion::orchard_v2();
    let flags = bundle_version.default_flags();

    let mut builder = orchard::builder::Builder::new(
        BundleType::DEFAULT,
        bundle_version,
        flags,
        anchor.into(),
    )
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
    if action == Action::Update || action == Action::Release {
        let prev_note = wallet
            .orchard_notes_for(crate::mint::REGISTRY_ACCOUNT)
            .find(|n| {
                if exclude.contains(&n.note.rho()) {
                    return false;
                }
                if let Some((n_name, _, _, _)) =
                    crate::mint::decode_name_note(n.memo.as_array())
                {
                    &n_name == name
                } else {
                    false
                }
            })
            .cloned()
            .ok_or("previous name note not found in wallet")?;

        let merkle_path = wallet
            .orchard_witness(prev_note.position, target_height)
            .ok()
            .flatten()
            .ok_or("witness for previous note not found")?;

        let tip = registry.tip(name).ok_or("tip not found in registry")?;

        builder
            .add_zns_spend(
                fvk.clone(),
                prev_note.note.clone(),
                merkle_path.into(),
                tip.rcm.into_scalar(),
                tip.psi.into_base(),
            )
            .map_err(|_| "failed to add zns spend")?;
    }

    // 4. Create new ZNS output
    let (new_rcm, new_psi) = crate::mint::zns_psi_rcm(
        name,
        action,
        ua_str,
        prev_commitment,
    );

    let rcm = Rcm::from_scalar(new_rcm);
    let psi = Psi::from_base(new_psi);

    let memo = crate::mint::encode_name_note(
        name,
        action,
        ua_str,
        prev_commitment,
    )
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
    // where logical_actions = max(num_spends, num_outputs) for Orchard-only.
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

    // Collect funding notes sorted smallest-first (dust sweep).
    let mut funding_notes: Vec<_> = wallet
        .orchard_notes_for(crate::mint::REGISTRY_ACCOUNT)
        .filter(|n| !exclude.contains(&n.note.rho()))
        .filter(|n| n.note.value().inner() > 0)
        .cloned()
        .collect();
    funding_notes.sort_by_key(|n| n.note.value().inner());

    let mut selected_count: usize = 0;
    let mut total_funded: u64 = 0;
    let mut fee: u64 = 0;

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

    // Add the selected funding notes as standard Orchard spends.
    for i in 0..selected_count {
        let prev_note = &funding_notes[i];
        let merkle_path = wallet
            .orchard_witness(prev_note.position, target_height)
            .ok()
            .flatten()
            .ok_or("witness for funding note not found")?;

        builder
            .add_spend(fvk.clone(), prev_note.note.clone(), merkle_path.into())
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

    // Assert the bundle's value balance equals the intended fee. The orchard
    // value balance is (sum of spend values) - (sum of output values). For a
    // correctly balanced transaction, this equals the fee the network will
    // charge. A mismatch means the transaction is misbalanced or the fee was
    // computed wrong — either way it must not be broadcast.
    let actual_fee: i64 = bundle
        .value_balance()
        .try_into()
        .map_err(|_| "value balance overflow")?;
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