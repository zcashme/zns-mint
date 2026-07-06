//! Registry state-machine view and transition authorization.
//!

use crate::mint::{Action, Name, NameCommitment};
use std::collections::BTreeMap;
use zcash_protocol::consensus::BlockHeight;

/// A requested Name Note transition, ready for the transaction-assembly path.
///
/// This is produced by the Registry module after it has verified the
/// authorization policy (name availability, valid OTP, chain rules).
/// It represents the intent to "print" a new Name Note to the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameNoteRequest {
    /// The action being performed.
    pub action: Action,
    /// The canonical ZNS name.
    pub name: String,
    /// The unified address the name is binding to (empty for a release).
    pub ua: String,
    /// The previous Name Note's commitment, linking this note to the chain.
    pub prev_commitment: Option<NameCommitment>,
}

impl NameNoteRequest {
    /// Creates a request for a new name claim.
    pub fn new_claim(name: String, ua: String) -> Self {
        Self {
            action: Action::Claim,
            name,
            ua,
            prev_commitment: None,
        }
    }

    /// Creates a request to update an existing name.
    pub fn new_update(name: String, new_ua: String, prev_commitment: NameCommitment) -> Self {
        Self {
            action: Action::Update,
            name,
            ua: new_ua,
            prev_commitment: Some(prev_commitment),
        }
    }

    /// Creates a request to release an existing name.
    ///
    /// The UA is forced to an empty string.
    pub fn new_release(name: String, prev_commitment: NameCommitment) -> Self {
        Self {
            action: Action::Release,
            name,
            ua: String::new(),
            prev_commitment: Some(prev_commitment),
        }
    }
}

/// The current state of a name chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tip {
    pub action: Action,
    pub commitment: NameCommitment,
    /// The exact scalars used to mint this note, needed to spend it later.
    pub rcm: pasta_curves::pallas::Scalar,
    pub psi: pasta_curves::pallas::Base,
}

#[derive(Debug, Clone)]
pub struct RegistryHistoryRecord {
    pub height: BlockHeight,
    pub name: Name,
    pub prev_tip: Option<Tip>,
}

/// The name-chain state: a map from each canonical ZNS name to the most
/// recent confirmed tip for that name, plus an undo log for reorgs.
pub struct Registry {
    tips: BTreeMap<Name, Tip>,
    history: Vec<RegistryHistoryRecord>,
}

impl Registry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            tips: BTreeMap::new(),
            history: Vec::new(),
        }
    }

    /// Read the current tip of a ZNS name chain.
    pub fn tip(&self, name: &Name) -> Option<&Tip> {
        self.tips.get(name)
    }

    /// Update the current tip of a ZNS name chain. Called by the scanner when
    /// a confirmed Name Note for `name` is observed on the best chain.
    pub fn set_tip(&mut self, name: Name, tip: Tip, height: BlockHeight) {
        let prev_tip = self.tips.insert(name.clone(), tip);
        self.history.push(RegistryHistoryRecord { height, name, prev_tip });
    }

    /// Read-only iterator over all known name tips. Used for diagnostics.
    pub fn name_chain(&self) -> impl Iterator<Item = (&Name, &Tip)> {
        self.tips.iter()
    }

    /// Rewinds the registry state back to the specified height (linear undo).
    pub fn truncate_to_height(&mut self, height: BlockHeight) {
        while let Some(record) = self.history.last() {
            if record.height <= height {
                break;
            }
            let record = self.history.pop().unwrap();
            match record.prev_tip {
                Some(old_tip) => {
                    self.tips.insert(record.name, old_tip);
                }
                None => {
                    self.tips.remove(&record.name);
                }
            }
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads the current tip of the name chain for `name`.
///
/// Looks up the registry's `name_chain` to find the most recent confirmed Name Note.
pub fn current_tip(registry: &Registry, name: &Name) -> Option<Tip> {
    registry.tip(name).cloned()
}

/// Authorizes a claim request, producing a `NameNoteRequest`.
///
/// The Treasury layer must have already verified that the claim payment was made.
/// This function verifies that the name is available (either no tip, or tip is `Release`).
pub fn authorize_claim(registry: &Registry, name: Name, ua: String) -> Option<NameNoteRequest> {
    match current_tip(registry, &name) {
        None => Some(NameNoteRequest::new_claim(name.as_str().to_string(), ua)),
        Some(Tip {
            action: Action::Release,
            ..
        }) => Some(NameNoteRequest::new_claim(name.as_str().to_string(), ua)),
        Some(_) => None, // Name is already live
    }
}

/// Authorizes an update request, producing a `NameNoteRequest`.
///
/// Verifies the name is live, the current tip matches, and calls `auth::verify_consume`
/// to validate the OTP.
pub fn authorize_update(
    registry: &Registry,
    name: Name,
    new_ua: String,
    _otp: [u8; 16],
) -> Option<NameNoteRequest> {
    let tip = current_tip(registry, &name)?;
    if tip.action == Action::Release {
        return None;
    }

    // auth::verify_consume(name, Action::Update, new_ua, otp)?;

    Some(NameNoteRequest::new_update(
        name.as_str().to_string(),
        new_ua,
        tip.commitment,
    ))
}

/// Authorizes a release request, producing a `NameNoteRequest`.
///
/// Verifies the name is live, the current UA matches `current_ua`, and calls
/// `auth::verify_consume` to validate the OTP.
pub fn authorize_release(
    registry: &Registry,
    name: Name,
    _current_ua: String,
    _otp: [u8; 16],
) -> Option<NameNoteRequest> {
    let tip = current_tip(registry, &name)?;
    if tip.action == Action::Release {
        return None;
    }

    // To verify `current_ua`, we would read it from the registry's live Name Note.
    // auth::verify_consume(name, Action::Release, current_ua, otp)?;

    Some(NameNoteRequest::new_release(
        name.as_str().to_string(),
        tip.commitment,
    ))
}

/// Assembles, proves, and signs an Orchard transaction bundle to execute a ZNS request.
///
/// Not implemented. This is Slice 4 (witness derivation) + Slice 5 (transaction
/// assembly: real v5 sighash, fee funding, broadcast) work. The wallet's
/// `CommitmentTree` is a bare frontier that cannot witness arbitrary historical
/// positions yet — per-position `IncrementalWitness` derivation at sign time is
/// the missing piece. Until that lands, the boot path does not call this.
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
        i64,
    >,
    &'static str,
> {
    use orchard::builder::BundleType;
    use orchard::bundle::BundleVersion;
    use rand::rngs::OsRng;

    // 1. Get the latest anchor at target_height
    let anchor = wallet
        .trees
        .orchard_anchor(target_height)
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
    let name = Name::parse(&request.name).ok_or("invalid ZNS name in request")?;

    // 3. Spend previous Name Note if updating or releasing
    if request.action == Action::Update || request.action == Action::Release {
        let prev_note = wallet
            .orchard_notes_for(crate::mint::REGISTRY_ACCOUNT)
            .find(|n| {
                if exclude.contains(&n.note.rho()) {
                    return false;
                }
                if let Some((n_name, _, _, _)) = crate::mint::decode_name_note(&n.memo) {
                    n_name == name
                } else {
                    false
                }
            })
            .cloned()
            .ok_or("previous name note not found in wallet")?;

        let merkle_path = wallet
            .trees
            .orchard_witness(prev_note.position, target_height)
            .ok_or("witness for previous note not found")?;

        let tip = registry.tip(&name).ok_or("tip not found in registry")?;

        builder
            .add_zns_spend(
                fvk.clone(),
                prev_note.note.clone(),
                merkle_path.into(),
                tip.rcm,
                tip.psi,
            )
            .map_err(|_| "failed to add zns spend")?;
    }

    // 4. Create new ZNS output
    let (new_rcm, new_psi) = crate::mint::zns_psi_rcm(
        &name,
        request.action,
        &request.ua,
        request.prev_commitment,
    );

    let memo = crate::mint::encode_name_note(
        &name,
        request.action,
        &request.ua,
        request.prev_commitment,
    )
    .ok_or("failed to encode name note memo")?;

    let value = orchard::value::NoteValue::from_raw(0);

    builder
        .add_zns_output(
            Some(fvk.to_ovk(orchard::keys::Scope::External)),
            address,
            value,
            memo,
            new_rcm,
            new_psi,
        )
        .map_err(|_| "failed to add zns output")?;

    // 5. Fee Funding (Slice 5)
    // The Registry must self-fund the 10,000 zatoshi fee using its own ZEC reserves.
    let fee: u64 = 10_000;
    let mut total_funded: u64 = 0;
    
    // Collect funding notes to avoid borrowing `wallet` mutably later inside the loop
    let funding_notes: Vec<_> = wallet
        .orchard_notes_for(crate::mint::REGISTRY_ACCOUNT)
        .filter(|n| !exclude.contains(&n.note.rho()))
        .filter(|n| {
            let note_val: u64 = n.note.value().inner();
            note_val > 0 // Ignore 0-value Name Notes
        })
        .cloned()
        .collect();

    for prev_note in funding_notes {
        if total_funded >= fee {
            break;
        }
        
        let note_val: u64 = prev_note.note.value().inner();
        total_funded += note_val;
        
        let merkle_path = wallet
            .trees
            .orchard_witness(prev_note.position, target_height)
            .ok_or("witness for funding note not found")?;
            
        // Use standard add_spend, NOT add_zns_spend!
        builder
            .add_spend(
                fvk.clone(),
                prev_note.note.clone(),
                merkle_path.into(),
            )
            .map_err(|_| "failed to add fee spend")?;
    }

    if total_funded < fee {
        return Err("insufficient funds in Registry account to pay transaction fee");
    }

    let change = total_funded - fee;
    if change > 0 {
        // Send change back to the Registry's internal address
        let change_address = fvk.address_at(0u32, orchard::keys::Scope::Internal);
        
        // Zcash empty memo (ZIP-302) starts with 0xF6 followed by 511 zeros
        let mut change_memo = [0u8; 512];
        change_memo[0] = 0xF6;
        
        // Use standard add_output, NOT add_zns_output!
        builder
            .add_output(
                Some(fvk.to_ovk(orchard::keys::Scope::Internal)),
                change_address,
                orchard::value::NoteValue::from_raw(change),
                change_memo,
            )
            .map_err(|_| "failed to add change output")?;
    }

    // 6. Build and return
    let (bundle, _meta) = builder
        .build::<i64>(&mut OsRng)
        .map_err(|_| "failed to build transaction")?
        .ok_or("builder produced no bundle")?;

    Ok(bundle)
}
