//! Shared protocol logic for ZNS minting and wallet operations.

pub mod mtp;
pub mod note;
pub mod otp;
pub mod presale;
pub mod pricing;
pub mod registry;

pub mod treasury;

/// The mint's authoritative position on the Zcash chain.
pub use zcash_client_backend::data_api::BlockMetadata as ChainTip;

// The Name Note type and its codec.
pub use note::{decrypt_name_notes, DecryptedNameNote, Expiry, NameNote, Term};
pub use time::Timestamp;

pub use zcash_keys::address::UnifiedAddress;

use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zip32::AccountId;

use otp::OtpCode;
use presale::AccessCode;

pub const TREASURY_ACCOUNT: AccountId = AccountId::const_from_u32(0);
pub const REGISTRY_ACCOUNT: AccountId = AccountId::const_from_u32(1);

/// First block the mint observes; everything before it is pre-birth.
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
pub const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(3_400_000);

#[cfg(all(feature = "testnet", not(feature = "regtest")))]
pub const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(4_338_933);

/// Regtest birth: first block after the harness's NU6.3 activation (height 4).
#[cfg(feature = "regtest")]
pub const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(4);

/// The liveness interval: one Julian year (365.25 days), in seconds.
pub const LIVENESS_INTERVAL: i64 = 31_557_600;

/// Liveness challenge lead: how far before `release_deadline` the mint
/// begins asking the current controller to prove control. Independent of
/// `D_OTP`: the notification lead is not the response window. Seven days.
pub const CHALLENGE_LEAD: i64 = 7 * 24 * 60 * 60;

/// Minimum cadence between successive liveness challenges for the same
/// current record. Bounds challenge issuance during the lead window so a
/// silent controller sees at most one relay per day, not one per OTP TTL.
pub const LIVENESS_RETRY_COOLDOWN: i64 = 24 * 60 * 60;

/// Minimum Treasury Ironwood balance after boot sync (0.002 ZEC).
pub const MIN_TREASURY_BALANCE: u64 = 200_000;

/// The longest name the wire accepts.
pub const MAX_NAME_LEN: usize = 63;

/// Decodes a controller Unified Address — known receivers only, and
/// the Orchard family among them (relays deliver and echo over it).
/// The ZIP-316 receiver kinds are fixed-size, so such an address is
/// bounded by construction: inside every memo it is ever re-embedded
/// into. Unknown receivers are unbounded by design; refusing them is
/// the memo budget.
pub fn decode_controller_ua<P: Parameters>(network: &P, ua_str: &str) -> Option<UnifiedAddress> {
    let ua = match zcash_keys::address::Address::decode(network, ua_str)? {
        zcash_keys::address::Address::Unified(ua) => ua,
        _ => return None,
    };
    (ua.unknown().is_empty() && ua.orchard().is_some()).then_some(ua)
}

/// ZNS action kinds.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    /// Point a name to an address
    Claim,
    /// Rebinds a name to a new address
    Update,
    /// Terminates a name's linkage to an address
    Release,
}

impl Action {
    /// Returns the canonical ASCII verb for this action.
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::Claim => "claim",
            Action::Update => "update",
            Action::Release => "release",
        }
    }

    /// Parses the canonical ASCII verb — the inverse of [`Self::as_str`].
    pub fn parse(verb: &str) -> Option<Self> {
        match verb {
            "claim" => Some(Action::Claim),
            "update" => Some(Action::Update),
            "release" => Some(Action::Release),
            _ => None,
        }
    }

    /// True when this action terminates a registration.
    pub const fn is_release(self) -> bool {
        matches!(self, Action::Release)
    }

    /// True when this action creates a fresh registration (spends an
    /// anchor, not a predecessor).
    pub const fn is_claim(self) -> bool {
        matches!(self, Action::Claim)
    }

    /// True when this action rebinds an existing registration to a new
    /// address or term.
    pub const fn is_update(self) -> bool {
        matches!(self, Action::Update)
    }

    /// True when this action spends the registration's current note as
    /// its authority; a claim spends an anchor instead.
    pub const fn needs_predecessor(self) -> bool {
        matches!(self, Action::Update | Action::Release)
    }
}

/// An authorized transition the loop is about to assemble.
///
/// Built from [`treasury::parse_request`];
/// memo bytes stay on that parser. Claims carry a term (`forever` or
/// `<N>y`) and an optional leading pre-sale access code; updates carry
/// `none` (carried forward), `<N>y`, or `forever` — the upgrade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Create a new registration; the term slot is never empty.
    /// `code` is the leading pre-sale slot when present (exactly six
    /// ASCII digits); the codeless wire form stays byte-identical to
    /// `ZNS:claim:<term>:<name>:<ua>`.
    Claim {
        name: Name,
        ua: UnifiedAddress,
        term: Term,
        code: Option<AccessCode>,
    },
    /// Rebind; `None` carries the expiry forward, `Some(Years)` extends
    /// it, `Some(Forever)` upgrades it to no fixed expiration.
    Update {
        name: Name,
        ua: UnifiedAddress,
        term: Option<Term>,
    },
    Release {
        name: Name,
        ua: UnifiedAddress,
    },
}

/// A mint-issued challenge to a wallet, proving that the wallet controls a name via shielded-memos.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub code: OtpCode,
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
}

impl Challenge {
    /// Encodes the challenge memo. Claims are never challenged, so
    /// [`Action::is_claim`] guards the lane.
    pub fn encode<P: Parameters>(&self, network: &P) -> Option<[u8; 512]> {
        if self.action.is_claim() {
            return None;
        }
        let verb = self.action.as_str();

        let ua_field = self.ua.encode(network);
        let otp_digits = self.code.digits();
        let mut memo = [0u8; 512];
        let mut offset = 0usize;
        for field in [
            b"ZNS:otp:".as_slice(),
            otp_digits.as_slice(),
            b":".as_slice(),
            self.name.as_str().as_bytes(),
            b":".as_slice(),
            verb.as_bytes(),
            b":".as_slice(),
            ua_field.as_bytes(),
        ] {
            let end = offset + field.len();
            memo[offset..end].copy_from_slice(field);
            offset = end;
        }
        Some(memo)
    }

    /// Decodes a relay sentence. The verb is `update` or `release` —
    /// challenges never claim — and the UA must carry an Orchard-family
    /// receiver.
    pub fn decode<P: Parameters>(network: &P, memo: &[u8; 512]) -> Option<Self> {
        let end = memo.iter().position(|&b| b == 0).unwrap_or(memo.len());
        if memo[end..].iter().any(|&b| b != 0) {
            return None;
        }
        let text = std::str::from_utf8(&memo[..end]).ok()?;

        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() != 6 || parts[0] != "ZNS" || parts[1] != "otp" {
            return None;
        }

        let digits = parts[2].as_bytes();
        if digits.len() != 6 || !digits.iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let code = OtpCode::from_digits(digits.try_into().ok()?)?;

        let name = Name::parse(parts[3])?;
        // Challenges never claim: parse the verb, then refuse claims.
        let action = Action::parse(parts[4]).filter(|action| !action.is_claim())?;

        let ua = decode_controller_ua(network, parts[5])?;

        Some(Self {
            code,
            name,
            action,
            ua,
        })
    }
}

/// What a user said to the Treasury, in the shape each consumer takes.
/// Intake classifies once, at block application; the drain decides.
#[derive(Clone, Debug)]
pub enum MintInbound {
    /// A request — what `authorize` takes.
    Request(Request),
    /// An OTP respond — the relay memo returned; what `awaiting` takes.
    Echo(Challenge),
    /// A payment with no parseable message: the drain logs it once and
    /// the sweep keeps the value; the txid names it in the log.
    Unrecognized(TxId),
}

/// A ZNS name-chain commitment — the trapdoor that links consecutive Name Notes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameCommitment(orchard::note::NoteCommitTrapdoor);

impl NameCommitment {
    /// Wraps a `NoteCommitTrapdoor` derived via [`NameNote::rcm`].
    pub fn from_inner(inner: orchard::note::NoteCommitTrapdoor) -> Self {
        Self(inner)
    }

    /// Unwraps back to the upstream type for the `unsafe-zns` builder surface.
    pub fn into_inner(self) -> orchard::note::NoteCommitTrapdoor {
        self.0
    }

    /// Deserializes from the canonical 32-byte little-endian representation.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        orchard::note::NoteCommitTrapdoor::from_bytes(bytes)
            .into_option()
            .map(Self)
    }

    /// Serializes to the canonical 32-byte little-endian representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// A ZcashName
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(String);

impl Name {
    /// Attempts to parse a string into a valid ZNS name.
    pub fn parse(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_NAME_LEN {
            return None;
        }
        if bytes.iter().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9')) {
            Some(Self(s.to_string()))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Block application
// ---------------------------------------------------------------------------

/// Applies one verified canonical successor to every faculty: scan, clock,
/// Registry law, wallet commit, Treasury intake, Name Note storage, cursor.
/// Never fetches, never broadcasts; `main` passes the live queues, boot
/// passes scratch ones.
#[allow(clippy::too_many_arguments)]
pub fn apply_block<P: Parameters + Send + 'static>(
    network: &P,
    registry_keys: &crate::key::RegistryKeys,
    treasury_keys: &crate::key::TreasuryKeys,
    from_state: &zcash_client_backend::data_api::chain::ChainState,
    block: zcash_primitives::block::Block,
    height: BlockHeight,
    wallet: &mut crate::wallet::Wallet<P>,
    registry: &mut registry::Registry,
    mtp: &mut mtp::MtpTracker,
    cursor: &mut ChainTip,
    requests: &mut treasury::RequestQueue,
) {
    use std::collections::BTreeMap;
    use std::convert::Infallible;

    use incrementalmerkletree::Position;
    use zcash_client_backend::scanning::full::{decrypt_block, scan_block};
    use zcash_client_backend::scanning::Nullifiers;

    assert_eq!(
        from_state.block_height(),
        cursor.block_height(),
        "FATAL: previous chain-state height mismatch"
    );
    assert_eq!(
        from_state.block_hash(),
        cursor.block_hash(),
        "FATAL: previous chain state does not describe the applied cursor"
    );
    assert_eq!(
        block.header().prev_block,
        cursor.block_hash(),
        "FATAL: fetched block does not continue the applied cursor"
    );

    let block_time = block.header().time;
    let candidates = decrypt_name_notes(network, &block, registry_keys);
    let treasury_memos = note::decrypt_treasury_memos(&block, treasury_keys);

    let (header, batches) = decrypt_block(network, block, wallet.scanning_keys());
    let nullifiers =
        Nullifiers::unspent(wallet).expect("FATAL: wallet could not expose its unspent nullifiers");
    let scanned = scan_block(
        network,
        height,
        &header,
        batches,
        wallet.scanning_keys(),
        &nullifiers,
        Some(&*cursor),
        |_| {
            Ok::<
                Option<(
                    zip32::AccountId,
                    Option<transparent::keys::TransparentKeyScope>,
                )>,
                Infallible,
            >(None)
        },
    )
    .expect("FATAL: a canonical block failed deterministic wallet scanning");

    let mut next_mtp = mtp.clone();
    next_mtp.update(height, block_time);
    let block_mtp = next_mtp
        .current()
        .expect("FATAL: MTP unavailable after applying a block");

    // The confirmation pass: the scanner's transactions in canonical
    // order, the ZNS decryption lane joined on txid — the
    // authentication boundary — each candidate offered to the Registry.
    // Sequencing is here; the law is the Registry's.
    let mut notes_by_tx: BTreeMap<TxId, Vec<usize>> = BTreeMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        notes_by_tx.entry(candidate.txid).or_default().push(index);
    }
    for notes in notes_by_tx.values_mut() {
        notes.sort_by_key(|index| candidates[*index].action_index);
    }

    let mut accepted_name_notes = Vec::new();
    for wtx in scanned.transactions() {
        let txid = wtx.txid();
        let nfs: Vec<orchard::note::Nullifier> = wtx
            .ironwood_spends()
            .iter()
            .map(|spend| *spend.nf())
            .collect();
        let registry_outputs: Vec<_> = wtx
            .ironwood_outputs()
            .iter()
            .filter(|output| *output.account_id() == REGISTRY_ACCOUNT)
            .collect();

        // Ceremony filling: zero-value Registry outputs join the pool in
        // canonical order while below standing size.
        for output in &registry_outputs {
            if output.note().0.value().inner() == 0 {
                if let Some(nf) = output.nf() {
                    registry.adopt_anchor(height, *nf);
                }
            }
        }

        let spends_claim_anchor = nfs.iter().any(|nf| registry.anchor_pool().contains(nf));
        let spends_record = !registry.names_spent_by(&nfs).is_empty();
        let notes: &[usize] = notes_by_tx.get(&txid).map(Vec::as_slice).unwrap_or(&[]);
        match notes {
            [] => {
                assert!(
                    !(spends_claim_anchor || spends_record),
                    "Registry authority was spent without a Name Note successor"
                );
            }
            [index] => {
                let candidate = &candidates[*index];
                let action = candidate.payload.action();
                let accepted = if action.is_claim() {
                    // The successor anchor: a backed claim creates
                    // exactly one zero-value Registry output.
                    let successor = if registry_outputs.len() == 1
                        && registry_outputs[0].note().0.value().inner() == 0
                    {
                        registry_outputs[0].nf().copied()
                    } else {
                        None
                    };
                    registry.accept_claim(
                        network,
                        &candidate.payload,
                        candidate.nullifier,
                        successor,
                        &nfs,
                        height,
                        block_mtp,
                    )
                } else {
                    assert!(
                        registry_outputs.is_empty(),
                        "update/release must not create a claim anchor"
                    );
                    match action {
                        Action::Update => registry.accept_update(
                            network,
                            &candidate.payload,
                            candidate.nullifier,
                            &nfs,
                            height,
                            block_mtp,
                        ),
                        Action::Release => registry.accept_release(
                            network,
                            &candidate.payload,
                            candidate.nullifier,
                            &nfs,
                            height,
                            block_mtp,
                        ),
                        Action::Claim => unreachable!("claims are routed above"),
                    }
                };
                if accepted {
                    accepted_name_notes.push(*index);
                }
            }
            _ => {
                if spends_claim_anchor || spends_record {
                    panic!(
                        "mint produced multiple Name Notes in one transaction \
                         — assembly creates exactly one"
                    );
                }
            }
        }
    }

    let ironwood_start = scanned
        .ironwood()
        .final_tree_size()
        .checked_sub(
            u32::try_from(scanned.ironwood().commitments().len())
                .expect("Ironwood block action count fits u32"),
        )
        .expect("FATAL: scanner returned an impossible Ironwood tree size");
    let accepted_name_notes = accepted_name_notes
        .into_iter()
        .map(|index| {
            let candidate = &candidates[index];
            let position = Position::from(
                u64::from(ironwood_start)
                    + u64::try_from(candidate.ordinal).expect("Name Note ordinal fits u64"),
            );
            (index, position)
        })
        .collect::<Vec<_>>();
    let next_metadata = scanned.to_block_metadata();

    // Accepted Name Note commitments are marked at the commit — the
    // scanner cannot decrypt them, so they would otherwise enter the
    // tree Ephemeral, prune with the checkpoints, and leave the note
    // without a witness.
    let marks: Vec<orchard::tree::MerkleHashOrchard> = accepted_name_notes
        .iter()
        .map(|(index, _)| orchard::tree::MerkleHashOrchard::from_cmx(&candidates[*index].cmx))
        .collect();
    wallet
        .put_blocks_marked(from_state, vec![scanned], &marks)
        .expect("FATAL: wallet block commit failed");
    // Upstream's ScannedBlock drops note plaintexts; the Treasury
    // lane's memos were decrypted above. Decoded once, here, they
    // are recorded as the requests they carry — nothing is stored
    // for later re-reading; the block is the durable source,
    // refetched on every application.
    // Intake classifies; the drain decides. An echo is the relay memo
    // itself, byte-for-byte, routed by Challenge::decode — the wire never
    // carries an OTP on a request. A memo that parses to nothing is a
    // payment with no message; it rides the queue like anything else.
    for (txid, _action_index, paid, memo) in treasury_memos {
        let inbound = if let Some(echo) = Challenge::decode(network, &memo) {
            MintInbound::Echo(echo)
        } else {
            match treasury::parse_request(network, &memo) {
                Some(request) => MintInbound::Request(request),
                None => MintInbound::Unrecognized(txid),
            }
        };
        requests.record(inbound, paid, height);
    }
    for (index, position) in accepted_name_notes {
        let candidate = &candidates[index];
        wallet
            .store_name_note(
                height,
                position,
                candidate.txid,
                candidate.action_index,
                candidate.note,
                candidate.nullifier,
                candidate.ephemeral_key.clone(),
                candidate.memo,
            )
            .expect("FATAL: Name Note disagreed with applied wallet state");
    }
    *mtp = next_mtp;
    *cursor = next_metadata;

    tracing::debug!(
        height = u32::from(cursor.block_height()),
        hash = %cursor.block_hash(),
        "canonical block applied"
    );
}
