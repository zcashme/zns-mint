//! Shared protocol logic for ZNS minting and wallet operations.

pub mod mtp;
pub mod note;
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

use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::memo::{Memo, MemoBytes};
use zcash_protocol::value::Zatoshis;
use zip32::AccountId;

use sapling::circuit::{OutputParameters, SpendParameters};
use tokio::sync::mpsc;

use crate::wallet::Wallet;
use crate::zcash::{CanonicalBlockSource, ChainClient, MempoolChangeKind, MempoolSession};
use crate::TreasuryKeys;

use note::NameNoteQueue;
use presale::AccessCode;
use pricing::Oracle;
use registry::Registry;
use treasury::{OtpChallenge, OtpCode, OtpQueue};

pub const TREASURY_ACCOUNT: AccountId = AccountId::const_from_u32(0);
pub const REGISTRY_ACCOUNT: AccountId = AccountId::const_from_u32(1);

/// The liveness interval: one Julian year (365.25 days), in seconds.
pub const LIVENESS_INTERVAL: i64 = 31_557_600;

/// Minimum Treasury Ironwood balance after boot sync (0.002 ZEC).
pub const MIN_TREASURY_BALANCE: u64 = 200_000;

/// The longest name a memo accepts.
pub const MAX_NAME_LEN: usize = 63;

/// Decodes a controller UA: known receivers only, Orchard among them.
fn decode_controller_ua<P: Parameters>(network: &P, ua_str: &str) -> Option<UnifiedAddress> {
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
/// Built by the Treasury memo grammar (`Request::decode`); memo bytes
/// stay on that parser. Claims carry a term (`forever` or `<N>y`) and
/// an optional leading pre-sale access code; updates carry `none`
/// (carried forward), `<N>y`, or `forever` — the upgrade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Create a new registration; the term slot is never empty.
    /// `code` is the leading pre-sale slot when present (exactly six
    /// ASCII digits); the codeless form stays byte-identical to
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

impl Request {
    /// Parses a request memo:
    ///
    /// - `ZNS:claim:<term>:<name>:<ua>`, or with a six-digit pre-sale
    ///   code leading: `ZNS:claim:<code>:<term>:<name>:<ua>`
    /// - `ZNS:update:<none | <N>y | forever>:<name>:<ua>`
    /// - `ZNS:release:<name>:<ua>`
    fn decode<P: Parameters>(network: &P, memo: &MemoBytes) -> Option<Request> {
        let text = match Memo::try_from(memo).ok()? {
            Memo::Text(text) => text,
            _ => return None,
        };

        let mut fields = text.split(':');
        if fields.next()? != "ZNS" {
            return None;
        }
        let action = Action::parse(fields.next()?)?;

        // Claims may lead with a pre-sale code; the discriminator is whether
        // the next field is a term. Updates say `none`, `<N>y`, or `forever`.
        let (claim_code, term) = match action {
            Action::Claim => {
                let first = fields.next()?;
                if first.is_empty() {
                    return None;
                }
                if let Some(term) = Term::parse(first) {
                    (None, Some(term))
                } else {
                    let code = AccessCode::parse(first)?;
                    let term = Term::parse(fields.next()?)?;
                    (Some(code), Some(term))
                }
            }
            Action::Update => {
                let term = match fields.next()? {
                    "none" => None,
                    "forever" => Some(Term::Forever),
                    field => Some(Term::parse(field)?),
                };
                (None, term)
            }
            Action::Release => (None, None),
        };

        let name = Name::parse(fields.next()?)?;
        let ua_str = fields.next()?;
        if ua_str.is_empty() || fields.next().is_some() {
            return None;
        }
        let ua = decode_controller_ua(network, ua_str)?;

        Some(match (action, term) {
            (Action::Claim, Some(term)) => Request::Claim {
                name,
                ua,
                term,
                code: claim_code,
            },
            (Action::Update, _) => Request::Update { name, ua, term },
            (Action::Release, _) => Request::Release { name, ua },
            // A claim always carries a term.
            (Action::Claim, None) => unreachable!("claims always carry a term"),
        })
    }
}

/// A mint-issued challenge to a wallet, proving that the wallet controls a name via shielded-memos.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtpMemo {
    pub code: OtpCode,
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
}

impl OtpMemo {
    /// Encodes the challenge memo; claims are never challenged.
    pub fn encode<P: Parameters>(&self, network: &P) -> Option<MemoBytes> {
        if self.action.is_claim() {
            return None;
        }
        let otp: String = self.code.digits().into_iter().map(|b| b as char).collect();
        let text = format!(
            "ZNS:otp:{otp}:{}:{}:{}",
            self.name.as_str(),
            self.action.as_str(),
            self.ua.encode(network),
        );
        // `from_bytes` pads; the UA guard bounds the length.
        MemoBytes::from_bytes(text.as_bytes()).ok()
    }

    /// Decodes a relay sentence; claims never appear.
    fn decode<P: Parameters>(network: &P, memo: &MemoBytes) -> Option<Self> {
        let text = match Memo::try_from(memo).ok()? {
            Memo::Text(text) => text,
            _ => return None,
        };

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
/// Classified once, at block application; the deciding pass resolves.
#[derive(Clone, Debug)]
pub enum MintInbound {
    /// A request — a user's proposed transition, decoded from a Treasury
    /// memo; the Registry's `authorize_*` family rules on it.
    Request(Request),
    /// An OTP consume — the relay memo returned; what `awaiting` takes.
    Echo(OtpMemo),
    /// A payment with no parseable message: the deciding pass logs it once and
    /// the sweep keeps the value; the queue names it by its txid.
    Unrecognized,
}

impl MintInbound {
    /// Classifies one Treasury memo: echo, request, or unrecognized
    /// payment. Called once per memo, at block application.
    pub fn decode<P: Parameters>(network: &P, memo: &MemoBytes) -> Self {
        if let Some(echo) = OtpMemo::decode(network, memo) {
            Self::Echo(echo)
        } else if let Some(request) = Request::decode(network, memo) {
            Self::Request(request)
        } else {
            Self::Unrecognized
        }
    }
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
/// Registry law, wallet commit, Treasury decode, Name Note storage, cursor.
/// Returns Treasury arrivals for the run loop to route; boot discards them.
/// Before birthday, applies only wallet history, clock, and cursor.
/// Never fetches, never broadcasts.
#[allow(clippy::too_many_arguments)]
pub fn apply_block<P: Parameters + Send + 'static>(
    network: &P,
    birthday: BlockHeight,
    registry_keys: &crate::RegistryKeys,
    treasury_keys: &crate::TreasuryKeys,
    from_state: &zcash_client_backend::data_api::chain::ChainState,
    block: zcash_primitives::block::Block,
    height: BlockHeight,
    wallet: &mut crate::wallet::Wallet<P>,
    registry: &mut registry::Registry,
    mtp: &mut mtp::MtpTracker,
    cursor: &mut ChainTip,
) -> Vec<(TxId, MintInbound, Zatoshis)> {
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

    let expiry_by_txid: BTreeMap<TxId, BlockHeight> = block
        .vtx()
        .iter()
        .map(|tx| (tx.txid(), tx.expiry_height()))
        .collect();
    let block_time = block.header().time;
    let (candidates, treasury_memos) = if height >= birthday {
        (
            decrypt_name_notes(network, &block, registry_keys),
            note::decrypt_treasury_memos(&block, treasury_keys),
        )
    } else {
        (Vec::new(), Vec::new())
    };

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

    // The confirmation pass: the scanner's transactions in block order.
    // Two claims for one name in the same block: the lower vtx is
    // offered first and wins. The loser's payment is not returned.
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
        if height < birthday {
            continue;
        }
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

        // The keygen transaction carries every standing anchor and no
        // name note. A zero-value note in any other transaction does not
        // join. A claim's successor still enters through `accept_claim`.
        let name_notes = notes_by_tx.get(&txid).map(Vec::len).unwrap_or(0);
        let ceremony: Vec<_> = registry_outputs
            .iter()
            .filter(|output| output.note().0.value().inner() == 0)
            .filter_map(|output| output.nf().copied())
            .collect();
        if registry::is_ceremony_fill(ceremony.len(), name_notes) {
            for nf in ceremony {
                registry.adopt_anchor(height, nf);
            }
        }

        let notes: &[usize] = notes_by_tx.get(&txid).map(Vec::as_slice).unwrap_or(&[]);
        match notes {
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
                    let expiry = expiry_by_txid
                        .get(&txid)
                        .copied()
                        .expect("FATAL: scanned transaction is missing from the block");
                    registry.accept_claim(
                        network,
                        &candidate.payload,
                        candidate.nullifier,
                        successor,
                        &nfs,
                        height,
                        block_mtp,
                        expiry,
                    )
                } else {
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
            _ => registry.follow_spends(&nfs, height),
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
    if let Err(error) = wallet.put_blocks_marked(from_state, vec![scanned], &marks) {
        match error {
            crate::wallet::WalletError::UnexpectedOrchardReceive => {
                panic!("FATAL: ordinary-Orchard receive — consensus violation or key compromise")
            }
            error => panic!("FATAL: wallet block commit failed: {error}"),
        }
    }
    // The scanner drops note plaintexts, so Treasury memos decode
    // here, once per block, into arrivals; the block remains the
    // durable record. Decisions belong to the run loop. The mempool
    // quick path reads the same memos earlier and ephemerally; it
    // records nothing — this pass stays the only intake.
    let arrivals = treasury_memos
        .into_iter()
        .map(|(txid, _action_index, paid, memo)| (txid, MintInbound::decode(network, &memo), paid))
        .collect();
    for (index, position) in accepted_name_notes {
        let candidate = &candidates[index];
        wallet
            .store_name_note(
                height,
                position,
                candidate.txid,
                candidate.action_index,
                candidate.note,
                orchard::note::NoteCommitTrapdoor::from_inner(candidate.payload.rcm(network)),
                candidate.payload.psi(network),
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
    arrivals
}

// ===========================================================================
// OtpMemo submission
// ===========================================================================

/// Builds and submits the challenge for a request already admitted to
/// `OtpQueue`. Returns false when Treasury funds or node acceptance defer it.
#[allow(clippy::too_many_arguments)]
pub async fn relay<P: Parameters + Send + 'static>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &TreasuryKeys,
    spend_prover: &SpendParameters,
    output_prover: &OutputParameters,
    controller_ua: &UnifiedAddress,
    source: &CanonicalBlockSource,
    request: &OtpChallenge,
    lane: &'static str,
) -> bool {
    let memo = match request.memo().encode(network) {
        Some(memo) => memo,
        None if request.action.is_claim() => {
            unreachable!("claims never enter the controller challenge relay")
        }
        None => {
            tracing::error!(
                lane,
                name = %request.name.as_str(),
                action = request.action.as_str(),
                "controller challenge memo exceeds the ZIP-302 512-byte limit"
            );
            return false;
        }
    };
    let transaction = match treasury::challenge(
        network,
        wallet,
        treasury_keys,
        spend_prover,
        output_prover,
        controller_ua,
        memo,
    ) {
        Ok(transaction) => transaction,
        Err(error) => {
            tracing::warn!(
                lane,
                %error,
                name = %request.name.as_str(),
                action = request.action.as_str(),
                "controller challenge not built"
            );
            return false;
        }
    };
    if source.submit(&transaction, "controller challenge").await {
        tracing::info!(
            lane,
            txid = %transaction.txid(),
            name = %request.name.as_str(),
            action = request.action.as_str(),
            "controller challenged"
        );
        true
    } else {
        tracing::debug!(
            lane,
            name = %request.name.as_str(),
            action = request.action.as_str(),
            "controller challenge rejected — deferred"
        );
        false
    }
}

// ===========================================================================
// Mempool intake
// ===========================================================================

/// The most challenges one serve of the mempool news relays. The rest
/// wait for the retry pass at the tip. One serve must not hold the loop
/// for a burst of relays.
pub const RELAYS_PER_SERVE: usize = 2;

/// Watches the mempool and reports what the mint can act on.
///
/// The node reports three changes. This task gives each change its own
/// home:
///
/// * `Added` — the task gets the transaction from the node; the node
///   checks its mempool first. It reports the transaction on the
///   sightings channel.
/// * `Invalidated` — the task reports the txid on the deaths channel.
/// * `Mined` — the task reports nothing. The block path owns a mined
///   request. An invalidation for a mined txid would retire a live
///   entry; the mint would then relay a second code.
///
/// The task sends in stream order and waits for each send, so a
/// sighting reports before the death of its own transaction. The task
/// holds no key material and no wallet; every judgment stays with the
/// loop.
pub async fn watch_mempool<P: Parameters + Send + 'static>(
    network: P,
    chain: ChainClient,
    sightings: mpsc::Sender<(TxId, Transaction)>,
    deaths: mpsc::Sender<TxId>,
) {
    let mut session = MempoolSession::open(chain.clone()).await;
    let source = CanonicalBlockSource::new(chain);
    let branch_id = BranchId::for_height(&network, BlockHeight::from_u32(u32::MAX));
    loop {
        let (kind, txid) = session.next().await;
        match kind {
            MempoolChangeKind::Added => {
                if !added(&source, branch_id, &sightings, txid).await {
                    return;
                }
            }
            MempoolChangeKind::Invalidated => {
                if !invalidated(&deaths, txid).await {
                    return;
                }
            }
            MempoolChangeKind::Mined => mined(txid),
        }
    }
}

/// A transaction entered the node mempool: get it — the fetch is the
/// check — and report it for the loop to admit. Returns false when the
/// loop stopped reading; the task then stops.
async fn added(
    source: &CanonicalBlockSource,
    branch_id: BranchId,
    sightings: &mpsc::Sender<(TxId, Transaction)>,
    txid: TxId,
) -> bool {
    match source.get_raw_transaction(branch_id, txid).await {
        Ok(Some(transaction)) => sightings.send((txid, transaction)).await.is_ok(),
        Ok(None) => {
            tracing::debug!(%txid, "mempool transaction gone before fetch");
            true
        }
        Err(error) => {
            tracing::warn!(%error, %txid, "mempool transaction fetch failed");
            true
        }
    }
}

/// A mempool transaction died: report its txid for the loop to retire
/// the entries it stamped. Returns false when the loop stopped reading.
async fn invalidated(deaths: &mpsc::Sender<TxId>, txid: TxId) -> bool {
    deaths.send(txid).await.is_ok()
}

/// A mempool transaction entered a block: the block path owns it from
/// here. The intake reports nothing — an invalidation for a mined txid
/// would retire a live entry, and the mint would relay a second code.
fn mined(txid: TxId) {
    tracing::trace!(%txid, "mempool transaction mined; the block path owns it");
}

/// The loop's one home for the reports of the watch task.
///
/// The service owns what a reorg never replaces: the network, the node
/// view, and the two report channels. The state a reorg does replace —
/// the wallet, the registry, the queue — comes in with each serve, as
/// arguments, so no borrow outlives the reorg lines.
///
/// Nothing in this service receives outside a serve. Every report is
/// taken with `try_recv` inside a serve, so a report that wakes
/// nothing is never dropped: a report waits in its channel until the
/// next serve reads it.
pub struct MempoolNews<P> {
    network: P,
    source: CanonicalBlockSource,
    sightings: mpsc::Receiver<(TxId, Transaction)>,
    deaths: mpsc::Receiver<TxId>,
}

impl<P: Parameters + Send + 'static> MempoolNews<P> {
    /// Opens the service on the watch task's two report channels.
    pub fn new(
        network: P,
        source: CanonicalBlockSource,
        sightings: mpsc::Receiver<(TxId, Transaction)>,
        deaths: mpsc::Receiver<TxId>,
    ) -> Self {
        Self {
            network,
            source,
            sightings,
            deaths,
        }
    }

    /// Serves the waiting mempool news, in one fixed order:
    ///
    /// 1. Admit every waiting sighting — the decode, the gate, the fee
    ///    check, and the admission, the same checks in the deciding
    ///    pass's order. No await runs here, so the admits of one serve
    ///    hold nothing and wait for nothing. Admission is idempotent:
    ///    a request the block path also confirms stays one entry.
    /// 2. Retire every waiting death, before any relay: a death that
    ///    waits in this serve must not let its challenge go out.
    /// 3. Relay at most [`RELAYS_PER_SERVE`] of the requested
    ///    challenges. The retry pass at the tip relays the rest.
    ///
    /// The run loop calls this serve after each timer wake, after each
    /// applied block, and once before the pass at the tip relays.
    #[allow(clippy::too_many_arguments)]
    pub async fn serve(
        &mut self,
        wallet: &mut Wallet<P>,
        treasury_keys: &TreasuryKeys,
        spend_prover: &SpendParameters,
        output_prover: &OutputParameters,
        registry: &Registry,
        name_notes: &NameNoteQueue,
        oracle: &Oracle,
        challenges: &mut OtpQueue,
        tip: BlockHeight,
        mtp_now: Timestamp,
    ) {
        challenges.prune(mtp_now);
        let target_height = tip + 1;
        while let Ok((txid, transaction)) = self.sightings.try_recv() {
            admit_sighting(
                &self.network,
                treasury_keys,
                registry,
                name_notes,
                oracle,
                challenges,
                target_height,
                mtp_now,
                txid,
                &transaction,
            );
        }
        retire_deaths(challenges, &mut self.deaths);
        relay_requested(
            &self.network,
            wallet,
            treasury_keys,
            spend_prover,
            output_prover,
            &self.source,
            registry,
            name_notes,
            challenges,
            target_height,
            mtp_now,
            RELAYS_PER_SERVE,
            "mempool",
        )
        .await;
    }
}

/// Admits one sighted transaction: the decode with the Treasury keys,
/// the gate, the fee check, and the admission — the same checks, in the
/// same order, as the deciding pass. Claims stay out: the deciding pass
/// owns them. Pure calls over loop state; no await runs here.
#[allow(clippy::too_many_arguments)]
fn admit_sighting<P: Parameters>(
    network: &P,
    treasury_keys: &TreasuryKeys,
    registry: &Registry,
    name_notes: &NameNoteQueue,
    oracle: &Oracle,
    challenges: &mut OtpQueue,
    target_height: BlockHeight,
    mtp_now: Timestamp,
    txid: TxId,
    transaction: &Transaction,
) {
    for (_action_index, paid, memo) in
        note::decrypt_treasury_transaction(transaction, treasury_keys)
    {
        let MintInbound::Request(request) = MintInbound::decode(network, &memo) else {
            continue;
        };
        let (name, action, requested_ua, term) = match &request {
            Request::Update { name, ua, term } => (name, Action::Update, ua, *term),
            Request::Release { name, ua } => (name, Action::Release, ua, None),
            Request::Claim { .. } => continue,
        };
        let Some(record) = registry.authorize_challenge(
            name_notes,
            name,
            action,
            requested_ua,
            term,
            target_height,
            mtp_now,
        ) else {
            continue;
        };
        if paid < oracle.challenge_fee() {
            continue;
        }
        let pending = OtpChallenge::issue(
            name.clone(),
            action,
            requested_ua.clone(),
            record.commitment,
            term,
            mtp_now,
        );
        challenges.admit(pending, txid);
    }
}

/// Retires every waiting death: the queue removes the unrelayed entries
/// the txid stamps. A relayed challenge keeps its life.
fn retire_deaths(challenges: &mut OtpQueue, deaths: &mut mpsc::Receiver<TxId>) {
    while let Ok(txid) = deaths.try_recv() {
        challenges.invalidate(txid);
    }
}

/// Relays up to `limit` of the still-requested challenges, oldest
/// first. Each relay re-runs the gate and the commitment check against
/// the state as it stands now; an entry whose gate fails waits for the
/// next pass, and prune retires it at expiry. The pass at the tip calls
/// this with no limit; a serve of the mempool news calls it with
/// [`RELAYS_PER_SERVE`], so one serve cannot hold the loop for a burst
/// of relays.
#[allow(clippy::too_many_arguments)]
pub async fn relay_requested<P: Parameters + Send + 'static>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &TreasuryKeys,
    spend_prover: &SpendParameters,
    output_prover: &OutputParameters,
    source: &CanonicalBlockSource,
    registry: &Registry,
    name_notes: &NameNoteQueue,
    challenges: &mut OtpQueue,
    target_height: BlockHeight,
    mtp_now: Timestamp,
    limit: usize,
    lane: &'static str,
) {
    for pending in challenges.requested().into_iter().take(limit) {
        let Some(record) = registry.authorize_challenge(
            name_notes,
            &pending.name,
            pending.action,
            &pending.ua,
            pending.term,
            target_height,
            mtp_now,
        ) else {
            continue;
        };
        if record.commitment != pending.tip_rcm {
            continue;
        }
        if relay(
            network,
            wallet,
            treasury_keys,
            spend_prover,
            output_prover,
            &record.ua,
            source,
            &pending,
            lane,
        )
        .await
        {
            challenges.challenge_issued(&pending);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — the Treasury memo grammars
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_address::unified::{Address as Ua, Encoding, Receiver};
    use zcash_protocol::consensus::MainNetwork;

    const TEST_UA: &str = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";

    fn padded(s: &str) -> MemoBytes {
        let mut m = [0u8; 512];
        m[..s.len()].copy_from_slice(s.as_bytes());
        MemoBytes::from_bytes(&m).expect("a 512-byte memo fits")
    }

    fn test_ua() -> UnifiedAddress {
        match zcash_keys::address::Address::decode(&MainNetwork, TEST_UA) {
            Some(zcash_keys::address::Address::Unified(ua)) => ua,
            _ => panic!("vector is a mainnet Unified Address"),
        }
    }

    #[test]
    fn accepts_exactly_the_three_request_forms() {
        let network = MainNetwork;

        assert!(matches!(
            Request::decode(&network, &padded(&format!("ZNS:claim:forever:alice:{TEST_UA}"))),
            Some(Request::Claim {
                name,
                term: Term::Forever,
                code: None,
                ..
            }) if name.as_str() == "alice"
        ));
        assert!(matches!(
            Request::decode(
                &network,
                &padded(&format!("ZNS:update:none:alice:{TEST_UA}"))
            ),
            Some(Request::Update { term: None, .. })
        ));
        assert!(matches!(
            Request::decode(&network, &padded(&format!("ZNS:release:alice:{TEST_UA}"))),
            Some(Request::Release { .. })
        ));
        // The upgrade spelling.
        assert!(matches!(
            Request::decode(
                &network,
                &padded(&format!("ZNS:update:forever:alice:{TEST_UA}"))
            ),
            Some(Request::Update {
                term: Some(Term::Forever),
                ..
            })
        ));
    }

    #[test]
    fn claim_may_lead_with_a_presale_code() {
        let network = MainNetwork;
        let code = AccessCode::parse("004206").unwrap();

        assert!(matches!(
            Request::decode(
                &network,
                &padded(&format!("ZNS:claim:004206:forever:alice:{TEST_UA}"))
            ),
            Some(Request::Claim {
                term: Term::Forever,
                code: Some(ref parsed),
                ..
            }) if parsed == &code
        ));
        // A term-shaped first field is never taken as a code.
        assert!(matches!(
            Request::decode(&network, &padded(&format!("ZNS:claim:12y:alice:{TEST_UA}"))),
            Some(Request::Claim {
                code: None,
                term: Term::Years(12),
                ..
            })
        ));
        // Not exactly six digits.
        assert!(Request::decode(
            &network,
            &padded(&format!("ZNS:claim:4206:forever:alice:{TEST_UA}"))
        )
        .is_none());
        assert!(Request::decode(
            &network,
            &padded(&format!("ZNS:claim:a1b2c3:forever:alice:{TEST_UA}"))
        )
        .is_none());
    }

    #[test]
    fn rejects_extra_field_and_non_zns_and_invalid_name() {
        let network = MainNetwork;
        assert!(Request::decode(
            &network,
            &padded(&format!("ZNS:release:alice:{TEST_UA}:004206"))
        )
        .is_none());
        assert!(Request::decode(&network, &padded("hello world")).is_none());
        assert!(Request::decode(
            &network,
            &padded(&format!("ZNS:claim:forever:INVALID:{TEST_UA}"))
        )
        .is_none());
    }

    #[test]
    fn rejects_nonzero_tail_after_the_first_nul() {
        let network = MainNetwork;
        let s = format!("ZNS:claim:forever:alice:{TEST_UA}");
        let mut m = [0u8; 512];
        m[..s.len()].copy_from_slice(s.as_bytes());
        m[400] = 1; // garbage inside the zero tail
        let memo = MemoBytes::from_bytes(&m).expect("a 512-byte memo fits");
        // The tail lands inside the terminal UA field — nothing parses.
        assert!(Request::decode(&network, &memo).is_none());
        assert!(OtpMemo::decode(&network, &memo).is_none());
        assert!(matches!(
            MintInbound::decode(&network, &memo),
            MintInbound::Unrecognized
        ));
    }

    #[test]
    fn unknown_receiver_ua_is_rejected() {
        let network = MainNetwork;
        // A valid UA carrying an unknown receiver — ZIP-316's
        // forward-compatibility channel, unbounded by design.
        let ua = Ua::try_from_items(vec![
            Receiver::Orchard([0x07; 43]),
            Receiver::Unknown {
                typecode: 5,
                data: vec![0u8; 32],
            },
        ])
        .expect("ZIP-316 composition rules permit it")
        .encode(&zcash_protocol::consensus::NetworkType::Main);

        // No verb parses — requests and echoes alike.
        for memo in [
            format!("ZNS:claim:forever:alice:{ua}"),
            format!("ZNS:update:none:alice:{ua}"),
            format!("ZNS:release:alice:{ua}"),
            format!("ZNS:otp:417293:alice:update:{ua}"),
        ] {
            assert!(matches!(
                MintInbound::decode(&network, &padded(&memo)),
                MintInbound::Unrecognized
            ));
        }
    }

    /// The pre-fix corpus vector: a real Sapling+P2pkh address with no
    /// Orchard receiver — inside the memo budget, but a controller the
    /// relay lane could never challenge.
    const ORCHARDLESS_UA: &str = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";

    #[test]
    fn orchardless_known_receiver_ua_is_rejected() {
        let network = MainNetwork;
        assert!(Request::decode(
            &network,
            &padded(&format!("ZNS:claim:forever:alice:{ORCHARDLESS_UA}"))
        )
        .is_none());
    }

    #[test]
    fn largest_known_receiver_ua_is_accepted() {
        let network = MainNetwork;
        // The corpus vector carries every known receiver kind — the
        // longest address shape the guard admits.
        assert!(TEST_UA.len() > 200);
        assert!(Request::decode(
            &network,
            &padded(&format!("ZNS:claim:forever:alice:{TEST_UA}"))
        )
        .is_some());
    }

    #[test]
    fn decode_classifies_each_kind() {
        let network = MainNetwork;

        let echo = padded(&format!("ZNS:otp:417293:alice:update:{TEST_UA}"));
        assert!(matches!(
            MintInbound::decode(&network, &echo),
            MintInbound::Echo(_)
        ));
        let request = padded(&format!("ZNS:claim:forever:alice:{TEST_UA}"));
        assert!(matches!(
            MintInbound::decode(&network, &request),
            MintInbound::Request(_)
        ));
        // A bare payment: the queue names it by its txid.
        let garbage = padded("hello world");
        assert!(matches!(
            MintInbound::decode(&network, &garbage),
            MintInbound::Unrecognized
        ));
    }

    #[test]
    fn challenge_roundtrips() {
        let network = MainNetwork;
        let ua = test_ua();

        for action in [Action::Update, Action::Release] {
            let challenge = OtpMemo {
                code: OtpCode::for_test(*b"417293"),
                name: Name::parse("alice").unwrap(),
                action,
                ua: ua.clone(),
            };
            let memo = challenge.encode(&network).expect("non-claims encode");
            assert_eq!(OtpMemo::decode(&network, &memo), Some(challenge));
        }
        // Claims are never challenged: encode refuses.
        let claim = OtpMemo {
            code: OtpCode::for_test(*b"417293"),
            name: Name::parse("alice").unwrap(),
            action: Action::Claim,
            ua,
        };
        assert!(claim.encode(&network).is_none());
    }
}
