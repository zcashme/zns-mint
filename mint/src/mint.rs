//! Shared protocol logic for ZNS minting and wallet operations.

pub mod mtp;
pub mod note;
pub mod presale;
pub mod pricing;
pub mod registry;
pub mod sale;
pub mod treasury;

// The Name Note type and its codec.
pub use note::{decrypt_name_notes, DecryptedNameNote, Expiry, NameNote, Term};
pub use time::Timestamp;

pub use zcash_keys::address::UnifiedAddress;

use transparent::address::TransparentAddress;
use zcash_address::unified::{Container as _, Encoding};
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::{Memo, MemoBytes};
use zcash_protocol::value::Zatoshis;
use zip32::AccountId;

use sapling::circuit::{OutputParameters, SpendParameters};
use std::str::Split;
use tokio::sync::mpsc;

use crate::wallet::Wallet;
use crate::zcash::{CanonicalBlockSource, ChainClient, MempoolChangeKind, MempoolSession};
use crate::TreasuryKeys;

use presale::AccessCode;
use treasury::OtpCode;

pub const TREASURY_ACCOUNT: AccountId = AccountId::const_from_u32(0);
pub const REGISTRY_ACCOUNT: AccountId = AccountId::const_from_u32(1);

/// The liveness interval: one Julian year (365.25 days), in seconds.
pub const LIVENESS_INTERVAL: i64 = 31_557_600;

/// Minimum Treasury Ironwood balance after boot sync (0.002 ZEC).
pub const MIN_TREASURY_BALANCE: u64 = 200_000;

/// The longest name a memo accepts.
pub const MAX_NAME_LEN: usize = 63;

/// Decodes a controller UA: known receivers only, at least one shielded.
pub(crate) fn decode_controller_ua<P: Parameters>(
    network: &P,
    ua_str: &str,
) -> Option<UnifiedAddress> {
    let (net, revision, container) = zcash_address::unified::Address::decode(ua_str).ok()?;
    if net != network.network_type()
        || revision != zcash_address::unified::Revision::R0
        || !container.metadata_items().is_empty()
    {
        return None;
    }
    let ua = UnifiedAddress::try_from(container).ok()?;
    (ua.unknown().is_empty() && (ua.has_orchard() || ua.has_sapling())).then_some(ua)
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
    /// Spends the holder's note and binds the buyer. The name stays live.
    Sale,
    /// Lists the name at a fixed price.
    List,
    /// Removes a listing.
    Delist,
    /// Lists the name at a falling price.
    Auction,
}

impl Action {
    /// Returns the canonical ASCII verb for this action.
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::Claim => "claim",
            Action::Update => "update",
            Action::Release => "release",
            Action::Sale => "sale",
            Action::List => "list",
            Action::Delist => "delist",
            Action::Auction => "auction",
        }
    }

    /// Parses the canonical ASCII verb — the inverse of [`Self::as_str`].
    pub fn parse(verb: &str) -> Option<Self> {
        match verb {
            "claim" => Some(Action::Claim),
            "update" => Some(Action::Update),
            "release" => Some(Action::Release),
            "sale" => Some(Action::Sale),
            "list" => Some(Action::List),
            "delist" => Some(Action::Delist),
            "auction" => Some(Action::Auction),
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

    /// True when this action hands the name to a buyer.
    pub const fn is_sale(self) -> bool {
        matches!(self, Action::Sale)
    }

    /// True when this action is a list challenge.
    pub const fn is_list(self) -> bool {
        matches!(self, Action::List)
    }

    /// True when this action is a delist challenge.
    pub const fn is_delist(self) -> bool {
        matches!(self, Action::Delist)
    }

    /// True when this action is an auction challenge.
    pub const fn is_auction(self) -> bool {
        matches!(self, Action::Auction)
    }

    /// True when this action spends the registration's current note as
    /// its authority; a claim spends an anchor instead.
    pub const fn needs_predecessor(self) -> bool {
        matches!(self, Action::Update | Action::Release | Action::Sale)
    }
}

/// A name request, decoded before authorization.
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
    /// Alice lists the name she owns, at the t1 she names, once she
    /// returns the challenge.
    List(sale::Listing),
    /// Alice takes her listing down, once she returns the challenge.
    Delist {
        name: Name,
        ua: UnifiedAddress,
    },
    /// Bob asks for a listed name. `ua` is where the buy OTP goes.
    Buy {
        name: Name,
        ua: UnifiedAddress,
    },
}

impl Request {
    /// The name every variant carries.
    pub fn name(&self) -> &Name {
        match self {
            Request::Claim { name, .. }
            | Request::Update { name, .. }
            | Request::Release { name, .. }
            | Request::Delist { name, .. }
            | Request::Buy { name, .. } => name,
            Request::List(listing) => &listing.name,
        }
    }

    /// A buy asks for a sale.
    pub fn action(&self) -> Action {
        match self {
            Request::Claim { .. } => Action::Claim,
            Request::Update { .. } => Action::Update,
            Request::Release { .. } => Action::Release,
            Request::List(listing) => match listing.ask {
                sale::Ask::Flat(_) => Action::List,
                sale::Ask::Dutch(_) => Action::Auction,
            },
            Request::Delist { .. } => Action::Delist,
            Request::Buy { .. } => Action::Sale,
        }
    }

    /// The requested Unified Address every variant carries.
    pub fn ua(&self) -> &UnifiedAddress {
        match self {
            Request::Claim { ua, .. }
            | Request::Update { ua, .. }
            | Request::Release { ua, .. }
            | Request::Delist { ua, .. }
            | Request::Buy { ua, .. } => ua,
            Request::List(listing) => &listing.ua,
        }
    }

    /// Parses a request memo:
    ///
    /// - `ZNS:claim:<term>:<name>:<ua>`, or with a six-digit pre-sale
    ///   code leading: `ZNS:claim:<code>:<term>:<name>:<ua>`
    /// - `ZNS:update:<none | <N>y | forever>:<name>:<ua>`
    /// - `ZNS:release:<name>:<ua>`
    /// - `ZNS:list:<name>:<ua>:<t1>:<price>`
    /// - `ZNS:auction:<name>:<ua>:<t1>:<start>:<min>:<start-block>:<end-block>`
    /// - `ZNS:delist:<name>:<ua>`
    /// - `ZNS:buy:<name>:<ua>`
    pub(crate) fn decode<P: Parameters>(network: &P, memo: &MemoBytes) -> Option<Request> {
        decode_zns(memo, |verb, fields| match verb {
            // Claims may lead with a pre-sale code; the discriminator is
            // whether the next field is a term.
            "claim" => {
                let first = fields.next()?;
                let (code, term) = match Term::parse(first) {
                    Some(term) => (None, term),
                    None => (
                        Some(AccessCode::parse(first)?),
                        Term::parse(fields.next()?)?,
                    ),
                };
                let (name, ua) = decode_name_and_ua(network, fields)?;
                Some(Request::Claim {
                    name,
                    ua,
                    term,
                    code,
                })
            }
            "update" => {
                let term = match fields.next()? {
                    "none" => None,
                    "forever" => Some(Term::Forever),
                    field => Some(Term::parse(field)?),
                };
                let (name, ua) = decode_name_and_ua(network, fields)?;
                Some(Request::Update { name, ua, term })
            }
            "release" => {
                decode_name_and_ua(network, fields).map(|(name, ua)| Request::Release { name, ua })
            }
            "list" | "auction" => {
                let (name, ua) = decode_name_and_ua(network, fields)?;
                let (pay_to, ask) = sale::decode_terms(network, Action::parse(verb)?, fields)?;
                Some(Request::List(sale::Listing {
                    name,
                    ua,
                    pay_to,
                    ask,
                }))
            }
            "delist" => {
                decode_name_and_ua(network, fields).map(|(name, ua)| Request::Delist { name, ua })
            }
            "buy" => {
                decode_name_and_ua(network, fields).map(|(name, ua)| Request::Buy { name, ua })
            }
            _ => None,
        })
    }
}

/// Runs `parse` on the verb and the fields after it in a `ZNS:<verb>:…`
/// text memo. A field `parse` leaves unread refuses the memo.
pub(crate) fn decode_zns<T>(
    memo: &MemoBytes,
    parse: impl FnOnce(&str, &mut Split<'_, char>) -> Option<T>,
) -> Option<T> {
    let Memo::Text(text) = Memo::try_from(memo).ok()? else {
        return None;
    };
    let mut fields = text.split(':');
    if fields.next()? != "ZNS" {
        return None;
    }
    let verb = fields.next()?;
    let value = parse(verb, &mut fields)?;
    fields.next().is_none().then_some(value)
}

/// The `<name>:<ua>` pair every request names.
pub(crate) fn decode_name_and_ua<P: Parameters>(
    network: &P,
    fields: &mut Split<'_, char>,
) -> Option<(Name, UnifiedAddress)> {
    let name = Name::parse(fields.next()?)?;
    let ua = fields.next()?;
    if ua.is_empty() {
        return None;
    }
    Some((name, decode_controller_ua(network, ua)?))
}

/// A mint-issued challenge to a wallet, proving that the wallet controls a name via shielded-memos.
/// A list challenge also carries the t1 and the price she is authorizing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtpMemo {
    pub code: OtpCode,
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
    /// The t1 and price on a list challenge. Absent for every other verb.
    pub listing: Option<(TransparentAddress, Zatoshis)>,
    /// The t1 and terms on an auction challenge. Absent for every other verb.
    pub auction: Option<(TransparentAddress, sale::AuctionTerms)>,
}

impl OtpMemo {
    /// Encodes the challenge memo. A list sentence appends the t1 and the
    /// price. Claims are never challenged.
    pub fn encode<P: Parameters>(&self, network: &P) -> Option<MemoBytes> {
        if self.action.is_claim() {
            return None;
        }
        let otp: String = self.code.digits().into_iter().map(|b| b as char).collect();
        let terms = if self.action.is_list() {
            let (pay_to, price) = self.listing.as_ref()?;
            Some(sale::encode_terms(
                network,
                pay_to,
                &sale::Ask::Flat(*price),
            ))
        } else if self.action.is_auction() {
            let (pay_to, terms) = self.auction.as_ref()?;
            Some(sale::encode_terms(
                network,
                pay_to,
                &sale::Ask::Dutch(terms.clone()),
            ))
        } else {
            None
        };
        let text = if let Some(terms) = terms {
            format!(
                "ZNS:otp:{otp}:{}:{}:{}:{terms}",
                self.name.as_str(),
                self.action.as_str(),
                self.ua.encode(network),
            )
        } else {
            format!(
                "ZNS:otp:{otp}:{}:{}:{}",
                self.name.as_str(),
                self.action.as_str(),
                self.ua.encode(network),
            )
        };
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
        if parts.len() < 6 || parts[0] != "ZNS" || parts[1] != "otp" {
            return None;
        }

        let digits = parts[2].as_bytes();
        if digits.len() != 6 || !digits.iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let code = OtpCode::from_digits(digits.try_into().ok()?)?;

        let name = Name::parse(parts[3])?;
        // A challenge is an update, a release, a list, or a delist.
        let action = Action::parse(parts[4]).filter(|action| {
            action.is_update()
                || action.is_release()
                || action.is_list()
                || action.is_delist()
                || action.is_auction()
        })?;

        // A list sentence carries the t1 and the price. An auction sentence
        // carries the t1 and the terms. The other verbs stay six fields.
        let (ua, listing, auction) = if action.is_list() || action.is_auction() {
            if parts.len() != if action.is_list() { 8 } else { 11 } {
                return None;
            }
            let ua = decode_controller_ua(network, parts[5])?;
            match sale::decode_terms(network, action, &mut parts[6..].iter().copied())? {
                (pay_to, sale::Ask::Flat(price)) => (ua, Some((pay_to, price)), None),
                (pay_to, sale::Ask::Dutch(terms)) => (ua, None, Some((pay_to, terms))),
            }
        } else {
            if parts.len() != 6 {
                return None;
            }
            (decode_controller_ua(network, parts[5])?, None, None)
        };

        Some(Self {
            code,
            name,
            action,
            ua,
            listing,
            auction,
        })
    }
}

/// What a user said to the Treasury, in the shape each consumer takes.
/// Classified once, at block application; the deciding pass resolves.
#[derive(Clone, Debug)]
pub enum MintInbound {
    /// A request decoded from a Treasury memo. A claim, update, or
    /// release goes to the Registry's `authorize_*` family; a list,
    /// delist, or buy to [`sale::Market::admit`].
    Request(Request),
    /// An OTP response — the relay memo returned; the OTP queue takes it.
    Response(OtpMemo),
    /// A payment with no parseable message: the deciding pass logs it once and
    /// the sweep keeps the value; the queue names it by its txid.
    Unrecognized,
}

impl MintInbound {
    /// Classifies one Treasury memo: OTP response, request, or
    /// unrecognized payment. Called once per memo, at block application.
    pub fn decode<P: Parameters>(network: &P, memo: &MemoBytes) -> Self {
        if let Some(response) = OtpMemo::decode(network, memo) {
            Self::Response(response)
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
/// Registry law, wallet commit, Treasury decode, and Name Note storage.
/// Returns Treasury arrivals, which the caller routes.
/// Before birthday, applies only wallet history and clock.
/// Never fetches, never broadcasts.
#[allow(clippy::too_many_arguments)]
pub fn apply_block<P: Parameters + Send + 'static>(
    network: &P,
    birthday: BlockHeight,
    registry_keys: &crate::RegistryKeys,
    treasury_keys: &TreasuryKeys,
    block: zcash_primitives::block::Block,
    height: BlockHeight,
    wallet: &mut Wallet<P>,
    registry: &mut registry::Registry,
    mtp: &mut mtp::MtpTracker,
) -> Vec<(TxId, MintInbound, Zatoshis)> {
    use std::collections::BTreeMap;
    use std::convert::Infallible;

    use incrementalmerkletree::Position;
    use zcash_client_backend::scanning::full::{decrypt_block, scan_block};
    use zcash_client_backend::scanning::SpendIdentifiers;

    let cursor = wallet.tip();
    assert_eq!(
        height,
        cursor.block_height() + 1,
        "FATAL: block height does not follow the applied cursor"
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
            note::decrypt_treasury_memos(network, &block, height, treasury_keys),
        )
    } else {
        (Vec::new(), Vec::new())
    };

    let (header, batches) = decrypt_block(network, block, wallet.scanning_keys());
    let spend_identifiers = SpendIdentifiers::unspent(wallet)
        .expect("FATAL: wallet could not expose its unspent nullifiers");
    let scanned = scan_block(
        network,
        height,
        &header,
        batches,
        wallet.scanning_keys(),
        &spend_identifiers,
        Some(&cursor),
        |_| {
            Ok::<Option<(AccountId, Option<transparent::keys::TransparentKeyScope>)>, Infallible>(
                None,
            )
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
                    // The successor anchor: besides its Name Note, a backed
                    // claim creates exactly one zero-value Registry output.
                    let others: Vec<_> = registry_outputs
                        .iter()
                        .filter(|output| output.index() != candidate.action_index)
                        .collect();
                    let successor = match others.as_slice() {
                        [only] if only.note().0.value().inner() == 0 => only.nf().copied(),
                        _ => None,
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
                    registry.accept_transition(
                        network,
                        &candidate.payload,
                        candidate.nullifier,
                        &nfs,
                        height,
                        block_mtp,
                    )
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

    // Accepted Name Note commitments are marked at the commit — the
    // scanner cannot decrypt them, so they would otherwise enter the
    // tree Ephemeral, prune with the checkpoints, and leave the note
    // without a witness.
    let marks: Vec<orchard::tree::MerkleHashOrchard> = accepted_name_notes
        .iter()
        .map(|(index, _)| orchard::tree::MerkleHashOrchard::from_cmx(&candidates[*index].cmx))
        .collect();
    if let Err(error) = wallet.put_blocks_marked(&cursor, vec![scanned], &marks) {
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
        .map(|(txid, paid, memo)| (txid, MintInbound::decode(network, &memo), paid))
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
    let applied_tip = wallet.tip();
    tracing::debug!(
        height = u32::from(applied_tip.block_height()),
        hash = %applied_tip.block_hash(),
        "canonical block applied"
    );
    arrivals
}

// ===========================================================================
// OtpMemo submission
// ===========================================================================

/// Builds and submits a controller challenge. Returns false when Treasury
/// funds or node acceptance defer it.
#[allow(clippy::too_many_arguments)]
pub async fn relay<P: Parameters + Send + 'static>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &TreasuryKeys,
    spend_prover: &SpendParameters,
    output_prover: &OutputParameters,
    fee_rule: &FeeRule,
    controller_ua: &UnifiedAddress,
    source: &CanonicalBlockSource,
    challenge: &OtpMemo,
    lane: &'static str,
) -> bool {
    let memo = match challenge.encode(network) {
        Some(memo) => memo,
        None if challenge.action.is_claim() => {
            unreachable!("claims never enter the controller challenge relay")
        }
        None => {
            tracing::error!(
                lane,
                name = %challenge.name.as_str(),
                action = challenge.action.as_str(),
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
        fee_rule,
        controller_ua,
        memo,
    ) {
        Ok(transaction) => transaction,
        Err(error) => {
            tracing::warn!(
                lane,
                %error,
                name = %challenge.name.as_str(),
                action = challenge.action.as_str(),
                "controller challenge not built"
            );
            return false;
        }
    };
    if source.submit(&transaction, "controller challenge").await {
        tracing::info!(
            lane,
            txid = %transaction.txid(),
            name = %challenge.name.as_str(),
            action = challenge.action.as_str(),
            "controller challenged"
        );
        true
    } else {
        tracing::debug!(
            lane,
            name = %challenge.name.as_str(),
            action = challenge.action.as_str(),
            "controller challenge rejected — deferred"
        );
        false
    }
}

/// Submits the buy OTP. The memo verb is `buyotp`, so it cannot be
/// read as an update or release challenge. Returns false when Treasury
/// funds or node acceptance defer it.
#[allow(clippy::too_many_arguments)]
pub async fn relay_buy<P: Parameters + Send + 'static>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &TreasuryKeys,
    spend_prover: &SpendParameters,
    output_prover: &OutputParameters,
    fee_rule: &FeeRule,
    source: &CanonicalBlockSource,
    otp: &sale::BuyOtp,
) -> bool {
    let memo = match otp.encode(network) {
        Some(memo) => memo,
        None => {
            tracing::error!(
                name = %otp.name.as_str(),
                "buy OTP memo exceeds the ZIP-302 512-byte limit"
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
        fee_rule,
        &otp.ua,
        memo,
    ) {
        Ok(transaction) => transaction,
        Err(error) => {
            tracing::warn!(%error, name = %otp.name.as_str(), "buy OTP not built");
            return false;
        }
    };
    if source.submit(&transaction, "buy otp").await {
        tracing::info!(
            txid = %transaction.txid(),
            name = %otp.name.as_str(),
            "buy OTP sent"
        );
        true
    } else {
        tracing::debug!(name = %otp.name.as_str(), "buy OTP rejected — deferred");
        false
    }
}

/// True when `tx` spends a transparent prevout. A mempool request with
/// one is not relayed until it is mined.
pub fn spends_transparent(tx: &Transaction) -> bool {
    tx.transparent_bundle()
        .is_some_and(|bundle| !bundle.vin.is_empty())
}

/// Forwards Zebra's mempool changes to the run loop, which owns and updates
/// the OTP queue. The original change kind and txid stay paired.
pub async fn watch_mempool(chain: ChainClient, sender: mpsc::Sender<(MempoolChangeKind, TxId)>) {
    let mut session = MempoolSession::open(chain).await;
    loop {
        if sender.send(session.next().await).await.is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — the Treasury memo grammars
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_address::unified::{Address as Ua, Receiver, Revision, Uitem};
    use zcash_keys::address::Address;
    use zcash_protocol::consensus::MainNetwork;

    const TEST_UA: &str = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";

    fn padded(s: &str) -> MemoBytes {
        let mut m = [0u8; 512];
        m[..s.len()].copy_from_slice(s.as_bytes());
        MemoBytes::from_bytes(&m).expect("a 512-byte memo fits")
    }

    fn test_ua() -> UnifiedAddress {
        match zcash_keys::address::Address::decode(&MainNetwork, TEST_UA) {
            Some(zcash_keys::address::Address::Unified(ua)) => *ua,
            _ => panic!("vector is a mainnet Unified Address"),
        }
    }

    #[test]
    fn accepts_the_existing_request_forms() {
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
    fn rejects_malformed_requests() {
        let t1 = Address::Transparent(TransparentAddress::PublicKeyHash([0x11; 20]))
            .encode(&MainNetwork);
        for text in [
            "hello world".to_owned(),
            format!("ZNS:release:alice:{TEST_UA}:004206"),
            format!("ZNS:claim:forever:INVALID:{TEST_UA}"),
            format!("ZNS:list:alice:{TEST_UA}:{t1}"),
            format!("ZNS:list:alice:{TEST_UA}:{t1}:1.123456789"),
            format!("ZNS:list:alice:{TEST_UA}:{t1}:1.5:extra"),
            format!("ZNS:delist:alice:{TEST_UA}:extra"),
            format!("ZNS:buy:alice:{TEST_UA}:extra"),
            "ZNS:buy:alice".to_owned(),
            "ZNS:delist:alice".to_owned(),
            format!("ZNS:sale:alice:{TEST_UA}"),
        ] {
            assert!(
                matches!(
                    MintInbound::decode(&MainNetwork, &padded(&text)),
                    MintInbound::Unrecognized
                ),
                "accepted {text}"
            );
        }
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
        let ua = Ua::try_from_items(
            Revision::R0,
            vec![
                Uitem::Data(Receiver::Orchard([0x07; 43])),
                Uitem::Data(Receiver::Unknown {
                    typecode: 5,
                    data: vec![0u8; 32],
                }),
            ],
        )
        .expect("ZIP-316 composition rules permit it")
        .encode(&zcash_protocol::consensus::NetworkType::Main);

        // No verb parses — requests and OTP responses alike.
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

    /// A real Sapling+P2pkh address with no Orchard receiver. Its Sapling
    /// receiver is enough: the relay lane challenges it there.
    const SAPLING_CONTROLLER_UA: &str = "u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf";

    #[test]
    fn orchardless_sapling_controller_ua_is_accepted() {
        let network = MainNetwork;
        let ua = SAPLING_CONTROLLER_UA;
        let decoded = decode_controller_ua(&network, ua).expect("a Sapling receiver suffices");
        assert!(decoded.orchard().is_none());
        assert!(decoded.sapling().is_some());
        for memo in [
            format!("ZNS:claim:forever:alice:{ua}"),
            format!("ZNS:update:none:alice:{ua}"),
            format!("ZNS:release:alice:{ua}"),
        ] {
            assert!(matches!(
                MintInbound::decode(&network, &padded(&memo)),
                MintInbound::Request(_)
            ));
        }
        assert!(matches!(
            MintInbound::decode(
                &network,
                &padded(&format!("ZNS:otp:417293:alice:update:{ua}"))
            ),
            MintInbound::Response(_)
        ));
    }

    #[test]
    fn decode_classifies_each_kind() {
        let t1 = Address::Transparent(TransparentAddress::PublicKeyHash([0x11; 20]))
            .encode(&MainNetwork);
        for (text, action) in [
            (format!("ZNS:claim:forever:alice:{TEST_UA}"), Action::Claim),
            (format!("ZNS:update:none:alice:{TEST_UA}"), Action::Update),
            (format!("ZNS:release:alice:{TEST_UA}"), Action::Release),
        ] {
            assert!(
                matches!(
                    MintInbound::decode(&MainNetwork, &padded(&text)),
                    MintInbound::Request(request) if request.action() == action
                ),
                "misclassified {text}"
            );
        }
        for text in [
            format!("ZNS:list:alice:{TEST_UA}:{t1}:1.5"),
            format!("ZNS:delist:alice:{TEST_UA}"),
            format!("ZNS:buy:alice:{TEST_UA}"),
        ] {
            assert!(
                matches!(
                    MintInbound::decode(&MainNetwork, &padded(&text)),
                    MintInbound::Request(
                        Request::List(_) | Request::Delist { .. } | Request::Buy { .. }
                    )
                ),
                "misclassified {text}"
            );
        }
        assert!(matches!(
            MintInbound::decode(
                &MainNetwork,
                &padded(&format!("ZNS:otp:417293:alice:update:{TEST_UA}"))
            ),
            MintInbound::Response(_)
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
                listing: None,
                auction: None,
            };
            let memo = challenge.encode(&network).expect("non-claims encode");
            assert_eq!(OtpMemo::decode(&network, &memo), Some(challenge));
        }
        // Claims are never challenged: encode refuses.
        let claim = OtpMemo {
            code: OtpCode::for_test(*b"417293"),
            name: Name::parse("alice").unwrap(),
            action: Action::Claim,
            ua: ua.clone(),
            listing: None,
            auction: None,
        };
        assert!(claim.encode(&network).is_none());

        let pay_to = TransparentAddress::PublicKeyHash([0x11; 20]);
        let price = Zatoshis::from_u64(150_000_000).unwrap();
        let list = OtpMemo {
            code: OtpCode::for_test(*b"417293"),
            name: Name::parse("alice").unwrap(),
            action: Action::List,
            ua,
            listing: Some((pay_to, price)),
            auction: None,
        };
        let memo = list.encode(&network).expect("a list sentence encodes");
        assert_eq!(OtpMemo::decode(&network, &memo), Some(list));
        let bare = format!("ZNS:otp:417293:alice:list:{TEST_UA}");
        assert!(OtpMemo::decode(&network, &padded(&bare)).is_none());
    }
}
