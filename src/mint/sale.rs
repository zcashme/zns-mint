//! A sale: Alice lists her name at her transparent address, Bob asks
//! to buy it, and a payment of her price plus the buy OTP makes the
//! mint hand the name to Bob. The note is a sale, so the name stays live.
//! A dutch listing falls from a start price to a minimum across a span
//! of blocks. The first intent in a block holds that block's price.

use transparent::address::TransparentAddress;
use zcash_keys::address::Address;
use zcash_primitives::block::Block;
use zcash_protocol::consensus::Parameters;
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::TxId;

use crate::mint::presale::AccessCodeDerivationKey;
use crate::mint::registry::Registry;
use crate::mint::treasury::{OtpCode, D_OTP, FEE_ACTIONS, MAX_ATTEMPTS};
use crate::mint::{
    decode_name_and_ua, decode_zns, Action, Expiry, Name, NameCommitment, NameNote, OtpMemo,
    Timestamp, UnifiedAddress,
};

/// A list, delist, or buy, decoded before the market rules on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarketRequest {
    /// Alice lists the name she owns, at the transparent receiver on her
    /// controller address, once she returns the challenge.
    List(Listing),
    /// Alice takes her listing down, once she returns the challenge.
    Delist { name: Name, ua: UnifiedAddress },
    /// Bob asks for a listed name. `ua` is where the buy OTP goes.
    Buy { name: Name, ua: UnifiedAddress },
}

impl MarketRequest {
    /// `ZNS:list:<name>:<ua>:<t1>:<price>`,
    /// `ZNS:auction:<name>:<ua>:<t1>:<start>:<min>:<start-block>:<end-block>`,
    /// `ZNS:delist:<name>:<ua>`, or `ZNS:buy:<name>:<ua>`.
    pub fn decode<P: Parameters>(network: &P, memo: &MemoBytes) -> Option<Self> {
        decode_zns(memo, |verb, fields| match verb {
            "list" => {
                let (name, ua) = decode_name_and_ua(network, fields)?;
                Some(Self::List(Listing {
                    name,
                    ua,
                    pay_to: decode_t1(network, fields.next()?)?,
                    ask: Ask::Flat(decode_zec(fields.next()?)?),
                }))
            }
            "auction" => {
                let (name, ua) = decode_name_and_ua(network, fields)?;
                let pay_to = decode_t1(network, fields.next()?)?;
                let terms = AuctionTerms {
                    start_price: decode_zec(fields.next()?)?,
                    min_price: decode_zec(fields.next()?)?,
                    start: decode_height(fields.next()?)?,
                    end: decode_height(fields.next()?)?,
                };
                if !terms.is_valid() {
                    return None;
                }
                Some(Self::List(Listing {
                    name,
                    ua,
                    pay_to,
                    ask: Ask::Dutch(terms),
                }))
            }
            "delist" => {
                decode_name_and_ua(network, fields).map(|(name, ua)| Self::Delist { name, ua })
            }
            "buy" => decode_name_and_ua(network, fields).map(|(name, ua)| Self::Buy { name, ua }),
            _ => None,
        })
    }
}

/// The listing is from the current owner, and the transparent address
/// is the receiver on her controller address.
pub fn is_owner_listing(
    owner: &UnifiedAddress,
    ua: &UnifiedAddress,
    pay_to: &TransparentAddress,
) -> bool {
    owner == ua && owner.transparent() == Some(pay_to)
}

/// The mint's reply. The verb is `buyotp`, so a wallet cannot read it
/// as an update or release challenge (`ZNS:otp`).
#[derive(Clone, Debug)]
pub struct BuyOtp {
    pub code: OtpCode,
    pub name: Name,
    pub ua: UnifiedAddress,
    /// The frozen auction price and the time the hold ends.
    pub dutch: Option<(Zatoshis, Timestamp)>,
}

impl BuyOtp {
    /// `ZNS:buyotp:<code>:<name>:<ua>`. An auction quote is
    /// `ZNS:dutch:<code>:<name>:<ua>:<price>:<until>`.
    pub fn encode<P: Parameters>(&self, network: &P) -> Option<MemoBytes> {
        let otp: String = self.code.digits().into_iter().map(|b| b as char).collect();
        let text = if let Some((price, until)) = self.dutch {
            format!(
                "ZNS:dutch:{otp}:{}:{}:{}:{}",
                self.name.as_str(),
                self.ua.encode(network),
                encode_zec(price),
                until.as_seconds(),
            )
        } else {
            format!(
                "ZNS:buyotp:{otp}:{}:{}",
                self.name.as_str(),
                self.ua.encode(network),
            )
        };
        MemoBytes::from_bytes(text.as_bytes()).ok()
    }
}

/// Ten minutes. An auction quote stays payable for this long.
pub const D_DUTCH: i64 = 600;

/// A public-key-hash transparent address on this network. TEX and
/// script-hash addresses are not payment destinations for a sale.
pub(crate) fn decode_t1<P: Parameters>(network: &P, text: &str) -> Option<TransparentAddress> {
    match Address::decode(network, text)? {
        Address::Transparent(addr @ TransparentAddress::PublicKeyHash(_)) => Some(addr),
        _ => None,
    }
}

/// ZEC with at most eight decimal places, as zatoshis.
pub(crate) fn decode_zec(text: &str) -> Option<Zatoshis> {
    let (whole, frac) = match text.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (text, ""),
    };
    if whole.is_empty()
        || (whole.len() > 1 && whole.starts_with('0'))
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || frac.len() > 8
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let whole: u64 = whole.parse().ok()?;
    let frac_zats = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<8}").parse().ok()?
    };
    Zatoshis::from_u64(whole.checked_mul(100_000_000)?.checked_add(frac_zats)?).ok()
}

/// A block height written as a decimal. A leading zero is refused.
pub(crate) fn decode_height(text: &str) -> Option<BlockHeight> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    text.parse::<u32>().ok().map(BlockHeight::from_u32)
}

/// `price` as ZEC text that [`decode_zec`] accepts. Whole zatoshis
/// stay an integer. A fraction drops trailing zeros.
pub(crate) fn encode_zec(price: Zatoshis) -> String {
    let zats = price.into_u64();
    let whole = zats / 100_000_000;
    let frac = zats % 100_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    let digits = format!("{frac:08}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

/// The OTP as zatoshis. Code `123456` is `0.00123456` ZEC.
pub fn otp_amount(code: &OtpCode) -> Zatoshis {
    let digits = code.digits();
    let text = std::str::from_utf8(&digits).expect("digits are ASCII");
    let zats: u64 = text.parse().expect("six digits fit u64");
    Zatoshis::from_u64(zats).expect("a six-digit code is under one ZEC")
}

/// `value - price` equals the OTP amount.
pub fn payment_is_price_plus_otp(value: Zatoshis, price: Zatoshis, code: &OtpCode) -> bool {
    value.into_u64().checked_sub(price.into_u64()) == Some(otp_amount(code).into_u64())
}

fn payment_total(price: Zatoshis, code: &OtpCode) -> Option<u64> {
    price.into_u64().checked_add(otp_amount(code).into_u64())
}

/// Transparent outputs of one block that pay a public-key or script
/// address. The sale compares the address with the one Bob named.
pub fn transparent_payments(block: &Block) -> Vec<(TransparentAddress, Zatoshis)> {
    block
        .vtx()
        .iter()
        .filter_map(|tx| tx.transparent_bundle())
        .flat_map(|bundle| {
            bundle.vout.iter().filter_map(|out| {
                let addr = out.recipient_address()?;
                Some((addr, out.value()))
            })
        })
        .collect()
}

#[derive(Clone)]
enum Phase {
    /// Waiting for a transparent payment that carries the code.
    Paying {
        code: OtpCode,
        pay_to: TransparentAddress,
        price: Zatoshis,
        expires_at: Timestamp,
        relayed: bool,
    },
    /// The payment was seen while `alice` still held the name.
    Paid,
}

#[derive(Clone)]
struct Sale {
    name: Name,
    bob: UnifiedAddress,
    alice: UnifiedAddress,
    /// The live note when the buy opened. A later note ends the sale.
    held: NameCommitment,
    term: Expiry,
    /// The quote is an auction price, frozen for [`D_DUTCH`].
    dutch: bool,
    /// When the quote stops being payable. An auction sale keeps it after
    /// the payment matches, so a later intent can be told the deadline.
    until: Timestamp,
    phase: Phase,
}

/// Open sales. One per name. Rebuilt from the chain on startup.
#[derive(Default)]
pub struct SaleQueue {
    sales: Vec<Sale>,
}

impl SaleQueue {
    pub fn new() -> Self {
        Self { sales: Vec::new() }
    }

    /// Opens a sale and returns the OTP to send Bob. `None` when this
    /// name already has one. A flat quote stays payable for [`D_OTP`].
    /// An auction quote stays payable for [`D_DUTCH`].
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &mut self,
        name: &Name,
        bob: &UnifiedAddress,
        alice: UnifiedAddress,
        pay_to: TransparentAddress,
        price: Zatoshis,
        term: Expiry,
        held: NameCommitment,
        code: OtpCode,
        dutch: bool,
        mtp: Timestamp,
    ) -> Option<BuyOtp> {
        if self.sales.iter().any(|sale| sale.name == *name) {
            return None;
        }
        let window = if dutch { D_DUTCH } else { D_OTP };
        let expires_at = Timestamp::from_seconds(mtp.as_seconds() + window).ok()?;
        self.sales.push(Sale {
            name: name.clone(),
            bob: bob.clone(),
            alice,
            held,
            term,
            dutch,
            until: expires_at,
            phase: Phase::Paying {
                code: code.clone(),
                pay_to,
                price,
                expires_at,
                relayed: false,
            },
        });
        Some(BuyOtp {
            code,
            name: name.clone(),
            ua: bob.clone(),
            dutch: dutch.then_some((price, expires_at)),
        })
    }

    /// Buy OTPs not yet submitted.
    pub fn unrelayed(&self) -> Vec<BuyOtp> {
        self.sales
            .iter()
            .filter_map(|sale| match &sale.phase {
                Phase::Paying {
                    code,
                    price,
                    expires_at,
                    relayed: false,
                    ..
                } => Some(BuyOtp {
                    code: code.clone(),
                    name: sale.name.clone(),
                    ua: sale.bob.clone(),
                    dutch: sale.dutch.then_some((*price, *expires_at)),
                }),
                _ => None,
            })
            .collect()
    }

    /// Every open sale's name.
    pub fn names(&self) -> impl Iterator<Item = &Name> {
        self.sales.iter().map(|sale| &sale.name)
    }

    /// True when a buy already open pays `pay_to` the same total.
    fn same_payment(&self, pay_to: TransparentAddress, price: Zatoshis, code: &OtpCode) -> bool {
        let Some(total) = payment_total(price, code) else {
            return true;
        };
        self.sales.iter().any(|sale| match &sale.phase {
            Phase::Paying {
                code,
                pay_to: addr,
                price,
                ..
            } => *addr == pay_to && payment_total(*price, code) == Some(total),
            Phase::Paid => false,
        })
    }

    /// The buy OTP for this name was submitted.
    pub fn relayed(&mut self, name: &Name) {
        for sale in &mut self.sales {
            if sale.name == *name {
                if let Phase::Paying { relayed, .. } = &mut sale.phase {
                    *relayed = true;
                }
            }
        }
    }

    /// A payment counts when it pays the named address, the amount
    /// minus Alice's price is the OTP, the code has not expired, and
    /// `alice` still holds the name.
    pub fn observe(
        &mut self,
        holder: impl Fn(&Name) -> Option<UnifiedAddress>,
        payments: &[(TransparentAddress, Zatoshis)],
        mtp: Timestamp,
    ) -> Vec<(Name, OtpCode)> {
        let mut used = vec![false; payments.len()];
        let mut paid = Vec::new();
        for sale in &mut self.sales {
            let Phase::Paying {
                code,
                pay_to,
                price,
                expires_at,
                ..
            } = &sale.phase
            else {
                continue;
            };
            if mtp >= *expires_at {
                continue;
            }
            let still_alice = holder(&sale.name).is_some_and(|ua| ua == sale.alice);
            if !still_alice {
                continue;
            }
            let Some(index) = payments
                .iter()
                .enumerate()
                .position(|(index, (addr, value))| {
                    !used[index]
                        && addr == pay_to
                        && payment_is_price_plus_otp(*value, *price, code)
                })
            else {
                continue;
            };
            used[index] = true;
            let code = code.clone();
            sale.phase = Phase::Paid;
            paid.push((sale.name.clone(), code));
        }
        paid
    }

    /// Every unpaid buy counts as sent. Startup uses this so a code read
    /// from the chain is not submitted by this process.
    fn seal_relayed(&mut self) {
        for sale in &mut self.sales {
            if let Phase::Paying { relayed, .. } = &mut sale.phase {
                *relayed = true;
            }
        }
    }

    fn get(&self, name: &Name) -> Option<&Sale> {
        self.sales.iter().find(|sale| sale.name == *name)
    }

    /// The deadline on an open auction sale. The name stays reserved after
    /// the payment matches, until the sale note is signed.
    fn dutch_hold(&self, name: &Name) -> Option<Timestamp> {
        let sale = self.get(name)?;
        sale.dutch.then_some(sale.until)
    }

    fn restore(&mut self, sale: Sale) {
        if self.sales.iter().any(|open| open.name == sale.name) {
            return;
        }
        self.sales.push(sale);
    }

    fn mark_paid(&mut self, name: &Name, code: &OtpCode) {
        for sale in &mut self.sales {
            if sale.name == *name {
                if let Phase::Paying { code: open, .. } = &sale.phase {
                    if open == code {
                        sale.phase = Phase::Paid;
                    }
                }
            }
        }
    }

    fn close(&mut self, name: &Name) {
        self.sales.retain(|sale| sale.name != *name);
    }

    /// A buy is open from the OTP until it expires unpaid or Bob holds the name.
    pub fn is_open(&self, name: &Name) -> bool {
        self.sales.iter().any(|sale| sale.name == *name)
    }

    /// The payment has matched and the sale note is still owed.
    pub fn is_paid(&self, name: &Name) -> bool {
        self.sales
            .iter()
            .any(|sale| sale.name == *name && matches!(sale.phase, Phase::Paid))
    }

    /// Drops an unpaid sale whose code has expired. The names leave in order.
    pub fn expire(&mut self, mtp: Timestamp) -> Vec<Name> {
        let mut dropped = Vec::new();
        self.sales.retain(|sale| match &sale.phase {
            Phase::Paying { expires_at, .. } => {
                if mtp < *expires_at {
                    true
                } else {
                    dropped.push(sale.name.clone());
                    false
                }
            }
            Phase::Paid => true,
        });
        dropped
    }

    /// Drops a sale whose captured note is gone. A paid sale whose note is
    /// still that one stays, so the caller can sign it.
    pub fn reconcile(
        &mut self,
        live: impl Fn(&Name) -> Option<(UnifiedAddress, NameCommitment)>,
    ) -> Vec<Name> {
        let mut closed = Vec::new();
        self.sales.retain(|sale| {
            let moved = match live(&sale.name) {
                Some((ua, commitment)) => ua != sale.alice || commitment != sale.held,
                None => true,
            };
            if moved {
                closed.push(sale.name.clone());
                false
            } else {
                true
            }
        });
        closed
    }

    /// After a matching payment, sign a sale while the captured note is live.
    /// The sale leaves once that note is gone.
    pub fn poll(
        &mut self,
        registry: &Registry,
        pending: impl Fn(&Name) -> bool,
    ) -> (Vec<NameNote>, Vec<Name>) {
        let mut notes = Vec::new();
        let mut closed = Vec::new();
        self.sales.retain_mut(|sale| {
            if !matches!(sale.phase, Phase::Paid) {
                return true;
            }
            if pending(&sale.name) {
                return true;
            }
            let Some(record) = registry.record(&sale.name) else {
                closed.push(sale.name.clone());
                return false;
            };
            if record.ua == sale.bob || record.ua != sale.alice || record.commitment != sale.held {
                closed.push(sale.name.clone());
                return false;
            }
            let Some(note) = registry.sale_transfer(&sale.name, &sale.bob, sale.term, sale.held)
            else {
                closed.push(sale.name.clone());
                return false;
            };
            notes.push(note);
            true
        });
        (notes, closed)
    }
}

/// An auction's terms. The start block quotes `start_price`. The end
/// block quotes `min_price` and is the last block that sells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuctionTerms {
    pub start_price: Zatoshis,
    pub min_price: Zatoshis,
    pub start: BlockHeight,
    pub end: BlockHeight,
}

impl AuctionTerms {
    /// The end is after the start, and the price falls.
    pub fn is_valid(&self) -> bool {
        self.end > self.start && self.start_price > self.min_price
    }

    /// Whole-zatoshis fall. A height outside the span has no price.
    pub fn price_at(&self, height: BlockHeight) -> Option<Zatoshis> {
        if !self.is_valid() || height < self.start || height > self.end {
            return None;
        }
        let span = u128::from(u32::from(self.end) - u32::from(self.start));
        let elapsed = u128::from(u32::from(height) - u32::from(self.start));
        let drop = u128::from(self.start_price.into_u64() - self.min_price.into_u64());
        let fallen = u64::try_from(drop * elapsed / span).ok()?;
        Zatoshis::from_u64(self.start_price.into_u64() - fallen).ok()
    }
}

/// What the buyer pays. A flat price is the listing. An auction price is
/// the price of the block his intent is mined in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ask {
    Flat(Zatoshis),
    Dutch(AuctionTerms),
}

/// One listing per name. Rebuilt from the chain on startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    pub name: Name,
    pub ua: UnifiedAddress,
    pub pay_to: TransparentAddress,
    pub ask: Ask,
}

/// Why a list, delist, or buy did not change the market.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarketRefusal {
    /// A buy is open, so the listing stays as it was.
    BuyOpen,
    /// The caller does not own the name, or the t1 is not hers.
    NotOwner,
    /// The name has no listing.
    NotListed,
    /// A name note is already in flight.
    InFlight,
    /// The purchased term or the liveness deadline has passed.
    ReleaseDue,
    /// This name already has a buy.
    AlreadyOpen,
    /// An open challenge already carries this code.
    CodeTaken,
    /// An open buy already pays this address the same total.
    PaymentTaken,
    /// The auction has not reached its start block.
    Early { start: BlockHeight },
    /// An auction sale still reserves the name.
    Held { until: Timestamp },
    /// The end is not after the start, or the price does not fall.
    BadTerms,
    /// This block is after the auction's end block.
    Ended,
}

/// An auction lists through its end block. A later height leaves the book.
fn listable(ask: &Ask, height: BlockHeight) -> Result<(), MarketRefusal> {
    let Ask::Dutch(terms) = ask else {
        return Ok(());
    };
    if !terms.is_valid() {
        return Err(MarketRefusal::BadTerms);
    }
    if height > terms.end {
        return Err(MarketRefusal::Ended);
    }
    Ok(())
}

/// A list or delist waiting for the controller's code.
#[derive(Clone)]
struct MarketChallenge {
    kind: ChallengeKind,
    code: OtpCode,
    expires_at: Timestamp,
    relayed: bool,
    attempts: u32,
}

#[derive(Clone)]
enum ChallengeKind {
    List(Box<Listing>),
    Delist { name: Name, ua: Box<UnifiedAddress> },
}

impl MarketChallenge {
    fn name(&self) -> &Name {
        match &self.kind {
            ChallengeKind::List(listing) => &listing.name,
            ChallengeKind::Delist { name, .. } => name,
        }
    }

    fn ua(&self) -> &UnifiedAddress {
        match &self.kind {
            ChallengeKind::List(listing) => &listing.ua,
            ChallengeKind::Delist { ua, .. } => ua.as_ref(),
        }
    }

    fn action(&self) -> Action {
        match &self.kind {
            ChallengeKind::List(listing) => match &listing.ask {
                Ask::Flat(_) => Action::List,
                Ask::Dutch(_) => Action::Auction,
            },
            ChallengeKind::Delist { .. } => Action::Delist,
        }
    }

    fn memo(&self) -> OtpMemo {
        let (listing, auction) = match &self.kind {
            ChallengeKind::List(listed) => match &listed.ask {
                Ask::Flat(price) => (Some((listed.pay_to, *price)), None),
                Ask::Dutch(terms) => (None, Some((listed.pay_to, terms.clone()))),
            },
            ChallengeKind::Delist { .. } => (None, None),
        };
        OtpMemo {
            code: self.code.clone(),
            name: self.name().clone(),
            action: self.action(),
            ua: self.ua().clone(),
            listing,
            auction,
        }
    }

    fn held_by(&self, owner: &UnifiedAddress) -> bool {
        match &self.kind {
            ChallengeKind::List(listing) => is_owner_listing(owner, &listing.ua, &listing.pay_to),
            ChallengeKind::Delist { ua, .. } => ua.as_ref() == owner,
        }
    }

    fn same_list(&self, listing: &Listing) -> bool {
        matches!(&self.kind, ChallengeKind::List(held) if held.as_ref() == listing)
    }

    fn same_terms(&self, response: &OtpMemo) -> bool {
        match &self.kind {
            ChallengeKind::List(listing) => match &listing.ask {
                Ask::Flat(price) => {
                    response.auction.is_none()
                        && response.listing.as_ref().is_some_and(|(pay_to, quoted)| {
                            *pay_to == listing.pay_to && quoted == price
                        })
                }
                Ask::Dutch(terms) => response
                    .auction
                    .as_ref()
                    .is_some_and(|(pay_to, quoted)| *pay_to == listing.pay_to && quoted == terms),
            },
            ChallengeKind::Delist { .. } => {
                response.listing.is_none() && response.auction.is_none()
            }
        }
    }

    fn same_delist(&self, name: &Name, ua: &UnifiedAddress) -> bool {
        match &self.kind {
            ChallengeKind::Delist {
                name: held,
                ua: owner,
            } => held == name && owner.as_ref() == ua,
            ChallengeKind::List(_) => false,
        }
    }
}

enum MarketEvent {
    List { listing: Box<Listing> },
    Delist { name: Name },
    Open { sale: Box<Sale> },
    Paid { name: Name, code: OtpCode },
    Expire { name: Name },
    Close { name: Name },
    Challenge { challenge: Box<MarketChallenge> },
    ChallengeClosed { code: OtpCode },
}

struct Stamped {
    height: BlockHeight,
    event: MarketEvent,
}

/// Listings and the buys against them. A buy holds the name: no new
/// listing, no delist, and no update, release, or lifecycle release.
/// The event log is what a startup and a rollback rebuild from.
#[derive(Default)]
pub struct Market {
    sales: SaleQueue,
    challenges: Vec<MarketChallenge>,
    events: Vec<Stamped>,
}

impl Market {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn names(&self) -> impl Iterator<Item = &Name> {
        self.sales.names()
    }

    pub fn is_open(&self, name: &Name) -> bool {
        self.sales.is_open(name)
    }

    pub fn is_paid(&self, name: &Name) -> bool {
        self.sales.is_paid(name)
    }

    /// An update, a release, an OTP response, or a lifecycle release
    /// may proceed. False while a buy is open.
    pub fn allows_transition(&self, name: &Name) -> bool {
        !self.sales.is_open(name)
    }

    pub fn unrelayed(&self) -> Vec<BuyOtp> {
        self.sales.unrelayed()
    }

    /// The node accepted the buy OTP. The open event keeps `relayed` clear,
    /// so a rollback submits that code.
    pub fn relayed(&mut self, name: &Name) {
        self.sales.relayed(name);
    }

    /// An unpaid buy read from the chain stays payable and unsent. The
    /// open event records that, so a later rollback leaves the code unsent.
    pub fn seal_replayed_buys(&mut self) {
        self.sales.seal_relayed();
        for stamped in &mut self.events {
            if let MarketEvent::Open { sale } = &mut stamped.event {
                if let Phase::Paying { relayed, .. } = &mut sale.phase {
                    *relayed = true;
                }
            }
        }
    }

    pub fn observe(
        &mut self,
        holder: impl Fn(&Name) -> Option<UnifiedAddress>,
        payments: &[(TransparentAddress, Zatoshis)],
        mtp: Timestamp,
        height: BlockHeight,
    ) {
        for (name, code) in self.sales.observe(holder, payments, mtp) {
            self.record(height, MarketEvent::Paid { name, code });
        }
    }

    /// Drops unpaid sales and controller challenges whose time has
    /// passed, and an auction listing on the block after its end.
    pub fn expire(&mut self, registry: &mut Registry, mtp: Timestamp, height: BlockHeight) {
        for name in registry.delist_ended_auctions(height) {
            self.record(height, MarketEvent::Delist { name });
        }
        for name in self.sales.expire(mtp) {
            self.record(height, MarketEvent::Expire { name });
        }
        let expired: Vec<OtpCode> = self
            .challenges
            .iter()
            .filter(|challenge| mtp >= challenge.expires_at)
            .map(|challenge| challenge.code.clone())
            .collect();
        for code in expired {
            self.close_challenge(code, height);
        }
    }

    /// Drops a listing whose owner no longer holds the name, and a sale
    /// whose captured note is no longer live. A scan calls this before
    /// the block's memos, so a finished sale does not block them.
    pub fn reconcile(&mut self, registry: &mut Registry, height: BlockHeight) {
        for name in registry.reconcile_listings() {
            self.record(height, MarketEvent::Delist { name });
        }
        let live = |name: &Name| {
            registry
                .record(name)
                .map(|record| (record.ua.clone(), record.commitment))
        };
        let stale: Vec<OtpCode> = self
            .challenges
            .iter()
            .filter(|challenge| match live(challenge.name()) {
                Some((ua, _)) => ua != *challenge.ua(),
                None => true,
            })
            .map(|challenge| challenge.code.clone())
            .collect();
        for code in stale {
            self.close_challenge(code, height);
        }
        for name in self.sales.reconcile(live) {
            self.record(height, MarketEvent::Close { name });
        }
    }

    /// Drops entries from blocks above `height` and rebuilds the rest.
    pub fn truncate_to(&mut self, registry: &mut Registry, height: BlockHeight) {
        self.events.retain(|event| event.height <= height);
        let events = std::mem::take(&mut self.events);
        self.sales = SaleQueue::new();
        registry.clear_listings();
        self.challenges.clear();
        for stamped in &events {
            match &stamped.event {
                MarketEvent::List { listing } => registry.restore_listing(listing.as_ref().clone()),
                MarketEvent::Delist { name } => {
                    registry.remove_listing(name);
                }
                MarketEvent::Open { sale } => self.sales.restore(sale.as_ref().clone()),
                MarketEvent::Paid { name, code } => self.sales.mark_paid(name, code),
                MarketEvent::Expire { name } | MarketEvent::Close { name } => {
                    self.sales.close(name);
                }
                MarketEvent::Challenge { challenge } => {
                    self.restore_challenge(challenge.as_ref().clone());
                }
                MarketEvent::ChallengeClosed { code } => self.drop_challenge(code),
            }
        }
        self.events = events;
    }

    pub fn poll(
        &mut self,
        registry: &Registry,
        pending: impl Fn(&Name) -> bool,
        height: BlockHeight,
    ) -> Vec<NameNote> {
        let (notes, closed) = self.sales.poll(registry, pending);
        for name in closed {
            self.record(height, MarketEvent::Close { name });
        }
        notes
    }

    fn record(&mut self, height: BlockHeight, event: MarketEvent) {
        self.events.push(Stamped { height, event });
    }

    /// Lists when the registry confirms the controller and no buy is open.
    pub fn list(
        &mut self,
        registry: &mut Registry,
        listing: &Listing,
        height: BlockHeight,
    ) -> Result<(), MarketRefusal> {
        listable(&listing.ask, height)?;
        if self.sales.is_open(&listing.name) {
            return Err(MarketRefusal::BuyOpen);
        }
        let listing = listing.clone();
        registry.list(listing.clone())?;
        self.record(
            height,
            MarketEvent::List {
                listing: Box::new(listing),
            },
        );
        Ok(())
    }

    /// Delists when `ua` still owns the name and no buy is open.
    pub fn delist(
        &mut self,
        registry: &mut Registry,
        name: &Name,
        ua: &UnifiedAddress,
        height: BlockHeight,
    ) -> Result<(), MarketRefusal> {
        if self.sales.is_open(name) {
            return Err(MarketRefusal::BuyOpen);
        }
        registry.delist(name, ua)?;
        self.record(height, MarketEvent::Delist { name: name.clone() });
        Ok(())
    }

    /// Opens a buy from the current listing. The caller drops any
    /// challenge already queued for the name.
    #[allow(clippy::too_many_arguments)]
    pub fn open_buy(
        &mut self,
        registry: &Registry,
        name: &Name,
        bob: &UnifiedAddress,
        owner: &UnifiedAddress,
        term: Expiry,
        held: NameCommitment,
        release_due: bool,
        note_pending: bool,
        code: OtpCode,
        mtp: Timestamp,
        height: BlockHeight,
    ) -> Result<BuyOtp, MarketRefusal> {
        if self.sales.is_open(name) {
            if let Some(until) = self.sales.dutch_hold(name) {
                return Err(MarketRefusal::Held { until });
            }
            return Err(MarketRefusal::AlreadyOpen);
        }
        let (pay_to, price, dutch) = {
            let Some(listing) = registry.listing(name) else {
                return Err(MarketRefusal::NotListed);
            };
            if !is_owner_listing(owner, &listing.ua, &listing.pay_to) {
                return Err(MarketRefusal::NotOwner);
            }
            match &listing.ask {
                Ask::Flat(price) => (listing.pay_to, *price, false),
                Ask::Dutch(terms) => {
                    if height < terms.start {
                        return Err(MarketRefusal::Early { start: terms.start });
                    }
                    let Some(price) = terms.price_at(height) else {
                        return Err(MarketRefusal::NotListed);
                    };
                    (listing.pay_to, price, true)
                }
            }
        };
        if release_due {
            return Err(MarketRefusal::ReleaseDue);
        }
        if note_pending {
            return Err(MarketRefusal::InFlight);
        }
        if self.sales.same_payment(pay_to, price, &code) {
            return Err(MarketRefusal::PaymentTaken);
        }
        let otp = self
            .sales
            .open(
                name,
                bob,
                owner.clone(),
                pay_to,
                price,
                term,
                held,
                code,
                dutch,
                mtp,
            )
            .ok_or(MarketRefusal::AlreadyOpen)?;
        let sale = self.sales.get(name).expect("just opened").clone();
        self.record(
            height,
            MarketEvent::Open {
                sale: Box::new(sale),
            },
        );
        self.close_challenges_for(name, height);
        Ok(otp)
    }

    /// Controller challenges not yet sent, while `owner` still holds the
    /// name on the terms each one names.
    pub fn unrelayed_challenges(
        &self,
        owner: impl Fn(&Name) -> Option<UnifiedAddress>,
    ) -> Vec<OtpMemo> {
        self.challenges
            .iter()
            .filter(|challenge| !challenge.relayed && !self.sales.is_open(challenge.name()))
            .filter(|challenge| owner(challenge.name()).is_some_and(|ua| challenge.held_by(&ua)))
            .map(MarketChallenge::memo)
            .collect()
    }

    /// The node accepted the challenge memo. The challenge event keeps
    /// `relayed` clear, so a rollback submits that code.
    pub fn challenge_relayed(&mut self, code: &OtpCode) {
        for challenge in &mut self.challenges {
            if &challenge.code == code {
                challenge.relayed = true;
            }
        }
    }

    /// Records a list challenge. The listing changes when the controller
    /// returns `code`.
    pub fn propose_list(
        &mut self,
        listing: &Listing,
        owner: &UnifiedAddress,
        code: OtpCode,
        mtp: Timestamp,
        height: BlockHeight,
    ) -> Result<(), MarketRefusal> {
        listable(&listing.ask, height)?;
        if !is_owner_listing(owner, &listing.ua, &listing.pay_to) {
            return Err(MarketRefusal::NotOwner);
        }
        if self.sales.is_open(&listing.name) {
            return Err(MarketRefusal::BuyOpen);
        }
        if self
            .challenges
            .iter()
            .any(|challenge| challenge.same_list(listing))
        {
            return Ok(());
        }
        if self.code_is_open(&code) {
            return Err(MarketRefusal::CodeTaken);
        }
        self.push_challenge(
            MarketChallenge {
                kind: ChallengeKind::List(Box::new(listing.clone())),
                code,
                expires_at: Timestamp::from_seconds(mtp.as_seconds() + D_OTP)
                    .expect("challenge expiry fits a timestamp"),
                relayed: false,
                attempts: 0,
            },
            height,
        );
        Ok(())
    }

    /// Records a delist challenge. The listing leaves when the controller
    /// returns `code`.
    pub fn propose_delist(
        &mut self,
        registry: &Registry,
        name: &Name,
        ua: &UnifiedAddress,
        code: OtpCode,
        mtp: Timestamp,
        height: BlockHeight,
    ) -> Result<(), MarketRefusal> {
        if registry.record(name).is_none_or(|record| record.ua != *ua) {
            return Err(MarketRefusal::NotOwner);
        }
        if self.sales.is_open(name) {
            return Err(MarketRefusal::BuyOpen);
        }
        if registry.listing(name).is_none() {
            return Err(MarketRefusal::NotListed);
        }
        if self
            .challenges
            .iter()
            .any(|challenge| challenge.same_delist(name, ua))
        {
            return Ok(());
        }
        if self.code_is_open(&code) {
            return Err(MarketRefusal::CodeTaken);
        }
        self.push_challenge(
            MarketChallenge {
                kind: ChallengeKind::Delist {
                    name: name.clone(),
                    ua: Box::new(ua.clone()),
                },
                code,
                expires_at: Timestamp::from_seconds(mtp.as_seconds() + D_OTP)
                    .expect("challenge expiry fits a timestamp"),
                relayed: false,
                attempts: 0,
            },
            height,
        );
        Ok(())
    }

    /// Applies the challenge `response` names, when the code matches and
    /// the named address is still the controller. A matching code spends the challenge.
    pub fn answer(
        &mut self,
        registry: &mut Registry,
        response: &OtpMemo,
        height: BlockHeight,
    ) -> bool {
        if !response.action.is_list()
            && !response.action.is_delist()
            && !response.action.is_auction()
        {
            return false;
        }
        let named: Vec<usize> = self
            .challenges
            .iter()
            .enumerate()
            .filter(|(_, challenge)| {
                challenge.name() == &response.name
                    && challenge.ua() == &response.ua
                    && challenge.action() == response.action
            })
            .map(|(index, _)| index)
            .collect();
        if named.is_empty() {
            return false;
        }
        if let Some(index) = named.iter().copied().find(|&index| {
            let challenge = &self.challenges[index];
            challenge.code == response.code && challenge.same_terms(response)
        }) {
            let challenge = self.challenges.remove(index);
            self.record(
                height,
                MarketEvent::ChallengeClosed {
                    code: challenge.code.clone(),
                },
            );
            if self.sales.is_open(challenge.name()) {
                return true;
            }
            match &challenge.kind {
                ChallengeKind::List(listing) => {
                    let _ = self.list(registry, listing, height);
                }
                ChallengeKind::Delist { name, ua } => {
                    let _ = self.delist(registry, name, ua, height);
                }
            }
            return true;
        }
        for index in named.into_iter().rev() {
            self.challenges[index].attempts += 1;
            if self.challenges[index].attempts >= MAX_ATTEMPTS {
                let code = self.challenges[index].code.clone();
                self.close_challenge(code, height);
            }
        }
        false
    }

    fn code_is_open(&self, code: &OtpCode) -> bool {
        self.challenges
            .iter()
            .any(|challenge| &challenge.code == code)
    }

    fn push_challenge(&mut self, challenge: MarketChallenge, height: BlockHeight) {
        self.record(
            height,
            MarketEvent::Challenge {
                challenge: Box::new(challenge.clone()),
            },
        );
        self.challenges.push(challenge);
    }

    fn restore_challenge(&mut self, challenge: MarketChallenge) {
        if self
            .challenges
            .iter()
            .any(|held| held.code == challenge.code)
        {
            return;
        }
        self.challenges.push(challenge);
    }

    fn drop_challenge(&mut self, code: &OtpCode) {
        self.challenges.retain(|challenge| &challenge.code != code);
    }

    fn close_challenge(&mut self, code: OtpCode, height: BlockHeight) {
        self.drop_challenge(&code);
        self.record(height, MarketEvent::ChallengeClosed { code });
    }

    fn close_challenges_for(&mut self, name: &Name, height: BlockHeight) {
        let codes: Vec<OtpCode> = self
            .challenges
            .iter()
            .filter(|challenge| challenge.name() == name)
            .map(|challenge| challenge.code.clone())
            .collect();
        for code in codes {
            self.close_challenge(code, height);
        }
    }

    /// Applies one list, delist, or buy. `opened` is a buy the caller
    /// drops challenges for. `returned` is an intent payment to send back.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &mut self,
        txid: TxId,
        request: &MarketRequest,
        paid: Zatoshis,
        registry: &Registry,
        fee_rule: &FeeRule,
        height: BlockHeight,
        mtp: Timestamp,
        pending: impl Fn(&Name) -> bool,
        key: &AccessCodeDerivationKey,
    ) -> Admission {
        let fee_ok = (fee_rule.marginal_fee() * FEE_ACTIONS).is_some_and(|fee| paid >= fee);
        match request {
            MarketRequest::List(listing) => {
                let Some(record) = registry.record(&listing.name) else {
                    tracing::info!(
                        %txid,
                        name = %listing.name.as_str(),
                        "list fee kept: name is not live"
                    );
                    return Admission::none();
                };
                if !fee_ok || record.is_release_due(mtp) || pending(&listing.name) {
                    tracing::info!(
                        %txid,
                        name = %listing.name.as_str(),
                        "list fee kept: listing not opened"
                    );
                    return Admission::none();
                }
                let code = match &listing.ask {
                    Ask::Flat(price) => key.list_otp(&txid, &listing.name, *price, &listing.pay_to),
                    Ask::Dutch(terms) => {
                        key.auction_otp(&txid, &listing.name, terms, &listing.pay_to)
                    }
                };
                match self.propose_list(listing, &record.ua, code, mtp, height) {
                    Ok(()) => {}
                    Err(MarketRefusal::BuyOpen) => tracing::info!(
                        %txid,
                        name = %listing.name.as_str(),
                        "list fee kept: a buy is open"
                    ),
                    Err(MarketRefusal::CodeTaken) => tracing::info!(
                        %txid,
                        name = %listing.name.as_str(),
                        "list fee kept: that code is already open"
                    ),
                    Err(MarketRefusal::BadTerms) => tracing::info!(
                        %txid,
                        name = %listing.name.as_str(),
                        "list fee kept: bad auction terms"
                    ),
                    Err(MarketRefusal::Ended) => tracing::info!(
                        %txid,
                        name = %listing.name.as_str(),
                        "list fee kept: the auction has ended"
                    ),
                    Err(_) => tracing::info!(
                        %txid,
                        name = %listing.name.as_str(),
                        "list fee kept: lister is not the owner"
                    ),
                }
                Admission::none()
            }
            MarketRequest::Delist { name, ua } => {
                if registry.record(name).is_none_or(|record| record.ua != *ua) {
                    tracing::info!(
                        %txid,
                        name = %name.as_str(),
                        "delist fee kept: listing unchanged"
                    );
                    return Admission::none();
                };
                if !fee_ok || pending(name) {
                    tracing::info!(
                        %txid,
                        name = %name.as_str(),
                        "delist fee kept: listing unchanged"
                    );
                    return Admission::none();
                }
                let code = key.delist_otp(&txid, name);
                match self.propose_delist(registry, name, ua, code, mtp, height) {
                    Ok(()) => {}
                    Err(MarketRefusal::BuyOpen) => tracing::info!(
                        %txid,
                        name = %name.as_str(),
                        "delist fee kept: a buy is open"
                    ),
                    Err(MarketRefusal::CodeTaken) => tracing::info!(
                        %txid,
                        name = %name.as_str(),
                        "delist fee kept: that code is already open"
                    ),
                    Err(_) => tracing::info!(
                        %txid,
                        name = %name.as_str(),
                        "delist fee kept: listing unchanged"
                    ),
                }
                Admission::none()
            }
            MarketRequest::Buy { name, ua: bob } => {
                let Some(record) = registry.record(name) else {
                    tracing::info!(
                        %txid,
                        name = %name.as_str(),
                        paid = paid.into_u64(),
                        "buy fee kept: name is not live"
                    );
                    return Admission::none();
                };
                let release_due = record.is_release_due(mtp);
                let note_pending = pending(name);
                let owner = record.ua.clone();
                let term = record.expires_at;
                let held = record.commitment;
                let code = key.buy_otp(&txid, name);
                if !fee_ok {
                    tracing::info!(
                        %txid,
                        name = %name.as_str(),
                        paid = paid.into_u64(),
                        "buy fee kept: sale not opened"
                    );
                    return Admission::none();
                }
                match self.open_buy(
                    registry,
                    name,
                    bob,
                    &owner,
                    term,
                    held,
                    release_due,
                    note_pending,
                    code,
                    mtp,
                    height,
                ) {
                    Ok(_) => Admission::opened(name.clone()),
                    Err(MarketRefusal::Held { until }) => {
                        tracing::info!(
                            %txid,
                            name = %name.as_str(),
                            "buy returned: the name is held"
                        );
                        Admission {
                            opened: None,
                            returned: returned_intent(name, bob, MarketRefusal::Held { until }),
                        }
                    }
                    Err(MarketRefusal::Early { start }) => {
                        tracing::info!(
                            %txid,
                            name = %name.as_str(),
                            "buy returned: the auction has not started"
                        );
                        Admission {
                            opened: None,
                            returned: returned_intent(name, bob, MarketRefusal::Early { start }),
                        }
                    }
                    Err(MarketRefusal::NotListed) => {
                        tracing::info!(
                            %txid,
                            name = %name.as_str(),
                            "buy fee kept: name is not listed"
                        );
                        Admission::none()
                    }
                    Err(MarketRefusal::AlreadyOpen) => {
                        tracing::info!(
                            %txid,
                            name = %name.as_str(),
                            "buy fee kept: sale already open"
                        );
                        Admission::none()
                    }
                    Err(MarketRefusal::PaymentTaken) => {
                        tracing::info!(
                            %txid,
                            name = %name.as_str(),
                            "buy fee kept: that payment is already open"
                        );
                        Admission::none()
                    }
                    Err(_) => {
                        tracing::info!(
                            %txid,
                            name = %name.as_str(),
                            paid = paid.into_u64(),
                            "buy fee kept: sale not opened"
                        );
                        Admission::none()
                    }
                }
            }
        }
    }
}

/// What one market memo changed. `opened` is a buy the caller drops
/// challenges for. `returned` is an intent payment to send back.
#[derive(Clone, Debug)]
pub struct Admission {
    pub opened: Option<Name>,
    pub returned: Option<ReturnedIntent>,
}

impl Admission {
    fn none() -> Self {
        Self {
            opened: None,
            returned: None,
        }
    }

    fn opened(name: Name) -> Self {
        Self {
            opened: Some(name),
            returned: None,
        }
    }
}

/// An intent that did not win, and the sentence that goes back with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnedIntent {
    pub recipient: UnifiedAddress,
    pub name: Name,
    pub note: String,
}

fn returned_intent(
    name: &Name,
    bob: &UnifiedAddress,
    refusal: MarketRefusal,
) -> Option<ReturnedIntent> {
    let note = match refusal {
        MarketRefusal::Held { until } => {
            format!("ZNS:held:{}:{}", name.as_str(), until.as_seconds())
        }
        MarketRefusal::Early { start } => {
            format!("ZNS:wait:{}:{}", name.as_str(), u32::from(start))
        }
        _ => return None,
    };
    Some(ReturnedIntent {
        recipient: bob.clone(),
        name: name.clone(),
        note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::decode_controller_ua;
    use crate::mint::treasury::RefundQueue;
    use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;
    use zcash_protocol::consensus::MainNetwork;
    use zcash_protocol::memo::Memo;

    const TEST_UA: &str = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";

    fn padded(s: &str) -> MemoBytes {
        let mut m = [0u8; 512];
        m[..s.len()].copy_from_slice(s.as_bytes());
        MemoBytes::from_bytes(&m).expect("a 512-byte memo fits")
    }

    fn t1() -> String {
        Address::Transparent(TransparentAddress::PublicKeyHash([0x11; 20])).encode(&MainNetwork)
    }

    #[test]
    fn buy_memo_names_the_name_and_the_buyer() {
        let network = MainNetwork;
        let memo = padded(&format!("ZNS:buy:alice:{TEST_UA}"));
        assert!(matches!(
            crate::mint::MintInbound::decode(&network, &memo),
            crate::mint::MintInbound::Market(MarketRequest::Buy { name, .. }) if name.as_str() == "alice"
        ));
    }

    #[test]
    fn a_listing_requires_the_owner_and_her_transparent_receiver() {
        let network = MainNetwork;
        let base = decode_controller_ua(&network, TEST_UA).unwrap();
        let pay_to = TransparentAddress::PublicKeyHash([0x11; 20]);
        let owner = UnifiedAddress::from_receivers(
            base.orchard().copied(),
            base.sapling().cloned(),
            Some(pay_to),
            None,
            None,
        )
        .unwrap();
        let memo = padded(&format!(
            "ZNS:list:alice:{}:{}:1.5",
            owner.encode(&network),
            t1()
        ));
        let Some(MarketRequest::List(list)) = MarketRequest::decode(&network, &memo) else {
            panic!("expected list")
        };
        assert!(is_owner_listing(&owner, &list.ua, &list.pay_to));
        assert_eq!(
            list.ask,
            Ask::Flat(Zatoshis::from_u64(150_000_000).unwrap())
        );
        let other = TransparentAddress::PublicKeyHash([0x22; 20]);
        assert!(!is_owner_listing(&owner, &list.ua, &other));
        assert!(!is_owner_listing(&base, &list.ua, &list.pay_to));
        assert!(MarketRequest::decode(
            &network,
            &padded(&format!(
                "ZNS:list:alice:{}:{}:1.123456789",
                owner.encode(&network),
                t1()
            ))
        )
        .is_none());
    }

    #[test]
    fn delist_names_the_owner() {
        let network = MainNetwork;
        let memo = padded(&format!("ZNS:delist:alice:{TEST_UA}"));
        assert!(matches!(
            crate::mint::MintInbound::decode(&network, &memo),
            crate::mint::MintInbound::Market(MarketRequest::Delist { name, .. }) if name.as_str() == "alice"
        ));
    }

    #[test]
    fn a_buy_otp_is_not_a_challenge_sentence() {
        let network = MainNetwork;
        let otp = BuyOtp {
            code: OtpCode::for_test(*b"042831"),
            name: Name::parse("alice").unwrap(),
            ua: decode_controller_ua(&network, TEST_UA).unwrap(),
            dutch: None,
        };
        let memo = otp.encode(&network).expect("memo fits");
        let Memo::Text(text) = Memo::try_from(&memo).unwrap() else {
            panic!("text memo");
        };
        assert!(text.starts_with("ZNS:buyotp:042831:alice:"));
        // A buy OTP is not a challenge and not a buy request.
        assert!(matches!(
            crate::mint::MintInbound::decode(&network, &memo),
            crate::mint::MintInbound::Unrecognized
        ));
    }

    #[test]
    fn the_payment_minus_the_price_is_the_otp() {
        // Code 123456 is 0.00123456 ZEC.
        let code = OtpCode::for_test(*b"123456");
        let price = Zatoshis::from_u64(150_000_000).unwrap();
        let paid = Zatoshis::from_u64(150_123_456).unwrap();
        assert!(payment_is_price_plus_otp(paid, price, &code));
        // 1.009 ZEC + 0.002 ZEC = 1.011 ZEC. The difference is the code.
        let carried_price = Zatoshis::from_u64(100_900_000).unwrap();
        let carried = OtpCode::for_test(*b"200000");
        let carried_paid = Zatoshis::from_u64(101_100_000).unwrap();
        assert!(payment_is_price_plus_otp(
            carried_paid,
            carried_price,
            &carried
        ));
        let short = Zatoshis::from_u64(150_123_455).unwrap();
        assert!(!payment_is_price_plus_otp(short, price, &code));
    }

    #[test]
    fn an_unpaid_sale_expires_with_the_code() {
        let mut sales = SaleQueue::new();
        let mtp = Timestamp::from_seconds(1_700_000_000).unwrap();
        assert!(sales
            .open(
                &name(),
                &bob(),
                bob(),
                TransparentAddress::PublicKeyHash([0x11; 20]),
                Zatoshis::from_u64(150_000_000).unwrap(),
                Expiry::Never,
                held(),
                OtpCode::for_test(*b"042831"),
                false,
                mtp,
            )
            .is_some());
        assert_eq!(sales.unrelayed().len(), 1);
        assert!(sales.is_open(&name()));
        sales.expire(Timestamp::from_seconds(1_700_000_000 + D_OTP).unwrap());
        assert!(sales.unrelayed().is_empty());
        assert!(!sales.is_open(&name()));
    }

    fn alice() -> (UnifiedAddress, TransparentAddress) {
        let base = decode_controller_ua(&MainNetwork, TEST_UA).unwrap();
        let pay_to = TransparentAddress::PublicKeyHash([0x11; 20]);
        let ua = UnifiedAddress::from_receivers(
            base.orchard().copied(),
            base.sapling().cloned(),
            Some(pay_to),
            None,
            None,
        )
        .unwrap();
        (ua, pay_to)
    }

    fn bob() -> UnifiedAddress {
        decode_controller_ua(&MainNetwork, TEST_UA).unwrap()
    }

    fn name() -> Name {
        Name::parse("alice").unwrap()
    }

    fn held() -> NameCommitment {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        NameCommitment::from_bytes(&bytes).unwrap()
    }

    fn zats(n: u64) -> Zatoshis {
        Zatoshis::from_u64(n).unwrap()
    }

    fn mtp() -> Timestamp {
        Timestamp::from_seconds(1_700_000_000).unwrap()
    }

    fn height() -> BlockHeight {
        BlockHeight::from_u32(1)
    }

    fn list_for(price: u64) -> Listing {
        let (ua, pay_to) = alice();
        Listing {
            name: name(),
            ua,
            pay_to,
            ask: Ask::Flat(zats(price)),
        }
    }

    fn sale_registry() -> Registry {
        let mut registry = Registry::new();
        for (index, text) in ["alice", "zed"].into_iter().enumerate() {
            let anchor = nf(10 + index as u8);
            registry.adopt_anchor(BlockHeight::from_u32(0), anchor);
            let note = NameNote::Claim {
                name: Name::parse(text).unwrap(),
                ua: alice().0,
                expires_at: Expiry::Never,
            };
            assert!(registry.accept_claim(
                &MainNetwork,
                &note,
                nf(20 + index as u8),
                Some(nf(40 + index as u8)),
                &[anchor],
                height(),
                mtp(),
                BlockHeight::from_u32(41),
            ));
        }
        registry
    }

    fn listed(price: u64) -> (Market, Registry, UnifiedAddress, TransparentAddress) {
        let (owner, pay_to) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        market
            .list(&mut registry, &list_for(price), height())
            .unwrap();
        (market, registry, owner, pay_to)
    }

    fn buying(price: u64) -> (Market, Registry, UnifiedAddress, TransparentAddress, BuyOtp) {
        let (mut market, registry, owner, pay_to) = listed(price);
        let otp = market
            .open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                OtpCode::generate(),
                mtp(),
                height(),
            )
            .unwrap();
        (market, registry, owner, pay_to, otp)
    }

    #[test]
    fn a_delist_during_a_buy_leaves_the_listing() {
        let (mut market, mut registry, owner, _, _) = buying(150_000_000);
        assert_eq!(
            market.delist(&mut registry, &name(), &owner, height()),
            Err(MarketRefusal::BuyOpen)
        );
        assert_eq!(registry.price(&name()), Some(zats(150_000_000)));
        assert!(!market.allows_transition(&name()));
    }

    #[test]
    fn a_relist_during_a_buy_keeps_the_price() {
        let (mut market, mut registry, owner, pay_to, _) = buying(150_000_000);
        let higher = Listing {
            name: name(),
            ua: owner.clone(),
            pay_to,
            ask: Ask::Flat(zats(200_000_000)),
        };
        assert_eq!(
            market.list(&mut registry, &higher, height()),
            Err(MarketRefusal::BuyOpen)
        );
        assert_eq!(registry.price(&name()), Some(zats(150_000_000)));
    }

    #[test]
    fn an_update_or_release_waits_while_a_buy_is_open() {
        let (mut market, mut registry, owner, _, _) = buying(150_000_000);
        // The same gate refuses an update, a release, an OTP response,
        // and a lifecycle release.
        assert!(!market.allows_transition(&name()));
        market.expire(
            &mut registry,
            Timestamp::from_seconds(1_700_000_000 + D_OTP).unwrap(),
            height(),
        );
        assert!(market.allows_transition(&name()));
        assert!(market
            .delist(&mut registry, &name(), &owner, height())
            .is_ok());
        assert_eq!(registry.price(&name()), None);
    }

    #[test]
    fn a_paid_buy_still_holds_the_name() {
        let (mut market, mut registry, owner, pay_to, otp) = buying(150_000_000);
        let paid = zats(150_000_000 + otp_amount(&otp.code).into_u64());
        market.observe(|_| Some(owner.clone()), &[(pay_to, paid)], mtp(), height());
        assert!(market.is_paid(&name()));
        assert!(!market.allows_transition(&name()));
        assert_eq!(
            market.delist(&mut registry, &name(), &owner, height()),
            Err(MarketRefusal::BuyOpen)
        );
    }

    #[test]
    fn a_buy_does_not_open_while_a_note_is_pending_or_the_term_is_due() {
        let (mut market, registry, owner, _) = listed(150_000_000);
        assert!(matches!(
            market.open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                true,
                OtpCode::generate(),
                mtp(),
                height(),
            ),
            Err(MarketRefusal::InFlight)
        ));
        assert!(matches!(
            market.open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                true,
                false,
                OtpCode::generate(),
                mtp(),
                height(),
            ),
            Err(MarketRefusal::ReleaseDue)
        ));
        assert!(!market.is_open(&name()));
    }

    #[test]
    fn a_second_buy_does_not_open() {
        let (mut market, registry, owner, _, _) = buying(150_000_000);
        assert!(matches!(
            market.open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                OtpCode::generate(),
                mtp(),
                height(),
            ),
            Err(MarketRefusal::AlreadyOpen)
        ));
    }

    #[test]
    fn a_buy_does_not_open_for_a_stranger_or_an_unlisted_name() {
        let (mut market, registry, _, _) = listed(150_000_000);
        assert!(matches!(
            market.open_buy(
                &registry,
                &name(),
                &bob(),
                &bob(),
                Expiry::Never,
                held(),
                false,
                false,
                OtpCode::generate(),
                mtp(),
                height(),
            ),
            Err(MarketRefusal::NotOwner)
        ));
        let mut bare = Market::new();
        assert!(matches!(
            bare.open_buy(
                &Registry::new(),
                &name(),
                &bob(),
                &bob(),
                Expiry::Never,
                held(),
                false,
                false,
                OtpCode::generate(),
                mtp(),
                height(),
            ),
            Err(MarketRefusal::NotListed)
        ));
    }

    #[test]
    fn a_stranger_cannot_list_or_delist() {
        let (owner, pay_to) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        let foreign = Listing {
            name: name(),
            ua: owner.clone(),
            pay_to: TransparentAddress::PublicKeyHash([0x22; 20]),
            ask: Ask::Flat(zats(150_000_000)),
        };
        assert_eq!(
            market.list(&mut registry, &foreign, height()),
            Err(MarketRefusal::NotOwner)
        );
        assert_eq!(
            market.list(
                &mut registry,
                &Listing {
                    ua: bob(),
                    ..list_for(150_000_000)
                },
                height()
            ),
            Err(MarketRefusal::NotOwner)
        );
        market
            .list(&mut registry, &list_for(150_000_000), height())
            .unwrap();
        assert_eq!(
            market.delist(&mut registry, &name(), &bob(), height()),
            Err(MarketRefusal::NotOwner)
        );
        assert_eq!(registry.price(&name()), Some(zats(150_000_000)));
        assert_eq!(pay_to, TransparentAddress::PublicKeyHash([0x11; 20]));
    }

    #[test]
    fn a_payment_must_be_the_price_plus_the_code() {
        let (mut market, _registry, owner, pay_to, otp) = buying(150_000_000);
        let exact = zats(150_000_000 + otp_amount(&otp.code).into_u64());
        let short = zats(exact.into_u64() - 1);
        market.observe(|_| Some(owner.clone()), &[(pay_to, short)], mtp(), height());
        assert!(!market.is_paid(&name()));
        let elsewhere = TransparentAddress::PublicKeyHash([0x22; 20]);
        market.observe(
            |_| Some(owner.clone()),
            &[(elsewhere, exact)],
            mtp(),
            height(),
        );
        assert!(!market.is_paid(&name()));
        // She no longer holds the name.
        market.observe(|_| Some(bob()), &[(pay_to, exact)], mtp(), height());
        assert!(!market.is_paid(&name()));
        market.observe(|_| None, &[(pay_to, exact)], mtp(), height());
        assert!(!market.is_paid(&name()));
        market.observe(|_| Some(owner.clone()), &[(pay_to, exact)], mtp(), height());
        assert!(market.is_paid(&name()));
    }

    #[test]
    fn a_tail_digit_payment_does_not_count() {
        // The last six digits are the code. The amount minus the price is not.
        let (mut market, _registry, owner, pay_to, otp) = buying(100_900_000);
        let code = otp_amount(&otp.code).into_u64();
        let price = 100_900_000u64;
        let tail = (price / 1_000_000 + 1) * 1_000_000 + code;
        assert_ne!(tail - price, code);
        market.observe(
            |_| Some(owner.clone()),
            &[(pay_to, zats(tail))],
            mtp(),
            height(),
        );
        assert!(!market.is_paid(&name()));
    }

    #[test]
    fn a_payment_after_the_code_expires_does_not_count() {
        let (mut market, mut registry, owner, pay_to, otp) = buying(150_000_000);
        let exact = zats(150_000_000 + otp_amount(&otp.code).into_u64());
        let later = Timestamp::from_seconds(1_700_000_000 + D_OTP).unwrap();
        market.expire(&mut registry, later, height());
        market.observe(|_| Some(owner.clone()), &[(pay_to, exact)], later, height());
        assert!(!market.is_open(&name()));
        assert!(market
            .delist(&mut registry, &name(), &owner, height())
            .is_ok());
    }

    #[test]
    fn a_rollback_keeps_blocks_that_are_still_valid() {
        let (owner, pay_to) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        let low = BlockHeight::from_u32(10);
        let high = BlockHeight::from_u32(20);
        market
            .list(&mut registry, &list_for(100_000_000), low)
            .unwrap();
        let code = OtpCode::for_test(*b"123456");
        let otp = market
            .open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                code.clone(),
                mtp(),
                low,
            )
            .unwrap();
        assert_eq!(otp.code.digits(), code.digits());
        let paid = zats(100_000_000 + otp_amount(&code).into_u64());
        market.observe(|_| Some(owner.clone()), &[(pay_to, paid)], mtp(), high);
        assert!(market.is_paid(&name()));

        market.truncate_to(&mut registry, low);
        assert_eq!(registry.price(&name()), Some(zats(100_000_000)));
        assert!(market.is_open(&name()));
        assert!(!market.is_paid(&name()));
        market.observe(|_| Some(owner.clone()), &[(pay_to, paid)], mtp(), high);
        assert!(market.is_paid(&name()));

        market.truncate_to(&mut registry, BlockHeight::from_u32(5));
        assert_eq!(registry.price(&name()), None);
        assert!(!market.is_open(&name()));
    }

    #[test]
    fn the_buy_code_is_the_same_on_a_second_read() {
        let txid = [7u8; 32];
        assert_eq!(
            OtpCode::buy(b"mint-key", &txid, b"alice"),
            OtpCode::buy(b"mint-key", &txid, b"alice")
        );
        assert_ne!(
            OtpCode::buy(b"mint-key", &txid, b"alice"),
            OtpCode::buy(b"other-key", &txid, b"alice")
        );
        assert_ne!(
            OtpCode::buy(b"mint-key", &txid, b"alice"),
            OtpCode::buy(b"mint-key", &txid, b"bob")
        );
    }

    #[test]
    fn a_list_waits_for_the_controllers_code() {
        let (owner, pay_to) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        let code = OtpCode::for_test(*b"042831");
        let request = list_for(150_000_000);
        market
            .propose_list(&request, &owner, code.clone(), mtp(), height())
            .unwrap();
        assert_eq!(registry.price(&name()), None);
        let wrong = OtpMemo {
            code: OtpCode::for_test(*b"000000"),
            name: name(),
            action: Action::List,
            ua: owner.clone(),
            listing: Some((pay_to, zats(150_000_000))),
            auction: None,
        };
        assert!(!market.answer(&mut registry, &wrong, height()));
        assert_eq!(registry.price(&name()), None);
        let other_price = OtpMemo {
            code: code.clone(),
            name: name(),
            action: Action::List,
            ua: owner.clone(),
            listing: Some((pay_to, zats(1))),
            auction: None,
        };
        assert!(!market.answer(&mut registry, &other_price, height()));
        assert_eq!(registry.price(&name()), None);
        let right = OtpMemo {
            code,
            name: name(),
            action: Action::List,
            ua: owner.clone(),
            listing: Some((pay_to, zats(150_000_000))),
            auction: None,
        };
        assert!(market.answer(&mut registry, &right, height()));
        assert_eq!(registry.price(&name()), Some(zats(150_000_000)));
        assert_eq!(pay_to, request.pay_to);
    }

    #[test]
    fn a_stranger_cannot_open_a_list_challenge() {
        let (owner, _) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        assert_eq!(
            market.propose_list(&list_for(1), &bob(), OtpCode::generate(), mtp(), height()),
            Err(MarketRefusal::NotOwner)
        );
        market
            .propose_list(
                &list_for(150_000_000),
                &owner,
                OtpCode::for_test(*b"042831"),
                mtp(),
                height(),
            )
            .unwrap();
        let stranger = OtpMemo {
            code: OtpCode::for_test(*b"042831"),
            name: name(),
            action: Action::List,
            ua: bob(),
            listing: Some((
                TransparentAddress::PublicKeyHash([0x11; 20]),
                zats(150_000_000),
            )),
            auction: None,
        };
        assert!(!market.answer(&mut registry, &stranger, height()));
        assert_eq!(registry.price(&name()), None);
    }

    #[test]
    fn a_delist_waits_for_the_controllers_code() {
        let (owner, _) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        market
            .list(&mut registry, &list_for(150_000_000), height())
            .unwrap();
        let code = OtpCode::for_test(*b"042831");
        market
            .propose_delist(&registry, &name(), &owner, code.clone(), mtp(), height())
            .unwrap();
        assert_eq!(registry.price(&name()), Some(zats(150_000_000)));
        let right = OtpMemo {
            code,
            name: name(),
            action: Action::Delist,
            ua: owner.clone(),
            listing: None,
            auction: None,
        };
        assert!(market.answer(&mut registry, &right, height()));
        assert_eq!(registry.price(&name()), None);
    }

    #[test]
    fn one_output_settles_one_sale() {
        let (owner, pay_to) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        market
            .list(&mut registry, &list_for(100_000_000), height())
            .unwrap();
        let second = Name::parse("zed").unwrap();
        market
            .list(
                &mut registry,
                &Listing {
                    name: second.clone(),
                    ua: owner.clone(),
                    pay_to,
                    ask: Ask::Flat(zats(100_000_000)),
                },
                height(),
            )
            .unwrap();
        let code = OtpCode::for_test(*b"123456");
        market
            .open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                code.clone(),
                mtp(),
                height(),
            )
            .unwrap();
        market
            .open_buy(
                &registry,
                &second,
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                OtpCode::for_test(*b"654321"),
                mtp(),
                height(),
            )
            .unwrap();
        let paid = zats(100_000_000 + otp_amount(&code).into_u64());
        market.observe(|_| Some(owner.clone()), &[(pay_to, paid)], mtp(), height());
        assert!(market.is_paid(&name()));
        assert!(!market.is_paid(&second));
    }

    #[test]
    fn an_expired_buy_does_not_take_a_later_payment() {
        let (owner, pay_to) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        let open_at = BlockHeight::from_u32(10);
        let expired_at = BlockHeight::from_u32(15);
        let next_at = BlockHeight::from_u32(16);
        let paid_at = BlockHeight::from_u32(20);
        market
            .list(&mut registry, &list_for(100_000_000), open_at)
            .unwrap();
        let first = OtpCode::for_test(*b"111111");
        market
            .open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                first,
                mtp(),
                open_at,
            )
            .unwrap();
        let later = Timestamp::from_seconds(1_700_000_000 + D_OTP).unwrap();
        market.expire(&mut registry, later, expired_at);
        assert!(!market.is_open(&name()));
        let second = OtpCode::for_test(*b"222222");
        market
            .open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                second.clone(),
                later,
                next_at,
            )
            .unwrap();
        let paid = zats(100_000_000 + otp_amount(&second).into_u64());
        market.observe(|_| Some(owner.clone()), &[(pay_to, paid)], later, paid_at);
        assert!(market.is_paid(&name()));

        market.truncate_to(&mut registry, paid_at);
        assert!(market.is_paid(&name()));
        assert!(market.is_open(&name()));

        market.truncate_to(&mut registry, open_at);
        assert!(market.is_open(&name()));
        assert!(!market.is_paid(&name()));
        let first_paid = zats(100_000_000 + otp_amount(&OtpCode::for_test(*b"111111")).into_u64());
        market.observe(
            |_| Some(owner.clone()),
            &[(pay_to, first_paid)],
            mtp(),
            expired_at,
        );
        assert!(market.is_paid(&name()));
    }

    #[test]
    fn a_code_already_open_does_not_open_another_challenge() {
        let (owner, _) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        let code = OtpCode::for_test(*b"042831");
        market
            .propose_list(
                &list_for(150_000_000),
                &owner,
                code.clone(),
                mtp(),
                height(),
            )
            .unwrap();
        let cheaper = list_for(1);
        assert_eq!(
            market.propose_list(&cheaper, &owner, code.clone(), mtp(), height()),
            Err(MarketRefusal::CodeTaken)
        );
        market
            .list(&mut registry, &list_for(150_000_000), height())
            .unwrap();
        assert_eq!(
            market.propose_delist(&registry, &name(), &owner, code, mtp(), height()),
            Err(MarketRefusal::CodeTaken)
        );
        assert_eq!(
            market.unrelayed_challenges(|_| Some(owner.clone())).len(),
            1
        );
    }

    #[test]
    fn a_challenge_is_sent_only_while_she_holds_the_name() {
        let (owner, _) = alice();
        let mut market = Market::new();
        market
            .propose_list(
                &list_for(150_000_000),
                &owner,
                OtpCode::for_test(*b"042831"),
                mtp(),
                height(),
            )
            .unwrap();
        assert_eq!(
            market.unrelayed_challenges(|_| Some(owner.clone())).len(),
            1
        );
        assert!(market.unrelayed_challenges(|_| Some(bob())).is_empty());
        assert!(market.unrelayed_challenges(|_| None).is_empty());
    }

    #[test]
    fn a_rollback_submits_an_open_code() {
        let (owner, _) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        let code = OtpCode::for_test(*b"042831");
        market
            .propose_list(
                &list_for(150_000_000),
                &owner,
                code.clone(),
                mtp(),
                height(),
            )
            .unwrap();
        market.challenge_relayed(&code);
        assert!(market
            .unrelayed_challenges(|_| Some(owner.clone()))
            .is_empty());
        market.truncate_to(&mut registry, height());
        assert_eq!(
            market.unrelayed_challenges(|_| Some(owner.clone())).len(),
            1
        );

        let (mut market, mut registry, owner, _) = listed(100_000_000);
        let buy = OtpCode::for_test(*b"123456");
        market
            .open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                buy,
                mtp(),
                height(),
            )
            .unwrap();
        market.relayed(&name());
        assert!(market.unrelayed().is_empty());
        market.truncate_to(&mut registry, height());
        assert_eq!(market.unrelayed().len(), 1);
    }

    #[test]
    fn a_buy_whose_payment_is_already_open_stays_closed() {
        let (owner, pay_to) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        let second = Name::parse("zed").unwrap();
        market
            .list(&mut registry, &list_for(100_000_000), height())
            .unwrap();
        market
            .list(
                &mut registry,
                &Listing {
                    name: second.clone(),
                    ua: owner.clone(),
                    pay_to,
                    ask: Ask::Flat(zats(100_000_001)),
                },
                height(),
            )
            .unwrap();
        market
            .open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                OtpCode::for_test(*b"000002"),
                mtp(),
                height(),
            )
            .unwrap();
        assert!(matches!(
            market.open_buy(
                &registry,
                &second,
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                OtpCode::for_test(*b"000001"),
                mtp(),
                height(),
            ),
            Err(MarketRefusal::PaymentTaken)
        ));
        assert!(!market.is_open(&second));
        market
            .open_buy(
                &registry,
                &second,
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                OtpCode::for_test(*b"000003"),
                mtp(),
                height(),
            )
            .unwrap();
        assert!(market.is_open(&second));
    }

    #[test]
    fn a_listing_leaves_when_she_no_longer_holds_the_name() {
        let (mut market, mut registry, owner, _) = listed(100_000_000);
        let listed_at = height();
        let later = BlockHeight::from_u32(2);
        market.reconcile(&mut registry, later);
        assert_eq!(registry.price(&name()), Some(zats(100_000_000)));

        let record = registry.record(&name()).unwrap().clone();
        let note = NameNote::Update {
            name: name(),
            ua: bob(),
            expires_at: Expiry::Never,
            prev: record.commitment,
        };
        assert!(registry.accept_update(
            &MainNetwork,
            &note,
            nf(30),
            &[record.predecessor_nullifier],
            later,
            mtp(),
        ));
        assert_eq!(
            registry.list(list_for(100_000_000)),
            Err(MarketRefusal::NotOwner)
        );
        assert_eq!(
            registry.delist(&name(), &owner),
            Err(MarketRefusal::NotOwner)
        );
        market.reconcile(&mut registry, later);
        assert_eq!(registry.price(&name()), None);
        market.truncate_to(&mut registry, later);
        assert!(registry.listing(&name()).is_none());
        registry.truncate_to_height(listed_at);
        market.truncate_to(&mut registry, listed_at);
        assert_eq!(registry.record(&name()).unwrap().ua, owner);
        assert_eq!(registry.price(&name()), Some(zats(100_000_000)));

        let record = registry.record(&name()).unwrap().clone();
        let release = NameNote::Release {
            name: name(),
            ua: owner,
            prev: record.commitment,
        };
        assert!(registry.accept_release(
            &MainNetwork,
            &release,
            nf(31),
            &[record.predecessor_nullifier],
            later,
            mtp(),
        ));
        market.reconcile(&mut registry, later);
        assert_eq!(registry.price(&name()), None);
    }

    #[test]
    fn listing_replay_preserves_ownership_records_and_history() {
        let (mut market, mut registry, _, _) = listed(100_000_000);
        let record = registry.record(&name()).unwrap().clone();
        let later = BlockHeight::from_u32(2);
        market
            .list(&mut registry, &list_for(200_000_000), later)
            .unwrap();
        registry.truncate_to_height(height());
        market.truncate_to(&mut registry, height());
        assert_eq!(registry.price(&name()), Some(zats(100_000_000)));
        assert_eq!(registry.record(&name()), Some(&record));
        assert_eq!(registry.record_history(&name()), &[record]);
    }

    #[test]
    fn a_buy_read_from_the_chain_stays_payable_and_unsent() {
        let (owner, pay_to) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        market
            .list(&mut registry, &list_for(100_000_000), height())
            .unwrap();
        let code = OtpCode::for_test(*b"123456");
        market
            .open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                code.clone(),
                mtp(),
                height(),
            )
            .unwrap();
        assert_eq!(market.unrelayed().len(), 1);
        market.seal_replayed_buys();
        assert!(market.unrelayed().is_empty());
        market.truncate_to(&mut registry, height());
        assert!(market.is_open(&name()));
        assert!(market.unrelayed().is_empty());

        let second = Name::parse("zed").unwrap();
        market
            .list(
                &mut registry,
                &Listing {
                    name: second.clone(),
                    ua: owner.clone(),
                    pay_to,
                    ask: Ask::Flat(zats(50_000_000)),
                },
                height(),
            )
            .unwrap();
        market
            .open_buy(
                &registry,
                &second,
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                OtpCode::for_test(*b"654321"),
                mtp(),
                height(),
            )
            .unwrap();
        assert_eq!(market.unrelayed().len(), 1);
        assert_eq!(market.unrelayed()[0].name, second);

        let paid = zats(100_000_000 + otp_amount(&code).into_u64());
        market.observe(|_| Some(owner.clone()), &[(pay_to, paid)], mtp(), height());
        assert!(market.is_paid(&name()));
    }

    fn auction_listing(start: u32, end: u32) -> Listing {
        let (ua, pay_to) = alice();
        Listing {
            name: name(),
            ua,
            pay_to,
            ask: Ask::Dutch(AuctionTerms {
                start_price: zats(100_000_000),
                min_price: zats(40_000_000),
                start: BlockHeight::from_u32(start),
                end: BlockHeight::from_u32(end),
            }),
        }
    }

    #[test]
    fn the_auction_price_falls_in_whole_zatoshis() {
        let terms = AuctionTerms {
            start_price: zats(100_000_000),
            min_price: zats(40_000_000),
            start: BlockHeight::from_u32(10),
            end: BlockHeight::from_u32(20),
        };
        assert_eq!(
            terms.price_at(BlockHeight::from_u32(10)),
            Some(zats(100_000_000))
        );
        assert_eq!(
            terms.price_at(BlockHeight::from_u32(15)),
            Some(zats(70_000_000))
        );
        assert_eq!(
            terms.price_at(BlockHeight::from_u32(20)),
            Some(zats(40_000_000))
        );
        assert_eq!(terms.price_at(BlockHeight::from_u32(9)), None);
        assert_eq!(terms.price_at(BlockHeight::from_u32(21)), None);
    }

    #[test]
    fn the_first_intent_holds_that_blocks_price() {
        let (owner, pay_to) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        let at = BlockHeight::from_u32(15);
        market
            .list(&mut registry, &auction_listing(10, 20), at)
            .unwrap();
        let code = OtpCode::for_test(*b"042831");
        let otp = market
            .open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                code.clone(),
                mtp(),
                at,
            )
            .unwrap();
        let until = Timestamp::from_seconds(mtp().as_seconds() + D_DUTCH).unwrap();
        assert_eq!(otp.dutch, Some((zats(70_000_000), until)));
        let memo = otp.encode(&MainNetwork).unwrap();
        let Memo::Text(text) = Memo::try_from(&memo).unwrap() else {
            panic!("text memo");
        };
        assert!(text.starts_with("ZNS:dutch:042831:alice:"));
        assert!(text.contains(":0.7:"));
        assert!(text.ends_with(&until.as_seconds().to_string()));
        assert!(matches!(
            crate::mint::MintInbound::decode(&MainNetwork, &memo),
            crate::mint::MintInbound::Unrecognized
        ));
        assert!(matches!(
            market.open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                OtpCode::for_test(*b"111111"),
                mtp(),
                at,
            ),
            Err(MarketRefusal::Held { until: held_until }) if held_until == until
        ));
        let back = returned_intent(&name(), &bob(), MarketRefusal::Held { until }).unwrap();
        assert_eq!(back.note, format!("ZNS:held:alice:{}", until.as_seconds()));
        let paid = zats(70_000_000 + otp_amount(&code).into_u64());
        market.observe(|_| Some(owner.clone()), &[(pay_to, paid)], mtp(), at);
        assert!(market.is_paid(&name()));
    }

    #[test]
    fn an_intent_before_the_start_waits() {
        let (owner, _) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        let early = BlockHeight::from_u32(9);
        market
            .list(&mut registry, &auction_listing(10, 20), early)
            .unwrap();
        assert!(matches!(
            market.open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                OtpCode::for_test(*b"042831"),
                mtp(),
                early,
            ),
            Err(MarketRefusal::Early { start }) if start == BlockHeight::from_u32(10)
        ));
        let back = returned_intent(
            &name(),
            &bob(),
            MarketRefusal::Early {
                start: BlockHeight::from_u32(10),
            },
        )
        .unwrap();
        assert_eq!(back.note, "ZNS:wait:alice:10");
    }

    #[test]
    fn the_listing_leaves_on_the_block_after_the_end() {
        let (owner, pay_to) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        let at = BlockHeight::from_u32(20);
        market
            .list(&mut registry, &auction_listing(10, 20), at)
            .unwrap();
        let code = OtpCode::for_test(*b"042831");
        market
            .open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                code.clone(),
                mtp(),
                at,
            )
            .unwrap();
        assert_eq!(registry.quote(&name(), at), Some(zats(40_000_000)));
        let later = BlockHeight::from_u32(21);
        market.expire(&mut registry, mtp(), later);
        assert_eq!(registry.quote(&name(), at), None);
        assert!(market.is_open(&name()));
        let paid = zats(40_000_000 + otp_amount(&code).into_u64());
        market.observe(|_| Some(owner.clone()), &[(pay_to, paid)], mtp(), later);
        assert!(market.is_paid(&name()));
        market.expire(
            &mut registry,
            Timestamp::from_seconds(mtp().as_seconds() + D_DUTCH).unwrap(),
            later,
        );
        assert!(market.is_paid(&name()));
    }

    #[test]
    fn an_auction_memo_decodes_only_falling_terms() {
        let network = MainNetwork;
        let (owner, _) = alice();
        let memo = padded(&format!(
            "ZNS:auction:alice:{}:{}:1:0.4:10:20",
            owner.encode(&network),
            t1()
        ));
        let Some(MarketRequest::List(list)) = MarketRequest::decode(&network, &memo) else {
            panic!("expected auction")
        };
        assert_eq!(
            list.ask,
            Ask::Dutch(AuctionTerms {
                start_price: zats(100_000_000),
                min_price: zats(40_000_000),
                start: BlockHeight::from_u32(10),
                end: BlockHeight::from_u32(20),
            })
        );
        let flat = padded(&format!(
            "ZNS:auction:alice:{}:{}:0.4:1:10:20",
            owner.encode(&network),
            t1()
        ));
        assert!(matches!(
            crate::mint::MintInbound::decode(&network, &flat),
            crate::mint::MintInbound::Unrecognized
        ));
    }

    #[test]
    fn an_auction_challenge_lists_its_terms() {
        let (owner, _) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        let code = OtpCode::for_test(*b"042831");
        market
            .propose_list(&auction_listing(10, 20), &owner, code, mtp(), height())
            .unwrap();
        assert_eq!(registry.quote(&name(), BlockHeight::from_u32(15)), None);
        let memo = market
            .unrelayed_challenges(|_| Some(owner.clone()))
            .remove(0);
        assert!(memo.action.is_auction());
        let encoded = memo.encode(&MainNetwork).unwrap();
        assert_eq!(OtpMemo::decode(&MainNetwork, &encoded), Some(memo.clone()));
        assert!(market.answer(&mut registry, &memo, height()));
        assert_eq!(
            registry.quote(&name(), BlockHeight::from_u32(10)),
            Some(zats(100_000_000))
        );
        assert_eq!(
            registry.quote(&name(), BlockHeight::from_u32(15)),
            Some(zats(70_000_000))
        );
        assert_eq!(
            registry.quote(&name(), BlockHeight::from_u32(20)),
            Some(zats(40_000_000))
        );
    }

    #[test]
    fn a_hold_ends_after_ten_minutes() {
        let (owner, _) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        let at = BlockHeight::from_u32(15);
        market
            .list(&mut registry, &auction_listing(10, 20), at)
            .unwrap();
        market
            .open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                OtpCode::for_test(*b"042831"),
                mtp(),
                at,
            )
            .unwrap();
        market.expire(
            &mut registry,
            Timestamp::from_seconds(mtp().as_seconds() + D_DUTCH - 1).unwrap(),
            at,
        );
        assert!(market.is_open(&name()));
        let after = Timestamp::from_seconds(mtp().as_seconds() + D_DUTCH).unwrap();
        market.expire(&mut registry, after, at);
        assert!(!market.is_open(&name()));
        assert_eq!(registry.quote(&name(), at), Some(zats(70_000_000)));
    }

    #[test]
    fn a_reply_after_the_end_leaves_the_flat_listing() {
        let (owner, _) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        market
            .list(&mut registry, &list_for(150_000_000), height())
            .unwrap();
        let code = OtpCode::for_test(*b"042831");
        market
            .propose_list(&auction_listing(10, 20), &owner, code, mtp(), height())
            .unwrap();
        let memo = market
            .unrelayed_challenges(|_| Some(owner.clone()))
            .remove(0);
        let after = BlockHeight::from_u32(21);
        assert!(market.answer(&mut registry, &memo, after));
        assert_eq!(registry.price(&name()), Some(zats(150_000_000)));
        assert!(matches!(
            market.list(&mut registry, &auction_listing(10, 20), after),
            Err(MarketRefusal::Ended)
        ));
        assert_eq!(registry.price(&name()), Some(zats(150_000_000)));
        assert!(market
            .list(
                &mut registry,
                &auction_listing(10, 20),
                BlockHeight::from_u32(20),
            )
            .is_ok());
        assert_eq!(
            registry.quote(&name(), BlockHeight::from_u32(20)),
            Some(zats(40_000_000))
        );
    }

    #[test]
    fn a_paid_auction_buy_keeps_the_hold_through_a_replay() {
        let (owner, pay_to) = alice();
        let mut registry = sale_registry();
        let mut market = Market::new();
        let at = BlockHeight::from_u32(15);
        let paid_at = BlockHeight::from_u32(16);
        market
            .list(&mut registry, &auction_listing(10, 20), at)
            .unwrap();
        let code = OtpCode::for_test(*b"042831");
        market
            .open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                code.clone(),
                mtp(),
                at,
            )
            .unwrap();
        let until = Timestamp::from_seconds(mtp().as_seconds() + D_DUTCH).unwrap();
        let paid = zats(70_000_000 + otp_amount(&code).into_u64());
        market.observe(|_| Some(owner.clone()), &[(pay_to, paid)], mtp(), paid_at);
        assert!(market.is_paid(&name()));
        market.truncate_to(&mut registry, paid_at);
        assert!(market.is_paid(&name()));
        assert!(matches!(
            market.open_buy(
                &registry,
                &name(),
                &bob(),
                &owner,
                Expiry::Never,
                held(),
                false,
                false,
                OtpCode::for_test(*b"111111"),
                mtp(),
                paid_at,
            ),
            Err(MarketRefusal::Held { until: held_until }) if held_until == until
        ));
    }

    fn nf(seed: u8) -> orchard::note::Nullifier {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        orchard::note::Nullifier::from_bytes(&bytes)
            .into_option()
            .expect("test nullifier")
    }

    fn derivation() -> AccessCodeDerivationKey {
        AccessCodeDerivationKey::from_seed(&[0x22; 32])
    }

    fn intent_fee() -> Zatoshis {
        (MARGINAL_FEE * FEE_ACTIONS).unwrap()
    }

    fn buy_of_alice() -> MarketRequest {
        MarketRequest::Buy {
            name: name(),
            ua: bob(),
        }
    }

    fn admit_buy(
        market: &mut Market,
        registry: &Registry,
        tx: u8,
        paid: Zatoshis,
        height: BlockHeight,
    ) -> Admission {
        market.admit(
            TxId::from_bytes([tx; 32]),
            &buy_of_alice(),
            paid,
            registry,
            &FeeRule::standard(),
            height,
            mtp(),
            |_| false,
            &derivation(),
        )
    }

    /// The return, less the refund fee, as the run loop would queue it.
    fn queued(back: &ReturnedIntent, paid: Zatoshis, height: BlockHeight) -> RefundQueue {
        let mut queue = RefundQueue::default();
        queue.admit_with_note(
            &FeeRule::standard(),
            TxId::from_bytes([9; 32]),
            &back.recipient,
            &back.name,
            height,
            paid,
            Some(back.note.clone()),
        );
        queue
    }

    fn due_note(queue: &RefundQueue) -> (Zatoshis, String) {
        let due = queue.due(BlockHeight::from_u32(1_000));
        assert_eq!(due.len(), 1);
        (due[0].amount(), due[0].note().unwrap().to_string())
    }

    #[test]
    fn a_second_intent_in_the_block_is_returned() {
        let mut registry = sale_registry();
        let mut market = Market::new();
        let at = BlockHeight::from_u32(15);
        market
            .list(&mut registry, &auction_listing(10, 20), at)
            .unwrap();
        let first = admit_buy(&mut market, &registry, 1, zats(1_000_000), at);
        assert!(first.opened.is_some());
        assert!(first.returned.is_none());

        let second = admit_buy(&mut market, &registry, 2, zats(1_000_000), at);
        let back = second.returned.expect("the second intent is returned");
        let until = Timestamp::from_seconds(mtp().as_seconds() + D_DUTCH).unwrap();
        assert_eq!(back.recipient, bob());
        assert_eq!(back.note, format!("ZNS:held:alice:{}", until.as_seconds()));
        let (amount, note) = due_note(&queued(&back, zats(1_000_000), at));
        assert_eq!(amount, zats(500_000));
        assert_eq!(note, back.note);

        let exact = admit_buy(&mut market, &registry, 3, intent_fee(), at);
        let kept = exact.returned.expect("an exact fee is still a return");
        assert_eq!(kept.note, back.note);
        assert!(queued(&kept, intent_fee(), at).is_empty());
    }

    #[test]
    fn an_intent_before_the_start_is_returned() {
        let mut registry = sale_registry();
        let mut market = Market::new();
        let early = BlockHeight::from_u32(9);
        market
            .list(&mut registry, &auction_listing(10, 20), early)
            .unwrap();
        let admitted = admit_buy(&mut market, &registry, 1, zats(1_000_000), early);
        let back = admitted.returned.expect("the auction has not started");
        assert_eq!(back.recipient, bob());
        assert_eq!(back.note, "ZNS:wait:alice:10");
        let (amount, note) = due_note(&queued(&back, zats(1_000_000), early));
        assert_eq!(amount, zats(500_000));
        assert_eq!(note, back.note);
    }

    #[test]
    fn an_intent_after_the_payment_is_returned() {
        let mut registry = sale_registry();
        let (owner, pay_to) = alice();
        let mut market = Market::new();
        let at = BlockHeight::from_u32(15);
        let later = BlockHeight::from_u32(16);
        market
            .list(&mut registry, &auction_listing(10, 20), at)
            .unwrap();
        let txid = TxId::from_bytes([1; 32]);
        let first = market.admit(
            txid,
            &buy_of_alice(),
            zats(1_000_000),
            &registry,
            &FeeRule::standard(),
            at,
            mtp(),
            |_| false,
            &derivation(),
        );
        assert!(first.opened.is_some());
        let code = derivation().buy_otp(&txid, &name());
        let settlement = zats(70_000_000 + otp_amount(&code).into_u64());
        market.observe(
            |_| Some(owner.clone()),
            &[(pay_to, settlement)],
            mtp(),
            later,
        );
        assert!(market.is_paid(&name()));

        let next = admit_buy(&mut market, &registry, 2, zats(1_000_000), later);
        let back = next.returned.expect("the paid sale still holds the name");
        let until = Timestamp::from_seconds(mtp().as_seconds() + D_DUTCH).unwrap();
        assert_eq!(back.recipient, bob());
        assert_eq!(back.note, format!("ZNS:held:alice:{}", until.as_seconds()));
        let (amount, note) = due_note(&queued(&back, zats(1_000_000), later));
        assert_eq!(amount, zats(500_000));
        assert_eq!(note, back.note);
    }
}
