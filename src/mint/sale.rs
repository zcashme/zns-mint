//! A sale: Alice lists her name at her transparent address, Bob asks
//! to buy it, and a payment of her price plus the buy OTP makes the
//! mint hand the name to Bob. The note is a sale, so the name stays live.

use std::collections::BTreeMap;

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
    /// `ZNS:list:<name>:<ua>:<t1>:<price>`, `ZNS:delist:<name>:<ua>`, or
    /// `ZNS:buy:<name>:<ua>`.
    pub fn decode<P: Parameters>(network: &P, memo: &MemoBytes) -> Option<Self> {
        decode_zns(memo, |verb, fields| match verb {
            "list" => {
                let (name, ua) = decode_name_and_ua(network, fields)?;
                Some(Self::List(Listing {
                    name,
                    ua,
                    pay_to: decode_t1(network, fields.next()?)?,
                    price: decode_zec(fields.next()?)?,
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
}

impl BuyOtp {
    /// `ZNS:buyotp:<code>:<name>:<ua>`.
    pub fn encode<P: Parameters>(&self, network: &P) -> Option<MemoBytes> {
        let otp: String = self.code.digits().into_iter().map(|b| b as char).collect();
        let text = format!(
            "ZNS:buyotp:{otp}:{}:{}",
            self.name.as_str(),
            self.ua.encode(network),
        );
        MemoBytes::from_bytes(text.as_bytes()).ok()
    }
}

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
    /// name already has one. The code stays payable for [`D_OTP`].
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
        mtp: Timestamp,
    ) -> Option<BuyOtp> {
        if self.sales.iter().any(|sale| sale.name == *name) {
            return None;
        }
        let expires_at = Timestamp::from_seconds(mtp.as_seconds() + D_OTP).ok()?;
        self.sales.push(Sale {
            name: name.clone(),
            bob: bob.clone(),
            alice,
            held,
            term,
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
        })
    }

    /// Buy OTPs not yet submitted.
    pub fn unrelayed(&self) -> Vec<BuyOtp> {
        self.sales
            .iter()
            .filter_map(|sale| match &sale.phase {
                Phase::Paying {
                    code,
                    relayed: false,
                    ..
                } => Some(BuyOtp {
                    code: code.clone(),
                    name: sale.name.clone(),
                    ua: sale.bob.clone(),
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

/// One listing per name. Rebuilt from the chain on startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    pub name: Name,
    pub ua: UnifiedAddress,
    pub pay_to: TransparentAddress,
    pub price: Zatoshis,
}

/// Alice's open listings.
#[derive(Default)]
pub struct ListingBook {
    listings: BTreeMap<Name, Listing>,
}

impl ListingBook {
    pub fn new() -> Self {
        Self {
            listings: BTreeMap::new(),
        }
    }

    pub fn get(&self, name: &Name) -> Option<&Listing> {
        self.listings.get(name)
    }

    fn insert(&mut self, listing: Listing) {
        self.listings.insert(listing.name.clone(), listing);
    }

    fn lost(&self, holder: impl Fn(&Name) -> Option<UnifiedAddress>) -> Vec<Name> {
        self.listings
            .values()
            .filter(|listing| holder(&listing.name).as_ref() != Some(&listing.ua))
            .map(|listing| listing.name.clone())
            .collect()
    }

    /// Removes the listing. The caller has checked that `ua` owns the name.
    pub fn delist(&mut self, name: &Name) -> bool {
        self.listings.remove(name).is_some()
    }
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
        match self.kind {
            ChallengeKind::List(_) => Action::List,
            ChallengeKind::Delist { .. } => Action::Delist,
        }
    }

    fn memo(&self) -> OtpMemo {
        OtpMemo {
            code: self.code.clone(),
            name: self.name().clone(),
            action: self.action(),
            ua: self.ua().clone(),
            listing: match &self.kind {
                ChallengeKind::List(listing) => Some((listing.pay_to, listing.price)),
                ChallengeKind::Delist { .. } => None,
            },
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
            ChallengeKind::List(listing) => {
                response.listing.as_ref().is_some_and(|(pay_to, price)| {
                    *pay_to == listing.pay_to && *price == listing.price
                })
            }
            ChallengeKind::Delist { .. } => response.listing.is_none(),
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
    listings: ListingBook,
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

    /// Drops unpaid sales and controller challenges whose clock has
    /// passed, and records each one.
    pub fn expire(&mut self, mtp: Timestamp, height: BlockHeight) {
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
    pub fn reconcile(
        &mut self,
        live: impl Fn(&Name) -> Option<(UnifiedAddress, NameCommitment)>,
        height: BlockHeight,
    ) {
        let lost = self.listings.lost(|name| live(name).map(|(ua, _)| ua));
        for name in lost {
            self.listings.delist(&name);
            self.record(height, MarketEvent::Delist { name });
        }
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
    pub fn truncate_to(&mut self, height: BlockHeight) {
        self.events.retain(|event| event.height <= height);
        let events = std::mem::take(&mut self.events);
        self.sales = SaleQueue::new();
        self.listings = ListingBook::new();
        self.challenges.clear();
        for stamped in &events {
            match &stamped.event {
                MarketEvent::List { listing } => self.listings.insert(listing.as_ref().clone()),
                MarketEvent::Delist { name } => {
                    self.listings.delist(name);
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

    pub fn price(&self, name: &Name) -> Option<Zatoshis> {
        self.listings.get(name).map(|listing| listing.price)
    }

    /// Lists when `owner` is the controller and no buy is open.
    pub fn list(
        &mut self,
        listing: &Listing,
        owner: &UnifiedAddress,
        height: BlockHeight,
    ) -> Result<(), MarketRefusal> {
        if !is_owner_listing(owner, &listing.ua, &listing.pay_to) {
            return Err(MarketRefusal::NotOwner);
        }
        if self.sales.is_open(&listing.name) {
            return Err(MarketRefusal::BuyOpen);
        }
        let listing = listing.clone();
        self.listings.insert(listing.clone());
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
        name: &Name,
        ua: &UnifiedAddress,
        owner: &UnifiedAddress,
        height: BlockHeight,
    ) -> Result<(), MarketRefusal> {
        if self.sales.is_open(name) {
            return Err(MarketRefusal::BuyOpen);
        }
        if ua != owner {
            return Err(MarketRefusal::NotOwner);
        }
        if !self.listings.delist(name) {
            return Err(MarketRefusal::NotListed);
        }
        self.record(height, MarketEvent::Delist { name: name.clone() });
        Ok(())
    }

    /// Opens a buy from the current listing. The caller drops any
    /// challenge already queued for the name.
    #[allow(clippy::too_many_arguments)]
    pub fn open_buy(
        &mut self,
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
        let (pay_to, price) = {
            let Some(listing) = self.listings.get(name) else {
                return Err(MarketRefusal::NotListed);
            };
            if !is_owner_listing(owner, &listing.ua, &listing.pay_to) {
                return Err(MarketRefusal::NotOwner);
            }
            (listing.pay_to, listing.price)
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
        name: &Name,
        ua: &UnifiedAddress,
        owner: &UnifiedAddress,
        code: OtpCode,
        mtp: Timestamp,
        height: BlockHeight,
    ) -> Result<(), MarketRefusal> {
        if ua != owner {
            return Err(MarketRefusal::NotOwner);
        }
        if self.sales.is_open(name) {
            return Err(MarketRefusal::BuyOpen);
        }
        if self.listings.get(name).is_none() {
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
    /// `owner` is still the controller. A matching code spends the challenge.
    pub fn answer(
        &mut self,
        response: &OtpMemo,
        owner: Option<&UnifiedAddress>,
        height: BlockHeight,
    ) -> bool {
        if !response.action.is_list() && !response.action.is_delist() {
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
            let Some(owner) = owner else {
                return true;
            };
            match &challenge.kind {
                ChallengeKind::List(listing) => {
                    let _ = self.list(listing, owner, height);
                }
                ChallengeKind::Delist { name, ua } => {
                    let _ = self.delist(name, ua, owner, height);
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

    /// Applies one list, delist, or buy. `Some` is a buy that opened;
    /// the caller drops challenges for that name.
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
    ) -> Option<Name> {
        let fee_ok = (fee_rule.marginal_fee() * FEE_ACTIONS).is_some_and(|fee| paid >= fee);
        match request {
            MarketRequest::List(listing) => {
                let Some(record) = registry.record(&listing.name) else {
                    tracing::info!(
                        %txid,
                        name = %listing.name.as_str(),
                        "list fee kept: name is not live"
                    );
                    return None;
                };
                if !fee_ok || record.is_release_due(mtp) || pending(&listing.name) {
                    tracing::info!(
                        %txid,
                        name = %listing.name.as_str(),
                        "list fee kept: listing not opened"
                    );
                    return None;
                }
                let code = key.list_otp(&txid, &listing.name, listing.price, &listing.pay_to);
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
                    Err(_) => tracing::info!(
                        %txid,
                        name = %listing.name.as_str(),
                        "list fee kept: lister is not the owner"
                    ),
                }
                None
            }
            MarketRequest::Delist { name, ua } => {
                let Some(owner) = registry
                    .record(name)
                    .filter(|record| record.ua == *ua)
                    .map(|record| record.ua.clone())
                else {
                    tracing::info!(
                        %txid,
                        name = %name.as_str(),
                        "delist fee kept: listing unchanged"
                    );
                    return None;
                };
                if !fee_ok || pending(name) {
                    tracing::info!(
                        %txid,
                        name = %name.as_str(),
                        "delist fee kept: listing unchanged"
                    );
                    return None;
                }
                let code = key.delist_otp(&txid, name);
                match self.propose_delist(name, ua, &owner, code, mtp, height) {
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
                None
            }
            MarketRequest::Buy { name, ua: bob } => {
                let Some(record) = registry.record(name) else {
                    tracing::info!(
                        %txid,
                        name = %name.as_str(),
                        paid = paid.into_u64(),
                        "buy fee kept: name is not live"
                    );
                    return None;
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
                    return None;
                }
                match self.open_buy(
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
                    Ok(_) => Some(name.clone()),
                    Err(MarketRefusal::NotListed) => {
                        tracing::info!(
                            %txid,
                            name = %name.as_str(),
                            "buy fee kept: name is not listed"
                        );
                        None
                    }
                    Err(MarketRefusal::AlreadyOpen) => {
                        tracing::info!(
                            %txid,
                            name = %name.as_str(),
                            "buy fee kept: sale already open"
                        );
                        None
                    }
                    Err(MarketRefusal::PaymentTaken) => {
                        tracing::info!(
                            %txid,
                            name = %name.as_str(),
                            "buy fee kept: that payment is already open"
                        );
                        None
                    }
                    Err(_) => {
                        tracing::info!(
                            %txid,
                            name = %name.as_str(),
                            paid = paid.into_u64(),
                            "buy fee kept: sale not opened"
                        );
                        None
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::decode_controller_ua;
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
        assert_eq!(list.price, Zatoshis::from_u64(150_000_000).unwrap());
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
            price: zats(price),
        }
    }

    fn listed(price: u64) -> (Market, UnifiedAddress, TransparentAddress) {
        let (owner, pay_to) = alice();
        let mut market = Market::new();
        market.list(&list_for(price), &owner, height()).unwrap();
        (market, owner, pay_to)
    }

    fn buying(price: u64) -> (Market, UnifiedAddress, TransparentAddress, BuyOtp) {
        let (mut market, owner, pay_to) = listed(price);
        let otp = market
            .open_buy(
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
        (market, owner, pay_to, otp)
    }

    #[test]
    fn a_delist_during_a_buy_leaves_the_listing() {
        let (mut market, owner, _, _) = buying(150_000_000);
        assert_eq!(
            market.delist(&name(), &owner, &owner, height()),
            Err(MarketRefusal::BuyOpen)
        );
        assert_eq!(market.price(&name()), Some(zats(150_000_000)));
        assert!(!market.allows_transition(&name()));
    }

    #[test]
    fn a_relist_during_a_buy_keeps_the_price() {
        let (mut market, owner, pay_to, _) = buying(150_000_000);
        let higher = Listing {
            name: name(),
            ua: owner.clone(),
            pay_to,
            price: zats(200_000_000),
        };
        assert_eq!(
            market.list(&higher, &owner, height()),
            Err(MarketRefusal::BuyOpen)
        );
        assert_eq!(market.price(&name()), Some(zats(150_000_000)));
    }

    #[test]
    fn an_update_or_release_waits_while_a_buy_is_open() {
        let (mut market, owner, _, _) = buying(150_000_000);
        // The same gate refuses an update, a release, an OTP response,
        // and a lifecycle release.
        assert!(!market.allows_transition(&name()));
        market.expire(
            Timestamp::from_seconds(1_700_000_000 + D_OTP).unwrap(),
            height(),
        );
        assert!(market.allows_transition(&name()));
        assert!(market.delist(&name(), &owner, &owner, height()).is_ok());
        assert_eq!(market.price(&name()), None);
    }

    #[test]
    fn a_paid_buy_still_holds_the_name() {
        let (mut market, owner, pay_to, otp) = buying(150_000_000);
        let paid = zats(150_000_000 + otp_amount(&otp.code).into_u64());
        market.observe(|_| Some(owner.clone()), &[(pay_to, paid)], mtp(), height());
        assert!(market.is_paid(&name()));
        assert!(!market.allows_transition(&name()));
        assert_eq!(
            market.delist(&name(), &owner, &owner, height()),
            Err(MarketRefusal::BuyOpen)
        );
    }

    #[test]
    fn a_buy_does_not_open_while_a_note_is_pending_or_the_term_is_due() {
        let (mut market, owner, _) = listed(150_000_000);
        assert!(matches!(
            market.open_buy(
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
        let (mut market, owner, _, _) = buying(150_000_000);
        assert!(matches!(
            market.open_buy(
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
        let (mut market, _, _) = listed(150_000_000);
        assert!(matches!(
            market.open_buy(
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
        let mut market = Market::new();
        let foreign = Listing {
            name: name(),
            ua: owner.clone(),
            pay_to: TransparentAddress::PublicKeyHash([0x22; 20]),
            price: zats(150_000_000),
        };
        assert_eq!(
            market.list(&foreign, &owner, height()),
            Err(MarketRefusal::NotOwner)
        );
        assert_eq!(
            market.list(&list_for(150_000_000), &bob(), height()),
            Err(MarketRefusal::NotOwner)
        );
        market
            .list(&list_for(150_000_000), &owner, height())
            .unwrap();
        assert_eq!(
            market.delist(&name(), &bob(), &owner, height()),
            Err(MarketRefusal::NotOwner)
        );
        assert_eq!(market.price(&name()), Some(zats(150_000_000)));
        assert_eq!(pay_to, TransparentAddress::PublicKeyHash([0x11; 20]));
    }

    #[test]
    fn a_payment_must_be_the_price_plus_the_code() {
        let (mut market, owner, pay_to, otp) = buying(150_000_000);
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
        let (mut market, owner, pay_to, otp) = buying(100_900_000);
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
        let (mut market, owner, pay_to, otp) = buying(150_000_000);
        let exact = zats(150_000_000 + otp_amount(&otp.code).into_u64());
        let later = Timestamp::from_seconds(1_700_000_000 + D_OTP).unwrap();
        market.expire(later, height());
        market.observe(|_| Some(owner.clone()), &[(pay_to, exact)], later, height());
        assert!(!market.is_open(&name()));
        assert!(market.delist(&name(), &owner, &owner, height()).is_ok());
    }

    #[test]
    fn a_rollback_keeps_blocks_that_are_still_valid() {
        let (owner, pay_to) = alice();
        let mut market = Market::new();
        let low = BlockHeight::from_u32(10);
        let high = BlockHeight::from_u32(20);
        market.list(&list_for(100_000_000), &owner, low).unwrap();
        let code = OtpCode::for_test(*b"123456");
        let otp = market
            .open_buy(
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

        market.truncate_to(low);
        assert_eq!(market.price(&name()), Some(zats(100_000_000)));
        assert!(market.is_open(&name()));
        assert!(!market.is_paid(&name()));
        market.observe(|_| Some(owner.clone()), &[(pay_to, paid)], mtp(), high);
        assert!(market.is_paid(&name()));

        market.truncate_to(BlockHeight::from_u32(5));
        assert_eq!(market.price(&name()), None);
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
        let mut market = Market::new();
        let code = OtpCode::for_test(*b"042831");
        let request = list_for(150_000_000);
        market
            .propose_list(&request, &owner, code.clone(), mtp(), height())
            .unwrap();
        assert_eq!(market.price(&name()), None);
        let wrong = OtpMemo {
            code: OtpCode::for_test(*b"000000"),
            name: name(),
            action: Action::List,
            ua: owner.clone(),
            listing: Some((pay_to, zats(150_000_000))),
        };
        assert!(!market.answer(&wrong, Some(&owner), height()));
        assert_eq!(market.price(&name()), None);
        let other_price = OtpMemo {
            code: code.clone(),
            name: name(),
            action: Action::List,
            ua: owner.clone(),
            listing: Some((pay_to, zats(1))),
        };
        assert!(!market.answer(&other_price, Some(&owner), height()));
        assert_eq!(market.price(&name()), None);
        let right = OtpMemo {
            code,
            name: name(),
            action: Action::List,
            ua: owner.clone(),
            listing: Some((pay_to, zats(150_000_000))),
        };
        assert!(market.answer(&right, Some(&owner), height()));
        assert_eq!(market.price(&name()), Some(zats(150_000_000)));
        assert_eq!(pay_to, request.pay_to);
    }

    #[test]
    fn a_stranger_cannot_open_a_list_challenge() {
        let (owner, _) = alice();
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
        };
        assert!(!market.answer(&stranger, Some(&owner), height()));
        assert_eq!(market.price(&name()), None);
    }

    #[test]
    fn a_delist_waits_for_the_controllers_code() {
        let (owner, _) = alice();
        let mut market = Market::new();
        market
            .list(&list_for(150_000_000), &owner, height())
            .unwrap();
        let code = OtpCode::for_test(*b"042831");
        market
            .propose_delist(&name(), &owner, &owner, code.clone(), mtp(), height())
            .unwrap();
        assert_eq!(market.price(&name()), Some(zats(150_000_000)));
        let right = OtpMemo {
            code,
            name: name(),
            action: Action::Delist,
            ua: owner.clone(),
            listing: None,
        };
        assert!(market.answer(&right, Some(&owner), height()));
        assert_eq!(market.price(&name()), None);
    }

    #[test]
    fn one_output_settles_one_sale() {
        let (owner, pay_to) = alice();
        let mut market = Market::new();
        market
            .list(&list_for(100_000_000), &owner, height())
            .unwrap();
        let second = Name::parse("zed").unwrap();
        market
            .list(
                &Listing {
                    name: second.clone(),
                    ua: owner.clone(),
                    pay_to,
                    price: zats(100_000_000),
                },
                &owner,
                height(),
            )
            .unwrap();
        let code = OtpCode::for_test(*b"123456");
        market
            .open_buy(
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
        let mut market = Market::new();
        let open_at = BlockHeight::from_u32(10);
        let expired_at = BlockHeight::from_u32(15);
        let next_at = BlockHeight::from_u32(16);
        let paid_at = BlockHeight::from_u32(20);
        market
            .list(&list_for(100_000_000), &owner, open_at)
            .unwrap();
        let first = OtpCode::for_test(*b"111111");
        market
            .open_buy(
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
        market.expire(later, expired_at);
        assert!(!market.is_open(&name()));
        let second = OtpCode::for_test(*b"222222");
        market
            .open_buy(
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

        market.truncate_to(paid_at);
        assert!(market.is_paid(&name()));
        assert!(market.is_open(&name()));

        market.truncate_to(open_at);
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
            .list(&list_for(150_000_000), &owner, height())
            .unwrap();
        assert_eq!(
            market.propose_delist(&name(), &owner, &owner, code, mtp(), height()),
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
        market.truncate_to(height());
        assert_eq!(
            market.unrelayed_challenges(|_| Some(owner.clone())).len(),
            1
        );

        let (mut market, owner, _) = listed(100_000_000);
        let buy = OtpCode::for_test(*b"123456");
        market
            .open_buy(
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
        market.truncate_to(height());
        assert_eq!(market.unrelayed().len(), 1);
    }

    #[test]
    fn a_buy_whose_payment_is_already_open_stays_closed() {
        let (owner, pay_to) = alice();
        let mut market = Market::new();
        let second = Name::parse("zed").unwrap();
        market
            .list(&list_for(100_000_000), &owner, height())
            .unwrap();
        market
            .list(
                &Listing {
                    name: second.clone(),
                    ua: owner.clone(),
                    pay_to,
                    price: zats(100_000_001),
                },
                &owner,
                height(),
            )
            .unwrap();
        market
            .open_buy(
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
        let (owner, _) = alice();
        let mut market = Market::new();
        let listed_at = height();
        market
            .list(&list_for(100_000_000), &owner, listed_at)
            .unwrap();
        let later = BlockHeight::from_u32(2);
        market.reconcile(|_| None, later);
        assert_eq!(market.price(&name()), None);
        market.truncate_to(listed_at);
        assert_eq!(market.price(&name()), Some(zats(100_000_000)));

        market.reconcile(|_| Some((owner.clone(), held())), later);
        assert_eq!(market.price(&name()), Some(zats(100_000_000)));
        market.reconcile(|_| Some((bob(), held())), later);
        assert_eq!(market.price(&name()), None);
    }

    #[test]
    fn a_buy_read_from_the_chain_stays_payable_and_unsent() {
        let (owner, pay_to) = alice();
        let mut market = Market::new();
        market
            .list(&list_for(100_000_000), &owner, height())
            .unwrap();
        let code = OtpCode::for_test(*b"123456");
        market
            .open_buy(
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
        market.truncate_to(height());
        assert!(market.is_open(&name()));
        assert!(market.unrelayed().is_empty());

        let second = Name::parse("zed").unwrap();
        market
            .list(
                &Listing {
                    name: second.clone(),
                    ua: owner.clone(),
                    pay_to,
                    price: zats(50_000_000),
                },
                &owner,
                height(),
            )
            .unwrap();
        market
            .open_buy(
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
}
