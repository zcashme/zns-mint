//! A sale: Alice lists her name at her transparent address, Bob asks
//! to buy it, and a payment of her price plus the buy OTP makes the
//! mint hand the name to Bob. The note is a sale, so the name stays live.

use transparent::address::TransparentAddress;
use zcash_keys::address::Address;
use zcash_primitives::block::Block;
use zcash_protocol::consensus::Parameters;
use zcash_protocol::memo::{Memo, MemoBytes};
use zcash_protocol::value::Zatoshis;

use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::TxId;

use crate::mint::registry::Registry;
use crate::mint::treasury::{OtpCode, D_OTP, FEE_ACTIONS};
use crate::mint::{
    decode_controller_ua, Expiry, MintInbound, Name, NameNote, Timestamp, UnifiedAddress,
};

/// Bob's request. `ua` is where the buy OTP goes. The price and the
/// transparent address come from Alice's listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuyRequest {
    pub name: Name,
    pub ua: UnifiedAddress,
}

impl BuyRequest {
    /// `ZNS:buy:<name>:<ua>`.
    pub fn decode<P: Parameters>(network: &P, memo: &MemoBytes) -> Option<Self> {
        let Memo::Text(text) = Memo::try_from(memo).ok()? else {
            return None;
        };
        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() != 4 || parts[0] != "ZNS" || parts[1] != "buy" {
            return None;
        }
        let name = Name::parse(parts[2])?;
        let ua = decode_controller_ua(network, parts[3])?;
        Some(Self { name, ua })
    }
}

/// Alice's listing. `ua` must be the controller of the name, and
/// `pay_to` must be the transparent receiver on that address. `price`
/// is ZEC with at most eight decimal places.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListRequest {
    pub name: Name,
    pub ua: UnifiedAddress,
    pub pay_to: TransparentAddress,
    pub price: Zatoshis,
}

impl ListRequest {
    /// `ZNS:list:<name>:<ua>:<t-addr>:<price>`.
    pub fn decode<P: Parameters>(network: &P, memo: &MemoBytes) -> Option<Self> {
        let parts = zns_parts(memo)?;
        if parts.len() != 6 || parts[1] != "list" {
            return None;
        }
        Some(Self {
            name: Name::parse(&parts[2])?,
            ua: decode_controller_ua(network, &parts[3])?,
            pay_to: decode_t1(network, &parts[4])?,
            price: decode_zec(&parts[5])?,
        })
    }
}

/// Alice takes the name off the market. `ua` must still own it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelistRequest {
    pub name: Name,
    pub ua: UnifiedAddress,
}

impl DelistRequest {
    /// `ZNS:delist:<name>:<ua>`.
    pub fn decode<P: Parameters>(network: &P, memo: &MemoBytes) -> Option<Self> {
        let parts = zns_parts(memo)?;
        if parts.len() != 4 || parts[1] != "delist" {
            return None;
        }
        Some(Self {
            name: Name::parse(&parts[2])?,
            ua: decode_controller_ua(network, &parts[3])?,
        })
    }
}

fn zns_parts(memo: &MemoBytes) -> Option<Vec<String>> {
    let Memo::Text(text) = Memo::try_from(memo).ok()? else {
        return None;
    };
    let parts: Vec<String> = text.split(':').map(str::to_string).collect();
    (parts.first().map(String::as_str) == Some("ZNS")).then_some(parts)
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
fn decode_t1<P: Parameters>(network: &P, text: &str) -> Option<TransparentAddress> {
    match Address::decode(network, text)? {
        Address::Transparent(addr @ TransparentAddress::PublicKeyHash(_)) => Some(addr),
        _ => None,
    }
}

/// ZEC with at most eight decimal places, as zatoshis.
fn decode_zec(text: &str) -> Option<Zatoshis> {
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
        request: &BuyRequest,
        alice: UnifiedAddress,
        pay_to: TransparentAddress,
        price: Zatoshis,
        term: Expiry,
        code: OtpCode,
        mtp: Timestamp,
    ) -> Option<BuyOtp> {
        if self.sales.iter().any(|sale| sale.name == request.name) {
            return None;
        }
        let expires_at = Timestamp::from_seconds(mtp.as_seconds() + D_OTP).ok()?;
        self.sales.push(Sale {
            name: request.name.clone(),
            bob: request.ua.clone(),
            alice,
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
            name: request.name.clone(),
            ua: request.ua.clone(),
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
    ) -> Vec<Name> {
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
            let matched = payments.iter().any(|(addr, value)| {
                addr == pay_to && payment_is_price_plus_otp(*value, *price, code)
            });
            if matched {
                sale.phase = Phase::Paid;
                paid.push(sale.name.clone());
            }
        }
        paid
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

    fn mark_paid(&mut self, name: &Name) {
        for sale in &mut self.sales {
            if sale.name == *name && matches!(sale.phase, Phase::Paying { .. }) {
                sale.phase = Phase::Paid;
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

    /// Drops an unpaid sale whose code has expired.
    pub fn expire(&mut self, mtp: Timestamp) {
        self.sales.retain(|sale| match &sale.phase {
            Phase::Paying { expires_at, .. } => mtp < *expires_at,
            Phase::Paid => true,
        });
    }

    /// After a matching payment, sign a sale while `alice` holds the name.
    /// The sale leaves once Bob holds it. A name someone else holds is dropped.
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
            if record.ua == sale.bob || record.ua != sale.alice {
                closed.push(sale.name.clone());
                return false;
            }
            if let Some(note) = registry.sale_transfer(&sale.name, &sale.bob, sale.term) {
                notes.push(note);
            }
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
    listings: Vec<Listing>,
}

impl ListingBook {
    pub fn new() -> Self {
        Self {
            listings: Vec::new(),
        }
    }

    pub fn get(&self, name: &Name) -> Option<&Listing> {
        self.listings.iter().find(|listing| listing.name == *name)
    }

    fn insert(&mut self, listing: Listing) {
        self.listings.retain(|kept| kept.name != listing.name);
        self.listings.push(listing);
    }

    /// Replaces any listing for this name.
    pub fn list(&mut self, request: &ListRequest) {
        self.listings.retain(|listing| listing.name != request.name);
        self.listings.push(Listing {
            name: request.name.clone(),
            ua: request.ua.clone(),
            pay_to: request.pay_to,
            price: request.price,
        });
    }

    /// Removes the listing. The caller has checked that `ua` owns the name.
    pub fn delist(&mut self, name: &Name) -> bool {
        let before = self.listings.len();
        self.listings.retain(|listing| listing.name != *name);
        self.listings.len() != before
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
}

enum MarketEvent {
    List { listing: Box<Listing> },
    Delist { name: Name },
    Open { sale: Box<Sale> },
    Paid { name: Name },
    Close { name: Name },
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

    pub fn relayed(&mut self, name: &Name) {
        self.sales.relayed(name);
        if let Some(stamped) = self.events.iter_mut().rev().find(
            |stamped| matches!(&stamped.event, MarketEvent::Open { sale } if sale.name == *name),
        ) {
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
        for name in self.sales.observe(holder, payments, mtp) {
            self.record(height, MarketEvent::Paid { name });
        }
    }

    pub fn expire(&mut self, mtp: Timestamp) {
        self.sales.expire(mtp);
    }

    /// Drops entries from blocks above `height` and rebuilds the rest.
    pub fn truncate_to(&mut self, height: BlockHeight) {
        self.events.retain(|event| event.height <= height);
        let events = std::mem::take(&mut self.events);
        self.sales = SaleQueue::new();
        self.listings = ListingBook::new();
        for stamped in &events {
            match &stamped.event {
                MarketEvent::List { listing } => self.listings.insert(listing.as_ref().clone()),
                MarketEvent::Delist { name } => {
                    self.listings.delist(name);
                }
                MarketEvent::Open { sale } => self.sales.restore(sale.as_ref().clone()),
                MarketEvent::Paid { name } => self.sales.mark_paid(name),
                MarketEvent::Close { name } => self.sales.close(name),
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
        request: &ListRequest,
        owner: &UnifiedAddress,
        height: BlockHeight,
    ) -> Result<(), MarketRefusal> {
        if !is_owner_listing(owner, &request.ua, &request.pay_to) {
            return Err(MarketRefusal::NotOwner);
        }
        if self.sales.is_open(&request.name) {
            return Err(MarketRefusal::BuyOpen);
        }
        self.listings.list(request);
        let listing = self
            .listings
            .get(&request.name)
            .expect("just listed")
            .clone();
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
        request: &BuyRequest,
        owner: &UnifiedAddress,
        term: Expiry,
        release_due: bool,
        note_pending: bool,
        code: OtpCode,
        mtp: Timestamp,
        height: BlockHeight,
    ) -> Result<BuyOtp, MarketRefusal> {
        let (pay_to, price) = {
            let Some(listing) = self.listings.get(&request.name) else {
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
        let otp = self
            .sales
            .open(request, owner.clone(), pay_to, price, term, code, mtp)
            .ok_or(MarketRefusal::AlreadyOpen)?;
        let sale = self.sales.get(&request.name).expect("just opened").clone();
        self.record(
            height,
            MarketEvent::Open {
                sale: Box::new(sale),
            },
        );
        Ok(otp)
    }

    /// Applies one list, delist, or buy. `Some` is a buy that opened;
    /// the caller drops challenges for that name.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &mut self,
        txid: TxId,
        inbound: &MintInbound,
        paid: Zatoshis,
        registry: &Registry,
        fee_rule: &FeeRule,
        height: BlockHeight,
        mtp: Timestamp,
        pending: impl Fn(&Name) -> bool,
        code: OtpCode,
    ) -> Option<Name> {
        let fee_ok = (fee_rule.marginal_fee() * FEE_ACTIONS).is_some_and(|fee| paid >= fee);
        match inbound {
            MintInbound::List(list) => {
                let Some(record) = registry.record(&list.name) else {
                    tracing::info!(
                        %txid,
                        name = %list.name.as_str(),
                        "list fee kept: name is not live"
                    );
                    return None;
                };
                if !fee_ok || record.is_release_due(mtp) {
                    tracing::info!(
                        %txid,
                        name = %list.name.as_str(),
                        "list fee kept: listing not opened"
                    );
                    return None;
                }
                match self.list(list, &record.ua, height) {
                    Ok(()) => {}
                    Err(MarketRefusal::BuyOpen) => tracing::info!(
                        %txid,
                        name = %list.name.as_str(),
                        "list fee kept: a buy is open"
                    ),
                    Err(_) => tracing::info!(
                        %txid,
                        name = %list.name.as_str(),
                        "list fee kept: lister is not the owner"
                    ),
                }
                None
            }
            MintInbound::Delist(delist) => {
                let Some(owner) = registry
                    .record(&delist.name)
                    .filter(|record| record.ua == delist.ua)
                    .map(|record| record.ua.clone())
                else {
                    tracing::info!(
                        %txid,
                        name = %delist.name.as_str(),
                        "delist fee kept: listing unchanged"
                    );
                    return None;
                };
                if !fee_ok {
                    tracing::info!(
                        %txid,
                        name = %delist.name.as_str(),
                        "delist fee kept: listing unchanged"
                    );
                    return None;
                }
                match self.delist(&delist.name, &delist.ua, &owner, height) {
                    Ok(()) => {}
                    Err(MarketRefusal::BuyOpen) => tracing::info!(
                        %txid,
                        name = %delist.name.as_str(),
                        "delist fee kept: a buy is open"
                    ),
                    Err(_) => tracing::info!(
                        %txid,
                        name = %delist.name.as_str(),
                        "delist fee kept: listing unchanged"
                    ),
                }
                None
            }
            MintInbound::Buy(buy) => {
                let Some(record) = registry.record(&buy.name) else {
                    tracing::info!(
                        %txid,
                        name = %buy.name.as_str(),
                        paid = paid.into_u64(),
                        "buy fee kept: name is not live"
                    );
                    return None;
                };
                let release_due = record.is_release_due(mtp);
                let note_pending = pending(&buy.name);
                let owner = record.ua.clone();
                let term = record.expires_at;
                if !fee_ok {
                    tracing::info!(
                        %txid,
                        name = %buy.name.as_str(),
                        paid = paid.into_u64(),
                        "buy fee kept: sale not opened"
                    );
                    return None;
                }
                match self.open_buy(
                    buy,
                    &owner,
                    term,
                    release_due,
                    note_pending,
                    code,
                    mtp,
                    height,
                ) {
                    Ok(_) => Some(buy.name.clone()),
                    Err(MarketRefusal::NotListed) => {
                        tracing::info!(
                            %txid,
                            name = %buy.name.as_str(),
                            "buy fee kept: name is not listed"
                        );
                        None
                    }
                    Err(MarketRefusal::AlreadyOpen) => {
                        tracing::info!(
                            %txid,
                            name = %buy.name.as_str(),
                            "buy fee kept: sale already open"
                        );
                        None
                    }
                    Err(_) => {
                        tracing::info!(
                            %txid,
                            name = %buy.name.as_str(),
                            paid = paid.into_u64(),
                            "buy fee kept: sale not opened"
                        );
                        None
                    }
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::MainNetwork;

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
        let buy = BuyRequest::decode(&network, &memo).expect("buy memo");
        assert!(matches!(
            crate::mint::MintInbound::decode(&network, &memo),
            crate::mint::MintInbound::Buy(_)
        ));
        assert_eq!(buy.name.as_str(), "alice");
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
        let list = ListRequest::decode(&network, &memo).expect("list memo");
        assert!(is_owner_listing(&owner, &list.ua, &list.pay_to));
        assert_eq!(list.price, Zatoshis::from_u64(150_000_000).unwrap());
        let other = TransparentAddress::PublicKeyHash([0x22; 20]);
        assert!(!is_owner_listing(&owner, &list.ua, &other));
        assert!(!is_owner_listing(&base, &list.ua, &list.pay_to));
        assert!(ListRequest::decode(
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
        let delist = DelistRequest::decode(&network, &memo).expect("delist memo");
        assert_eq!(delist.name.as_str(), "alice");
        assert!(matches!(
            crate::mint::MintInbound::decode(&network, &memo),
            crate::mint::MintInbound::Delist(_)
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
        let network = MainNetwork;
        let request =
            BuyRequest::decode(&network, &padded(&format!("ZNS:buy:alice:{TEST_UA}"))).unwrap();
        let mut sales = SaleQueue::new();
        let mtp = Timestamp::from_seconds(1_700_000_000).unwrap();
        assert!(sales
            .open(
                &request,
                request.ua.clone(),
                TransparentAddress::PublicKeyHash([0x11; 20]),
                Zatoshis::from_u64(150_000_000).unwrap(),
                Expiry::Never,
                OtpCode::for_test(*b"042831"),
                mtp,
            )
            .is_some());
        assert_eq!(sales.unrelayed().len(), 1);
        assert!(sales.is_open(&request.name));
        sales.expire(Timestamp::from_seconds(1_700_000_000 + D_OTP).unwrap());
        assert!(sales.unrelayed().is_empty());
        assert!(!sales.is_open(&request.name));
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

    fn zats(n: u64) -> Zatoshis {
        Zatoshis::from_u64(n).unwrap()
    }

    fn mtp() -> Timestamp {
        Timestamp::from_seconds(1_700_000_000).unwrap()
    }

    fn height() -> BlockHeight {
        BlockHeight::from_u32(1)
    }

    fn list_for(price: u64) -> ListRequest {
        let (ua, pay_to) = alice();
        ListRequest {
            name: name(),
            ua,
            pay_to,
            price: zats(price),
        }
    }

    fn buy_for() -> BuyRequest {
        BuyRequest {
            name: name(),
            ua: bob(),
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
                &buy_for(),
                &owner,
                Expiry::Never,
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
        let mut higher = list_for(200_000_000);
        higher.pay_to = pay_to;
        higher.ua = owner.clone();
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
        market.expire(Timestamp::from_seconds(1_700_000_000 + D_OTP).unwrap());
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
                &buy_for(),
                &owner,
                Expiry::Never,
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
                &buy_for(),
                &owner,
                Expiry::Never,
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
                &buy_for(),
                &owner,
                Expiry::Never,
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
                &buy_for(),
                &bob(),
                Expiry::Never,
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
                &buy_for(),
                &bob(),
                Expiry::Never,
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
        let mut foreign = list_for(150_000_000);
        foreign.pay_to = TransparentAddress::PublicKeyHash([0x22; 20]);
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
        market.expire(later);
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
                &buy_for(),
                &owner,
                Expiry::Never,
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
            OtpCode::buy(b"mint-key", &txid),
            OtpCode::buy(b"mint-key", &txid)
        );
        assert_ne!(
            OtpCode::buy(b"mint-key", &txid),
            OtpCode::buy(b"other-key", &txid)
        );
    }
}
