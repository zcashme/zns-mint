//! The settle step: turn one confirmed Treasury request note into exactly
//! one transaction — the transition itself, or a refund of the payment.
//!
//! The loop sequences (scan → settle → submit → sweep); this module owns
//! the mint's policy arc per request: payment freshness, price, the
//! `authorize_*` gates, fee selection and funding, and finalization. The
//! orchestration never touches a builder; [`super::bundle`] never touches
//! the wallet.
//!
//! The contract is closed: a claim payment note leaves the intake exactly
//! one way or the other — it becomes a claim, or it becomes a refund of
//! itself minus the processing fee. An unrefunded payment would be
//! re-observed by every subsequent intake pass, so there is no policy
//! rejection that leaves money sitting.

use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::data_api::{SentTransaction, WalletWrite as _};
use zcash_client_backend::wallet::{NoteId, ReceivedNote};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;
use time::Timestamp;

use crate::key::{RegistryKeys, TreasuryKeys};
use crate::mint::NameNote;
use crate::mint::otp::OtpQueue;
use crate::mint::registry::Registry;
use crate::mint::{Action, CLAIM_PRICE, PROCESSING_FEE, REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use crate::wallet::Wallet;

use super::bundle::{self, PreparedSpend};

/// A change output below this value is not emitted; the fee absorbs it.
/// The ZIP-317 marginal fee is the conventional dust bound.
const DUST: Zatoshis = Zatoshis::const_from_u64(5_000);

/// The error surface of the settle step: upstream error payloads plus the
/// wallet-state conditions that are not upstream errors.
#[derive(Debug)]
pub enum SettleError {
    /// The finalizer rejected the bundle (prove, sign, verify, freeze).
    Finalize(orchard::builder::BuildError),
    /// The wallet rejected the sent-transaction record.
    Store(crate::wallet::WalletError),
    /// A commitment-tree structural error while fetching a witness or anchor.
    Tree(crate::wallet::TreeError),
    /// A note the wallet owns has no witness at the anchor height — tree
    /// state is behind the chain tip the wallet itself reported.
    Witness,
    /// The ZIP-317 fee computation failed.
    Fee(zcash_primitives::transaction::fees::zip317::FeeError),
    /// The Treasury float cannot fund the fee for this shape.
    Float,
    /// The predecessor's stored memo does not decode into the transition
    /// that produced it — the note and its memo disagree.
    Opening(zcash_primitives::transaction::TxId),
    /// The authorized transition's memo overflows 512 bytes.
    Memo,
}

impl std::fmt::Display for SettleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettleError::Finalize(e) => write!(f, "bundle composition or finalization failed: {e}"),
            SettleError::Store(e) => write!(f, "wallet rejected the sent transaction: {e}"),
            SettleError::Tree(e) => write!(f, "commitment tree error: {e}"),
            SettleError::Witness => write!(f, "note has no witness at the anchor height"),
            SettleError::Fee(e) => write!(f, "fee computation failed: {e}"),
            SettleError::Float => write!(f, "Treasury float cannot fund the fee"),
            SettleError::Opening(txid) => {
                write!(f, "predecessor memo does not re-open its note: {txid}")
            }
            SettleError::Memo => write!(f, "transition memo overflows 512 bytes"),
        }
    }
}

impl std::error::Error for SettleError {}

/// The settle context: everything ambient to one settle pass, constructed
/// once per tick by the orchestration loop.
pub struct Settle<'a, P: Parameters> {
    network: &'a P,
    wallet: &'a mut Wallet,
    registry: &'a Registry,
    otp_queue: &'a mut OtpQueue,
    treasury_keys: &'a TreasuryKeys,
    registry_keys: &'a RegistryKeys,
    tip: BlockHeight,
    target_height: BlockHeight,
}

impl<'a, P: Parameters> Settle<'a, P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: &'a P,
        wallet: &'a mut Wallet,
        registry: &'a Registry,
        otp_queue: &'a mut OtpQueue,
        treasury_keys: &'a TreasuryKeys,
        registry_keys: &'a RegistryKeys,
        tip: BlockHeight,
        target_height: BlockHeight,
    ) -> Self {
        Self {
            network,
            wallet,
            registry,
            otp_queue,
            treasury_keys,
            registry_keys,
            tip,
            target_height,
        }
    }

    /// Settles a claim request: the returned transaction is either the
    /// claim itself, or a refund of the payment to the request memo's UA.
    ///
    /// The claim settles only when the name is claimable, the payment is
    /// fresh (confirmed after the name's current chain state — a payment
    /// cannot reach across a release/reclaim boundary), and the payment
    /// covers the claim price. Every other outcome refunds.
    pub fn claim(
        &mut self,
        name: crate::mint::Name,
        ua: zcash_keys::address::UnifiedAddress,
        payment: &ReceivedNote<NoteId, orchard::note::Note>,
    ) -> Result<Transaction, SettleError> {
        let confirmed_height = payment
            .mined_height()
            .expect("the intake only passes confirmed request notes");

        // Freshness: a payment confirmed at or before the name's current
        // tip is rejected — it cannot be reused after a release/reclaim
        // boundary.
        let fresh = self
            .registry
            .record(&name)
            .is_none_or(|record| confirmed_height > record.confirmed_height);
        // The payment must at least cover the claim price.
        let paid = payment.note().value().inner() >= CLAIM_PRICE.into_u64();
        // Policy gate: name availability.
        let claim = if fresh && paid {
            super::authorize_claim(self.registry, name, ua.clone())
        } else {
            None
        };

        let tx = match claim {
            Some(note) => self.claim_transaction(note, payment)?,
            // Rejected claim: refund the payment, minus the processing fee.
            None => self.refund_transaction(payment, ua.orchard().copied())?,
        };
        self.record(&tx)?;
        Ok(tx)
    }

    /// Settles an OTP-authorized update or release from the controller's
    /// echo. There is no money at stake — the request note is not consumed
    /// — so a policy rejection is a silent skip (`Ok(None)`), never a
    /// transaction. The OTP is consumed only by a successful verification
    /// inside the authorize step.
    pub fn transition(
        &mut self,
        name: crate::mint::Name,
        action: Action,
        ua: zcash_keys::address::UnifiedAddress,
        otp: &[u8; 6],
        mtp: Timestamp,
    ) -> Result<Option<Transaction>, SettleError> {
        // The predecessor is looked up *before* the OTP is consumed: an
        // in-flight transition for the same name (its predecessor note
        // spent-pending) must not burn the controller's pass.
        let Some(record) = self.registry.record(&name).cloned() else {
            return Ok(None);
        };
        if record.action == Action::Release {
            return Ok(None);
        }
        let Some(predecessor) = self.wallet.unspent_ironwood_note_by_rho(
            REGISTRY_ACCOUNT,
            record.rho,
            TargetHeight::from(self.tip),
        ) else {
            return Ok(None);
        };

        let transition = match action {
            Action::Claim => return Ok(None),
            Action::Update => {
                super::authorize_update(self.registry, self.otp_queue, mtp, name, ua, otp)
            }
            Action::Release => {
                super::authorize_release(self.registry, self.otp_queue, mtp, name, ua, otp)
            }
        };

        let Some(transition) = transition else {
            return Ok(None);
        };

        let tx = self.transition_transaction(transition, &predecessor)?;
        self.record(&tx)?;
        Ok(Some(tx))
    }

    // -- Transaction assembly (economics + prepared pieces) ------------------

    /// The claim transaction: the payment note is spent, the name note is
    /// minted, the excess minus the processing fee is refunded to the
    /// payer, and the retained value less the fee returns to the Treasury's
    /// internal address. The payment note is the only input — the price
    /// dwarfs any ZIP-317 fee, so no float top-up is ever needed.
    fn claim_transaction(
        &mut self,
        claim: NameNote,
        payment: &ReceivedNote<NoteId, orchard::note::Note>,
    ) -> Result<Transaction, SettleError> {
        let payment_value = Zatoshis::from_u64(payment.note().value().inner())
            .expect("note values fit in u64 zatoshis by consensus");
        let excess = (payment_value - CLAIM_PRICE).unwrap_or(Zatoshis::ZERO);
        let kept = PROCESSING_FEE.min(excess);
        let payer = payer_of(&claim);
        let refund = match (payer, excess > PROCESSING_FEE) {
            (Some(payer), true) => {
                Some((payer, (excess - PROCESSING_FEE).expect("excess > processing fee")))
            }
            _ => None,
        };

        // Actions: payment spend + name-note output + refund? + change.
        let fee = self.fee(3 + usize::from(refund.is_some()))?;
        let change = ((CLAIM_PRICE + kept).expect("price plus processing fee fits in u64 zatoshis")
            - fee)
            .expect("CLAIM_PRICE dwarfs any ZIP-317 fee");

        let anchor = self.anchor()?;
        let payment_spend = self.prepare(payment)?;
        let memo = claim.encode(self.network).ok_or(SettleError::Memo)?;
        let (rcm, psi) = claim.opening(self.network);
        let opening = (orchard::note::NoteCommitTrapdoor::from_inner(rcm), psi);

        let bundle = bundle::build_claim_bundle(
            self.network,
            anchor,
            memo,
            opening,
            payment_spend,
            refund,
            Some(change),
            self.treasury_keys,
            self.registry_keys,
            self.target_height,
        )
        .map_err(SettleError::Finalize)?;
        crate::wallet::assembly::build_name_note_transaction(
            self.network,
            bundle,
            self.treasury_keys,
            self.registry_keys,
            self.target_height,
        )
        .map_err(SettleError::Finalize)
    }

    /// The update or release transaction: the predecessor name note is
    /// spent under its own transition opening, the successor note is
    /// minted, and the Treasury float funds the fee.
    fn transition_transaction(
        &mut self,
        transition: NameNote,
        predecessor: &ReceivedNote<NoteId, orchard::note::Note>,
    ) -> Result<Transaction, SettleError> {
        // One name-note spend, one name-note output, one change output —
        // plus one spend per fee note; notes are added until the float
        // covers the recomputed fee.
        let (fee_notes, funding, fee) =
            self.select_fee_notes(3, |funding, fee| funding >= fee)?;
        let change = (funding - fee).expect("selection guarantees coverage");

        let anchor = self.anchor()?;
        let predecessor_spend = self.prepare(predecessor)?;
        let predecessor_opening = self.predecessor_opening(predecessor)?;
        let memo = transition.encode(self.network).ok_or(SettleError::Memo)?;
        let (rcm, psi) = transition.opening(self.network);
        let opening = (orchard::note::NoteCommitTrapdoor::from_inner(rcm), psi);

        let change_out = (change >= DUST).then_some(change);
        let bundle = match transition.action() {
            Action::Update => bundle::build_update_bundle(
                self.network,
                anchor,
                memo,
                opening,
                predecessor_spend,
                predecessor_opening,
                &fee_notes,
                change_out,
                self.treasury_keys,
                self.registry_keys,
                self.target_height,
            ),
            // Releases are unreachable here — `transition` gates them out —
            // but the composition is the release path's, kept for
            // completeness of the fork surface.
            Action::Release => bundle::build_release_bundle(
                self.network,
                anchor,
                memo,
                opening,
                predecessor_spend,
                predecessor_opening,
                &fee_notes,
                (change >= DUST).then_some(change),
                self.treasury_keys,
                self.registry_keys,
                self.target_height,
            ),
            Action::Claim => unreachable!("settle::transition gates claims out"),
        }
        .map_err(SettleError::Finalize)?;
        crate::wallet::assembly::build_name_note_transaction(
            self.network,
            bundle,
            self.treasury_keys,
            self.registry_keys,
            self.target_height,
        )
        .map_err(SettleError::Finalize)
    }

    /// The rejection refund: the payment is consumed, its value minus the
    /// fee and the processing charge returns to the payer, and the
    /// Treasury nets the processing charge. When the payment is too small
    /// to fund a refund even with float top-up, everything is retained
    /// (saturating) — every rejected claim is self-funding.
    fn refund_transaction(
        &mut self,
        payment: &ReceivedNote<NoteId, orchard::note::Note>,
        payer: Option<orchard::Address>,
    ) -> Result<Transaction, SettleError> {
        // Float notes are added until a refund output becomes possible
        // (pool ≥ fee + processing fee) — or, when the payer has no
        // Ironwood receiver, until the fee alone is covered and the whole
        // payment is retained.
        let covered = |funding: Zatoshis, fee: Zatoshis| match payer {
            Some(_) => funding
                >= (fee + PROCESSING_FEE).expect("fee and processing fee fit in u64 zatoshis"),
            None => funding >= fee,
        };
        let (fee_notes, funding, _) = self.select_fee_notes(3, covered)?;
        let fee = self.fee(1 + fee_notes.len() + usize::from(payer.is_some()))?;

        let refund = payer.and_then(|payer| {
            (funding - fee - PROCESSING_FEE).map(|value| (payer, value))
        });
        let change = match &refund {
            Some((_, value)) => {
                (funding - *value - fee).expect("refund plus fee is at most the pool")
            }
            None => (funding - fee).expect("selection covers the fee"),
        };

        let anchor = self.anchor()?;
        let payment_spend = self.prepare(payment)?;
        let bundle = bundle::build_refund_bundle(
            self.network,
            anchor,
            payment_spend,
            refund,
            (change >= DUST).then_some(change),
            &fee_notes,
            self.treasury_keys,
            self.target_height,
        )
        .map_err(SettleError::Finalize)?;
        crate::wallet::assembly::build_name_note_transaction(
            self.network,
            bundle,
            self.treasury_keys,
            self.registry_keys,
            self.target_height,
        )
        .map_err(SettleError::Finalize)
    }

    // -- Wallet projections --------------------------------------------------

    /// The Ironwood anchor at the tip — the root every spend of this pass
    /// is witnessed under. A missing root at the tip the wallet itself
    /// reported is a structural inconsistency, not a transient.
    fn anchor(&mut self) -> Result<orchard::tree::Anchor, SettleError> {
        self.wallet
            .ironwood_anchor(self.tip)
            .map_err(SettleError::Tree)?
            .ok_or(SettleError::Witness)
    }

    /// A spend prepared with its witness under the anchor.
    fn prepare(
        &mut self,
        note: &ReceivedNote<NoteId, orchard::note::Note>,
    ) -> Result<PreparedSpend, SettleError> {
        let path = self
            .wallet
            .ironwood_witness(note.note_commitment_tree_position(), self.tip)
            .map_err(SettleError::Tree)?
            .ok_or(SettleError::Witness)
            .map(orchard::tree::MerklePath::from)?;
        Ok(PreparedSpend { note: note.note().clone(), path })
    }

    /// The ZIP-317 fee for `ironwood_actions` actions.
    fn fee(&self, ironwood_actions: usize) -> Result<Zatoshis, SettleError> {
        use zcash_primitives::transaction::fees::FeeRule as _;
        zcash_primitives::transaction::fees::zip317::FeeRule::standard()
            .fee_required(
                self.network,
                self.target_height,
                std::iter::empty::<zcash_primitives::transaction::fees::transparent::InputSize>(),
                std::iter::empty::<usize>(),
                0,
                0,
                0,
                ironwood_actions,
            )
            .map_err(SettleError::Fee)
    }

    /// Greedily witnesses Treasury fee notes (largest first) until
    /// `covered(funding, fee)` holds. Each added note is one more spend —
    /// one more action — so the fee is recomputed after every addition.
    /// `Float` if the float is exhausted without coverage.
    fn select_fee_notes(
        &mut self,
        base_actions: usize,
        covered: impl Fn(Zatoshis, Zatoshis) -> bool,
    ) -> Result<(Vec<PreparedSpend>, Zatoshis, Zatoshis), SettleError> {
        let candidates = crate::mint::treasury::fee_note_candidates(self.wallet, self.tip);
        let mut prepared = Vec::new();
        let mut funding = Zatoshis::ZERO;
        let mut fee = self.fee(base_actions)?;
        for note in candidates {
            if covered(funding, fee) {
                break;
            }
            prepared.push(self.prepare(&note)?);
            funding = (funding
                + Zatoshis::from_u64(note.note().value().inner())
                    .expect("note values fit in u64 zatoshis by consensus"))
            .expect("Treasury float fits in u64 zatoshis by consensus");
            fee = self.fee(base_actions + prepared.len())?;
        }
        if !covered(funding, fee) {
            return Err(SettleError::Float);
        }
        Ok((prepared, funding, fee))
    }

    /// The (rcm, ψ) opening of a name note already on chain: decoded from
    /// its stored memo, which is the same payload the minted note's
    /// commitment was derived from — so the spend's opening is
    /// self-verifying against the predecessor's cmx.
    fn predecessor_opening(
        &self,
        note: &ReceivedNote<NoteId, orchard::note::Note>,
    ) -> Result<(orchard::note::NoteCommitTrapdoor, pasta_curves::pallas::Base), SettleError> {
        let memo = self
            .wallet
            .get_memo(*note.internal_note_id())
            .map_err(|_| SettleError::Opening(*note.txid()))?;
        let payload = match memo {
            Some(zcash_protocol::memo::Memo::Future(bytes)) => {
                crate::mint::note::decode_name_note(self.network, bytes.as_array())
            }
            _ => None,
        }
        .ok_or(SettleError::Opening(*note.txid()))?;
        let (rcm, psi) = payload.opening(self.network);
        Ok((orchard::note::NoteCommitTrapdoor::from_inner(rcm), psi))
    }

    /// Records the built transaction's spends into the wallet so the next
    /// intake pass cannot re-select the consumed notes — the wallet's
    /// pending-spend map is the whole of submission tracking. If the
    /// transaction expires unmined, the spend records release the notes
    /// automatically.
    fn record(&mut self, tx: &Transaction) -> Result<(), SettleError> {
        // Output bookkeeping is not consumed by any wallet read today;
        // the spend records are what protect against double selection.
        let sent = SentTransaction::new(
            tx,
            time::OffsetDateTime::now_utc(),
            TargetHeight::from(self.target_height),
            TREASURY_ACCOUNT,
            &[],
            Zatoshis::ZERO,
            &[],
        );
        self.wallet
            .store_transactions_to_be_sent(&[sent])
            .map_err(SettleError::Store)
    }
}
/// The claim refund target: the bound UA's Ironwood-capable receiver, when
/// its address carries one.
fn payer_of(claim: &NameNote) -> Option<orchard::Address> {
    claim.ua().and_then(|ua| ua.orchard().copied())
}
