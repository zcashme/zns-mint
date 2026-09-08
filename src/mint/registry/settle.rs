//! The settle step: turn one confirmed Treasury request note into exactly
//! one transaction — the transition itself, or a refund of the payment.
//!
//! The loop sequences (scan → settle → submit → sweep); this module owns
//! the mint's policy arc per request: payment freshness, price, the
//! `authorize_*` gates, fee selection and funding, and transaction
//! assembly. The orchestration never touches a builder.
//!
//! The contract is closed: a claim payment note leaves the intake exactly
//! one way or the other — it becomes a claim, or it becomes a refund of
//! itself minus the processing fee. An unrefunded payment would be
//! re-observed by every subsequent intake pass, so there is no policy
//! rejection that leaves money sitting.

use time::Timestamp;
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::data_api::{SentTransaction, WalletWrite as _};
use zcash_client_backend::wallet::{NoteId, ReceivedNote};
use zcash_primitives::transaction::builder::BundlePadding;
use zcash_primitives::transaction::builder::{BuildConfig, Builder};
use zcash_primitives::transaction::fees::zip317::FeeError;
use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;

use crate::key::{RegistryKeys, TreasuryKeys};
use crate::mint::otp::{required_echo_value, OtpQueue};
use crate::mint::registry::Registry;
use crate::mint::NameNote;
use crate::mint::{Action, CLAIM_PRICE, PROCESSING_FEE, REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use crate::wallet::Wallet;

/// A change output below this value is not emitted; the fee absorbs it.
/// The ZIP-317 marginal fee is the conventional dust bound.
const DUST: Zatoshis = Zatoshis::const_from_u64(5_000);

/// The expiry height buffer: 20 blocks (~25 minutes at 75s/block).
const TX_EXPIRY_BUFFER: u32 = 20;

/// The error surface of the settle step.
#[derive(Debug)]
pub enum SettleError {
    /// The transaction Builder rejected composition or failed to build.
    Build(zcash_primitives::transaction::builder::Error<FeeError>),
    /// The wallet rejected the sent-transaction record.
    Store(crate::wallet::WalletError),
    /// A commitment-tree structural error while fetching a witness or anchor.
    Tree(crate::wallet::TreeError),
    /// A note the wallet owns has no witness at the anchor height — tree
    /// state is behind the chain tip the wallet itself reported.
    Witness,
    /// The ZIP-317 fee computation failed.
    Fee(FeeError),
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
            SettleError::Build(e) => write!(f, "transaction build failed: {e}"),
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
    spend_prover: &'a sapling::circuit::SpendParameters,
    output_prover: &'a sapling::circuit::OutputParameters,
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
        spend_prover: &'a sapling::circuit::SpendParameters,
        output_prover: &'a sapling::circuit::OutputParameters,
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
            spend_prover,
            output_prover,
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

    /// Settles an OTP-authorized update from the controller's echo.
    /// Returns `Ok(None)` on policy rejection — the echo value is checked
    /// before the OTP is burned, so a dust or mis-valued echo leaves the
    /// challenge intact.
    pub fn update(
        &mut self,
        name: crate::mint::Name,
        ua: zcash_keys::address::UnifiedAddress,
        payment: &ReceivedNote<NoteId, orchard::note::Note>,
        otp: &[u8; 6],
        mtp: Timestamp,
    ) -> Result<Option<Transaction>, SettleError> {
        let Some(record) = self.registry.record(&name).cloned() else {
            return Ok(None);
        };
        if record.action == Action::Release {
            return Ok(None);
        }
        let Some(predecessor) = self.predecessor_for(&record)? else {
            return Ok(None);
        };

        let paid = Zatoshis::from_u64(payment.note().value().inner())
            .expect("note values fit in u64 zatoshis by consensus");
        if paid != required_echo_value(self.network, self.target_height) {
            return Ok(None);
        }

        let Some(transition) =
            super::authorize_update(self.registry, self.otp_queue, mtp, name, ua, otp)
        else {
            return Ok(None);
        };

        let tx = self.update_transaction(transition, &predecessor)?;
        self.record(&tx)?;
        Ok(Some(tx))
    }

    /// Settles an OTP-authorized release from the controller's echo.
    /// Same shape as an update, different authorized note.
    pub fn release(
        &mut self,
        name: crate::mint::Name,
        ua: zcash_keys::address::UnifiedAddress,
        payment: &ReceivedNote<NoteId, orchard::note::Note>,
        otp: &[u8; 6],
        mtp: Timestamp,
    ) -> Result<Option<Transaction>, SettleError> {
        let Some(record) = self.registry.record(&name).cloned() else {
            return Ok(None);
        };
        if record.action == Action::Release {
            return Ok(None);
        }
        let Some(predecessor) = self.predecessor_for(&record)? else {
            return Ok(None);
        };

        let paid = Zatoshis::from_u64(payment.note().value().inner())
            .expect("note values fit in u64 zatoshis by consensus");
        if paid != required_echo_value(self.network, self.target_height) {
            return Ok(None);
        }

        let Some(transition) =
            super::authorize_release(self.registry, self.otp_queue, mtp, name, ua, otp)
        else {
            return Ok(None);
        };

        let tx = self.release_transaction(transition, &predecessor)?;
        self.record(&tx)?;
        Ok(Some(tx))
    }

    // ── Claim ────────────────────────────────────────────────────────────

    fn claim_transaction(
        &mut self,
        claim: NameNote,
        payment: &ReceivedNote<NoteId, orchard::note::Note>,
    ) -> Result<Transaction, SettleError> {
        let payment_value = Zatoshis::from_u64(payment.note().value().inner())
            .expect("note values fit in u64 zatoshis by consensus");
        let excess = (payment_value - CLAIM_PRICE).unwrap_or(Zatoshis::ZERO);
        let kept = PROCESSING_FEE.min(excess);
        let payer = claim.ua().and_then(|ua| ua.orchard().copied());
        let refund = match (payer, excess > PROCESSING_FEE) {
            (Some(payer), true) => Some((
                payer,
                (excess - PROCESSING_FEE).expect("excess > processing fee"),
            )),
            _ => None,
        };

        let fee = self.fee(3 + usize::from(refund.is_some()))?;
        let change =
            ((CLAIM_PRICE + kept).expect("price plus processing fee fits in u64 zatoshis") - fee)
                .expect("CLAIM_PRICE dwarfs any ZIP-317 fee");

        let anchor = self.anchor()?;
        let (payment_note, payment_path) = self.prepare(payment)?;
        let memo = claim.encode(self.network).ok_or(SettleError::Memo)?;
        let (rcm, psi) = claim.opening(self.network);
        let opening = orchard::note::NoteCommitTrapdoor::from_inner(rcm);

        let registry_fvk = self.registry_keys.orchard_fvk();
        let treasury_fvk = self.treasury_keys.orchard_fvk();

        let mut builder = Builder::new(
            self.network.clone(),
            self.target_height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(anchor),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder = builder.with_expiry_height(self.expiry());

        builder
            .add_ironwood_spend(treasury_fvk.clone(), payment_note, payment_path)
            .map_err(SettleError::Build)?;

        builder
            .add_zns_output(
                Some(registry_fvk.to_ovk(orchard::keys::Scope::External)),
                registry_fvk.address_at(0u32, orchard::keys::Scope::External),
                Zatoshis::ZERO,
                memo,
                opening,
                psi,
            )
            .map_err(SettleError::Build)?;

        if let Some((payer, value)) = refund {
            builder
                .add_ironwood_output(
                    Some(treasury_fvk.to_ovk(orchard::keys::Scope::External)),
                    payer,
                    value,
                    zcash_protocol::memo::MemoBytes::empty(),
                )
                .map_err(SettleError::Build)?;
        }

        if change >= DUST {
            builder
                .add_ironwood_output(
                    Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
                    treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal),
                    change,
                    zcash_protocol::memo::MemoBytes::empty(),
                )
                .map_err(SettleError::Build)?;
        }

        let result = builder
            .build(
                &Default::default(),
                &[],
                &[
                    orchard::keys::SpendAuthorizingKey::from(
                        self.treasury_keys.orchard_spending_key(),
                    ),
                    orchard::keys::SpendAuthorizingKey::from(
                        self.registry_keys.orchard_spending_key(),
                    ),
                ],
                &mut rand::rngs::OsRng,
                self.spend_prover,
                self.output_prover,
                &zcash_primitives::transaction::fees::zip317::FeeRule::standard(),
            )
            .map_err(SettleError::Build)?;
        Ok(result.transaction().clone())
    }

    // ── Update ───────────────────────────────────────────────────────────

    fn update_transaction(
        &mut self,
        transition: NameNote,
        predecessor: &ReceivedNote<NoteId, orchard::note::Note>,
    ) -> Result<Transaction, SettleError> {
        let (fee_notes, funding, fee) = self.select_fee_notes(3, |funding, fee| funding >= fee)?;
        let change = (funding - fee).expect("selection guarantees coverage");

        let anchor = self.anchor()?;
        let (pred_note, pred_path) = self.prepare(predecessor)?;
        let pred_opening = self.predecessor_opening(predecessor)?;
        let memo = transition.encode(self.network).ok_or(SettleError::Memo)?;
        let (rcm, psi) = transition.opening(self.network);
        let opening = orchard::note::NoteCommitTrapdoor::from_inner(rcm);

        let registry_fvk = self.registry_keys.orchard_fvk();
        let treasury_fvk = self.treasury_keys.orchard_fvk();

        let mut builder = Builder::new(
            self.network.clone(),
            self.target_height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(anchor),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder = builder.with_expiry_height(self.expiry());

        builder
            .add_zns_spend(
                registry_fvk.clone(),
                pred_note,
                pred_path,
                pred_opening.0,
                pred_opening.1,
            )
            .map_err(SettleError::Build)?;

        builder
            .add_zns_output(
                Some(registry_fvk.to_ovk(orchard::keys::Scope::External)),
                registry_fvk.address_at(0u32, orchard::keys::Scope::External),
                Zatoshis::ZERO,
                memo,
                opening,
                psi,
            )
            .map_err(SettleError::Build)?;

        for spend in &fee_notes {
            builder
                .add_ironwood_spend(treasury_fvk.clone(), spend.0.clone(), spend.1.clone())
                .map_err(SettleError::Build)?;
        }

        if change >= DUST {
            builder
                .add_ironwood_output(
                    Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
                    treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal),
                    change,
                    zcash_protocol::memo::MemoBytes::empty(),
                )
                .map_err(SettleError::Build)?;
        }

        let result = builder
            .build(
                &Default::default(),
                &[],
                &[
                    orchard::keys::SpendAuthorizingKey::from(
                        self.treasury_keys.orchard_spending_key(),
                    ),
                    orchard::keys::SpendAuthorizingKey::from(
                        self.registry_keys.orchard_spending_key(),
                    ),
                ],
                &mut rand::rngs::OsRng,
                self.spend_prover,
                self.output_prover,
                &zcash_primitives::transaction::fees::zip317::FeeRule::standard(),
            )
            .map_err(SettleError::Build)?;
        Ok(result.transaction().clone())
    }

    // ── Release ──────────────────────────────────────────────────────────

    fn release_transaction(
        &mut self,
        transition: NameNote,
        predecessor: &ReceivedNote<NoteId, orchard::note::Note>,
    ) -> Result<Transaction, SettleError> {
        let (fee_notes, funding, fee) = self.select_fee_notes(3, |funding, fee| funding >= fee)?;
        let change = (funding - fee).expect("selection guarantees coverage");

        let anchor = self.anchor()?;
        let (pred_note, pred_path) = self.prepare(predecessor)?;
        let pred_opening = self.predecessor_opening(predecessor)?;
        let memo = transition.encode(self.network).ok_or(SettleError::Memo)?;
        let (rcm, psi) = transition.opening(self.network);
        let opening = orchard::note::NoteCommitTrapdoor::from_inner(rcm);

        let registry_fvk = self.registry_keys.orchard_fvk();
        let treasury_fvk = self.treasury_keys.orchard_fvk();

        let mut builder = Builder::new(
            self.network.clone(),
            self.target_height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(anchor),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder = builder.with_expiry_height(self.expiry());

        builder
            .add_zns_spend(
                registry_fvk.clone(),
                pred_note,
                pred_path,
                pred_opening.0,
                pred_opening.1,
            )
            .map_err(SettleError::Build)?;

        builder
            .add_zns_output(
                Some(registry_fvk.to_ovk(orchard::keys::Scope::External)),
                registry_fvk.address_at(0u32, orchard::keys::Scope::External),
                Zatoshis::ZERO,
                memo,
                opening,
                psi,
            )
            .map_err(SettleError::Build)?;

        for spend in &fee_notes {
            builder
                .add_ironwood_spend(treasury_fvk.clone(), spend.0.clone(), spend.1.clone())
                .map_err(SettleError::Build)?;
        }

        if change >= DUST {
            builder
                .add_ironwood_output(
                    Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
                    treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal),
                    change,
                    zcash_protocol::memo::MemoBytes::empty(),
                )
                .map_err(SettleError::Build)?;
        }

        let result = builder
            .build(
                &Default::default(),
                &[],
                &[
                    orchard::keys::SpendAuthorizingKey::from(
                        self.treasury_keys.orchard_spending_key(),
                    ),
                    orchard::keys::SpendAuthorizingKey::from(
                        self.registry_keys.orchard_spending_key(),
                    ),
                ],
                &mut rand::rngs::OsRng,
                self.spend_prover,
                self.output_prover,
                &zcash_primitives::transaction::fees::zip317::FeeRule::standard(),
            )
            .map_err(SettleError::Build)?;
        Ok(result.transaction().clone())
    }

    // ── Refund ───────────────────────────────────────────────────────────

    fn refund_transaction(
        &mut self,
        payment: &ReceivedNote<NoteId, orchard::note::Note>,
        payer: Option<orchard::Address>,
    ) -> Result<Transaction, SettleError> {
        let covered = |funding: Zatoshis, fee: Zatoshis| match payer {
            Some(_) => {
                funding
                    >= (fee + PROCESSING_FEE).expect("fee and processing fee fit in u64 zatoshis")
            }
            None => funding >= fee,
        };
        let (fee_notes, funding, _) = self.select_fee_notes(3, covered)?;
        let fee = self.fee(1 + fee_notes.len() + usize::from(payer.is_some()))?;

        let refund =
            payer.and_then(|payer| (funding - fee - PROCESSING_FEE).map(|value| (payer, value)));
        let change = match &refund {
            Some((_, value)) => {
                (funding - *value - fee).expect("refund plus fee is at most the pool")
            }
            None => (funding - fee).expect("selection covers the fee"),
        };

        let anchor = self.anchor()?;
        let (payment_note, payment_path) = self.prepare(payment)?;

        let treasury_fvk = self.treasury_keys.orchard_fvk();

        let mut builder = Builder::new(
            self.network.clone(),
            self.target_height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(anchor),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder = builder.with_expiry_height(self.expiry());

        builder
            .add_ironwood_spend(treasury_fvk.clone(), payment_note, payment_path)
            .map_err(SettleError::Build)?;

        for (note, path) in &fee_notes {
            builder
                .add_ironwood_spend(treasury_fvk.clone(), note.clone(), path.clone())
                .map_err(SettleError::Build)?;
        }

        if let Some((payer, value)) = refund {
            builder
                .add_ironwood_output(
                    Some(treasury_fvk.to_ovk(orchard::keys::Scope::External)),
                    payer,
                    value,
                    zcash_protocol::memo::MemoBytes::empty(),
                )
                .map_err(SettleError::Build)?;
        }

        if change >= DUST {
            builder
                .add_ironwood_output(
                    Some(treasury_fvk.to_ovk(orchard::keys::Scope::Internal)),
                    treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal),
                    change,
                    zcash_protocol::memo::MemoBytes::empty(),
                )
                .map_err(SettleError::Build)?;
        }

        let result = builder
            .build(
                &Default::default(),
                &[],
                &[
                    orchard::keys::SpendAuthorizingKey::from(
                        self.treasury_keys.orchard_spending_key(),
                    ),
                    orchard::keys::SpendAuthorizingKey::from(
                        self.registry_keys.orchard_spending_key(),
                    ),
                ],
                &mut rand::rngs::OsRng,
                self.spend_prover,
                self.output_prover,
                &zcash_primitives::transaction::fees::zip317::FeeRule::standard(),
            )
            .map_err(SettleError::Build)?;
        Ok(result.transaction().clone())
    }

    // ── Wallet projections ───────────────────────────────────────────────

    fn anchor(&mut self) -> Result<orchard::tree::Anchor, SettleError> {
        self.wallet
            .ironwood_anchor(self.tip)
            .map_err(SettleError::Tree)?
            .ok_or(SettleError::Witness)
    }

    fn prepare(
        &mut self,
        note: &ReceivedNote<NoteId, orchard::note::Note>,
    ) -> Result<(orchard::note::Note, orchard::tree::MerklePath), SettleError> {
        let path = self
            .wallet
            .ironwood_witness(note.note_commitment_tree_position(), self.tip)
            .map_err(SettleError::Tree)?
            .ok_or(SettleError::Witness)
            .map(orchard::tree::MerklePath::from)?;
        Ok((note.note().clone(), path))
    }

    fn expiry(&self) -> BlockHeight {
        BlockHeight::from_u32(
            u32::from(self.target_height)
                .checked_add(TX_EXPIRY_BUFFER)
                .expect("target height + expiry buffer fits in u32"),
        )
    }

    fn fee(&self, ironwood_actions: usize) -> Result<Zatoshis, SettleError> {
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

    fn predecessor_for(
        &self,
        record: &crate::mint::registry::NameRecord,
    ) -> Result<Option<ReceivedNote<NoteId, orchard::note::Note>>, SettleError> {
        Ok(self.wallet.unspent_ironwood_note_by_rho(
            REGISTRY_ACCOUNT,
            record.rho,
            TargetHeight::from(self.tip),
        ))
    }

    fn select_fee_notes(
        &mut self,
        base_actions: usize,
        covered: impl Fn(Zatoshis, Zatoshis) -> bool,
    ) -> Result<
        (
            Vec<(orchard::note::Note, orchard::tree::MerklePath)>,
            Zatoshis,
            Zatoshis,
        ),
        SettleError,
    > {
        let candidates = crate::mint::treasury::fee_note_candidates(self.wallet, self.tip);
        let mut prepared = Vec::new();
        let mut funding = Zatoshis::ZERO;
        let mut fee = self.fee(base_actions)?;
        for note in candidates {
            if covered(funding, fee) {
                break;
            }
            let (n, p) = self.prepare(&note)?;
            prepared.push((n, p));
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

    fn predecessor_opening(
        &self,
        note: &ReceivedNote<NoteId, orchard::note::Note>,
    ) -> Result<
        (
            orchard::note::NoteCommitTrapdoor,
            pasta_curves::pallas::Base,
        ),
        SettleError,
    > {
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

    fn record(&mut self, tx: &Transaction) -> Result<(), SettleError> {
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
