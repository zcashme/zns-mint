//! Where the move stands. `main` syncs to the tip once per block and calls
//! [`Phase::advance`]; each phase acts at that tip or waits for the next.
//!
//! A sent anchor or sweep that passes its expiry unmined is built again a
//! block later, once the wallet releases its notes.

use std::collections::BTreeMap;

use zcash_client_backend::data_api::WalletRead as _;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;
use zns_mint::mint::{Name, NameNote};

use crate::{anchor, claim, registry, sweep, Chain, Rebind};

/// What the Treasury must hold in Ironwood before the move starts (0.05 ZEC): about
/// four times the fees of moving ~300 names at 1,000 zats per action,
/// plus the new mint's boot floor. What the move does not spend stays.
const MIN_REBIND_BALANCE: u64 = 5_000_000;

/// A transaction this run submitted and the node accepted.
#[derive(Clone, Copy)]
pub struct Sent {
    pub txid: TxId,
    pub expiry: BlockHeight,
}

pub enum Phase {
    /// The scan to the tip with the live mint's law.
    Names { old: registry::Registry },
    /// One claim per live name; the anchor transaction is not yet mined.
    Anchor {
        claims: Vec<NameNote>,
        sent: Option<Sent>,
    },
    /// H is the block holding `anchor`.
    Claims {
        claims: Vec<NameNote>,
        h: BlockHeight,
        anchor: TxId,
        in_flight: BTreeMap<Name, BlockHeight>,
    },
    /// Whatever the Treasury still holds from before H, into one note.
    Sweep {
        claims: Vec<NameNote>,
        h: BlockHeight,
        anchor: TxId,
        sent: Option<Sent>,
    },
    Done {
        claims: Vec<NameNote>,
        h: BlockHeight,
        anchor: TxId,
    },
}

impl Phase {
    /// The live mint's law, applied only while the names are read.
    pub fn old_law(&mut self) -> Option<&mut registry::Registry> {
        match self {
            Phase::Names { old } => Some(old),
            _ => None,
        }
    }

    /// The anchor transaction `sync` watches for.
    pub fn anchor_txid(&self) -> Option<TxId> {
        match self {
            Phase::Anchor {
                sent: Some(sent), ..
            } => Some(sent.txid),
            _ => None,
        }
    }

    /// One step at the wallet's tip. `anchored` is H, when the sync just
    /// applied the anchor transaction's block.
    pub async fn advance(
        self,
        chain: &mut Chain,
        rebind: &Rebind,
        anchored: Option<BlockHeight>,
    ) -> Phase {
        let tip = chain.wallet.tip().block_height();
        match self {
            Phase::Names { old } => {
                let claims = read_live_names(&old, chain);
                check_funds(chain);
                Phase::Anchor { claims, sent: None }
            }
            Phase::Anchor { claims, sent } => match (sent, anchored) {
                (Some(sent), Some(h)) => {
                    tracing::info!(h = u32::from(h), txid = %sent.txid, "rebind: anchors at the new birthday");
                    Phase::Claims {
                        claims,
                        h,
                        anchor: sent.txid,
                        in_flight: BTreeMap::new(),
                    }
                }
                (Some(sent), None) => Phase::Anchor {
                    sent: unexpired(chain, sent, tip, "anchor transaction"),
                    claims,
                },
                (None, _) => {
                    let sent = send_anchor(chain, rebind, claims.len(), tip).await;
                    Phase::Anchor { claims, sent }
                }
            },
            Phase::Claims {
                claims,
                h,
                anchor,
                mut in_flight,
            } => {
                if claims.iter().all(|c| claim::held(&chain.law, c)) {
                    return Phase::Sweep {
                        claims,
                        h,
                        anchor,
                        sent: None,
                    };
                }
                claim::round(
                    &rebind.network,
                    &mut chain.wallet,
                    &rebind.treasury_keys,
                    &rebind.registry_keys,
                    &rebind.spend_prover,
                    &rebind.output_prover,
                    &rebind.fee_rule,
                    &rebind.source,
                    &chain.law,
                    &claims,
                    &mut in_flight,
                )
                .await;
                Phase::Claims {
                    claims,
                    h,
                    anchor,
                    in_flight,
                }
            }
            Phase::Sweep {
                claims,
                h,
                anchor,
                sent: Some(sent),
            } => {
                let mined = chain
                    .wallet
                    .get_tx_height(sent.txid)
                    .expect("FATAL: wallet transaction lookup")
                    .is_some();
                if mined {
                    return Phase::Done { claims, h, anchor };
                }
                Phase::Sweep {
                    sent: unexpired(chain, sent, tip, "sweep"),
                    claims,
                    h,
                    anchor,
                }
            }
            Phase::Sweep {
                claims,
                h,
                anchor,
                sent: None,
            } => {
                if !sweep::due(&chain.wallet, h, tip) {
                    return Phase::Done { claims, h, anchor };
                }
                let sent = send_sweep(chain, rebind).await;
                Phase::Sweep {
                    claims,
                    h,
                    anchor,
                    sent: Some(sent),
                }
            }
            done @ Phase::Done { .. } => done,
        }
    }
}

/// One claim per live name. No names means this manifest's anchor is not
/// the live mint's: there is nothing to move, and nothing may be rewritten.
fn read_live_names(old: &registry::Registry, chain: &Chain) -> Vec<NameNote> {
    let claims: Vec<_> = old.name_chain().map(claim::of).collect();
    assert!(
        !claims.is_empty(),
        "FATAL: no live old-format names from {}; refusing to move an empty registry",
        u32::from(chain.old_birthday)
    );
    tracing::info!(names = claims.len(), "rebind: live names read");
    claims
}

/// The operator funds the Treasury first; a short balance refuses here,
/// before anything is sent.
fn check_funds(chain: &Chain) {
    let have = chain.treasury_ironwood();
    assert!(
        have >= MIN_REBIND_BALANCE,
        "FATAL: the Treasury holds {have} zats in Ironwood; the move needs \
         {MIN_REBIND_BALANCE}. Send {} more to the Treasury and run again.",
        MIN_REBIND_BALANCE - have
    );
}

/// `sent`, until the chain passes its expiry with it unmined. Its notes
/// come back to the wallet the block after, and the phase builds again.
fn unexpired(chain: &Chain, sent: Sent, tip: BlockHeight, what: &str) -> Option<Sent> {
    if chain.wallet.expired_unmined_at(sent.txid, tip) {
        tracing::warn!(txid = %sent.txid, expiry = u32::from(sent.expiry), "rebind: the {what} expired unmined");
        return None;
    }
    Some(sent)
}

/// Sends the anchor transaction at `tip`. A refusal leaves nothing sent,
/// and the next block builds again.
async fn send_anchor(
    chain: &mut Chain,
    rebind: &Rebind,
    names: usize,
    tip: BlockHeight,
) -> Option<Sent> {
    // A fee note can pay one claim (3 actions) in every round, its change
    // paying the next.
    let marginal = rebind.fee_rule.marginal_fee().into_u64();
    let rounds = names.div_ceil(anchor::LANES) as u64;
    let fee_note = Zatoshis::from_u64(rounds * 3 * marginal + marginal)
        .expect("fee note fits the monetary range");
    let (transaction, fee) = anchor::build(
        &rebind.network,
        &mut chain.wallet,
        &rebind.treasury_keys,
        &rebind.registry_keys,
        &rebind.spend_prover,
        &rebind.output_prover,
        &rebind.fee_rule,
        fee_note,
        tip,
    );
    let txid = transaction.txid();
    if !rebind.source.submit(&transaction, "rebind anchors").await {
        tracing::error!(%txid, "rebind: the node refused the anchor transaction");
        return None;
    }
    chain.wallet.record_sent(&transaction, tip + 1, fee);
    tracing::info!(%txid, "rebind: anchor transaction sent");
    Some(Sent {
        txid,
        expiry: transaction.expiry_height(),
    })
}

/// Sends the sweep. Building it already stored it in the wallet, holding
/// its notes until its expiry, so a refusal waits that out like an
/// expired sweep.
async fn send_sweep(chain: &mut Chain, rebind: &Rebind) -> Sent {
    let transaction = sweep::build(
        &rebind.network,
        &mut chain.wallet,
        &rebind.treasury_keys,
        &rebind.spend_prover,
        &rebind.output_prover,
        &rebind.fee_rule,
    );
    let txid = transaction.txid();
    if rebind.source.submit(&transaction, "rebind sweep").await {
        tracing::info!(%txid, "rebind: sweep sent");
    } else {
        tracing::error!(%txid, "rebind: the node refused the sweep");
    }
    Sent {
        txid,
        expiry: transaction.expiry_height(),
    }
}
