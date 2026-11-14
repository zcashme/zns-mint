//! Where the move stands. `main` syncs to the settled tip and calls
//! [`Phase::advance`]. A phase that moves on acts again at the same tip; one
//! that stays waits for the next block.
//!
//! A built anchor or sweep counts as sent, whatever the node answered, until
//! it is mined or passes its expiry. Then it is built again a block later,
//! once the wallet releases its notes.

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

pub enum Phase {
    /// The scan to the tip with the live mint's law.
    Names {
        old: registry::Registry,
    },
    /// One claim per live name; the anchor transaction is not yet mined.
    Anchor {
        claims: Vec<NameNote>,
        sent: Option<TxId>,
    },
    Claims {
        moved: Moved,
        in_flight: BTreeMap<Name, BlockHeight>,
    },
    /// Whatever the Treasury still holds from before H, into one note.
    Sweep {
        moved: Moved,
        sent: Option<TxId>,
    },
    Done(Moved),
}

/// The move from the anchor transaction's block on.
pub struct Moved {
    pub claims: Vec<NameNote>,
    /// The block holding `anchor`: the new birthday.
    pub h: BlockHeight,
    pub anchor: TxId,
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
            Phase::Anchor { sent, .. } => *sent,
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
                (Some(anchor), Some(h)) => {
                    tracing::info!(h = u32::from(h), txid = %anchor, "rebind: anchors at the new birthday");
                    Phase::Claims {
                        moved: Moved { claims, h, anchor },
                        in_flight: BTreeMap::new(),
                    }
                }
                (Some(txid), None) => Phase::Anchor {
                    sent: unexpired(chain, txid, tip, "anchor transaction"),
                    claims,
                },
                (None, _) => {
                    let sent = Some(send_anchor(chain, rebind, claims.len(), tip).await);
                    Phase::Anchor { claims, sent }
                }
            },
            Phase::Claims {
                moved,
                mut in_flight,
            } => {
                if moved.claims.iter().all(|c| claim::held(&chain.law, c)) {
                    return Phase::Sweep { moved, sent: None };
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
                    &moved.claims,
                    &mut in_flight,
                )
                .await;
                Phase::Claims { moved, in_flight }
            }
            Phase::Sweep {
                moved,
                sent: Some(txid),
            } => {
                let mined = chain
                    .wallet
                    .get_tx_height(txid)
                    .expect("FATAL: wallet transaction lookup")
                    .is_some();
                if mined {
                    return Phase::Done(moved);
                }
                let sent = unexpired(chain, txid, tip, "sweep");
                Phase::Sweep { moved, sent }
            }
            Phase::Sweep { moved, sent: None } => {
                if !sweep::due(&chain.wallet, moved.h, tip) {
                    return Phase::Done(moved);
                }
                let sent = Some(send_sweep(chain, rebind).await);
                Phase::Sweep { moved, sent }
            }
            done @ Phase::Done(_) => done,
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

/// `txid`, until the chain passes its expiry with it unmined. Its notes
/// come back to the wallet the block after, and the phase builds again.
fn unexpired(chain: &Chain, txid: TxId, tip: BlockHeight, what: &str) -> Option<TxId> {
    if chain.wallet.expired_unmined_at(txid, tip) {
        tracing::warn!(%txid, "rebind: the {what} expired unmined");
        return None;
    }
    Some(txid)
}

/// Sends the anchor transaction at `tip`. `submit` can answer false for a
/// transaction the node holds, such as one mined during a retry, so the
/// wallet holds its notes either way and `sync` watches for it.
async fn send_anchor(chain: &mut Chain, rebind: &Rebind, names: usize, tip: BlockHeight) -> TxId {
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
    chain.wallet.record_sent(&transaction, tip + 1, fee);
    if rebind.source.submit(&transaction, "rebind anchors").await {
        tracing::info!(%txid, "rebind: anchor transaction sent");
    } else {
        tracing::error!(%txid, "rebind: the node refused the anchor transaction");
    }
    txid
}

/// Sends the sweep. Building it already stored it in the wallet, holding
/// its notes until its expiry.
async fn send_sweep(chain: &mut Chain, rebind: &Rebind) -> TxId {
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
    txid
}
