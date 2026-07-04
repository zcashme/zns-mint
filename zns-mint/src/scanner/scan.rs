//! Block scanning logic.

use crate::registry::Registry;
use crate::wallet::Wallet;
use zcash_protocol::consensus::BlockHeight;

use crate::scanner::reorg::{BlockMetadata, ReorgBuffer};

/// Bootstraps the scanner state. If this is a fresh boot with an empty wallet,
/// it injects the Birthday Checkpoint into the Wallet's tree and initializes
/// the ReorgBuffer cursor.
pub async fn bootstrap(_wallet: &mut Wallet) -> ReorgBuffer {
    tracing::info!("scanner: bootstrapping state from Birthday Checkpoint");

    // TODO: Load src/checkpoints/birthday.json, seed the wallet tree

    // For now, return a stub cursor representing the birthday height
    let birthday_height = BlockHeight::from_u32(2_999_999);
    let birthday_hash = [0u8; 32]; // Stub

    ReorgBuffer::new(BlockMetadata {
        height: birthday_height,
        hash: birthday_hash,
    })
}

/// Scans a single verified block and updates the wallet and registry state.
///
/// `wallet` and `registry` are peers: each owns its own domain state and the
/// scanner borrows both for the duration of the block. The scanner is
/// account-agnostic (per `08-chain-sync.md` "Scanner Boundary") and owns no
/// state of its own — it is a pure pipeline from verified block bytes into
/// `Wallet` and `Registry` mutations.
pub fn scan_verified_block(
    wallet: &mut Wallet,
    registry: &mut Registry,
    keys: &crate::key::Keys,
    block: &zcash_primitives::block::Block,
    height: BlockHeight,
) {
    // 1. Extract the Incoming Viewing Keys (IVKs) for our two accounts
    let treasury_ivk = keys
        .treasury_fvk()
        .orchard()
        .expect("Missing Treasury Orchard key")
        .to_ivk(orchard::keys::Scope::External);
    let registry_ivk = keys
        .registry_fvk()
        .orchard()
        .expect("Missing Registry Orchard key")
        .to_ivk(orchard::keys::Scope::External);
    let ivks = [treasury_ivk.clone(), registry_ivk.clone()];

    // 2. Loop through every transaction in the block
    for tx in block.vtx() {
        if let Some(bundle) = tx.orchard_bundle() {
            // 3a. Append EVERY commitment in the bundle to the global Merkle tree,
            // even if it's not ours, so we stay perfectly synced with the chain.
            let mut action_positions = std::collections::HashMap::new();
            for (idx, action) in bundle.actions().iter().enumerate() {
                let cmx = orchard::tree::MerkleHashOrchard::from_cmx(action.cmx());
                let pos = wallet.append_commitment(cmx);
                action_positions.insert(idx, pos);
            }

            // 3b. Trial decrypt all Orchard outputs using the upstream API
            let decrypted = bundle.decrypt_outputs_with_keys(&ivks);

            for (action_idx, matched_ivk, note, _address, memo) in decrypted {
                let account_id = if matched_ivk.to_bytes() == treasury_ivk.to_bytes() {
                    crate::mint::TREASURY_ACCOUNT
                } else if matched_ivk.to_bytes() == registry_ivk.to_bytes() {
                    crate::mint::REGISTRY_ACCOUNT
                } else {
                    unreachable!("Decrypted with unknown IVK")
                };

                // Store the decrypted note in the wallet
                let position = action_positions[&action_idx];
                let spendable = crate::wallet::SpendableNote {
                    note,
                    account_id,
                    position,
                    confirmed_height: height,
                };
                wallet.insert_note(spendable);

                // If this is a Registry Name Note, parse the memo and update the
                // name-chain tip. The scanner does not own name state — it hands
                // the parsed tip to `Registry`, which owns the name chain.
                if account_id == crate::mint::REGISTRY_ACCOUNT {
                    if let Some((name, action, ua, prev_rcm)) =
                        crate::mint::decode_name_note(&memo)
                    {
                        let (rcm, psi) = crate::mint::zns_psi_rcm(&name, action, &ua, prev_rcm);
                        use pasta_curves::group::ff::PrimeField;
                        let mut current_rcm_bytes = [0u8; 32];
                        current_rcm_bytes.copy_from_slice(rcm.to_repr().as_ref());
                        let tip = crate::registry::Tip {
                            action,
                            commitment: current_rcm_bytes,
                            rcm,
                            psi,
                        };
                        registry.set_tip(name, tip);
                    }
                }
            }
        }
    }
}

/// Scans all blocks from the current wallet height to the chain tip.
pub async fn scan_to_tip(
    _chain: &mut crate::zcash::chain::Reader,
    _wallet: &mut Wallet,
    _registry: &mut Registry,
    _reorg_buffer: &mut ReorgBuffer,
    _tip_height: BlockHeight,
) {
    // TODO: implement loop to fetch and scan blocks
}