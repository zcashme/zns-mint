//! Block scanning logic.

use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_client_backend::scanning::{ScanningKeys, Nullifiers, full::{decrypt_block, scan_block}};
use std::convert::Infallible;

use crate::registry::Registry;
use crate::wallet::Wallet;
use crate::sync::reorg::{BlockMetadata, ReorgBuffer};
use crate::wallet::transaction::{TransactionRecord, ReceivedOrchardNote, SpentOrchardNote, SpentSaplingNote};

/// Bootstraps the scanner state.
pub async fn bootstrap(_wallet: &mut Wallet) -> ReorgBuffer {
    tracing::info!("scanner: bootstrapping state from Birthday Checkpoint");
    let birthday_height = BlockHeight::from_u32(2_999_999);
    let birthday_hash = [0u8; 32];
    ReorgBuffer::new(BlockMetadata {
        height: birthday_height,
        hash: birthday_hash,
    })
}

/// Scans a single verified block and updates the wallet state.
pub fn scan_verified_block<P: Parameters + Send + 'static>(
    params: &P,
    wallet: &mut Wallet,
    registry: &mut Registry,
    block: zcash_primitives::block::Block,
    height: BlockHeight,
) {
    let treasury_fvk = wallet
        .ufvk_for(crate::mint::TREASURY_ACCOUNT)
        .expect("missing treasury UFVK in wallet");
    let registry_fvk = wallet
        .ufvk_for(crate::mint::REGISTRY_ACCOUNT)
        .expect("missing registry UFVK in wallet");

    let scanning_keys = ScanningKeys::from_account_ufvks([
        (crate::mint::TREASURY_ACCOUNT, treasury_fvk.clone()),
        (crate::mint::REGISTRY_ACCOUNT, registry_fvk.clone()),
    ]);

    let nullifiers = Nullifiers::empty();

    // 1. Extract memos before consuming the block.
    // scan_block strips memos, so we grab them up front.
    let treasury_ivk = treasury_fvk.orchard().unwrap().to_ivk(orchard::keys::Scope::External);
    let registry_ivk = registry_fvk.orchard().unwrap().to_ivk(orchard::keys::Scope::External);
    let ivks = [treasury_ivk.clone(), registry_ivk.clone()];

    let mut orchard_memos = std::collections::HashMap::new();
    for tx in block.vtx() {
        if let Some(bundle) = tx.orchard_bundle() {
            let decrypted = bundle.decrypt_outputs_with_keys(&ivks);
            for (idx, _, _, _, memo) in decrypted {
                orchard_memos.insert((tx.txid(), idx), memo);
            }
        }
    }
    
    // 2. Trial decrypt using librustzcash
    let (header, batch_results) = decrypt_block(params, block, &scanning_keys);
    let scanned_block = scan_block(
        params,
        height,
        &header,
        batch_results,
        &scanning_keys,
        &nullifiers,
        None,
        |_| Ok::<_, Infallible>(None),
    ).expect("scan_block failed");

    // 3. Process the results into our TransactionRecords
    for tx in scanned_block.transactions() {
        let mut record = TransactionRecord {
            txid: *tx.txid().as_ref(),
            block_height: height,
            received_orchard: vec![],
            received_sapling: vec![],
            spent_orchard: vec![],
            spent_sapling: vec![],
        };

        for spend in tx.orchard_spends() {
            let nf = spend.nf().to_bytes();
            let original_note = wallet.ledger.get_orchard_note_by_nf(&nf).expect("spent note not found").clone();
            record.spent_orchard.push(SpentOrchardNote {
                account_id: *spend.account_id(),
                nullifier: nf,
                original_note,
            });
        }
        for spend in tx.sapling_spends() {
            let nf = spend.nf().0;
            let original_note = wallet.ledger.get_sapling_note_by_nf(&nf).expect("spent note not found").clone();
            record.spent_sapling.push(SpentSaplingNote {
                account_id: *spend.account_id(),
                nullifier: nf,
                original_note,
            });
        }

        // Extract Received Orchard
        for output in tx.orchard_outputs() {
            if let Some(memo) = orchard_memos.get(&(tx.txid(), output.index())) {
                let mut memo_bytes = [0u8; 512];
                memo_bytes.copy_from_slice(memo);
                
                let account_id = *output.account_id();
                record.received_orchard.push(ReceivedOrchardNote {
                    account_id,
                    note: output.note().clone(),
                    memo: memo_bytes,
                    position: output.note_commitment_tree_position(),
                    confirmed_height: height,
                });

                // If this is a Registry Name Note, parse the memo and update the
                // name-chain tip. The scanner does not own name state — it hands
                // the parsed tip to `Registry`, which owns the name chain.
                if account_id == zip32::AccountId::const_from_u32(1) { // REGISTRY_ACCOUNT
                    if let Some((name, action, ua, prev_rcm)) =
                        crate::mint::decode_name_note(&memo_bytes)
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
        
        wallet.ledger.add_transaction(&record);
    }

    // 4. Update the ShardTree with all commitments
    let orchard_commitments = scanned_block.into_commitments().orchard;
    for cmx in orchard_commitments {
        wallet.trees.append_orchard(cmx.0, cmx.1);
    }
}

pub async fn scan_to_tip(
    _chain: &mut crate::zcash::chain::Reader,
    _wallet: &mut Wallet,
    _registry: &mut Registry,
    _reorg_buffer: &mut ReorgBuffer,
    _tip_height: BlockHeight,
) {}