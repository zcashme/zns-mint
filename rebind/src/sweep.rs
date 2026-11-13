//! The sweep: every Treasury note the old history left, Sapling and
//! Ironwood, sent to the Treasury's own address after H. The new mint's
//! wallet starts at H − 1, so this is how the old balance reaches it.

use std::convert::Infallible;

use zcash_client_backend::data_api::locking::LockedInputPolicy;
use zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelectorError;
use zcash_client_backend::data_api::wallet::{
    create_proposed_transactions, propose_send_max_transfer,
};
use zcash_client_backend::data_api::{MaxSpendMode, WalletRead as _};
use zcash_client_backend::util::SystemClock;
use zcash_client_backend::wallet::OvkPolicy;
use zcash_keys::address::Address;
use zcash_primitives::transaction::fees::zip317::{FeeError, FeeRule};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::ShieldedPool;
use zns_mint::boot::TREASURY_ADDRESS_REQUEST;
use zns_mint::mint::TREASURY_ACCOUNT;
use zns_mint::wallet::{Wallet, CONFIRMATIONS};
use zns_mint::TreasuryKeys;

/// Whether any Treasury note mined before `h` is still unspent.
pub fn due<P: Parameters>(wallet: &Wallet<P>, h: BlockHeight, tip: BlockHeight) -> bool {
    use zcash_client_backend::data_api::wallet::TargetHeight;
    let target = TargetHeight::from(tip);
    let before_h = |mined: Option<BlockHeight>| mined.is_some_and(|height| height < h);
    wallet
        .unspent_ironwood_notes(TREASURY_ACCOUNT, target)
        .iter()
        .any(|note| before_h(note.mined_height()))
        || wallet
            .unspent_sapling_notes(TREASURY_ACCOUNT, target)
            .iter()
            .any(|note| before_h(note.mined_height()))
}

/// Builds the sweep with upstream's send-max proposal and stores it in
/// the wallet, as the mint's vault sweep does.
pub fn build<P: Parameters>(
    network: &P,
    wallet: &mut Wallet<P>,
    treasury_keys: &TreasuryKeys,
    spend_prover: &sapling::circuit::SpendParameters,
    output_prover: &sapling::circuit::OutputParameters,
    fee_rule: &FeeRule,
) -> Transaction {
    let (treasury, _) = treasury_keys
        .fvk()
        .default_address(TREASURY_ADDRESS_REQUEST)
        .expect("FATAL: Treasury FVK missing default address");
    let proposal = propose_send_max_transfer::<_, _, _, Infallible>(
        wallet,
        network,
        TREASURY_ACCOUNT,
        &[ShieldedPool::Sapling, ShieldedPool::Ironwood],
        fee_rule,
        Address::from(treasury).to_zcash_address(network),
        None,
        MaxSpendMode::MaxSpendable,
        CONFIRMATIONS,
        &LockedInputPolicy::Exclude,
        None,
    )
    .expect("FATAL: sweep proposal failed");
    let txids = create_proposed_transactions::<_, _, GreedyInputSelectorError, _, FeeError, _>(
        wallet,
        network,
        &SystemClock,
        &mut rand::rand_core::UnwrapErr(rand::rngs::SysRng),
        spend_prover,
        output_prover,
        &treasury_keys.spending_keys(),
        OvkPolicy::Sender,
        &proposal,
        None,
    )
    .expect("FATAL: sweep build failed");
    wallet
        .get_transaction(*txids.first())
        .expect("FATAL: sweep lookup failed after build")
        .expect("FATAL: built sweep missing from wallet")
}
