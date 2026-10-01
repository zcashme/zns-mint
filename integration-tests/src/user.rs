//! The user: a real Zallet wallet that pays Treasury request memos.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::json;
use zns_integration_tests::treasury_ua;
use zns_integration_tests::Zebrad;

use crate::{mature_coinbase_zats, wait_until_sees_coinbase, wait_until_shielded, Zallet};

/// ZEC per request payment. Deliberately overpays the oracle-priced fees:
/// intake is fail-closed and an underpay is a dead attempt.
const PAYMENT_ZEC: f64 = 2.0;

const SYNC_TIMEOUT: Duration = Duration::from_secs(300);

/// This test's spending plan — claim, update, and release, each followed
/// by an OTP echo payment, plus fees with margin — as the spendable
/// shielded balance the wallet must hold before the run starts.
const USER_BUDGET_ZATS: u64 = 1_200_000_000;

/// A funded Zallet wallet playing the user.
pub struct User {
    pub zallet: Zallet,
    /// Transparent address zebrad mines to so the wallet holds coinbase.
    pub miner_address: String,
    /// The wallet-derived Orchard UA that goes into request memos. The
    /// wallet sees payments made back to it, which the OTP challenge
    /// read relies on.
    pub ua: String,
}

impl User {
    /// Bring up a funded user: fresh wallet, mature coinbase, and a
    /// shielded balance, with the wallet synced to the chain.
    ///
    /// Restarts zebrad — call before the ceremony and before mint runs:
    /// restarts drop non-finalized blocks, which would erase the freshly
    /// mined ceremony block.
    pub async fn fund(zebra: &mut Zebrad, mature_coinbases: u32) -> Result<Self> {
        if mature_coinbases == 0 {
            bail!("fund requires at least one mature coinbase");
        }

        let mut zallet = Zallet::init(zebra)?;
        zebra.restart_with_miner(&zallet.miner_address).await?;
        zebra
            .generate_blocks(crate::COINBASE_MATURITY + mature_coinbases)
            .await?;
        let target = zebra.tip_height().await?;

        zallet.start_daemon().await?;
        zallet.wait_until_synced(target, SYNC_TIMEOUT).await?;
        // The shield must capture every mature UTXO, which requires the
        // wallet's scan to reach the node's mature-coinbase truth first:
        // status sync trails the balance scan.
        let truth = mature_coinbase_zats(zebra, &zallet.miner_address).await?;
        wait_until_sees_coinbase(&zallet, truth, SYNC_TIMEOUT).await?;
        zallet.shield_coinbase().await?;
        zebra.generate_blocks(1).await?;
        let target = zebra.tip_height().await?;
        zallet.wait_until_synced(target, SYNC_TIMEOUT).await?;
        wait_until_shielded(&zallet, USER_BUDGET_ZATS, SYNC_TIMEOUT).await?;

        let ua = zallet.orchard_ua().await?;
        Ok(Self {
            miner_address: zallet.miner_address.clone(),
            ua,
            zallet,
        })
    }

    /// Spend shielded funds to the Treasury with `memo`; returns the txid.
    pub async fn pay_treasury(&self, memo: &str) -> Result<String> {
        self.zallet.wait_until_synced(0, SYNC_TIMEOUT).await?;
        let memo_hex: String = memo.bytes().map(|b| format!("{b:02x}")).collect();
        let recipients = json!([
            {
                "address": treasury_ua()?,
                "amount": PAYMENT_ZEC,
                "memo": memo_hex,
            }
        ]);
        self.zallet
            .send_from_account("orchard", recipients, "FullPrivacy")
            .await
            .context("user pays treasury")
    }
}
