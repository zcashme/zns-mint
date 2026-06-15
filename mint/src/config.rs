use std::time::Duration;

use zcash_protocol::consensus::Network;

/// Poll interval — wake to check for new chain blocks.
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Orchard spend anchor depth (confirmed blocks behind tip).
pub const ANCHOR_CONFIRMATIONS: u32 = 3;

/// ZIP-203 transaction expiry window.
pub const TX_EXPIRY_BLOCKS: u32 = 40;

/// Minimum note value to fund a mint or OTP relay (ZIP-317 floor).
pub const MINT_FEE_ZAT: u64 = 10_000;

/// Minimum incoming value for a CLAIM request.
pub const MIN_CLAIM_FEE_ZAT: u64 = 10_000;

/// Minimum incoming value for UPDATE / RELEASE (two relay/mint fees).
pub const MIN_MUTATION_FEE_ZAT: u64 = 2 * MINT_FEE_ZAT;

/// Hot treasury balance above which a cold sweep is considered (0.05 ZEC).
pub const HIGH_WATERMARK_ZAT: u64 = 5_000_000;

/// Minimum blocks between sweep attempts (~24h at 75s block time).
pub const SWEEP_INTERVAL_BLOCKS: u32 = 1_152;

/// lightwalletd gRPC endpoint.
pub const LWD_URL: &str = "https://testnet.zec.rocks:443";

/// Name registry / scan state database.
pub const REGISTRY_DB: &str = "zns-registry-testnet.sqlite";

/// Treasury wallet notes database.
pub const TREASURY_WALLET_DB: &str = "zns-treasury-testnet.sqlite";

/// Treasury block cache database.
pub const TREASURY_BLOCK_DB: &str = "zns-treasury-blocks-testnet.sqlite";

/// First block height to scan from (testnet NU5).
pub const BIRTHDAY: u32 = 1_842_420;

/// Blocks behind `birthday` to rewind `scan_tip` on startup (safety re-sync window).
pub const STARTUP_REWIND_BLOCKS: u32 = 100;

/// JSON-RPC control plane bind address (`host:port`).
pub const RPC_BIND: &str = "127.0.0.1:8320";

/// Paths and endpoints the orchestrator needs at boot.
#[derive(Clone, Debug)]
pub struct MintConfig {
    pub lwd_url: String,
    pub registry_db: String,
    pub treasury_wallet_db: String,
    pub treasury_block_db: String,
    pub network: Network,
    pub birthday: u32,
    pub high_watermark_zat: u64,
    pub rpc_bind: String,
}

impl Default for MintConfig {
    fn default() -> Self {
        Self {
            lwd_url: LWD_URL.into(),
            registry_db: REGISTRY_DB.into(),
            treasury_wallet_db: TREASURY_WALLET_DB.into(),
            treasury_block_db: TREASURY_BLOCK_DB.into(),
            network: Network::TestNetwork,
            birthday: BIRTHDAY,
            high_watermark_zat: HIGH_WATERMARK_ZAT,
            rpc_bind: RPC_BIND.into(),
        }
    }
}

