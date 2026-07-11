use zns_mint::boot::BootEnv;
use zns_mint::zcash;
use zns_mint::key::{self, AccountKeys};
use zns_mint::wallet::Wallet;
use secrecy::Secret;
use zcash_protocol::consensus::BlockHeight;
use zip32::AccountId;

pub struct MintBootEnv;

impl BootEnv for MintBootEnv {
    type BlockchainInfo = zcash::BlockchainInfo;
    type ChainTip = BlockHeight;
    type AccountKeys = AccountKeys;
    type Wallet = Wallet;
    type NetworkClient = zcash::ChainClient;

    async fn check_liveness(&self) -> Self::BlockchainInfo {
        let zebra_rpc = zcash::JsonRpc::new();
        let info = zebra_rpc
            .get_blockchain_info()
            .await
            .expect("json-rpc getblockchaininfo failed, node is unreachable");

        tracing::info!(
            height = info.blocks,
            hash = %info.bestblockhash,
            "boot: zebra json-rpc liveness ok"
        );
        info
    }

    async fn verify_chain_integrity(&self, info: &Self::BlockchainInfo) -> (Self::NetworkClient, Self::ChainTip) {
        let mut chain = zcash::ChainClient::connect().await
            .expect("FATAL: Zebra gRPC unreachable or timed out");

        let resp = chain
            .client()
            .chain_tip_change(zebra_indexer_proto::Empty {})
            .await
            .expect("chain_tip_change failed");
        let mut stream = resp.into_inner();
        let tip = stream
            .message()
            .await
            .expect("no chain tip message")
            .expect("stream closed with no tip");
        let (tip_height, tip_hash) = zns_mint::sync::scan::tip_height_hash(&tip);

        assert_eq!(
            info.blocks,
            u32::from(tip_height),
            "split-brain: json-rpc height != grpc height"
        );

        assert_eq!(
            info.bestblockhash,
            tip_hash.to_string(),
            "split-brain: json-rpc tip hash != grpc tip hash"
        );

        let block = zns_mint::sync::scan::fetch_verified_block(&mut chain, tip_height).await;

        const NU5_MAINNET_ACTIVATION_HEIGHT: u32 = 1_687_104;
        assert!(
            u32::from(tip_height) >= NU5_MAINNET_ACTIVATION_HEIGHT,
            "consensus failure: node is on a pre-NU5 branch"
        );

        let tip_time = block.header().time;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs() as u32;

        assert!(
            now.saturating_sub(tip_time) <= 7200,
            "liveness failure: node is fully synced but tip is too old (stuck node? tip_time={}, now={})",
            tip_time, now
        );

        tracing::info!(
            height = u32::from(tip_height),
            tx_count = block.vtx().len(),
            "boot: block verified ok, tip is fresh"
        );

        (chain, tip_height)
    }

    fn derive_keys(&self, seed: &Secret<[u8; 32]>) -> (Self::AccountKeys, Self::AccountKeys) {
        let treasury_keys = key::derive_account(seed, AccountId::const_from_u32(0));
        let registry_keys = key::derive_account(seed, AccountId::const_from_u32(1));
        (treasury_keys, registry_keys)
    }

    fn initialize_wallet(&self, treasury: &Self::AccountKeys, registry: &Self::AccountKeys) -> Self::Wallet {
        let ufvks = [
            (zns_mint::mint::TREASURY_ACCOUNT, treasury.fvk().clone()),
            (zns_mint::mint::REGISTRY_ACCOUNT, registry.fvk().clone()),
        ];
        Wallet::new(ufvks)
    }

    fn generate_attestation_report_data(&self, treasury_keys: &Self::AccountKeys, registry_keys: &Self::AccountKeys) -> [u8; 64] {
        use blake2b_simd::Params as Blake2bParams;
        use zcash_protocol::consensus::MAIN_NETWORK;

        let (treasury_addr, _) = treasury_keys
            .fvk()
            .default_address(zcash_keys::keys::UnifiedAddressRequest::SHIELDED)
            .expect("FATAL: Treasury missing default address");
        let treasury_addr_str = treasury_addr.encode(&MAIN_NETWORK);
        let registry_fvk_str = registry_keys.fvk().encode(&MAIN_NETWORK);

        let mut hasher = Blake2bParams::new().hash_length(64).to_state();
        hasher.update(treasury_addr_str.as_bytes());
        hasher.update(b"||");
        hasher.update(registry_fvk_str.as_bytes());
        let hash = hasher.finalize();

        let mut report_data = [0u8; 64];
        report_data.copy_from_slice(hash.as_bytes());
        report_data
    }
}
