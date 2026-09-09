//! The best chain: where it is, and what's in it.

use incrementalmerkletree::frontier::Frontier;
use sapling::Node as SaplingNode;
use serde::Deserialize;
use time::Timestamp;
use zcash_client_backend::data_api::chain::ChainState;
use zcash_primitives::block::{Block, BlockHash};
use zcash_primitives::merkle_tree::{read_commitment_tree, HashSer};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zebra_indexer_proto::{BlockHashAndHeight, Empty, ZebraClient};

use super::{
    not_on_best_chain, JsonRpc, TransportError, CONNECT_TIMEOUT, REQUEST_TIMEOUT, ZEBRA_INDEXER_URL,
};
use orchard::tree::MerkleHashOrchard;

/// A client for the node's gRPC announcements about the chain.
#[derive(Clone)]
pub struct ChainClient(pub(crate) ZebraClient);

impl ChainClient {
    /// Connects to the indexer's gRPC endpoint.
    pub(crate) async fn connect() -> Result<Self, tonic::transport::Error> {
        let endpoint = tonic::transport::Endpoint::from_static(ZEBRA_INDEXER_URL)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT);

        let client = ZebraClient::connect(endpoint).await?;
        Ok(Self(client))
    }

    /// Opens the gRPC stream of best-chain tip changes.
    ///
    /// The first message names the current tip; later messages name changes.
    /// A message is a wake-up, never an authoritative read — re-read the tip
    /// through [`CanonicalBlockSource::exact_tip`]. The stream may end
    /// silently or with an error; both mean reconnect and treat the gap as
    /// missed.
    pub async fn chain_tip_change_stream(
        &mut self,
    ) -> Result<tonic::codec::Streaming<BlockHashAndHeight>, TransportError> {
        self.0
            .chain_tip_change(Empty {})
            .await
            .map(|r| r.into_inner())
            .map_err(TransportError::from)
    }
}

/// A tip announcement, decoded: `(height, hash)` from one message.
pub fn tip_height_hash(tip: &BlockHashAndHeight) -> (BlockHeight, BlockHash) {
    let height = BlockHeight::from_u32(tip.height);
    let hash = block_hash_from_display(&tip.hash).expect("FATAL: invalid tip hash from Zebra");
    (height, hash)
}

/// Reverses Zebra's display-order bytes into a `BlockHash`.
pub(crate) fn block_hash_from_display(bytes: &[u8]) -> Option<BlockHash> {
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        arr.reverse();
        Some(BlockHash(arr))
    } else {
        None
    }
}

impl JsonRpc {
    /// Fetches blockchain state info, used for boot-time cross-validation.
    pub async fn get_blockchain_info(&self) -> Result<BlockchainInfo, TransportError> {
        self.send_request("getblockchaininfo", [(); 0])
            .await?
            .ok_or(TransportError::BadNodeData(
                "getblockchaininfo returned null",
            ))
    }

    /// Fetches a best-chain block hash by height, for reorg walks — the
    /// genesis block is fetched this way because [`Block::read`] rejects it.
    pub async fn get_block_hash(&self, height: BlockHeight) -> Result<BlockHash, TransportError> {
        let index = i32::try_from(u32::from(height))
            .map_err(|_| TransportError::BadNodeData("getblockhash height"))?;
        let hash_hex: String = self
            .send_request("getblockhash", [index])
            .await?
            .ok_or(TransportError::BadNodeData("getblockhash returned null"))?;

        let display_bytes =
            hex::decode(hash_hex).map_err(|_| TransportError::BadNodeData("getblockhash hex"))?;
        block_hash_from_display(&display_bytes)
            .ok_or(TransportError::BadNodeData("getblockhash length"))
    }

    /// Fetches the shielded tree state for a block, as the upstream
    /// [`ChainState`] — the connection point for `WalletWrite::put_blocks`.
    pub async fn chain_state_at(&self, height: BlockHeight) -> Result<ChainState, TransportError> {
        let response: TreeStateResponse = self
            .send_request("z_gettreestate", [u32::from(height).to_string()])
            .await
            .map_err(not_on_best_chain)?
            .ok_or(TransportError::BadNodeData("z_gettreestate returned null"))?;

        if response.height != u32::from(height) {
            return Err(TransportError::BadNodeData(
                "z_gettreestate answered a different height than requested",
            ));
        }

        chain_state_from_rpc_response(response)
    }

    /// Fetches a block header as `(hash, height, time)`, for MTP backfill.
    pub async fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<(BlockHash, BlockHeight, Timestamp), TransportError> {
        let response: BlockHeaderResponse = self
            .send_request("getblockheader", (u32::from(height).to_string(), true))
            .await
            .map_err(not_on_best_chain)?
            .ok_or(TransportError::BadNodeData("getblockheader returned null"))?;

        if response.height != u32::from(height) {
            return Err(TransportError::BadNodeData(
                "getblockheader answered a different height than requested",
            ));
        }

        let display_bytes = hex::decode(&response.hash)
            .map_err(|_| TransportError::BadNodeData("getblockheader hash hex"))?;
        let hash = block_hash_from_display(&display_bytes)
            .ok_or(TransportError::BadNodeData("getblockheader hash length"))?;

        let time = Timestamp::from_seconds(response.time as i64)
            .map_err(|_| TransportError::BadNodeData("getblockheader time"))?;

        Ok((hash, BlockHeight::from_u32(response.height), time))
    }

    /// Fetches a full block by height and parses it under the compiled
    /// consensus parameters — best-chain membership remains Zebra's word.
    pub async fn get_block<P: Parameters>(
        &self,
        network: &P,
        height: BlockHeight,
    ) -> Result<Block, TransportError> {
        let hex_str: String = self
            .send_request("getblock", (u32::from(height).to_string(), 0))
            .await
            .map_err(not_on_best_chain)?
            .ok_or(TransportError::BadNodeData("getblock returned null"))?;

        let bytes =
            hex::decode(hex_str).map_err(|_| TransportError::BadNodeData("getblock hex"))?;
        let block = Block::read(&bytes[..], network)
            .map_err(|_| TransportError::BadNodeData("getblock parse"))?;
        if block.claimed_height() != height {
            return Err(TransportError::BadNodeData(
                "getblock returned the wrong height",
            ));
        }
        Ok(block)
    }
}

impl super::CanonicalBlockSource {
    /// Returns the exact `(height, hash)` pair for the current best-chain
    /// tip, parsed from one `getblockchaininfo` response so observations
    /// from different tips cannot be combined.
    pub async fn exact_tip(&self) -> Result<(BlockHeight, BlockHash), TransportError> {
        self.0.get_blockchain_info().await?.canonical_tip()
    }

    /// Fetches a full canonical block by height (see [`JsonRpc::get_block`]).
    pub async fn get_block<P: Parameters>(
        &self,
        network: &P,
        height: BlockHeight,
    ) -> Result<Block, TransportError> {
        self.0.get_block(network, height).await
    }
}

// ============================================================================
// Typed responses
// ============================================================================

/// The `getblockchaininfo` answer.
#[derive(Debug, Deserialize)]
pub struct BlockchainInfo {
    pub blocks: u32,
    pub bestblockhash: String,
}

impl BlockchainInfo {
    /// Parses the height/hash pair carried by this one response.
    pub fn canonical_tip(&self) -> Result<(BlockHeight, BlockHash), TransportError> {
        let display_bytes = hex::decode(&self.bestblockhash)
            .map_err(|_| TransportError::BadNodeData("bestblockhash hex"))?;
        let hash = block_hash_from_display(&display_bytes)
            .ok_or(TransportError::BadNodeData("bestblockhash length"))?;

        Ok((BlockHeight::from_u32(self.blocks), hash))
    }
}

#[derive(Debug, Deserialize)]
struct BlockHeaderResponse {
    hash: String,
    height: u32,
    time: u32,
}

#[derive(Debug, Deserialize)]
struct TreeStateResponse {
    height: u32,
    hash: String,
    sapling: ShieldedTreeState,
    orchard: ShieldedTreeState,
    ironwood: Option<ShieldedTreeState>,
}

#[derive(Debug, Deserialize)]
struct ShieldedTreeState {
    commitments: TreeCommitments,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TreeCommitments {
    final_state: Option<String>,
}

/// `z_gettreestate` parsed into the upstream [`ChainState`]; an absent
/// Ironwood section (pre-NU6.3) and an empty tree are the same value.
fn chain_state_from_rpc_response(
    response: TreeStateResponse,
) -> Result<ChainState, TransportError> {
    let sapling_final_state = response
        .sapling
        .commitments
        .final_state
        .ok_or(TransportError::BadNodeData("missing Sapling finalState"))?;
    let sapling_tree = decode_tree::<SaplingNode>(&sapling_final_state, "Sapling")?;

    let orchard_final_state = response
        .orchard
        .commitments
        .final_state
        .ok_or(TransportError::BadNodeData("missing Orchard finalState"))?;
    let orchard_tree = decode_tree::<MerkleHashOrchard>(&orchard_final_state, "Orchard")?;

    // Zebra omits the `ironwood` key entirely before NU6.3 activation.
    let ironwood_tree = match response
        .ironwood
        .and_then(|state| state.commitments.final_state)
    {
        Some(hex) if !hex.is_empty() => decode_tree::<MerkleHashOrchard>(&hex, "Ironwood")?,
        _ => Frontier::empty(),
    };

    let expected_hash_bytes =
        hex::decode(&response.hash).map_err(|_| TransportError::BadNodeData("invalid hash hex"))?;
    let expected_hash = block_hash_from_display(&expected_hash_bytes)
        .ok_or(TransportError::BadNodeData("malformed 32-byte hash"))?;

    Ok(ChainState::new(
        BlockHeight::from_u32(response.height),
        expected_hash,
        sapling_tree,
        orchard_tree,
        ironwood_tree,
    ))
}

/// Decodes one `finalState` hex into the upstream frontier value.
fn decode_tree<Node>(
    hex_state: &str,
    name: &'static str,
) -> Result<Frontier<Node, 32>, TransportError>
where
    Node: HashSer + incrementalmerkletree::Hashable + Clone,
{
    let bytes = hex::decode(hex_state).map_err(|e| {
        TransportError::BadCheckpoint(format!("{name} tree hex decode failed: {e}"))
    })?;

    read_commitment_tree::<Node, _, 32>(&bytes[..])
        .map(|tree| tree.to_frontier())
        .map_err(|e| TransportError::BadCheckpoint(format!("{name} tree decode failed: {e}")))
}
