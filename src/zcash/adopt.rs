//! An adopted header's time has to sit after the previous median, at
//! most 90 minutes past it, and at most two hours ahead of the mint.
//!
//! Mainnet and testnet also require the node to serve a pinned block.
//! Regtest has no pinned block.

#[cfg(not(feature = "regtest"))]
use zcash_primitives::block::BlockHash;
#[cfg(not(feature = "regtest"))]
use zcash_protocol::consensus::BlockHeight;

#[cfg(not(feature = "regtest"))]
use super::chain::block_hash_from_display;
#[cfg(not(feature = "regtest"))]
use super::CanonicalBlockSource;

/// `nTime` may be at most this far ahead of the previous median.
const MEDIAN_WINDOW: i64 = 90 * 60;
/// `nTime` may be at most this far ahead of the mint's own time.
const MINT_WINDOW: i64 = 2 * 60 * 60;

/// Mainnet block 3,353,606. Below the heights this mint is born at.
#[cfg(not(any(feature = "testnet", feature = "regtest")))]
fn pinned() -> (BlockHeight, BlockHash) {
    (
        BlockHeight::from_u32(3_353_606),
        hash_from_display("00000000008b5211479a54c24191ff237efa3d39bb28b1cc696195eeff5e5605"),
    )
}

/// Testnet block 4,238,000.
#[cfg(all(feature = "testnet", not(feature = "regtest")))]
fn pinned() -> (BlockHeight, BlockHash) {
    (
        BlockHeight::from_u32(4_238_000),
        hash_from_display("0017b69a52b06033149cbb86f89488e7cfc525b3e5e98561a51b6ca271a0576e"),
    )
}

#[cfg(not(feature = "regtest"))]
fn hash_from_display(display_hex: &str) -> BlockHash {
    let bytes = hex::decode(display_hex).expect("pinned block hash is hex");
    block_hash_from_display(&bytes).expect("pinned block hash is 32 bytes")
}

/// The node has to serve the pinned block. One header, hashed locally.
#[cfg(not(feature = "regtest"))]
pub async fn require_pinned(source: &CanonicalBlockSource) {
    let (height, hash) = pinned();
    let header = source.header_at(height).await.unwrap_or_else(|error| {
        panic!(
            "FATAL: pinned block {} unavailable: {error}",
            u32::from(height)
        )
    });
    if header.hash() != hash {
        panic!("FATAL: block {} is not the pinned block", u32::from(height));
    }
    tracing::info!(height = u32::from(height), "pinned block present");
}

/// `time` has to be within two hours of `wall`. Once `enforced`, it also
/// has to be strictly after `prev_median` and at most 90 minutes past it.
pub(crate) fn block_time_ok(
    prev_median: Option<i64>,
    time: u32,
    wall: i64,
    enforced: bool,
) -> Result<(), &'static str> {
    let time = i64::from(time);
    if time > wall.saturating_add(MINT_WINDOW) {
        return Err("block time is more than two hours ahead of the mint");
    }
    if enforced {
        let median = prev_median.expect("a full window has a median");
        if time <= median {
            return Err("block time is not after the previous median");
        }
        if time > median.saturating_add(MEDIAN_WINDOW) {
            return Err("block time is more than 90 minutes past the previous median");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_time_has_to_sit_inside_both_bounds() {
        let median = 1_000_000;
        let wall = 1_000_000;
        assert!(block_time_ok(Some(median), (median + 1) as u32, wall, true).is_ok());
        assert!(block_time_ok(Some(median), (median + MEDIAN_WINDOW) as u32, wall, true).is_ok());
        assert!(block_time_ok(Some(median), median as u32, wall, true).is_err());
        assert!(block_time_ok(
            Some(median),
            (median + MEDIAN_WINDOW + 1) as u32,
            wall,
            true
        )
        .is_err());
        assert!(block_time_ok(None, (wall + MINT_WINDOW) as u32, wall, false).is_ok());
        assert!(block_time_ok(None, (wall + MINT_WINDOW + 1) as u32, wall, false).is_err());
    }

    #[cfg(not(any(feature = "testnet", feature = "regtest")))]
    const PINNED_HEIGHT: u32 = 3_353_606;
    #[cfg(not(any(feature = "testnet", feature = "regtest")))]
    const PINNED_HEADER: &str = include_str!("testdata/mainnet-3353606.header.hex");
    #[cfg(all(feature = "testnet", not(feature = "regtest")))]
    const PINNED_HEIGHT: u32 = 4_238_000;
    #[cfg(all(feature = "testnet", not(feature = "regtest")))]
    const PINNED_HEADER: &str = include_str!("testdata/testnet-4238000.header.hex");

    #[cfg(not(feature = "regtest"))]
    fn pinned_header() -> zcash_primitives::block::BlockHeader {
        let bytes = hex::decode(PINNED_HEADER.trim()).expect("pinned header is hex");
        zcash_primitives::block::BlockHeader::read(std::io::Cursor::new(bytes))
            .expect("pinned header parses")
    }

    #[cfg(not(feature = "regtest"))]
    #[test]
    fn the_pinned_header_hashes_to_the_pin() {
        let (height, hash) = pinned();
        assert_eq!(u32::from(height), PINNED_HEIGHT);
        assert_eq!(pinned_header().hash(), hash);
    }

    #[cfg(not(feature = "regtest"))]
    #[test]
    fn a_mismatched_header_is_not_the_pin() {
        let (_, hash) = pinned();
        let mut bytes = hex::decode(PINNED_HEADER.trim()).expect("pinned header is hex");
        bytes[0] ^= 1;
        let header = zcash_primitives::block::BlockHeader::read(std::io::Cursor::new(bytes))
            .expect("tampered header parses");
        assert_ne!(header.hash(), hash);
    }
}
