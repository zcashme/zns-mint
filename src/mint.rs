//! Shared protocol logic for ZNS minting and wallet operations.

pub mod mtp;
pub mod note;
pub mod otp;
pub mod pricing;
pub mod registry;

pub mod treasury;

/// The mint's authoritative position on the Zcash chain.
pub use zcash_client_backend::data_api::BlockMetadata as ChainTip;

// The Name Note type and its codec.
pub use note::{decrypt_name_notes, DecryptedNameNote, Expiry, NameNote, Term};
pub use time::Timestamp;

pub use zcash_keys::address::UnifiedAddress;

use zcash_protocol::consensus::{BlockHeight, Parameters};
use zip32::AccountId;

use otp::OtpCode;

pub const TREASURY_ACCOUNT: AccountId = AccountId::const_from_u32(0);
pub const REGISTRY_ACCOUNT: AccountId = AccountId::const_from_u32(1);

/// First block the mint observes; everything before it is pre-birth.
#[cfg(not(feature = "regtest"))]
#[cfg(not(feature = "testnet"))]
pub const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(3_400_000);

#[cfg(all(feature = "testnet", not(feature = "regtest")))]
pub const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(4_338_933);

/// Regtest birth: first block after the harness's NU6.3 activation (height 4).
#[cfg(feature = "regtest")]
pub const MINT_BIRTHDAY: BlockHeight = BlockHeight::from_u32(4);

/// The liveness interval: one Julian year (365.25 days), in seconds.
pub const LIVENESS_INTERVAL: i64 = 31_557_600;

/// Liveness challenge lead: how far before `release_deadline` the mint
/// begins asking the current controller to prove control. Independent of
/// `D_OTP`: the notification lead is not the response window. Seven days.
pub const CHALLENGE_LEAD: i64 = 7 * 24 * 60 * 60;

/// Minimum cadence between successive liveness challenges for the same
/// current record. Bounds challenge issuance during the lead window so a
/// silent controller sees at most one relay per day, not one per OTP TTL.
pub const LIVENESS_RETRY_COOLDOWN: i64 = 24 * 60 * 60;

/// Minimum Treasury Ironwood balance after boot sync (0.002 ZEC).
pub const MIN_TREASURY_BALANCE: u64 = 200_000;

/// ZNS action kinds.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    /// Point a name to an address
    Claim,
    /// Rebinds a name to a new address
    Update,
    /// Terminates a name's linkage to an address
    Release,
}

impl Action {
    /// Returns the canonical ASCII verb for this action.
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::Claim => "claim",
            Action::Update => "update",
            Action::Release => "release",
        }
    }
}

/// An authorized transition the loop is about to assemble.
///
/// Built from [`treasury::parse_request`];
/// memo bytes stay on that parser. Claims carry a term (`forever` or
/// `<N>y`); updates carry `none` (carried forward), `<N>y`, or
/// `forever` — the upgrade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Create a new registration; the term slot is never empty.
    Claim {
        name: Name,
        ua: UnifiedAddress,
        term: Term,
    },
    /// Rebind; `None` carries the expiry forward, `Some(Years)` extends
    /// it, `Some(Forever)` upgrades it to no fixed expiration.
    Update {
        name: Name,
        ua: UnifiedAddress,
        term: Option<Term>,
    },
    Release {
        name: Name,
        ua: UnifiedAddress,
    },
}

/// A mint-issued challenge to a wallet, proving that the wallet controls a name via shielded-memos.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub code: OtpCode,
    pub name: Name,
    pub action: Action,
    pub ua: UnifiedAddress,
}

impl Challenge {
    /// Encodes the challenge memo.
    pub fn encode<P: Parameters>(&self, network: &P) -> Option<[u8; 512]> {
        if self.action == Action::Claim {
            return None;
        }
        let verb = self.action.as_str();

        let ua_field = self.ua.encode(network);
        let otp_digits = self.code.digits();
        let mut memo = [0u8; 512];
        let mut offset = 0usize;
        for field in [
            b"ZNS:otp:".as_slice(),
            otp_digits.as_slice(),
            b":".as_slice(),
            self.name.as_str().as_bytes(),
            b":".as_slice(),
            verb.as_bytes(),
            b":".as_slice(),
            ua_field.as_bytes(),
        ] {
            let end = offset + field.len();
            memo[offset..end].copy_from_slice(field);
            offset = end;
        }
        Some(memo)
    }

    /// Decodes a relay sentence. The verb is `update` or `release` —
    /// challenges never claim — and the UA must carry an Orchard-family
    /// receiver.
    pub fn decode<P: Parameters>(network: &P, memo: &[u8; 512]) -> Option<Self> {
        let end = memo.iter().position(|&b| b == 0).unwrap_or(memo.len());
        if memo[end..].iter().any(|&b| b != 0) {
            return None;
        }
        let text = std::str::from_utf8(&memo[..end]).ok()?;

        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() != 6 || parts[0] != "ZNS" || parts[1] != "otp" {
            return None;
        }

        let digits = parts[2].as_bytes();
        if digits.len() != 6 || !digits.iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let code = OtpCode::from_digits(digits.try_into().ok()?)?;

        let name = Name::parse(parts[3])?;
        let action = match parts[4] {
            "update" => Action::Update,
            "release" => Action::Release,
            _ => return None,
        };

        let ua = match zcash_keys::address::Address::decode(network, parts[5])? {
            zcash_keys::address::Address::Unified(ua) if ua.orchard().is_some() => ua,
            _ => return None,
        };

        Some(Self {
            code,
            name,
            action,
            ua,
        })
    }
}

/// A ZNS name-chain commitment — the trapdoor that links consecutive Name Notes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameCommitment(orchard::note::NoteCommitTrapdoor);

impl NameCommitment {
    /// Wraps a `NoteCommitTrapdoor` derived via [`NameNote::rcm`].
    pub fn from_inner(inner: orchard::note::NoteCommitTrapdoor) -> Self {
        Self(inner)
    }

    /// Unwraps back to the upstream type for the `unsafe-zns` builder surface.
    pub fn into_inner(self) -> orchard::note::NoteCommitTrapdoor {
        self.0
    }

    /// Deserializes from the canonical 32-byte little-endian representation.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        orchard::note::NoteCommitTrapdoor::from_bytes(bytes)
            .into_option()
            .map(Self)
    }

    /// Serializes to the canonical 32-byte little-endian representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// A ZcashName
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(String);

impl Name {
    /// Attempts to parse a string into a valid ZNS name.
    pub fn parse(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        if bytes.iter().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9')) {
            Some(Self(s.to_string()))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Block application
// ---------------------------------------------------------------------------

/// Applies one verified canonical successor to every faculty: scan, clock,
/// Registry law, wallet commit, Treasury intake, Name Note storage, order
/// fulfillment, cursor. Never fetches, never broadcasts; `main` passes the
/// live queues, boot passes scratch ones.
#[allow(clippy::too_many_arguments)]
pub fn apply_block<P: Parameters + Send + Sync + 'static>(
    network: &P,
    registry_keys: &crate::key::RegistryKeys,
    treasury_keys: &crate::key::TreasuryKeys,
    from_state: &zcash_client_backend::data_api::chain::ChainState,
    block: zcash_primitives::block::Block,
    height: BlockHeight,
    wallet: &mut crate::wallet::Wallet,
    registry: &mut registry::Registry,
    mtp: &mut mtp::MtpTracker,
    cursor: &mut ChainTip,
    requests: &mut treasury::RequestQueue,
    name_notes: &mut note::NameNoteQueue,
) {
    use std::convert::Infallible;

    use incrementalmerkletree::Position;
    use zcash_client_backend::data_api::WalletWrite as _;
    use zcash_client_backend::scanning::full::{decrypt_block, scan_block};
    use zcash_client_backend::scanning::Nullifiers;

    assert_eq!(
        from_state.block_height(),
        cursor.block_height(),
        "FATAL: previous chain-state height mismatch"
    );
    assert_eq!(
        from_state.block_hash(),
        cursor.block_hash(),
        "FATAL: previous chain state does not describe the applied cursor"
    );
    assert_eq!(
        block.header().prev_block,
        cursor.block_hash(),
        "FATAL: fetched block does not continue the applied cursor"
    );

    let block_time = block.header().time;
    let candidates = decrypt_name_notes(network, &block, registry_keys);
    let treasury_memos = note::decrypt_treasury_memos(&block, treasury_keys);
    let received_name_notes = candidates
        .iter()
        .map(|candidate| {
            registry::ReceivedNameNote::new(
                candidate.txid,
                candidate.action_index,
                candidate.nullifier,
                candidate.payload.clone(),
            )
        })
        .collect::<Vec<_>>();

    let (header, batches) = decrypt_block(network, block, wallet.scanning_keys());
    let nullifiers =
        Nullifiers::unspent(wallet).expect("FATAL: wallet could not expose its unspent nullifiers");
    let scanned = scan_block(
        network,
        height,
        &header,
        batches,
        wallet.scanning_keys(),
        &nullifiers,
        Some(&*cursor),
        |_| {
            Ok::<
                Option<(
                    zip32::AccountId,
                    Option<transparent::keys::TransparentKeyScope>,
                )>,
                Infallible,
            >(None)
        },
    )
    .expect("FATAL: a canonical block failed deterministic wallet scanning");

    let mut next_mtp = mtp.clone();
    next_mtp.update(height, block_time);
    let block_mtp = next_mtp
        .current()
        .expect("FATAL: MTP unavailable after applying a block");

    let (next_registry, accepted_name_notes) =
        registry.apply_block(network, &scanned, &received_name_notes, block_mtp);

    let ironwood_start = scanned
        .ironwood()
        .final_tree_size()
        .checked_sub(
            u32::try_from(scanned.ironwood().commitments().len())
                .expect("Ironwood block action count fits u32"),
        )
        .expect("FATAL: scanner returned an impossible Ironwood tree size");
    let accepted_name_notes = accepted_name_notes
        .into_iter()
        .map(|index| {
            let candidate = &candidates[index];
            let position = Position::from(
                u64::from(ironwood_start)
                    + u64::try_from(candidate.ordinal).expect("Name Note ordinal fits u64"),
            );
            (index, position)
        })
        .collect::<Vec<_>>();
    let next_metadata = scanned.to_block_metadata();

    wallet
        .put_blocks(from_state, vec![scanned])
        .expect("FATAL: wallet block commit failed");
    // Upstream's ScannedBlock drops note plaintexts; the Treasury
    // lane's memos were decrypted above. Decoded once, here, they
    // are recorded as the requests they carry — nothing is stored
    // for later re-reading; the block is the durable source,
    // refetched on every application.
    for (txid, _action_index, paid, memo) in treasury_memos {
        // An echo is the relay memo itself, byte-for-byte — routed
        // here, not by parse_request: the wire never carries an
        // OTP on a request. The echo rides the queue in request
        // shape, its digits in the OTP slot; the queue holds the
        // order (the requested term), the memo proves identity.
        if let Some(echo) = Challenge::decode(network, &memo) {
            requests.record(
                treasury::ParsedRequest {
                    action: echo.action,
                    name: echo.name,
                    ua: echo.ua,
                    term: None,
                    otp: Some(echo.code.digits()),
                },
                paid,
                height,
            );
            continue;
        }
        match treasury::parse_request(network, &memo) {
            Some(request) => requests.record(request, paid, height),
            None => tracing::info!(
                txid = %txid,
                value_zec = paid.into_u64() as f64 / 1e8,
                height = u32::from(height),
                "treasury received non-request payment"
            ),
        }
    }
    for (index, position) in accepted_name_notes {
        let candidate = &candidates[index];
        wallet.store_name_note(
            height,
            position,
            candidate.txid,
            candidate.action_index,
            candidate.note,
            candidate.nullifier,
            candidate.ephemeral_key.clone(),
            candidate.memo,
        );
        // The block fulfilled the order.
        name_notes.fulfill(&candidate.payload);
    }
    *mtp = next_mtp;
    *registry = next_registry;
    *cursor = next_metadata;

    tracing::debug!(
        height = u32::from(cursor.block_height()),
        hash = %cursor.block_hash(),
        "canonical block applied"
    );
}
