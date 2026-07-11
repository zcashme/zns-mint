use incrementalmerkletree::Position;
use zcash_protocol::consensus::BlockHeight;
use zip32::AccountId;

/// A received Orchard note with its decrypted memo.
///
/// `Debug` is manually implemented to redact the memo (shielded user data)
/// per AGENTS.md "treat key material as radioactive" — the derived `Debug`
/// for `[u8; 512]` would print raw memo bytes (names, addresses, ZNS payloads)
/// to any `{:?}` log line.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedOrchardNote {
    pub account_id: AccountId,
    pub note: orchard::note::Note,
    pub memo: crate::mint::Memo,
    pub position: Position,
    pub confirmed_height: BlockHeight,
}

impl std::fmt::Debug for ReceivedOrchardNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedOrchardNote")
            .field("account_id", &self.account_id)
            .field("note", &"<redacted>")
            .field("memo", &self.memo) // Memo's Debug prints "Memo(<redacted>)"
            .field("position", &self.position)
            .field("confirmed_height", &self.confirmed_height)
            .finish()
    }
}

/// A received Sapling note with its decrypted memo.
///
/// `Debug` is manually implemented to redact the memo, matching
/// `ReceivedOrchardNote`.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedSaplingNote {
    pub account_id: AccountId,
    pub note: sapling::Note,
    pub memo: crate::mint::Memo,
    pub position: Position,
    pub confirmed_height: BlockHeight,
}

impl std::fmt::Debug for ReceivedSaplingNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedSaplingNote")
            .field("account_id", &self.account_id)
            .field("note", &"<redacted>")
            .field("memo", &self.memo)
            .field("position", &self.position)
            .field("confirmed_height", &self.confirmed_height)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct SpentOrchardNote {
    pub account_id: AccountId,
    pub nullifier: orchard::note::Nullifier,
    pub original_note: ReceivedOrchardNote, // The Ctrl-Z backup!
}

#[derive(Clone, Debug)]
pub struct SpentSaplingNote {
    pub account_id: AccountId,
    pub nullifier: sapling::Nullifier,
    pub original_note: ReceivedSaplingNote, // The Ctrl-Z backup!
}

#[derive(Clone, Debug)]
pub struct TransactionRecord {
    pub txid: zcash_primitives::transaction::TxId,
    pub block_height: BlockHeight,
    pub received_orchard: Vec<ReceivedOrchardNote>,
    pub received_sapling: Vec<ReceivedSaplingNote>,
    pub spent_orchard: Vec<SpentOrchardNote>,
    pub spent_sapling: Vec<SpentSaplingNote>,
}
