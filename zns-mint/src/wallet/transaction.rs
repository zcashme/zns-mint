use incrementalmerkletree::Position;
use zcash_protocol::consensus::BlockHeight;
use zip32::AccountId;

#[derive(Clone, Debug)]
pub struct ReceivedOrchardNote {
    pub account_id: AccountId,
    pub note: orchard::note::Note,
    pub memo: [u8; 512],
    pub position: Position,
    pub confirmed_height: BlockHeight,
}

#[derive(Clone, Debug)]
pub struct ReceivedSaplingNote {
    pub account_id: AccountId,
    pub note: sapling::Note,
    pub memo: [u8; 512],
    pub position: Position,
    pub confirmed_height: BlockHeight,
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
