//! Relaxed Orchard trial decryption — skips the ZIP-212 `cmx` check.

use orchard::{
    keys::PreparedIncomingViewingKey as OrchardPreparedIvk,
    note_encryption::{CompactAction, OrchardDomain},
    Action,
};
use zcash_protocol::memo::MemoBytes;

/// Compact-block orchard trial decryption, **without** the ZIP-212 commitment check.
pub fn try_compact_orchard_relaxed(
    ivk: &OrchardPreparedIvk,
    action: &CompactAction,
) -> Option<(orchard::Note, orchard::Address)> {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    use chacha20::ChaCha20;
    use zcash_note_encryption::{Domain, ShieldedOutput, COMPACT_NOTE_SIZE};

    let domain = OrchardDomain::for_compact_action(action);
    let ephemeral_key =
        ShieldedOutput::<OrchardDomain, COMPACT_NOTE_SIZE>::ephemeral_key(action);
    let epk = OrchardDomain::prepare_epk(OrchardDomain::epk(&ephemeral_key)?);
    let shared_secret = OrchardDomain::ka_agree_dec(ivk, &epk);
    let key = OrchardDomain::kdf(shared_secret, &ephemeral_key);

    let mut plaintext = [0u8; COMPACT_NOTE_SIZE];
    plaintext
        .copy_from_slice(ShieldedOutput::<OrchardDomain, COMPACT_NOTE_SIZE>::enc_ciphertext(action));
    let mut keystream = ChaCha20::new(key.as_ref().into(), [0u8; 12][..].into());
    keystream.seek(64u64);
    keystream.apply_keystream(&mut plaintext);

    domain.parse_note_plaintext_without_memo_ivk(ivk, &plaintext)
}

/// Full-transaction orchard trial decryption, **without** the ZIP-212 commitment check.
pub fn try_decrypt_orchard_relaxed<A>(
    action: &Action<A>,
    ivk: &OrchardPreparedIvk,
) -> Option<(orchard::Note, orchard::Address, MemoBytes)> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;
    use zcash_note_encryption::{
        Domain, NotePlaintextBytes, ShieldedOutput, ENC_CIPHERTEXT_SIZE, NOTE_PLAINTEXT_SIZE,
    };

    let domain = OrchardDomain::for_action(action);
    let ephemeral_key =
        ShieldedOutput::<OrchardDomain, ENC_CIPHERTEXT_SIZE>::ephemeral_key(action);
    let epk = OrchardDomain::prepare_epk(OrchardDomain::epk(&ephemeral_key)?);
    let shared_secret = OrchardDomain::ka_agree_dec(ivk, &epk);
    let key = OrchardDomain::kdf(shared_secret, &ephemeral_key);

    let enc = ShieldedOutput::<OrchardDomain, ENC_CIPHERTEXT_SIZE>::enc_ciphertext(action);
    let mut plaintext = NotePlaintextBytes(enc[..NOTE_PLAINTEXT_SIZE].try_into().unwrap());
    ChaCha20Poly1305::new(key.as_ref().into())
        .decrypt_in_place_detached(
            [0u8; 12][..].into(),
            &[],
            &mut plaintext.0,
            enc[NOTE_PLAINTEXT_SIZE..].into(),
        )
        .ok()?;

    let (note, recipient) = domain.parse_note_plaintext_without_memo_ivk(ivk, &plaintext.0)?;
    let memo = domain.extract_memo(&plaintext);
    Some((note, recipient, MemoBytes::from_bytes(&memo).unwrap()))
}