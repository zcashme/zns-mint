//! zns-scan — development-only Name Note scanner for the regtest harness.
//!
//! Scans a height range on the local regtest node (Zebra JSON-RPC on
//! 127.0.0.1:8232), trial-decrypts Ironwood actions with the dev Registry
//! keys (all-zero seed, account m/32'/133'/1', j=0 external — the same
//! material as the whitepaper Section 3.5 test vector), and prints one
//! JSON object per verified Name Note to stdout.
//!
//! `decrypt_name_notes` only surfaces a candidate when the memo parses, the
//! ZNS-derived (psi, rcm) reproduce the action's on-chain cmx, the value is
//! zero, and the recipient is exactly the Registry address — so anything
//! printed here is a chain-verified Name Note, not a heuristic.
//!
//! Usage: zns-scan --from <height> --to <height>
//! Output: one JSON object per line; {"verified":N,"scanned":M} summary last.

use zns_mint::zcash::JsonRpc;
use pasta_curves::group::ff::PrimeField as _;

#[tokio::main]
async fn main() {
    // Regtest parameters mirroring boot.rs / the harness zebrad config.
    let one = zcash_protocol::consensus::BlockHeight::from_u32(1);
    let four = zcash_protocol::consensus::BlockHeight::from_u32(4);
    let network = zcash_protocol::local_consensus::LocalNetwork {
        overwinter: Some(one),
        sapling: Some(one),
        blossom: Some(one),
        heartwood: Some(one),
        canopy: Some(one),
        nu5: Some(one),
        nu6: Some(one),
        nu6_1: Some(four),
        nu6_2: Some(four),
        nu6_3: Some(four),
    };

    let mut from = None;
    let mut to = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--from" => from = args.next().and_then(|v| v.parse().ok()),
            "--to" => to = args.next().and_then(|v| v.parse().ok()),
            _ => {}
        }
    }
    let (Some(from), Some(to)) = (from, to) else {
        eprintln!("usage: zns-scan --from <height> --to <height>");
        std::process::exit(2);
    };

    // Dev Registry keys: all-zero seed, account 1 (m/32'/133'/1').
    let seed = [0u8; 32];
    let _usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
        &network,
        &seed,
        zip32::AccountId::const_from_u32(1),
    )
    .expect("dev seed derives");
    let registry_orchard = zns_mint::key::RegistryKeys::derive(
        &network,
        &secrecy::Secret::new(seed),
    )
    .fvk()
    .orchard()
    .expect("orchard component")
    .clone();
    let registry_ivk = registry_orchard
        .to_ivk(orchard::keys::Scope::External)
        .prepare();
    let registry_recipient = registry_orchard.address_at(0u32, orchard::keys::Scope::External);

    let rpc = JsonRpc::new();
    let mut verified = 0usize;
    let mut scanned = 0usize;
    for height in from..=to {
        let Ok(block) = rpc
            .get_block(
                &network,
                zcash_protocol::consensus::BlockHeight::from_u32(height),
            )
            .await
        else {
            continue;
        };
        scanned += 1;
        for found in zns_mint::mint::decrypt_name_notes(
            &network,
            &block,
            &registry_ivk,
            registry_recipient,
        ) {
            verified += 1;
            let note = &found.payload;
            let (rcm, psi) = note.opening(&network);
            let (g_d, pk_d) = found.note.recipient().zns_commitment_keys();
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            println!(
                "{}",
                serde_json::json!({
                    "height": height,
                    "txid": found.txid.to_string(),
                    "action": found.action_index,
                    "name": note.name().as_str(),
                    "action_kind": note.action().as_str(),
                    "ua": note.ua().map(|u| u.encode(&network)),
                    "expires": match note.expires_at() {
                        Some(zns_mint::mint::note::Expiry::Never) => "none".to_string(),
                        Some(zns_mint::mint::note::Expiry::At(t)) => t.as_seconds().to_string(),
                        None => "n/a".to_string(),
                    },
                    "prev_rcm": hex(&note.prev_rcm().map(|p| p.to_bytes()).unwrap_or([0u8; 32]).as_slice()),
                    "g_d": hex(&g_d),
                    "pk_d": hex(&pk_d),
                    "value": found.note.value().inner(),
                    "rho": hex(&found.note.rho().to_bytes()),
                    "psi": hex(psi.to_repr().as_ref()),
                    "rcm": hex(rcm.to_repr().as_ref()),
                    "cmx": hex(&orchard::note::ExtractedNoteCommitment::from(
                        found.note.commitment()
                    ).to_bytes()),
                    "memo_ascii": String::from_utf8_lossy(&found.memo[..]).trim_end_matches('\0').to_string(),
                })
            );
        }
    }
    println!(
        "{}",
        serde_json::json!({"verified": verified, "scanned": scanned})
    );
}
