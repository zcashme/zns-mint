//! Write a capsule sealing an all-zeros seed, for dev runs.
//!
//! Requires `--features non-tee` (enforced via `required-features`;
//! release builds with that feature are `compile_error!`-blocked in
//! `src/lib.rs`). Capsules sealed this way use the public dev-escape
//! key — dev runs only, never production keys.
//!
//! Run: `cargo run --example write_fake_capsule --features non-tee`

use rand::rngs::OsRng;
use secrecy::Secret;
use std::fs;
use zns_canon::capsule::{seal_seed, serialize_capsule, CAPSULE_KEY_CONTEXT, SEED_LEN};
use zns_canon::sealing::dev_sealing_key;

fn main() {
    let seed = Secret::new([0u8; SEED_LEN]);
    let key = dev_sealing_key(CAPSULE_KEY_CONTEXT);
    let capsule = seal_seed(&key, &seed, &mut OsRng).expect("seal");
    let bytes = serialize_capsule(&capsule).expect("serialize");
    fs::create_dir_all("keys").unwrap();
    fs::write("keys/zns_seed.capsule", &bytes).unwrap();
    println!("wrote keys/zns_seed.capsule ({} bytes)", bytes.len());
}
