//! Write a fake-TEE-sealed all-zeros seed capsule to `keys/zns_seed.capsule`.
//!
//! Dev-only. Requires `--features fake-tee` (enforced via `required-features`
//! in `Cargo.toml`; that feature is `compile_error!`-blocked from release
//! builds in `src/lib.rs`). The resulting capsule can only be unsealed by
//! the same `FakeTee`.
//!
//! Run: `cargo run --example write_fake_capsule --features fake-tee`

use rand::rngs::OsRng;
use secrecy::Secret;
use std::fs;
use zns_mint::capsule::{seal_seed, serialize_capsule, SEED_LEN};
use zns_mint::tee::FakeTee;

fn main() {
    let seed = Secret::new([0u8; SEED_LEN]);
    let capsule = seal_seed(&FakeTee, &seed, &mut OsRng).expect("seal");
    let bytes = serialize_capsule(&capsule).expect("serialize");
    fs::create_dir_all("keys").unwrap();
    fs::write("keys/zns_seed.capsule", &bytes).unwrap();
    println!("wrote keys/zns_seed.capsule ({} bytes)", bytes.len());
}
