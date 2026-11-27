//! Access codes, separate from the seed ceremony.
//!
//! `zns-keygen access-code` unseals the seed capsule, prints the X25519
//! public key of `HMAC-SHA256(seed, "ZNS/access-code/x25519/v1")`, and drops
//! the seed. Nothing is written. The issuer agrees their private key with
//! the printed public key.

use secrecy::{ExposeSecret, Secret};
use x25519_dalek::{PublicKey, StaticSecret};
use zns_canon::access_code::seed_scalar;
use zns_canon::capsule::{self, SEED_LEN};

const CAPSULE_FILE: &str = "keys/zns_seed.capsule";

pub fn run(mut args: impl Iterator<Item = String>) {
    if args.next().is_some() {
        panic!("FATAL: usage: zns-keygen access-code");
    }
    println!("{}", hex::encode(access_public_key()));
}

fn access_public_key() -> [u8; 32] {
    let seed = open_seed();
    let secret = private_key_from_seed(seed.expose_secret());
    public_key(secret.expose_secret())
}

/// Read the ceremony capsule and unseal the seed. The file is not modified.
fn open_seed() -> Secret<[u8; SEED_LEN]> {
    let capsule_bytes = capsule::read_capsule_file(CAPSULE_FILE)
        .unwrap_or_else(|error| panic!("FATAL: read capsule: {error}"));
    let capsule = capsule::parse_capsule(&capsule_bytes)
        .unwrap_or_else(|error| panic!("FATAL: parse capsule: {error}"));
    let sealing_key = zns_canon::sealing::derive_sealing_key()
        .unwrap_or_else(|error| panic!("FATAL: derive sealing key: {error}"));
    capsule::unseal_seed(&sealing_key, &capsule)
        .unwrap_or_else(|error| panic!("FATAL: unseal capsule: {error}"))
}

fn private_key_from_seed(seed: &[u8; SEED_LEN]) -> Secret<[u8; 32]> {
    Secret::new(*seed_scalar(seed))
}

fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*private_key)).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_key_is_determined_by_the_seed() {
        let seed = [0x11; SEED_LEN];
        let private = private_key_from_seed(&seed);
        assert_eq!(
            hex::encode(private.expose_secret()),
            "cf5784abd38e10d8de32aa90525d15f4f55384dfa5e107e3f1cc265fc372509e"
        );
        assert_eq!(
            hex::encode(public_key(private.expose_secret())),
            "2a6582c9964d8908f1557412e8b8edd27e94d25126f235c84fbf01b1a8879425"
        );
    }
}
