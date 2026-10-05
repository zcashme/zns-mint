use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use rand::rngs::OsRng;
use secrecy::{ExposeSecret, Secret};
use zns_canon::capsule::{self, SEED_LEN};
use zns_canon::sealing::FakeTee;
use zns_canon::upgrade::UpgradeManifest;

use crate::cli::{Args, Role};
use crate::execute;
use crate::handoff;
use crate::transport::{ENCRYPTED_SEED_FILE, OFFER_FILE, RECEIPT_FILE};

struct Fixture {
    root: PathBuf,
    manifest: UpgradeManifest,
    seed: Secret<[u8; SEED_LEN]>,
}

impl Fixture {
    fn new(name: &str, measurement: [u8; 48], release: &str) -> Self {
        Self::with_measurements(name, measurement, measurement, release)
    }

    fn with_measurements(
        name: &str,
        from_measurement: [u8; 48],
        to_measurement: [u8; 48],
        release: &str,
    ) -> Self {
        let root =
            std::env::temp_dir().join(format!("zns-migrate-flow-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("channel")).unwrap();
        fs::create_dir_all(root.join("state")).unwrap();
        let manifest = UpgradeManifest {
            version: 1,
            sequence: 4,
            from_measurement,
            to_measurement,
            artifact_hash: [0x33; 32],
            release: release.to_string(),
        };
        fs::write(root.join("upgrade.toml"), manifest_toml(&manifest)).unwrap();
        Self {
            root,
            manifest,
            seed: Secret::new([0x5a; SEED_LEN]),
        }
    }

    fn seal_input(&self) {
        let capsule = capsule::seal_seed(&FakeTee, &self.seed, &mut OsRng).unwrap();
        let bytes = capsule::serialize_capsule(&capsule).unwrap();
        fs::write(self.input(), bytes).unwrap();
    }

    fn manifest_path(&self) -> PathBuf {
        self.root.join("upgrade.toml")
    }

    fn channel(&self) -> PathBuf {
        self.root.join("channel")
    }

    fn input(&self) -> PathBuf {
        self.root.join("state").join("in.capsule")
    }

    fn output(&self) -> PathBuf {
        self.root.join("state").join("out.capsule")
    }

    fn args(&self, role: Role, replace: bool, timeout: Duration) -> Args {
        Args {
            role,
            manifest: self.manifest_path(),
            transport_dir: self.channel(),
            input_capsule: (role == Role::Source).then(|| self.input()),
            output_capsule: (role == Role::Target).then(|| self.output()),
            replace_after_verified_migration: replace,
            timeout,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn manifest_toml(manifest: &UpgradeManifest) -> String {
    format!(
        "\
version = {}
sequence = {}
from_measurement = \"{}\"
to_measurement = \"{}\"
artifact_hash = \"{}\"
release = \"{}\"
",
        manifest.version,
        manifest.sequence,
        hex::encode(manifest.from_measurement),
        hex::encode(manifest.to_measurement),
        hex::encode(manifest.artifact_hash),
        manifest.release,
    )
}

fn both(
    fixture: &Fixture,
    replace: bool,
    timeout: Duration,
) -> (
    Result<(), crate::error::MigrateError>,
    Result<(), crate::error::MigrateError>,
) {
    let source_args = fixture.args(Role::Source, false, timeout);
    let target_args = fixture.args(Role::Target, replace, timeout);
    thread::scope(|scope| {
        let target = scope.spawn(|| execute(target_args));
        let source = scope.spawn(|| execute(source_args));
        (source.join().unwrap(), target.join().unwrap())
    })
}

#[test]
fn source_and_target_move_the_seed_and_reopen_the_new_capsule() {
    let fixture = Fixture::new("ok", [0xFA; 48], "guest-2");
    fixture.seal_input();
    let input_before = fs::read(fixture.input()).unwrap();
    let (source, target) = both(&fixture, false, Duration::from_secs(5));
    source.unwrap();
    target.unwrap();

    assert_eq!(fs::read(fixture.input()).unwrap(), input_before);
    let persisted = capsule::read_capsule_file(fixture.output()).unwrap();
    let parsed = capsule::parse_capsule(&persisted).unwrap();
    let opened = capsule::unseal_seed(&FakeTee, &parsed).unwrap();
    assert_eq!(opened.expose_secret(), fixture.seed.expose_secret());

    let source_capsule = capsule::parse_capsule(&input_before).unwrap();
    let receipt =
        handoff::decode_receipt(&fs::read(fixture.channel().join(RECEIPT_FILE)).unwrap()).unwrap();
    handoff::verify_receipt(
        &receipt,
        &fixture.manifest,
        &input_before,
        &source_capsule.fingerprint,
    )
    .unwrap();
    assert_eq!(receipt.new_capsule_hash, handoff::hash_capsule(&persisted));
    assert_eq!(receipt.seed_fingerprint, source_capsule.fingerprint);
}

#[test]
fn a_wrong_measurement_never_unseals() {
    let fixture = Fixture::new("measure", [0x01; 48], "guest-2");
    fs::write(fixture.input(), b"not-a-capsule").unwrap();
    let (source, target) = both(&fixture, false, Duration::from_secs(1));
    let source = source.unwrap_err().to_string();
    assert!(
        source.contains("not authorized"),
        "expected measurement failure, got {source}"
    );
    assert!(target.unwrap_err().to_string().contains("timed out"));
    assert!(!fixture.channel().join(ENCRYPTED_SEED_FILE).exists());
    assert!(!fixture.output().exists());
    assert_eq!(fs::read(fixture.input()).unwrap(), b"not-a-capsule");
}

#[test]
fn a_different_manifest_is_rejected_before_the_capsule_is_read() {
    let source_side = Fixture::new("manifest-source", [0xFA; 48], "guest-a");
    let target_side = Fixture::new("manifest-target", [0xFA; 48], "guest-b");
    fs::write(source_side.input(), b"not-a-capsule").unwrap();
    let timeout = Duration::from_secs(1);
    let source_args = source_side.args(Role::Source, false, timeout);
    let target_args = Args {
        manifest: target_side.manifest_path(),
        transport_dir: source_side.channel(),
        output_capsule: Some(source_side.output()),
        ..target_side.args(Role::Target, false, timeout)
    };
    let (source, target) = thread::scope(|scope| {
        let target = scope.spawn(|| execute(target_args));
        let source = scope.spawn(|| execute(source_args));
        (source.join().unwrap(), target.join().unwrap())
    });
    let source = source.unwrap_err().to_string();
    assert!(
        source.contains("different manifest"),
        "expected manifest failure before capsule parse, got {source}"
    );
    assert!(
        !source.contains("capsule"),
        "capsule was touched before authorization: {source}"
    );
    assert!(target.unwrap_err().to_string().contains("timed out"));
    assert!(!source_side.channel().join(ENCRYPTED_SEED_FILE).exists());
}

#[test]
fn target_refuses_an_existing_capsule_without_the_replace_flag() {
    let fixture = Fixture::new("exists", [0xFA; 48], "guest-2");
    fs::write(fixture.output(), b"keep-me").unwrap();
    let err = execute(fixture.args(Role::Target, false, Duration::from_secs(1))).unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");
    assert!(!fixture.channel().join(OFFER_FILE).exists());
    assert_eq!(fs::read(fixture.output()).unwrap(), b"keep-me");
}

#[test]
fn replace_flag_overwrites_only_after_the_new_capsule_reopens() {
    let fixture = Fixture::new("replace", [0xFA; 48], "guest-2");
    fixture.seal_input();
    fs::write(fixture.output(), b"old-capsule").unwrap();
    let (source, target) = both(&fixture, true, Duration::from_secs(5));
    source.unwrap();
    target.unwrap();
    let persisted = capsule::read_capsule_file(fixture.output()).unwrap();
    let parsed = capsule::parse_capsule(&persisted).unwrap();
    let opened = capsule::unseal_seed(&FakeTee, &parsed).unwrap();
    assert_eq!(opened.expose_secret(), fixture.seed.expose_secret());
}

#[test]
fn capsule_inside_the_transport_directory_is_refused() {
    let fixture = Fixture::new("inside", [0xFA; 48], "guest-2");
    let output = fixture.channel().join("out.capsule");
    let args = Args {
        output_capsule: Some(output),
        ..fixture.args(Role::Target, false, Duration::from_secs(1))
    };
    let err = execute(args).unwrap_err();
    assert!(err.to_string().contains("inside the transport"), "{err}");
    assert!(!fixture.channel().join(OFFER_FILE).exists());
}

#[test]
fn source_does_not_publish_when_its_measurement_is_not_authorized() {
    let fixture = Fixture::with_measurements("from", [0x11; 48], [0xFA; 48], "guest-2");
    fixture.seal_input();
    let (source, target) = both(&fixture, false, Duration::from_secs(1));
    let source = source.unwrap_err().to_string();
    assert!(
        source.contains("source measurement is not authorized"),
        "{source}"
    );
    assert!(target.unwrap_err().to_string().contains("timed out"));
    assert!(!fixture.channel().join(ENCRYPTED_SEED_FILE).exists());
    assert!(!fixture.output().exists());
}

#[test]
fn a_writer_cannot_install_a_seed_the_source_did_not_attest() {
    let fixture = Fixture::new("inject", [0xFA; 48], "guest-2");
    fs::write(fixture.output(), b"keep-me").unwrap();
    let transport =
        crate::transport::DirTransport::open(&fixture.channel(), Duration::from_secs(2)).unwrap();
    transport.source_begin().unwrap();
    let args = fixture.args(Role::Target, true, Duration::from_secs(2));
    let output = fixture.output();
    let target = thread::spawn(move || execute(args));

    let offer = handoff::decode_offer(&transport.wait_offer().unwrap()).unwrap();
    let attacker = Secret::new([0xee; SEED_LEN]);
    let transfer = handoff::encrypt_seed_for_target(
        &attacker,
        offer.ephemeral_pubkey,
        offer.nonce,
        offer.manifest_hash,
        &mut OsRng,
    )
    .unwrap();
    transport
        .publish_encrypted_seed(&handoff::encode_transfer(&transfer))
        .unwrap();
    transport
        .publish_source_attestation(b"not-a-source-report")
        .unwrap();

    let err = target.join().unwrap().unwrap_err();
    assert!(
        err.to_string().contains("attestation") || err.to_string().contains("report"),
        "{err}"
    );
    assert_eq!(fs::read(output).unwrap(), b"keep-me");
}
