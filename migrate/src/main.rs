//! One-shot migration between two measured guests.
//!
//! `source` runs in the guest that holds the capsule. `target` runs in the
//! guest that will hold the next one. Sealing, unsealing, the manifest hash,
//! and the migration `report_data` come from `zns-canon`. SNP report
//! verification on the source is `zns_canon::attestation::stored`.

mod attest;
mod cli;
mod error;
mod handoff;
mod manifest;
mod persist;
mod source;
mod target;
mod transport;

use cli::{Command, USAGE};
use error::MigrateError;
fn main() {
    let code = match run(std::env::args()) {
        Ok(()) => 0,
        Err(error) if error.is_usage() => {
            eprintln!("{error}\n\n{USAGE}");
            2
        }
        Err(error) => {
            eprintln!("FATAL: {error}");
            1
        }
    };
    std::process::exit(code);
}

fn run<I, S>(args: I) -> Result<(), MigrateError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    match cli::parse(args)? {
        Command::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Command::Run(args) => {
            let _ = tracing_subscriber::fmt().with_target(false).try_init();
            execute(args)
        }
    }
}

pub(crate) fn execute(args: cli::Args) -> Result<(), MigrateError> {
    let loaded = manifest::load(&args.manifest)?;
    let channel = transport::DirTransport::open(&args.transport_dir, args.timeout)?;
    for (path, kind) in [
        (args.manifest.as_path(), "manifest"),
        (args.upgrade_document.as_path(), "upgrade document"),
        (args.attestation_bundle.as_path(), "attestation bundle"),
    ] {
        transport::trusted_outside_transport(path, channel.dir(), kind)?;
    }
    manifest::authorize(&loaded, &args.upgrade_document, &args.attestation_bundle)?;
    // Migration attests every step, so it runs only on the enclave: derive
    // the hardware sealing key once and pass it through.
    let sealing_key =
        zns_canon::sealing::derive_sealing_key(zns_canon::capsule::CAPSULE_KEY_CONTEXT)
            .map_err(MigrateError::Tee)?;
    match args.role {
        cli::Role::Source => source::run(&sealing_key, &args, &loaded, &channel),
        cli::Role::Target => target::run(&sealing_key, &args, &loaded, &channel),
    }
}
