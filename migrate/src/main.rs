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

#[cfg(feature = "fake-tee")]
mod report;

#[cfg(all(test, feature = "fake-tee"))]
mod flow;

use cli::{Command, USAGE};
use error::MigrateError;
use zns_canon::sealing::Tee;

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
    let tee = open_tee();
    match args.role {
        cli::Role::Source => source::run(&tee, &args, &loaded, &channel),
        cli::Role::Target => target::run(&tee, &args, &loaded, &channel),
    }
}

fn open_tee() -> impl Tee {
    #[cfg(feature = "fake-tee")]
    {
        zns_canon::sealing::FakeTee
    }
    #[cfg(not(feature = "fake-tee"))]
    {
        zns_canon::sealing::RealSnpTee
    }
}
