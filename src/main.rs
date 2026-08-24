//! Binary entry point.
//!
//! The production run loop (boot, scan, settle, reconcile) is not yet
//! implemented — see `.github/BOOTSTRAP-PLAN.md`. Until it lands, the binary
//! exists only so the release target builds; it exits immediately.

fn main() {
    eprintln!("zns-mint: run loop not yet implemented (see BOOTSTRAP-PLAN.md)");
    std::process::exit(1);
}
