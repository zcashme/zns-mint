//! The mint's Prometheus surface: tip gauges, boot facts, and a scrape listener.
//!
//! Zebra's pattern, minus the knobs: the `metrics` facade resolves
//! every call site through the globally installed recorder, so there is
//! no registration plumbing anywhere else in the binary.
//!
//! The endpoint binds all interfaces: the guest has no SSH server, and
//! the only route in is the QEMU host forward of the host's loopback
//! port (zns-deployment `launch/qemu-snp.sh`). Standing rule for this
//! surface: labels carry public data only — account addresses, viewing
//! keys that are public by design, and hardware-attested launch facts.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Scrape endpoint, reachable from the host through the QEMU forward.
pub const METRICS_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9464);

/// Installs the global recorder and HTTP listener. Must be called inside
/// the tokio runtime; `install` spawns the listener and upkeep tasks.
/// Panics on bind failure: an unmonitored mint should not boot.
pub fn install() {
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(METRICS_ADDR)
        .install()
        .expect("FATAL: metrics endpoint bind failed");
    tracing::info!(addr = %METRICS_ADDR, "metrics endpoint listening");
}

/// Snapshots the three gauges. Called once per applied tip.
pub fn snapshot(
    tip: zcash_protocol::consensus::BlockHeight,
    treasury_zats: u64,
    oracle_zats_per_usd: u64,
) {
    metrics::gauge!("zns_mint_chain_tip_height").set(u32::from(tip) as f64);
    metrics::gauge!("zns_mint_treasury_zec").set(treasury_zats as f64 / 1e8);
    metrics::gauge!("zns_mint_oracle_zats_per_usd").set(oracle_zats_per_usd as f64);
}

/// The account identity the attestation binds. Set once at boot.
///
/// The Registry viewing key is public by design: the registry account is
/// name-notes-only and never spends, so the key discloses nothing beyond
/// the public registry log — resolvers run on it.
pub fn identity(treasury_address: &str, registry_ufvk: &str) {
    metrics::gauge!(
        "zns_mint_identity_info",
        "treasury_address" => treasury_address.to_owned(),
        "registry_ufvk" => registry_ufvk.to_owned(),
    )
    .set(1);
}

/// The verified fingerprint and hash of the capsule loaded at this boot.
/// Set once at boot; these supply the upgrade manifest's seed fingerprint
/// and source capsule hash. Re-sealing preserves the fingerprint but changes
/// the capsule hash.
pub fn ceremony(seed_fingerprint: &str, capsule_hash: &str) {
    metrics::gauge!(
        "zns_mint_ceremony_info",
        "seed_fingerprint" => seed_fingerprint.to_owned(),
        "capsule_hash" => capsule_hash.to_owned(),
    )
    .set(1);
}

/// Hardware-attested launch facts, quoted from the mint's own PSP report.
/// Set once at boot; TEE builds only — non-TEE builds have no report, and
/// the gauge's absence is the dev-mode signal. A verifier compares the
/// measurement against the release manifest's `tee_measurement`.
pub fn guest(measurement: &str, guest_policy: &str, tcb_version: &str) {
    metrics::gauge!(
        "zns_mint_guest_info",
        "measurement" => measurement.to_owned(),
        "guest_policy" => guest_policy.to_owned(),
        "tcb_version" => tcb_version.to_owned(),
    )
    .set(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_info_exports_only_the_public_label_contract() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            identity("u1treasury", "uview1registry");
            ceremony("fingerprint", "capsulehash");
        });
        assert!(!handle.render().contains("zns_mint_guest_info"));
        metrics::with_local_recorder(&recorder, || {
            guest(
                "measurement",
                "0x30000",
                "bootloader=1 tee=2 snp=3 microcode=4",
            );
        });

        let output = handle.render();
        let samples: Vec<_> = output
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        assert_eq!(samples.len(), 3);
        for (name, mut expected_labels) in [
            (
                "zns_mint_identity_info",
                vec![
                    "treasury_address=\"u1treasury\"",
                    "registry_ufvk=\"uview1registry\"",
                ],
            ),
            (
                "zns_mint_ceremony_info",
                vec![
                    "seed_fingerprint=\"fingerprint\"",
                    "capsule_hash=\"capsulehash\"",
                ],
            ),
            (
                "zns_mint_guest_info",
                vec![
                    "measurement=\"measurement\"",
                    "guest_policy=\"0x30000\"",
                    "tcb_version=\"bootloader=1 tee=2 snp=3 microcode=4\"",
                ],
            ),
        ] {
            let sample = samples.iter().find(|line| line.starts_with(name)).unwrap();
            let labels = sample
                .strip_prefix(name)
                .unwrap()
                .strip_prefix('{')
                .unwrap()
                .strip_suffix("} 1")
                .unwrap();
            let mut actual_labels: Vec<_> = labels.split(',').collect();
            actual_labels.sort_unstable();
            expected_labels.sort_unstable();
            assert_eq!(actual_labels, expected_labels);
        }
    }
}
