//! The mint's Prometheus surface: tip gauges, boot facts, the requests
//! in flight, and the scrape listener.
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
//! Amended by owner decision for `zns_mint_request_state` (#342): it
//! names the requests in flight — public once their Name Note lands;
//! the endpoint stays host-gated.
//!
//! The requests in flight never enter the recorder. The recorder keeps
//! every series it has seen, and a series per request would grow with
//! every request ever made; instead the loop hands over the whole set
//! once per pass and the listener prints it beside the recorder's text.
//! A finished request is absent: presence is processing.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::PrometheusHandle;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::Parameters;

use crate::mint::{Action, Name, UnifiedAddress};

/// Scrape endpoint, reachable from the host through the QEMU forward.
pub const METRICS_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9464);

/// Histogram drain interval; the exporter's own default.
const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);

/// The requests in flight at the last pass, as exposition lines.
static IN_FLIGHT: Mutex<String> = Mutex::new(String::new());

/// Installs the global recorder and the HTTP listener. Must be called
/// inside the tokio runtime; spawns the listener and upkeep tasks.
/// Panics on bind failure: an unmonitored mint should not boot.
pub fn install() {
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("FATAL: metrics recorder install failed");
    let listener = std::net::TcpListener::bind(METRICS_ADDR)
        .and_then(|listener| {
            listener.set_nonblocking(true)?;
            tokio::net::TcpListener::from_std(listener)
        })
        .expect("FATAL: metrics endpoint bind failed");
    tokio::spawn(serve(listener, handle.clone()));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(UPKEEP_INTERVAL).await;
            handle.run_upkeep();
        }
    });
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

/// Replaces the requests in flight. Called once per pass with every
/// request the queues still hold, each named by the payment that
/// carried it.
pub fn requests_in_flight<'a, P: Parameters>(
    network: &P,
    requests: impl IntoIterator<Item = (TxId, &'a Name, Action, &'a UnifiedAddress)>,
) {
    let lines = in_flight_lines(network, requests);
    *IN_FLIGHT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = lines;
}

/// One `zns_mint_request_state` sample per request, sorted, each once:
/// a scrape with a repeated series is rejected whole. Label values need
/// no escaping — names are `[a-z0-9]`, UAs bech32m, txids hex.
fn in_flight_lines<'a, P: Parameters>(
    network: &P,
    requests: impl IntoIterator<Item = (TxId, &'a Name, Action, &'a UnifiedAddress)>,
) -> String {
    let samples: BTreeSet<String> = requests
        .into_iter()
        .map(|(txid, name, action, ua)| {
            format!(
                "zns_mint_request_state{{name=\"{}\",action=\"{}\",ua=\"{}\",txid=\"{txid}\"}} 1\n",
                name.as_str(),
                action.as_str(),
                ua.encode_receiver_preserving(network),
            )
        })
        .collect();
    if samples.is_empty() {
        return String::new();
    }
    let mut lines = String::from("# TYPE zns_mint_request_state gauge\n");
    lines.extend(samples);
    lines
}

/// Answers every connection like the exporter's own listener did:
/// `/health` is `OK`, any other path is the page.
async fn serve(listener: tokio::net::TcpListener, handle: PrometheusHandle) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) => {
                tracing::warn!(%error, "metrics connection not accepted");
                continue;
            }
        };
        let handle = handle.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let body = if request.uri().path() == "/health" {
                    String::from("OK")
                } else {
                    page(&handle)
                };
                let mut response = Response::new(Full::new(Bytes::from(body)));
                response
                    .headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                async move { Ok::<_, Infallible>(response) }
            });
            if let Err(error) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(%error, "metrics connection closed with an error");
            }
        });
    }
}

/// The recorder's text, then the requests in flight.
fn page(handle: &PrometheusHandle) -> String {
    let mut page = handle.render();
    page.push_str(
        &IN_FLIGHT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
    page
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
pub fn guest(measurement: &str, guest_policy: &str) {
    metrics::gauge!(
        "zns_mint_guest_info",
        "measurement" => measurement.to_owned(),
        "guest_policy" => guest_policy.to_owned(),
    )
    .set(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::MAIN_NETWORK;

    const TEST_UA: &str = "u1d398kq0gfmegkvn0c57zmvq7gcnhxs6g3chfewlxq2yzhdjpx7uk3h80qgku5ygtyr9m7y6swgqe3pqdleu5uvwmangjj8yk7s5j0u78frtw9y9y5lx4c0x3cp054m9nl274xynwf5ad2uah7afyu4wgu3mwg5xvq4zmrdcplt8uqeqqw4vu4kdwngzvsn7gtdwtx3whkwt4z20pr0k";

    fn test_ua() -> UnifiedAddress {
        match zcash_keys::address::Address::decode(&MAIN_NETWORK, TEST_UA) {
            Some(zcash_keys::address::Address::Unified(ua)) => *ua,
            _ => panic!("vector is a mainnet Unified Address"),
        }
    }

    fn txid(n: u8) -> TxId {
        TxId::from_bytes([n; 32])
    }

    /// One sample per request, sorted, a repeat printed once; nothing at
    /// all when no request is in flight.
    #[test]
    fn requests_in_flight_print_once_each() {
        let ua = test_ua();
        let alice = Name::parse("alice").unwrap();
        let bob = Name::parse("bob").unwrap();
        let lines = in_flight_lines(
            &MAIN_NETWORK,
            [
                (txid(2), &bob, Action::Release, &ua),
                (txid(1), &alice, Action::Claim, &ua),
                (txid(2), &bob, Action::Release, &ua),
            ],
        );
        let ua = ua.encode_receiver_preserving(&MAIN_NETWORK);
        assert_eq!(
            lines,
            format!(
                "# TYPE zns_mint_request_state gauge\n\
                 zns_mint_request_state{{name=\"alice\",action=\"claim\",ua=\"{ua}\",txid=\"{}\"}} 1\n\
                 zns_mint_request_state{{name=\"bob\",action=\"release\",ua=\"{ua}\",txid=\"{}\"}} 1\n",
                txid(1),
                txid(2),
            )
        );
        assert_eq!(
            in_flight_lines(
                &MAIN_NETWORK,
                std::iter::empty::<(TxId, &Name, Action, &UnifiedAddress)>()
            ),
            ""
        );
    }

    /// The listener answers zns-supervise's probe — those exact bytes —
    /// with 200 and the page: the recorder's text, then the requests in
    /// flight. `/health` stays `OK`.
    #[tokio::test]
    async fn the_page_answers_the_supervisor_probe() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        async fn get(addr: SocketAddr, path: &str) -> String {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let probe =
                format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            stream.write_all(probe.as_bytes()).await.unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).await.unwrap();
            reply
        }

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            metrics::gauge!("zns_mint_chain_tip_height").set(7.0);
        });
        let ua = test_ua();
        let alice = Name::parse("alice").unwrap();
        requests_in_flight(&MAIN_NETWORK, [(txid(1), &alice, Action::Claim, &ua)]);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, handle));

        let reply = get(addr, "/metrics").await;
        assert!(
            reply.starts_with("HTTP/1.0 200") || reply.starts_with("HTTP/1.1 200"),
            "{reply}"
        );
        let (_, body) = reply.split_once("\r\n\r\n").unwrap();
        assert!(body.contains("zns_mint_chain_tip_height 7\n"), "{body}");
        assert!(
            body.ends_with(&format!(
                "\n# TYPE zns_mint_request_state gauge\n\
                 zns_mint_request_state{{name=\"alice\",action=\"claim\",ua=\"{}\",txid=\"{}\"}} 1\n",
                ua.encode_receiver_preserving(&MAIN_NETWORK),
                txid(1),
            )),
            "{body}"
        );

        let health = get(addr, "/health").await;
        assert!(health.starts_with("HTTP/1.1 200") || health.starts_with("HTTP/1.0 200"));
        assert!(health.ends_with("\r\n\r\nOK"), "{health}");
    }

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
            guest("measurement", "0x30000");
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
                vec!["measurement=\"measurement\"", "guest_policy=\"0x30000\""],
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
