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
//! names every name with a request in flight — public once its Name
//! Note lands; the endpoint stays host-gated.
//!
//! The requests in flight never enter the recorder. The recorder keeps
//! every series it has seen, and a series per name would grow with
//! every name ever requested; instead the loop hands over the whole set
//! once per pass and the listener prints it beside the recorder's text.
//! A name with nothing pending is absent; `1` while the mint holds the
//! next move, `2` while a relayed challenge awaits the owner's echo.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::sync::watch;

use crate::mint::Name;

/// Scrape endpoint, reachable from the host through the QEMU forward.
pub const METRICS_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9464);

/// Histogram drain interval; the exporter's own default.
const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);

/// The requests in flight at the last pass, as exposition lines.
static IN_FLIGHT: LazyLock<watch::Sender<String>> =
    LazyLock::new(|| watch::channel(String::new()).0);

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

/// Replaces the names in flight. Called once per pass: `working` names
/// every request the mint holds the next move on, `awaiting_echo` every
/// relayed challenge.
pub fn requests_in_flight<'a>(
    working: impl IntoIterator<Item = &'a Name>,
    awaiting_echo: impl IntoIterator<Item = &'a Name>,
) {
    // One `zns_mint_request_state` sample per name, sorted, each once: a
    // name in several queues is still one request in flight, and a scrape
    // with a repeated series is rejected whole. The mint's move wins: a
    // working name overwrites its `2`. Names are `[a-z0-9]` and need no
    // escaping.
    let mut states: BTreeMap<&str, u8> = awaiting_echo
        .into_iter()
        .map(|name| (name.as_str(), 2))
        .collect();
    states.extend(working.into_iter().map(|name| (name.as_str(), 1)));
    let mut exposition = String::new();
    if !states.is_empty() {
        exposition.push_str("# TYPE zns_mint_request_state gauge\n");
        for (name, state) in states {
            exposition.push_str(&format!(
                "zns_mint_request_state{{name=\"{name}\"}} {state}\n"
            ));
        }
    }
    IN_FLIGHT.send_replace(exposition);
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
    page.push_str(&IN_FLIGHT.borrow());
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

    /// The listener answers zns-supervise's probe — those exact bytes —
    /// with 200 and the page: the recorder's text, then the names in
    /// flight — one sample per name, sorted, a name in several queues
    /// printed once, nothing at all when none is in flight. `/health`
    /// stays `OK`. The only test that publishes: the names are global.
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
        let alice = Name::parse("alice").unwrap();
        let bob = Name::parse("bob").unwrap();
        let carol = Name::parse("carol").unwrap();
        requests_in_flight([&bob, &alice, &bob], [&carol, &alice]);

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
            body.ends_with(
                "\n# TYPE zns_mint_request_state gauge\n\
                 zns_mint_request_state{name=\"alice\"} 1\n\
                 zns_mint_request_state{name=\"bob\"} 1\n\
                 zns_mint_request_state{name=\"carol\"} 2\n"
            ),
            "{body}"
        );

        requests_in_flight(std::iter::empty::<&Name>(), std::iter::empty::<&Name>());
        let reply = get(addr, "/metrics").await;
        assert!(!reply.contains("zns_mint_request_state"), "{reply}");

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
