//! zns-rebind: moves every live Name Note to a bound claim, once, inside the
//! migrated guest before the new mint first boots.

mod boot;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    // ring and aws-lc-rs are both linked. Rustls will not choose a process
    // default, and the first HTTPS client panics without one.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let network = boot::boot_network();
    let (_manifest, custody, anchor) = boot::load_manifest();
    let (_treasury_keys, _registry_keys) = boot::unseal(&network, &custody);
    tracing::info!(
        network = boot::NETWORK_LABEL,
        birthday = anchor.birthday,
        "rebind: seed unsealed"
    );
}
