use std::process::Command;

#[test]
fn test_boot_rejects_banned_env_vars() {
    // Build the binary first to ensure it's up to date
    let status = Command::new("cargo")
        .arg("build")
        .status()
        .expect("failed to execute cargo build");
    assert!(status.success(), "cargo build failed");

    // The path to the compiled binary
    let bin_path = "target/debug/zns-mint";

    // Test with RUST_LOG
    let output_rust_log = Command::new(bin_path)
        .env("RUST_LOG", "trace")
        .output()
        .expect("failed to execute zns-mint");
    
    let stderr_rust_log = String::from_utf8_lossy(&output_rust_log.stderr);
    assert!(
        !output_rust_log.status.success(),
        "Mint should have crashed with RUST_LOG set"
    );
    assert!(
        stderr_rust_log.contains("FATAL: Banned environment variable"),
        "Mint did not crash with the expected RUST_LOG panic message: {}",
        stderr_rust_log
    );

    // Test with ZNS_ prefix
    let output_zns_env = Command::new(bin_path)
        .env("ZNS_SECRET", "123")
        .output()
        .expect("failed to execute zns-mint");
    
    let stderr_zns_env = String::from_utf8_lossy(&output_zns_env.stderr);
    assert!(
        !output_zns_env.status.success(),
        "Mint should have crashed with ZNS_ env var set"
    );
    assert!(
        stderr_zns_env.contains("FATAL: Banned environment variable"),
        "Mint did not crash with the expected ZNS_ panic message: {}",
        stderr_zns_env
    );
}
