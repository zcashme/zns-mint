//! The three user verbs against the live mint: claim, update, release.
//!
//! Update and release are gated by an on-chain OTP challenge the mint
//! relays to the controller on record; the wallet reads its own challenge
//! note and echoes the code. `D_OTP` is 1800 s of chain time, so echoes
//! are paid promptly after the challenge is read.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::stack::Stack;
use crate::verify::{
    block_contains_txid, challenge_txid, registration_txid, registry_commitment_keys,
    wait_for_verified_name_note, VerifiedNameNote,
};

const SETTLE_TIMEOUT: Duration = Duration::from_secs(600);
const OTP_READ_TIMEOUT: Duration = Duration::from_secs(180);

/// Pay `ZNS:claim:forever:alice:<ua>`, wait for mint, verify on chain.
///
/// Checks: mint logs the note in flight (not rejected / non-request /
/// unauthorized); `zns-verify` decrypt + `cmx`; fields alice / claim /
/// user UA / `none` / 0 / non-tee Registry keys; the mint's `txid=` line
/// matches the on-chain registration.
pub async fn claim(stack: &mut Stack) -> Result<VerifiedNameNote> {
    let mark = stack.mint.log_text().len();
    let memo = format!("ZNS:claim:forever:alice:{}", stack.user.ua);
    let pay_txid = stack.user.pay_treasury(&memo).await?;
    eprintln!("claim payment txid {pay_txid}");
    // Confirm the payment, then leave the tip still so mint's
    // `exact_tip == cursor` gate can run intake (a racing tip skips it).
    stack.zebra.generate_blocks(1).await?;

    let deadline = Instant::now() + SETTLE_TIMEOUT;
    let started = Instant::now();
    let mut poked = false;
    loop {
        let note = poll_submitted_note(stack, mark, "alice", "claim", &pay_txid).await?;
        if let Some(txid) = note {
            assert_eq!(txid.action, "claim");
            assert_eq!(txid.ua, stack.user.ua);
            assert_eq!(txid.expires_at.as_deref(), Some("none"));
            assert_eq!(txid.prev, "0".repeat(64));
            assert_eq!(txid.value, 0);
            let (g_d, pk_d) = registry_commitment_keys()?;
            assert_eq!(txid.g_d, g_d);
            assert_eq!(txid.pk_d, pk_d);
            return Ok(txid);
        }
        if Instant::now() >= deadline {
            bail!(
                "mint did not register alice within 600s:\n{}",
                stack.mint.exit_detail()
            );
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
        if !poked && started.elapsed() > Duration::from_secs(90) {
            stack.zebra.generate_blocks(1).await?;
            poked = true;
        }
    }
}

/// Pay the update request, answer the controller challenge, verify the
/// successor note. The term slot is `none` — carried forward — because a
/// forever record rejects a term-carrying update.
pub async fn update(stack: &mut Stack, prev: &VerifiedNameNote) -> Result<VerifiedNameNote> {
    transition(stack, "update", Some("none"), prev).await
}

/// Pay the release request, answer the controller challenge, verify the
/// release note that terminates the chain.
pub async fn release(stack: &mut Stack, prev: &VerifiedNameNote) -> Result<VerifiedNameNote> {
    transition(stack, "release", None, prev).await
}

/// One non-claim transition: request memo, OTP challenge, echo, successor.
async fn transition(
    stack: &mut Stack,
    action: &str,
    expires: Option<&str>,
    prev: &VerifiedNameNote,
) -> Result<VerifiedNameNote> {
    let ua = stack.user.ua.clone();
    let request = match action {
        "update" => format!("ZNS:update:none:alice:{ua}"),
        "release" => format!("ZNS:release:alice:{ua}"),
        other => bail!("unknown action {other}"),
    };

    let mark = stack.mint.log_text().len();
    let pay_txid = stack.user.pay_treasury(&request).await?;
    eprintln!("{action} payment txid {pay_txid}");
    stack.zebra.generate_blocks(1).await?;

    let challenge_txid = wait_for_challenge(stack, mark, action, &pay_txid).await?;
    eprintln!("{action} challenge txid {challenge_txid}");

    let code = read_otp(stack, &challenge_txid, &ua).await?;
    eprintln!("{action} otp read");

    let echo = format!("ZNS:otp:{code}:alice:{action}:{ua}");
    let echo_mark = stack.mint.log_text().len();
    let echo_txid = stack.user.pay_treasury(&echo).await?;
    eprintln!("{action} echo txid {echo_txid}");
    stack.zebra.generate_blocks(1).await?;

    let deadline = Instant::now() + SETTLE_TIMEOUT;
    let started = Instant::now();
    let mut poked = false;
    loop {
        let note = poll_submitted_note(stack, echo_mark, "alice", action, &echo_txid).await?;
        if let Some(txid) = note {
            assert_eq!(txid.action, action);
            assert_eq!(txid.ua, stack.user.ua);
            assert_eq!(txid.expires_at.as_deref(), expires);
            assert_eq!(txid.prev, prev.own_rcm);
            assert_eq!(txid.value, 0);
            let (g_d, pk_d) = registry_commitment_keys()?;
            assert_eq!(txid.g_d, g_d);
            assert_eq!(txid.pk_d, pk_d);
            return Ok(txid);
        }
        if Instant::now() >= deadline {
            bail!(
                "mint did not settle {action} within 600s:\n{}",
                stack.mint.exit_detail()
            );
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
        if !poked && started.elapsed() > Duration::from_secs(90) {
            stack.zebra.generate_blocks(1).await?;
            poked = true;
        }
    }
}

/// Poll the mint log after `mark` for the submitted Name Note. Returns the
/// verified note once mint submits it and the chain carries it.
async fn poll_submitted_note(
    stack: &mut Stack,
    mark: usize,
    name: &str,
    action: &str,
    pay_txid: &str,
) -> Result<Option<VerifiedNameNote>> {
    if !stack.mint.is_running() {
        bail!(
            "mint died while settling {action}:\n{}",
            stack.mint.exit_detail()
        );
    }
    let log = stack.mint.log_text();
    let tail = &log[mark.min(log.len())..];
    if tail.contains(name)
        && (tail.contains("NameNote submission rejected") || tail.contains("registration rejected"))
    {
        bail!(
            "mint rejected the {action} note:\n{}",
            stack.mint.exit_detail()
        );
    }
    if tail.contains("non-request payment") && tail.contains(pay_txid) {
        bail!(
            "mint saw the {action} payment as a non-request:\n{}",
            stack.mint.exit_detail()
        );
    }
    if action == "claim" && tail.contains("claim not authorized") && tail.contains(name) {
        bail!(
            "mint did not authorize alice:\n{}",
            stack.mint.exit_detail()
        );
    }
    let Some(expected) = registration_txid(tail, name) else {
        return Ok(None);
    };
    let scan_from = stack.zebra.tip_height().await?;
    let note = wait_for_verified_name_note(&stack.zebra, &mut stack.mint, name, scan_from).await?;
    eprintln!(
        "verified Name Note height={} txid={}",
        note.height, note.txid
    );
    if note.txid != expected {
        bail!(
            "on-chain Name Note txid {} != mint in-flight txid {expected}",
            note.txid
        );
    }
    Ok(Some(note))
}

/// Wait for the mint's controller-challenge line after `mark`.
async fn wait_for_challenge(
    stack: &mut Stack,
    mark: usize,
    action: &str,
    pay_txid: &str,
) -> Result<String> {
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        if !stack.mint.is_running() {
            bail!(
                "mint died before challenging {action}:\n{}",
                stack.mint.exit_detail()
            );
        }
        let log = stack.mint.log_text();
        let tail = &log[mark.min(log.len())..];
        if tail.contains("non-request payment") && tail.contains(pay_txid) {
            bail!(
                "mint saw the {action} request as a non-request:\n{}",
                stack.mint.exit_detail()
            );
        }
        if let Some(txid) = challenge_txid(tail, "alice", action) {
            return Ok(txid);
        }
        if Instant::now() >= deadline {
            bail!(
                "mint did not relay a {action} challenge within 600s:\n{}",
                stack.mint.exit_detail()
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Read the OTP code from the challenge note the wallet received.
///
/// The challenge is relayed to the controller's UA — this wallet's — so
/// `z_viewtransaction` shows the memo once the challenge is confirmed and
/// the wallet has scanned its block.
async fn read_otp(stack: &mut Stack, challenge_txid: &str, ua: &str) -> Result<String> {
    let deadline = Instant::now() + OTP_READ_TIMEOUT;
    let mut from_height = stack.zebra.tip_height().await?;
    let confirmed_height = loop {
        if !stack.mint.is_running() {
            bail!(
                "mint died while waiting for the OTP challenge:\n{}",
                stack.mint.exit_detail()
            );
        }
        stack.zebra.generate_blocks(1).await?;
        let tip = stack.zebra.tip_height().await?;
        let mut found = None;
        for height in from_height..=tip {
            if block_contains_txid(&stack.zebra, height, challenge_txid).await? {
                found = Some(height);
                break;
            }
        }
        if let Some(height) = found {
            break height;
        }
        if Instant::now() >= deadline {
            bail!("OTP challenge {challenge_txid} was not mined within {OTP_READ_TIMEOUT:?}");
        }
        from_height = tip.saturating_add(1);
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    stack
        .user
        .zallet
        .wait_until_synced(
            confirmed_height,
            deadline.saturating_duration_since(Instant::now()),
        )
        .await?;
    let view = stack
        .user
        .zallet
        .call("z_viewtransaction", json!([challenge_txid]))
        .await
        .context("z_viewtransaction challenge after wallet scan")?;
    let outputs = view
        .get("outputs")
        .and_then(|o| o.as_array())
        .cloned()
        .unwrap_or_default();
    for output in &outputs {
        let address = output.get("address").and_then(|a| a.as_str());
        if address != Some(ua) {
            continue;
        }
        let text = output
            .get("memoStr")
            .and_then(|m| m.as_str())
            .map(str::to_string)
            .or_else(|| {
                output
                    .get("memo")
                    .and_then(|m| m.as_str())
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|b| String::from_utf8(b).ok())
            });
        let Some(text) = text else { continue };
        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() == 6
            && parts[0] == "ZNS"
            && parts[1] == "otp"
            && parts[2].len() == 6
            && parts[2].bytes().all(|b| b.is_ascii_digit())
        {
            return Ok(parts[2].to_string());
        }
    }
    bail!("wallet scanned OTP challenge {challenge_txid} but found no memo for {ua}")
}
