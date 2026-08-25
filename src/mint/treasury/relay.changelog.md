# Treasury OTP relay changelog

## 2026-08-15 — Single-bundle Ironwood relay and Ironwood intake

- The mixed-V6 structure (Orchard request spend + output-only Ironwood
  delivery) is replaced by one Ironwood bundle: the Treasury spends the
  request note and delivers the controller's fee unit with the OTP memo in
  the same bundle. The bundle now spends, so its anchor is the exact-height
  Ironwood checkpoint root (not the latest-root form used by output-only
  bundles).
- Request notes are Ironwood notes: NU6.3 disables Orchard cross-address
  transfers, so users cannot send the Treasury Orchard notes at all. The
  relay request value is recomputed for the new two-action single-bundle
  shape (still exactly two ZIP-317 fee units: one network fee, one controller
  compensation).
- Only the Treasury signs the relay; the bundle carries no Registry spend.

## 2026-08-15 — Delivery pool recorded as policy: Ironwood

- Supersedes the 2026-07-24 entry's "standard Orchard transaction"
  description, which predates the mixed-V6 restructure. The relay spends the
  request note in an Orchard V3 bundle (pool-forced) and delivers the OTP in
  an output-only Ironwood V3 bundle to the controller's Orchard receiver.
- OTP relay policy (transport, mempool-keyed issuance, 24-block validity,
  economics, verification, re-issue) is defined by this module.

## 2026-07-30 — Boot-proven address and fee network

- Relay fee calculation and Unified Address decoding receive the same
  boot-proven consensus parameters used by the loop and signer.

## 2026-07-28 — Owner-visible relay and fixed relay value

- Relay memos begin with the fixed-width OTP:
  `ZNS:otp:<otp>:<name>:<verb>:<requested_ua>`. The output is encrypted to the
  current controller while the plaintext shows the requested update target.
- A relay request note must equal exactly twice the final ZIP-317 fee. One fee
  pays the network; the other is delivered to the original owner. Treasury
  retains no relay value.

## 2026-07-24 — OTP relay transaction assembly

- Added `src/treasury/relay.rs` with `assemble_otp_relay` — builds a standard
  Orchard transaction from the Treasury to the current controller's Orchard
  address, carrying the OTP relay memo.
- The controller's UA is parsed via `zcash_address::ZcashAddress::convert_if_network`
  to extract the Orchard receiver. If the UA has no Orchard receiver, the
  relay fails (open design question: non-Orchard controller handling).
- The OTP output carries value 0 (just the memo).
- Treasury fee funding uses a greedy iterative selection that converges on
  the ZIP-317 fee.
- Open design questions from `docs/design/09-transaction-assembly.md`:
  - Non-Orchard controller handling (current: fail if no Orchard receiver).
  - Output value (current: 0 zatoshis).
  - OVK recovery policy (current: Treasury external OVK).
