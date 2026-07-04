# 06 - Authorization

## Claim

Claim is single-pass:

```text
user -> Treasury: ZNS:claim:<name>:<ua>
```

The Treasury receives the request. The Registry accepts the claim (cross-account
handoff inside the mint) if the name is currently unclaimed or released. The
Registry then builds a claim Name Note with `prev_rcm = ZERO_PREV_RCM`.

Claim also requires payment for the name. The payment is sent to the Treasury
and is economic input to the mint transaction flow; the minted Name Note itself
remains value `0`.

The protocol-level claim rule is therefore:

- the request grammar is valid;
- the name is free or released;
- the required name payment is present and accepted at the Treasury;
- the Registry mints a zero-value Name Note for the claimed binding.

## Update

Update is two-pass:

```text
user -> Treasury: ZNS:update:<name>:<new_ua>
Treasury -> current UA: ZNS:otp:<name>:update:<new_ua>:<otp>
user -> Treasury: ZNS:update:<name>:<new_ua>:<otp>
```

The OTP is scoped to `(name, update, new_ua)` and consumed exactly once.

The OTP is delivered in-band from the Treasury to the current UA, so only a
wallet that can receive at the current binding can complete the update.

## Release

Release is two-pass:

```text
user -> Treasury: ZNS:release:<name>:<current_ua>
Treasury -> current UA: ZNS:otp:<name>:release:<current_ua>:<otp>
user -> Treasury: ZNS:release:<name>:<current_ua>:<otp>
```

The Treasury must verify that `<current_ua>` matches the live binding before
issuing or accepting a release OTP.

The committed release Name Note has an empty UA:

```text
ZNS:release:<name>::<prev_rcm>
```

## OTP Store

The OTP store is in-memory operational state. The production mint is expected to
run continuously with Prometheus metrics and logging around liveness, so pending
OTPs are not a restart-survival mechanism.

Successful verification consumes the OTP. Failed verification must not consume
it unless an explicit rate-limit or invalidation policy is added.

An OTP expires 30 minutes after issuance. Expired OTPs cannot authorize an
update or release; the user must request a fresh OTP.

## Logging

Names, UAs, and OTPs are shielded user data. Production logs should contain only
public transaction context, coarse outcomes, and redacted errors.
