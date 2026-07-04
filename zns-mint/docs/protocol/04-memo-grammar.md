# 04 - Memo Grammar

All ZNS memos are ZIP-302 512-byte memo fields. Text is ASCII/UTF-8 followed by
zero padding.

Parsing is strict. Unknown verbs, invalid names, bad field counts, bad hex, and
oversized encodings are rejected.

## Name Note Memo

Name Notes use:

```text
ZNS:<verb>:<name>:<ua>:<prev_rcm>
```

Where:

- `<verb>` is `claim`, `update`, or `release`;
- `<name>` is canonical lowercase;
- `<ua>` is non-empty for `claim` and `update`;
- `<ua>` is empty for `release`;
- `<prev_rcm>` is 32 bytes encoded as 64 lowercase hex characters.

Release preserves positional fields:

```text
ZNS:release:<name>::<prev_rcm>
```

The empty UA field is intentional. `prev_rcm` must never shift columns.

## User Request Memo

Request memos are sent to the Treasury (the user-facing account) and use:

```text
ZNS:claim:<name>:<ua>
ZNS:update:<name>:<ua>
ZNS:update:<name>:<ua>:<otp>
ZNS:release:<name>:<ua>
ZNS:release:<name>:<ua>:<otp>
```

Claim is single-pass and does not use OTP.

Update and release are two-pass. The no-OTP form requests authorization. The
OTP form proves possession of the in-band OTP issued for that exact transition.

For release requests, `<ua>` is the current live UA. This prevents a stale or
wrong release request from authorizing termination of a different binding.

## Treasury OTP Memo

The Treasury sends OTPs in shielded memos to the current binding UA:

```text
ZNS:otp:<name>:<verb>:<ua>:<otp>
```

`<verb>` is `update` or `release`. Claim has no OTP path. The Treasury, not the
Registry, is the OTP-relay origin. The Registry never sends OTP memos.

## OTP Encoding

An OTP is 16 random bytes encoded as 32 lowercase hex characters.

This length is deliberate. A Name Note `prev_rcm` is 64 lowercase hex
characters, so an OTP-bearing request cannot be confused with a valid Name Note.

## Name Rules

Names are DNS-label-like:

- 1 to 63 bytes;
- lowercase `a-z`, `0-9`, and `-`;
- no leading or trailing `-`;
- no implicit lowercasing inside the strict parser.

Any user-facing canonicalization must happen before strict protocol encoding.
