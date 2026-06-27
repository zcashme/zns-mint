# zns-core

Shared ZNS domain types. No cryptographic dependencies — nothing here pulls
in orchard, halo2, or any I/O layer, so a light consumer (resolver, indexer,
wallet) can parse memos and work with action types without compiling the
proving stack.

## What's in here

**`action`** — the three lifecycle events a ZNS name can undergo:

- `Claim` — first registration; no predecessor, `prev_rcm` is the zero sentinel.
- `Update` — rebinds a name to a new Unified Address.
- `Release` — terminates a name's chain; the UA field is empty by convention.

Each variant carries its canonical ASCII bytes (`"claim"`, `"update"`,
`"release"`) which feed directly into the `(ψ, rcm)` derivation. These bytes
are protocol constants — changing them requires a domain-tag bump.

**`memo`** — the ZNS memo parser and encoder.

The grammar is strict: exact field counts, DNS-label name validation, no
trailing junk absorbed. The format is:

```
ZNS:claim:alice:u1abc…              user CLAIM request
ZNS:update:alice:u1new…             user UPDATE request
ZNS:release:alice                   user RELEASE request
ZNS:challenge:alice:<nonce>         registry → owner OTP relay
ZNS:confirm:alice:<nonce>           owner → registry OTP confirm
ZNS:claim:alice:u1abc…:<hex64>      Name Note canonical form (registry-authored)
ZNS:release:alice::<hex64>          Name Note canonical form, RELEASE
```

The `<hex64>` fifth field is the `prev_rcm` witness — present only in
Name Notes the registry mints, never in user requests. The daemon uses it
to skip its own notes on rescan.

This implementation is kept **independent** of the verification kernel
(`zns-verify`). Producer and consumer maintain separate parsers against
the same spec so a bug in one is caught by the other.

**`error`** — `RegistryError`, the cross-cutting error type used across the
workspace.

## Memo grammar (formal)

```
memo     = "ZNS" ":" verb ":" name [ ":" ua [ ":" prev_rcm ] ]
verb     = "claim" | "update" | "release" | "challenge" | "confirm"
name     = dns-label          ; 1–63 bytes, [a-z0-9-], no leading/trailing hyphen
ua       = *( %x21-39 / %x3B-7E )  ; any printable ASCII except ":"
prev_rcm = 64HEXDIG           ; lowercase only
```

Field counts per verb:

| verb        | request form | Name Note form |
|-------------|-------------|----------------|
| `claim`     | 4 fields    | 5 fields       |
| `update`    | 4 fields    | 5 fields       |
| `release`   | 3 fields    | 5 fields (ua positional empty) |
| `challenge` | 4 fields    | —              |
| `confirm`   | 4 fields    | —              |

## Usage

```rust
use zns_core::{parse_memo, ParsedMemo, Action};

let raw = b"ZNS:claim:alice:u1abc\0\0\0"; // zero-padded per ZIP 302
match parse_memo(raw)? {
    ParsedMemo::Action { action: Action::Claim, name, ua, prev_rcm: None } => {
        // inbound user request
    }
    ParsedMemo::Action { prev_rcm: Some(_), .. } => {
        // registry's own Name Note — skip on rescan
    }
    _ => {}
}
```
