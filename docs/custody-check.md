# Custody Check — Transparent 3-of-5 P2SH Multisig PoC

**Status:** Proof of concept complete on regtest. Signing path verified to produce a
correctly-encoded P2SH-spend transaction. Not yet wired into `zns-registry`.

**Date:** 2026-06-12

---

## 1. Why this exists

### The audit finding

`zns-mint` (the ZNS registry signer) holds a **single Orchard spending key** in
memory (`signer/src/sign.rs`, `Signer::seed: Zeroizing<[u8; 32]>`). Every Name
Note mint, every OTP relay, and every treasury sweep is signed by this one key,
derived once via `SpendingKey::from_zip32_seed(seed, coin_type, account)`.

This is a **single point of failure**: whoever holds (or can exfiltrate) that
32-byte seed controls the entire ZNS treasury and can mint arbitrary names.
There is no DAO, no multisig, no recovery quorum — a single human (or a single
compromised enclave) is the trust root for the whole name service.

We looked at how adjacent systems handle this:
- **ENS**: treasury controlled by a Gnosis Safe multisig / DAO timelock.
- **DNS root zone**: physical multi-party ceremony (7 of N key-holders) for DNSSEC
  root key signing.
- **ZecHub / Zcash community funds**: typically Gnosis-style or transparent
  multisig cold wallets.

### The proposed mitigation: hot/cold split

Rather than try to make the *hot* Orchard spending key itself a multisig (which
would require Orchard threshold signatures — FROST over Pallas, a much bigger
lift, noted as a "future direction" in
`memory/zns-mint-daemon-architecture.md`), the pragmatic first step is:

- The hot signer (`Signer`) keeps only a **small operating float** — enough to
  pay mint fees and OTP relay dust.
- `Signer::sign_sweep` (already exists in `signer/src/sign.rs`) periodically
  **auto-sweeps** treasury value out of the hot Orchard pool to
  `SpendPolicy.cold_addr` — a destination the policy hard-codes, so even a fully
  compromised host can only move funds *to cold*, never elsewhere.
- Today `SpendPolicy.cold_addr: orchard::Address` — i.e. cold storage is just
  *another* single-key shielded address. The idea: make `cold_addr` a
  **transparent 3-of-5 P2SH multisig address** (`t2...`), so draining the cold
  vault requires collusion of 3 of 5 independently-held keys (e.g. founders,
  community reps, a hardware-security custodian).

### The question this PoC answers

> Does Zcash transparent P2SH multisig actually work end-to-end with our current
> dependency versions (`zcash_transparent` 0.8.0, `zcash_script` 0.4.5,
> `zcash_primitives` 0.28.0), well enough to trust it as the cold-storage
> mechanism?

Answer: **yes, but with one library bug that must be worked around** (see §4).

---

## 2. What "3-of-5 transparent P2SH" means concretely

- **Redeem script**: `OP_3 <pk1> <pk2> <pk3> <pk4> <pk5> OP_5 OP_CHECKMULTISIG`
  — 5 compressed secp256k1 pubkeys (33 bytes each), needs 3 valid signatures to
  spend. Total redeem script = 173 bytes:
  `1 (OP_3) + 5×(1+33) (pubkey pushes) + 1 (OP_5) + 1 (OP_CHECKMULTISIG)`.
- **P2SH address**: `t2...` = Base58Check(`HASH160(redeem_script)`), where
  `HASH160 = RIPEMD160(SHA256(x))`. On regtest/testnet this uses
  `ZcashAddress::from_transparent_p2sh(NetworkType::Test, h160)`.
- **Spending**: scriptSig = `OP_0 <sig_a> <sig_b> <sig_c> <redeem_script>` where
  `sig_a/b/c` are DER-encoded ECDSA signatures (+ `SIGHASH_ALL` byte) from any 3
  of the 5 keys, in the order their pubkeys appear in the redeem script.

This is the same mechanism used by Bitcoin/Zcash multisig cold wallets for over
a decade — well-understood, no new cryptography, no FROST/threshold-signature
research needed. That's the appeal: it's a **available today** custody
improvement, distinct from (and complementary to) any future Orchard FROST work.

---

## 3. What we built

New crate: **`tools/`** (package `zns-tools`), added to the workspace
`members` list in `/Users/jules/ZcashNames/zns-mint/Cargo.toml`.

- `tools/Cargo.toml` — depends on `secp256k1`, `zcash_script`, `zcash_transparent`
  (with `transparent-inputs`), `zcash_primitives` (with `transparent-inputs`),
  `zcash_address`, `zcash_protocol`, plus `sha2`, `bs58`, `hex`, `blake2b_simd`,
  `anyhow`, `rand`.
- `tools/src/main.rs` — two subcommands:

### `zns-tools keygen`
- Generates 1 fresh secp256k1 **miner P2PKH key** (regtest's existing miner
  address `tmYA1NXrtWBDJYp7VHZEGq5G9nyS5iGx1ed` had no known private key, so
  zebrad couldn't actually spend its coinbase rewards).
- Generates 5 fresh secp256k1 **multisig participant keys**.
- Builds the 3-of-5 redeem script (`zcash_script::pattern::check_multisig(3, &pks, false)`)
  and derives the `t2...` P2SH cold-vault address.
- Prints all WIF private keys + pubkeys + addresses.
- **Automatically rewrites `miner_address` in**
  `/Users/jules/ZcashNames/zebra-regtest/zebrad.toml`.

### `zns-tools demo-sign <wif1> <wif2> <wif3> [txid vout value_zat dest_addr [expiry]]`
- Re-derives the 3-of-5 redeem script and P2SH address (using the 3 supplied
  keys as participants 1-2-3, plus 2 fixed dummy keys for 4-5 — sufficient to
  satisfy a 3-of-5 threshold).
- Builds a v5 transparent transaction spending a P2SH UTXO (synthetic/fake
  prevout if none given) to a destination address.
- Computes the **ZIP-244 transparent sighash manually** (see §5).
- Signs with 3 of 5 keys directly via `secp256k1`.
- Hand-assembles the scriptSig bytes (see §4 for why) and serializes a complete
  v5 transaction.
- Prints the txid and the full signed transaction hex.

### Regtest run results (2026-06-12)

```
═══ MINER KEY (replace zebrad.toml miner_address) ════════════════════════
  WIF:     cPdvQpBCLRax9wkCJ7wTQcYP6QpX7KWUGxLHADAf2YFuGxdeTpx9
  Address: tmJtjQSQ2b5o1LReAvhv4PPASeS2u9HTMou

═══ MULTISIG PARTICIPANT 1 ══════════════════════════════════════════════
  WIF:    cT2pPoM2zpKSMVGdEwTGWfaepezdxHWfNXTz18T8s4i7oNmWJ5k9
  PubKey: 03095ef78d2b27c920349503360010a86b6f2dec7c5c262f8e98af698305330a7b
═══ MULTISIG PARTICIPANT 2 ══════════════════════════════════════════════
  WIF:    cRWGDe59TtyFcYAXk4UmvMQ5B9z2DP9x63Q4unbGHbCWontxPwBu
  PubKey: 027a43b6a2c875c64d1f9e52a02aff51d29c21d98e54eff2d0302f27cfd92ffe20
═══ MULTISIG PARTICIPANT 3 ══════════════════════════════════════════════
  WIF:    cQEUyEDhgfDZQSLUtq78zFjs2RB6T7JHse12TvKftw4STPfqxfr5
  PubKey: 0229f0e28942181806ee751a258684840f753b9841d31e8dd8e8d3893348627961
═══ MULTISIG PARTICIPANT 4 ══════════════════════════════════════════════
  WIF:    cP35F9i8TcW37zHMbLrHZA78jQF3TdhxLjAd4iiDKjuuNqoQrbKk
  PubKey: 02fe212fbd39c56b9d021c5fd8acccae4526003d5374b4c08977a155df25519db0
═══ MULTISIG PARTICIPANT 5 ══════════════════════════════════════════════
  WIF:    cQeRzxzPvayKAKsbZEuLwxzt7BERERSzvagJHKaE33Un42wd4hTS
  PubKey: 02444bc0a985f55e26fcef092f2a509f49e6089a4126ee4434d3843ad759d32e4c

═══ 3-OF-5 P2SH COLD VAULT ══════════════════════════════════════════════
  Address:       t2CweyvNhWCeNsvUQkHotMbHcRiPsu7deqQ
  RedeemScript:  532103095ef78d2b27c920349503360010a86b6f2dec7c5c262f8e98af698305330a7b21027a43b6a2c875c64d1f9e52a02aff51d29c21d98e54eff2d0302f27cfd92ffe20210229f0e28942181806ee751a258684840f753b9841d31e8dd8e8d38933486279612102fe212fbd39c56b9d021c5fd8acccae4526003d5374b4c08977a155df25519db02102444bc0a985f55e26fcef092f2a509f49e6089a4126ee4434d3843ad759d32e4c55ae
```

`zns-tools demo-sign` with participants 1, 2, 3 against a synthetic P2SH input
produced a 496-byte v5 transaction whose scriptSig, when parsed, is exactly:

```
OP_0
PUSH 72 bytes  <DER sig 1><SIGHASH_ALL>
PUSH 71 bytes  <DER sig 2><SIGHASH_ALL>
PUSH 72 bytes  <DER sig 3><SIGHASH_ALL>
OP_PUSHDATA1 173 <redeem_script>   (starts 0x53=OP_3, ends 0xAE=OP_CHECKMULTISIG)
```

`HASH160(redeem_script)` matches the P2SH address being spent — i.e. this is a
**structurally valid P2SH multisig spend**.

> ⚠️ **These are regtest demo keys, printed in plaintext, already committed to
> conversation history.** Treat all WIFs above as burned. Never reuse them for
> anything beyond this regtest experiment.

---

## 4. Bug found: `zcash_script 0.4.5` PUSHDATA1 encoding is broken for 128-255 byte pushes

### Symptom

The "obvious" implementation — build the bundle with
`TransparentBuilder::add_p2sh_input`, then call
`bundle.apply_signatures(sighash_fn, &signing_set)` — **compiles and runs**, but
produces a scriptSig where the redeem-script push is corrupted:

```
... 4c ad 00 53 21 03 ...      <- what apply_signatures produces (BROKEN)
... 4c ad    53 21 03 ...      <- what it should be (correct PUSHDATA1)
```

### Root cause

`zcash_transparent::builder::apply_signatures` (for the `P2sh` spend-info case)
calls `zcash_script::pattern::push_script(redeem_script)`, which calls
`pv::push_value(&redeem_script.to_bytes())`. For a 173-byte redeem script, this
produces `PushValue::LargeValue(LargeValue::OP_PUSHDATA1(173_bytes))`.

When `OP_PUSHDATA1` is serialized
(`~/.cargo/registry/.../zcash_script-0.4.5/src/opcode/push_value.rs`,
`impl From<&LargeValue> for Vec<u8>`):

```rust
OP_PUSHDATA1(bv) => to_vec(Some(LargeValue::PUSHDATA1_BYTE), bv.as_slice()),
// to_vec(prefix, contents) = prefix ++ num::serialize(contents.len()) ++ contents
```

`num::serialize` is the **Bitcoin script-number** encoding (used for things like
`OP_3`/`OP_16` arguments), *not* a plain unsigned byte. For `n = 173 = 0xAD`:
since `0xAD & 0x80 != 0`, script-number encoding appends a sign-disambiguation
byte: `num::serialize(173) = [0xAD, 0x00]` (2 bytes).

But the **PUSHDATA1 spec** requires the length to be a single plain unsigned
byte (0-255). So the serialized push becomes:

```
0x4C 0xAD 0x00 <173 bytes of redeem script>     (176 bytes total — WRONG)
```

A standards-compliant script interpreter reads `0x4C` (OP_PUSHDATA1), then 1
length byte `0xAD = 173`, then the next 173 bytes — which are
`[0x00, <first 172 bytes of the redeem script>]`. The real last byte
(`0xAE` = `OP_CHECKMULTISIG`) is left dangling in the script stream. The pushed
item's `HASH160` will **never** match the P2SH scriptPubKey → **the transaction
would be rejected by any real Zcash node.**

This bug only triggers for redeem scripts of **128-255 bytes**. The library's
own test suite (`apply_signatures_p2sh` in `zcash_transparent-0.8.0/src/builder.rs`)
only exercises a **2-of-2** multisig (71-byte redeem script — uses the 1-75 byte
`PushdataBytelength` path, where `num::serialize` happens to be correct), so the
bug was never caught. **A 3-of-5 multisig (173 bytes) always lands in the broken
range.** So would a 2-of-3 with redeem script ≥128 bytes (not the case here:
2-of-3 = 105 bytes, also fine), but any **k-of-n with n ≥ 4** (≥ 139 bytes for
n=4) is affected.

### Workaround used in `zns-tools`

`zcash_transparent::bundle::Authorized::ScriptSig = Script` where
`Script = zcash_transparent::address::Script(pub zcash_script::script::Code)`
and `Code = Code(pub Vec<u8>)` — i.e. **the final on-the-wire scriptSig is just
raw bytes**. So:

1. Don't call `apply_signatures` at all.
2. Take the `Bundle<Unauthorized>` from `builder.build()` (gives us prevout,
   value, scriptPubKey, vout — everything `TxSigHasher` needs).
3. Compute the ZIP-244 sighash ourselves (`TxSigHasher`, §5).
4. Sign with `secp256k1::sign_ecdsa` directly for each of the 3 keys.
5. Hand-assemble the scriptSig bytes with **correct** PUSHDATA encoding:
   - signatures (71-73 bytes each) use plain single-byte pushes (`<len><bytes>`,
     since len ≤ 75 always fits the `PushdataBytelength` opcode range).
   - the redeem script push: if ≤75 bytes use `<len><bytes>`; if 76-255 use
     `0x4C <len-as-single-unsigned-byte> <bytes>` (NOT `num::serialize`); if
     256-65535 use `0x4D <len as u16 LE> <bytes>`.
6. Construct `Bundle<Authorized>` directly as a struct literal:
   ```rust
   Bundle {
       vin: vec![TxIn::<TrAuthorized>::from_parts(prevout, Script(Code(ssig)), u32::MAX)],
       vout,
       authorization: TrAuthorized,
   }
   ```
   (`TrAuthorized` = `zcash_transparent::bundle::Authorized`, aliased to avoid a
   name collision with `zcash_primitives::transaction::Authorized`.)

### Recommendation

File an upstream issue against `zcash_script` (librustzcash monorepo):
`LargeValue::from for OP_PUSHDATA1/2/4` should use a plain little-endian byte
count, not `num::serialize` (script-number encoding), for the length prefix.
Until fixed, **any P2SH redeem script ≥128 bytes built via
`zcash_transparent::builder::apply_signatures` will be silently malformed.**
This affects k-of-n multisig for n≥4, and any larger custom redeem scripts
(timelocks, HTLCs, etc.).

---

## 5. ZIP-244 transparent sighash — implemented manually

`zcash_primitives` only exposes v5 sighash computation through the full
`Builder`, which requires Sapling `SpendProver`/`OutputProver` even for purely
transparent transactions — overkill for this tool. So `TxSigHasher` in
`tools/src/main.rs` implements ZIP-244 §4.10 / S.2 directly with
`blake2b_simd`, using the exact personalization strings (16 bytes each):

| Constant | Value |
|---|---|
| Header digest | `ZTxIdHeadersHash` |
| Prevouts digest | `ZTxIdPrevoutHash` (note: **not** "Prevouts") |
| Amounts digest (sig) | `ZTxTrAmountsHash` |
| Scripts digest (sig) | `ZTxTrScriptsHash` |
| Sequence digest | `ZTxIdSequencHash` |
| Outputs digest | `ZTxIdOutputsHash` |
| Per-input digest | `Zcash___TxInHash` |
| Transparent sig digest | `ZTxIdTranspaHash` |
| Empty Sapling digest | `ZTxIdSaplingHash` |
| Empty Orchard digest | `ZTxIdOrchardHash` |
| Outer sighash | `ZcashTxHash_` ‖ `branch_id.to_le_bytes()` |

V5 transaction constants used:
- `V5_HEADER = 0x8000_0005`
- `V5_VERSION_GROUP_ID = 0x26A7_270A`
- `NU6_2_BRANCH_ID = 0x5437_F330` (this regtest activates NU6.2 at height 22;
  current regtest height ~39,633)

---

## 6. Current repo state / file map

- `Cargo.toml` (workspace root) — `members` now includes `"tools"`.
- `tools/Cargo.toml` — new crate `zns-tools`.
- `tools/src/main.rs` — new; `keygen` + `demo-sign` subcommands, `TxSigHasher`,
  WIF encode/decode, redeem-script builder, manual scriptSig assembly.
- `/Users/jules/ZcashNames/zebra-regtest/zebrad.toml` — `miner_address` rewritten
  to `tmJtjQSQ2b5o1LReAvhv4PPASeS2u9HTMou` (was `tmYA1NXrtWBDJYp7VHZEGq5G9nyS5iGx1ed`,
  whose key was never known — that address could never spend its own coinbase).

---

## 7. Open / next steps

1. **Restart zebrad** with the rewritten `zebrad.toml` so it starts mining to
   `tmJtjQSQ2b5o1LReAvhv4PPASeS2u9HTMou` (a key we actually hold).
2. **Mine ≥100 blocks** for coinbase maturity.
3. **Send ZEC** from the miner P2PKH address to the 3-of-5 P2SH vault
   `t2CweyvNhWCeNsvUQkHotMbHcRiPsu7deqQ` (via `zcash-cli` / lightwalletd).
4. **Re-run `zns-tools demo-sign`** with the *real* txid/vout/value from step 3,
   and broadcast the resulting hex — first genuine on-chain proof that the
   3-of-5 P2SH multisig spends correctly under real consensus rules (this is
   the real test of the §4 workaround — regtest validation will catch it if the
   manual scriptSig encoding is still wrong somehow).
5. **Wire into `zns-registry` policy**:
   - Change `SpendPolicy.cold_addr` from `orchard::Address` to
     `zcash_transparent::address::TransparentAddress` (P2SH variant).
   - Update `build_sweep` (`signer/src/mint.rs`) to deshield from the Orchard
     hot pool to the transparent P2SH cold address instead of another Orchard
     address.
   - `Signer::sign_sweep` (`signer/src/sign.rs`) otherwise unchanged — it
     already enforces fee caps + velocity via `SpendGuard`/`SpendPolicy` before
     calling `build_sweep`.
6. **Decide custody of the 5 cold keys** — who holds participants 1-5 in
   production (founders / community / hardware custodian / legal entity), and
   how the 3-of-5 quorum is operationally exercised (manual ceremony vs. some
   coordination tooling).
7. **(Longer-term, noted in memory)**: FROST-based Orchard threshold signing for
   the *hot* signer itself, so even the operating float isn't single-key. This
   PoC is explicitly the "available today" interim step, not a replacement for
   that.
8. **File the `zcash_script` PUSHDATA1 bug upstream** (librustzcash) — see §4.
