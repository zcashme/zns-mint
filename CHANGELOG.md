# Changelog

## send_transaction builds its request with RawTransaction::new (#630)

2026-11-27

`send_transaction` builds its request with `zebra-indexer-proto`'s
`RawTransaction::new`, which holds Zebra's size limit. A transaction over
the limit is `Refused` without asking Zebra; it was already refused by
Zebra's `invalid_argument`. Six tests that restated one line of a private
helper each are deleted.

## A SendTransaction refusal is a SubmitOutcome, not a TransportError (#628)

2026-11-27

`SubmitOutcome` says what Zebra's answer means for the mint: `Accepted`
(Zebra's mempool holds the transaction) or `Refused`. `RpcError` and
`TransportError::Rpc` are gone, so a SendTransaction refusal is no longer
a `TransportError`. `send_transaction` logs Zebra's reason with the
txid where it reads it. Every answer leads to the same outcome as before,
and "transaction already exists in mempool" is still `Accepted`.

## Zebra is reached over gRPC only (#612)

2026-11-26

The mint makes no JSON-RPC calls. It talks to Zebra over two gRPC
services on the loopback interface:

- the Indexer, on port 8230 (testnet 18230), as before: blocks, the
  tip stream and the mempool stream;
- `CompactTxStreamer`, on port 9067 (testnet 19067), new: the latest
  block (`GetLatestBlock`), tree states (`GetTreeState`), transaction
  lookup (`GetTransaction`) and broadcast (`SendTransaction`).

Before, those four went over JSON-RPC on port 8232 (testnet 18232) as
`getblockchaininfo`, `z_gettreestate`, `getrawtransaction` and
`sendrawtransaction`.

**zebrad must serve `CompactTxStreamer`.** Set
`lightwalletd_listen_addr = "127.0.0.1:9067"` (testnet
`127.0.0.1:19067`) under `[rpc]` in `zebrad.toml`. Without it boot
stops with
`FATAL: Zebra CompactTxStreamer gRPC unreachable or timed out`.

**A dropped connection retries.** The mint retries every gRPC error
except the seven that are Zebra's own verdict on the request
(`InvalidArgument`, `NotFound`, `AlreadyExists`, `PermissionDenied`,
`FailedPrecondition`, `Unimplemented`, `Unauthenticated`). Before, it
retried three codes, and a connection reset reported under another
code, as happens when zebrad restarts, could stop the mint.

**Log lines.**

- `boot: zebra json-rpc liveness ok` is now
  `boot: zebra CompactTxStreamer liveness ok`.
- `FATAL: JSON-RPC getblockchaininfo failed, Zebra is unreachable` is
  gone; `FATAL: CompactTxStreamer GetLatestBlock failed` is new.
- `sendrawtransaction named a different transaction` is now
  `SendTransaction named a different transaction`.

## Block times are read over the Indexer (#610)

2026-11-25

The mint reads the 11 block times it needs at boot, and after a reorg,
from blocks fetched over Zebra's Indexer gRPC `GetBlock`. It no longer
calls `getblockheader`.

## A name is held for its term (#606)

2026-11-25

The mint releases a name when its paid term ends, and for no other
reason. Before, it also released a name one year after the name's
latest Name Note, so a name bought for several years, or forever,
had to be updated every year to be kept.

- A name bought for N years is held for N years with nothing to do.
- A forever name is never released by the mint. Only its controller
  can release it.
- `ZNS:update:none:<name>:<ua>` still changes the address a name
  points at. It no longer renews anything.
- An update, release, list, delist or buy is no longer refused because
  a year has passed since the name's last note. It is still refused
  once the term has ended.
- In `canon-vectors-v1.json`, every record loses
  `release_deadline_secs` and every event loses `mtp_secs`.
- `mint::LIVENESS_INTERVAL` is renamed `mint::JULIAN_YEAR`. Its value
  is unchanged; it is the length of one year of a term.

A resolver or client that applies the one-year rule itself must drop
it, and a wallet should stop asking holders to check in each year.

## An ordinary new block costs one block download (#600)

2026-11-24

To find where its chain and Zebra's meet, the mint fetches the block
above its own tip and checks that block's parent. When the parent is
the mint's tip, which is the ordinary case, that block is applied
directly. Before, every pass downloaded the mint's own tip block again
first.

- The log lines `ancestor hash unavailable; retrying` and
  `ancestor left the best chain mid-walk; re-converging`, and
  `FATAL: Zebra returned an invalid ancestor hash`, are gone.
- A chain that moves during the search logs
  `the chain moved under the fork-point walk; re-converging`.

## A broadcast Name Note is signed again only after it has expired (#574)

2026-11-20

The mint signs a broadcast Name Note again once the tip has reached
the transaction's expiry height, when the original can no longer be
mined. Before, it signed again one block earlier, while the original
could still confirm.

For a claim, both transactions could then be mined. The second was
refused, but it had spent a claim anchor that was not replaced, and a
second fee. The pool holds 40 claim anchors and cannot be refilled.

A rebuilt claim now uses the same anchor as the original.

## Boot fetches no subtree roots (#568, #570)

2026-11-20

The mint builds its wallet from the commitment-tree frontiers at its
starting block and no longer calls `z_getsubtreesbyindex`. It scans
every block in order from there, so the frontiers give it every
witness it needs.

- Boot no longer depends on Zebra's subtree index, and does not stop
  while Zebra rebuilds it.
- The `sapling_roots` and `ironwood_roots` fields are gone from the
  log line `boot: wallet born complete from the origin checkpoint`.

## zns_mint_serving is removed (#550)

2026-11-20

The gauge `zns_mint_serving` (#409) is no longer published. `/metrics`
answering at all means the wallet scan has finished.

Anything that waits for the gauge must wait for `/metrics` to answer.
A guest image that still waits for the gauge during a migration never
finishes the handover, so the image must change before it carries
this mint.

## Three unused items leave canon (#546)

2026-11-17

Removed from `canon`:

- `upgrade::authorize_artifact` and `UpgradeError::ArtifactHash`.
  `UpgradeManifest::artifact_hash` and `authorize_manifest` stay.
- `genesis::Anchor::rewrite`. Nothing in this repository writes
  `keys/zns_custody_manifest.toml` any more.
- `sealing::Attestation::report_data`. `Attestation::new` takes the
  report bytes alone.

## zns-rebind is removed (#535)

2026-11-17

The `zns-rebind` tool (#493) is deleted. It has run on mainnet and on
testnet, and both now start from the block of its anchor transaction.
No code in this repository can read the old Name Notes any more.

## The mainnet vault moves to a new address (#519)

2026-11-15

The mainnet Treasury sweep pays
`u1u0zxet96mm6chufy5y3mg5n93x69ht98js44rs4448xwcfk5l6xrx6zl34439vpup6fz040v4ensc3npx6jsk679e7kksdf7qv5mq53n`,
a Unified Address with one Orchard receiver. The testnet vault, the
1 ZEC minimum and the 0.01 ZEC left behind are unchanged.

The address is compiled in, so the vault moves with the release that
carries this change.

## New prices: nine length tiers, and forever costs four years (#517)

2026-11-15

Yearly prices in USD, by the length of the name:

| Length | Before | Now | Forever, now |
|---|---|---|---|
| 1 | 10,000 | 12,480 | 49,920 |
| 2 | 2,500 | 2,720 | 10,880 |
| 3 | 800 | 920 | 3,680 |
| 4 | 400 | 472 | 1,888 |
| 5 | 100 | 188 | 752 |
| 6 | 20 | 112 | 448 |
| 7 | 20 | 48 | 192 |
| 8 | 20 | 32 | 128 |
| 9 | 20 | 24 | 96 |
| 10 or more | 20 | 18 | 72 |

- Forever costs four yearly prices. Before, it cost three.
- A term of N years still costs N yearly prices.
- A renewal, or a change to forever, is priced from this table. Names
  already claimed keep their expiry.

A wallet or SDK that carries its own copy of the table must update
it. A payment below the price is refunded, less the refund fee.

## zns-rebind waits out short reorgs and node outages (#507, #510, #516)

2026-11-15

Three changes to the one-time `zns-rebind` tool (#493):

- It reads only blocks 3 deep, so a reorg of one or two blocks no
  longer ends a run.
- A transaction the node refuses, or that expires unmined, is built
  again after its expiry. Before, a refused anchor transaction or
  sweep ended the run.
- Tip and block reads retry while Zebra is unreachable, and up to four
  blocks are fetched ahead while one is applied.

## A block is judged at its own median time (#511)

2026-11-15

The median time of a block is the median of the 11 blocks before it,
as the Zcash protocol and Zebra define it. Before, the mint included
the block itself, which is the next block's median time. Everything
judged at a block moves one block earlier: OTP and buy expiry, whether
a response was in time, the deadline a Name Note sets, and the start
of each chain day.

An update, list, auction or delist that was approved in time is no
longer dropped when a later block's median passes the name's deadline.
The mint keeps the order until it lands, and the release waits for it.
Before, such an order was dropped with its payment and code spent, and
the name was released. The log line
`transition dropped: the tip median would release the name` is gone.

A resolver or client that recomputes deadlines from the chain must use
the same definition, or it will differ from the mint by one block at a
boundary.

## Fees are fixed: 1,000 zatoshis per action, 100,000 for a challenge (#513)

2026-11-14

The mint no longer reads its fee rate from the node.

- **Challenge fee.** An update, release, list, auction, delist or buy
  request costs 100,000 zatoshis. Before, it cost 100 actions at the
  node's rate, 500,000 zatoshis on mainnet. A request that pays more
  is still accepted.
- **Refund fee.** A refund withholds 100,000 zatoshis; before, 500,000
  on mainnet. A payment of 100,000 zatoshis or less is kept.
- **Network fee.** Every transaction the mint builds pays 1,000
  zatoshis per action under ZIP 317; before, the node's rate, 5,000 on
  mainnet. Notes of 5,000 zatoshis or less are still treated as dust.
- **Zebra.** The mint no longer calls `getstandardfee`, and boot no
  longer stops when that call fails. The log lines
  `boot: fee rate read`, `fee rate changed` and
  `fee rate unavailable; keeping the last rate` are gone.

A wallet that computed the challenge fee from the node should send
100,000 zatoshis. The rate no longer follows the network, so changing
it takes a new release.

## A wrong access code on a protected name keeps the payment (#508)

2026-11-14

A claim on a protected name that pays the price with a wrong access
code keeps its whole payment. Before, it was refunded less 1% of the
price and the refund fee.

The code is now the last thing checked, and only for a claim that
would otherwise succeed:

- no code on a protected name: refunded, less the refund fee;
- a payment below the price: refunded, less the refund fee, whatever
  the code;
- a name already registered, or queued for an earlier payment:
  refunded, less the refund fee, whatever the code;
- the price paid, the name free, and a wrong code: the payment is
  kept.

The 1% penalty is gone. The log line `wrong access code` is now
`access code refused; payment kept`, with the claim's `ua`, so the
payer of a mistaken payment can be found.

A wallet should warn that a mistyped code on a protected name forfeits
the payment.

## A claim on a free name registers, whatever its transaction expiry (#501)

2026-11-13

The rule that refused a claim "built before a release" is removed. It
refused a claim whose transaction expiry fell within the expiry window
after the name's latest release. The mint builds a claim only after it
has applied the release, so the rule could fire only after a reorg,
and there it could refuse a paid claim on a free name.

The claim rule is now: one claim anchor spent, no Name Note spent, one
successor anchor, and the name free.

In `canon-vectors-v1.json` the scenario `claim_inside_release_window`
and the claim event's `expiry_height` field are removed. The resolver
dropped the same rule in zcashme/zns-resolver#73.

## Every access code is rotated (#502)

2026-11-13

`canon::access_code::PURPOSE` changes from `access-code-v1` to
`zns-access-code-v1`. Every access code issued before stops working
once a mint built from this commit is live. New codes derive from the
same keys; no key ceremony is needed.

- Reference vectors: `alice` is `575692` (was `352582`), `bob` is
  `577225` (was `131624`).
- The issuer derives and sends out every code again. A tool that
  derives codes must build against this `canon`, or it keeps printing
  the old ones.
- A holder of an unused old code for a protected name needs a new one.

## One mempool challenge per name at a time (#500)

2026-11-13

A request seen in the mempool is challenged at once only when no
challenge on its name is open. Before, only an identical request was
held back, so repeated requests on one name with different addresses
or terms each cost the Treasury a challenge.

- A request held back this way is not refused. It is challenged when
  it is mined, about one block later.
- `/metrics` gains the counter `zns_mint_otp_dead_relays_total`: sent
  challenges that expired with their request never mined. The counter
  does not distinguish a request delayed in the mempool from one
  deliberately abandoned after its challenge was sent.

## Marketplace: a sale is signed one block after its payment (#496)

2026-11-13

The mint signs the sale note on the first tip after the block that
holds the buyer's payment. Before, it signed in the same pass that saw
the payment, so a one-block reorg of that block could move the name to
the buyer with the seller unpaid.

A name moves one block later than before, and a paid buy holds its
name for one more block.

## zns-rebind moves every live name to a bound Name Note (#493)

2026-11-13

`zns-rebind` is a one-time tool for the change to bound Name Notes
(#482). It claims every live name again in the new format and gives
the mint a new birthday. It takes no arguments and runs once, with the
old mint stopped and `keys/` writable, before the new mint first
boots.

1. It unseals the seed as the mint does and reads every live name,
   with its address and expiry, from the chain.
2. It sends one transaction with 40 new claim anchors. The block that
   mines it is the new birthday.
3. It claims each live name again as a bound Name Note, with the same
   address and expiry, at most 28 per block.
4. It sweeps the Treasury's older notes into one note.
5. It checks that the new registry holds exactly the live names, then
   rewrites `anchor_txid` and `birthday` in
   `keys/zns_custody_manifest.toml`. No other field changes.

- The Treasury needs at least 0.05 ZEC in Ironwood. It pays miner fees
  only; holders are charged nothing.
- The old Name Notes are not spent. They fall before the new birthday.
- Each name's history under the new birthday starts with a claim.
  Earlier updates are not replayed.
- A run that fails can be run again. It sends a new anchor transaction
  and claims every name again.

The tool ran on testnet at height 4,619,162 (3 names) and on mainnet
at height 3,575,820 (393 names). A resolver starts from that height.
Holders do nothing: addresses and expiries carry over.

## The wallet scans from the birthday (#488)

2026-11-13

On every network the wallet starts at the block before the `birthday`
in `keys/zns_custody_manifest.toml`, and the birthday is the first
block it scans. Before, mainnet and testnet started 100 blocks
earlier.

- Funds sent to the Treasury before the birthday are not seen.
  Everything the mint needs has to be created at or after it.
- A reorg can rewind the mint no further than the block before the
  birthday.
- The heights in the `boot:` log lines move up by 100.

## Name Notes are bound notes (#482)

2026-11-12

A Name Note is an ordinary Ironwood note whose randomness is derived
from its record. Before, the mint set the note's commitment randomness
(`rcm` and `ψ`) directly through a modified Orchard builder, and a
reader needed that modified code to decrypt and check a Name Note.

**Derivation.**

```
rseed = BLAKE2b-256(
    personalization = "ZNS___Name_Notes",
    input = 0x01 ‖ I2LEOSP64(len(fields)) ‖ fields ‖ prev)
```

- `fields` is the memo text between `ZNS:` and the last `:`, that is
  `verb:name:ua:expiry`, with `:terms` appended for a list or an
  auction.
- `prev` is 32 bytes: the predecessor Name Note's commitment (`cmx`)
  as its action published it, or zeros for a claim.

Orchard derives everything else from the rseed as for any Ironwood
note.

**The memo.** The text and layout are unchanged, but the last field
changes meaning: it was the predecessor's `rcm` and is now the
predecessor's on-chain `cmx`. A claim still carries 64 zeros.

**Reading a Name Note.** It decrypts under the standard Ironwood
domain with the Registry viewing key. It counts when its memo decodes
as a Name Note, its rseed equals the rseed derived from that memo, its
value is zero, and its recipient is the Registry address. Its
nullifier is the standard one.

- A name's identity is the `cmx` its note was mined with. It is known
  only once the transaction is built.
- A claim transaction has two zero-value outputs to the Registry: the
  Name Note and the successor claim anchor.
- In `canon-vectors-v1.json`, every claim, update and release event
  gains a `cmx`, and each record's `commitment` is that `cmx`. The
  file name is unchanged.
- The Orchard and `zcash_primitives` forks move to tags that cannot
  build the old notes.

This mint cannot read the old Name Notes. On a chain that holds them
it must not start until `zns-rebind` (#493) has moved every live name.
A resolver must verify the new binding, link notes by `cmx`, and
rescan; `zns-verify` 0.2.1 has `verify_bound_name_note`.

## Marketplace: the seller names the address a sale pays (#479)

2026-11-12

A listing pays whatever transparent address `<t1>` the owner writes in
`ZNS:list` or `ZNS:auction`. Before, `<t1>` had to be the transparent
receiver of the address the name points at, so an owner with a
shielded-only address could not list at all.

- The listing's `<ua>` must still be the owner's.
- The owner's answer to the challenge must repeat the same `<t1>` and
  price; an answer with another `<t1>` is refused.
- The same rule applies when the mint reads a list note from the chain
  and when a buy opens.

A wallet should show `<t1>` clearly before the owner lists: it is
where the buyer's payment goes. A resolver that checks `<t1>` against
the owner's transparent receiver must drop that check.

## A reorg drops every open buy (#478)

2026-11-12

On a reorg of any depth, every open buy is dropped, along with every
open challenge. The buyer sends `ZNS:buy` again. Before, a buy opened
below the fork point survived the reorg with its code.

Names and listings rewind with the chain as before. A payment made to
a seller against a code issued before a reorg matches nothing, so a
wallet should request a new code after a reorg before paying.

## A restart keeps names and listings and drops everything pending (#476)

2026-11-12

At boot the mint applies blocks and rebuilds nothing else. Names and
listings come back in full from their Name Notes. Every open challenge
(update, release, list, delist) and every open buy is gone; the owner
or the buyer sends a new request. Before, boot replayed old list,
delist and buy requests and their payments to rebuild them.

- A buy code is random. Before, it was derived from the access-code
  key and the buy transaction. `ZNS:buyotp` and `ZNS:dutch` are
  unchanged, but a wallet cannot compute a code; it reads it from the
  reply.
- If a buyer has paid the seller and the mint restarts before it
  writes the sale note, the sale does not complete. The payment went
  to the seller, so the mint has nothing to refund.

After a restart a wallet should request a new code and should not
answer or pay against an old one. An operator should not restart the
mint while a buy is paid and not yet settled.

## Marketplace: listings are Name Notes (#471)

2026-11-11

A listing is written to the chain. A name is listed exactly when its
current confirmed Name Note is a list or auction note. Before, listings
lived in the mint's memory and were rebuilt from history at boot.

**Three new Name Notes**, each spending the name's current note:

- `ZNS:list:<name>:<ua>:<expiry>:<t1>:<price>:<prev>`
- `ZNS:auction:<name>:<ua>:<expiry>:<t1>:<start>:<min>:<start-block>:<end-block>:<prev>`
- `ZNS:delist:<name>:<ua>:<expiry>:<prev>`

A list note has 8 fields and an auction note 11; every other note
keeps 6. For a list or an auction, the note's commitment also covers
the terms (`<t1>:<price>`, or `<t1>:<start>:<min>:<start-block>:<end-block>`),
as one more length-prefixed field before the predecessor. Every other
verb hashes as before.

**Rules.**

- When the owner answers a list, auction or delist challenge, the mint
  queues the note. The listing starts or ends when that note confirms,
  not when the answer is mined.
- Any later note for the name ends its listing: an update, a release,
  a sale or a delist.
- A list or delist note must carry the name's owner and expiry
  forward. A sale must spend a list or auction note and carry its
  expiry forward, binding the name to the buyer. A note that breaks
  these rules releases the name, as a wrong predecessor does.
- An ended auction's note stays the name's current note and quotes no
  price after its end block.
- A reorg rewinds a listing with the name's record.
- The log line `update dropped: the tip median would release the name`
  is now `transition dropped: …`, with an `action` field.

A resolver must read `list`, `auction` and `delist` notes, and their
extra commitment field, to follow a name through a listing.

## The ZEC rate is the best for the buyer of the last 120 price rounds (#467)

2026-11-11

Prices convert from USD at the highest ZEC price among the last 120
price rounds that returned a price. The mint runs one round per tip
pass, about one per block. Before, it used one rate per chain day, the
time-weighted average of the previous day, so a buyer quoted at
today's spot price could pay too little and be refunded.

- A payment at the spot price of any of those 120 rounds is meant to be
  enough. The mint rounds the zatoshis per USD up, so a client should
  compute the amount the same way or add a small margin.
- A round with no price changes nothing and does not push an old round
  out. During an exchange outage the rate stays where it was.
- The window is held in memory. After a restart it holds the boot round
  alone and refills one round per pass.
- `zns_mint_oracle_zats_per_usd` now moves during the day.
- The log line `pricing observation dropped: non-positive` is
  `pricing round dropped: non-positive`.

The price table and the way a round picks its price are unchanged.

## Sealing keys take no context (#461)

2026-11-11

In `canon`:

- `sealing::derive_sealing_key()` takes no argument. It took a context
  that was never sent to the chip.
- `sealing::dev_sealing_key()` (`non-tee` builds) takes no argument.
- `capsule::CAPSULE_KEY_CONTEXT` is removed.

The hardware sealing key is unchanged, and every production
`keys/zns_seed.capsule` opens as before. The `non-tee` development key
does change: a dev capsule sealed by an earlier build no longer opens
and has to be written again.

## Two retired ceremony file names are forgotten (#459)

2026-11-10

`zns_mint.conf` and `ceremony_state.toml` are file names no release
writes any more.

- `zns-migrate` starts an attempt when its transport directory holds a
  file with either name. Before, it refused with
  `already contains zns_mint.conf`. `transport::MINT_CONF_FILE` and
  `transport::CEREMONY_STATE_FILE` are removed.
- `zns-keygen`, when it clears an unfinished ceremony, deletes only
  `keys/zns_seed.capsule` and `keys/zns_attestation.bin`.

## canon, keygen, migrate and the integration tests join this repository (#451)

2026-11-10

`zns-canon`, `zns-keygen`, `zns-migrate` and `zns-integration-tests`
move into this repository, which becomes one Cargo workspace. No memo,
Name Note, price, metric or log line changes.

- The mint crate moves from the repository root to `mint/`. The other
  crates are `canon/`, `keygen/`, `migrate/` and `integration-tests/`.
- The binaries are built from this repository with `-p zns-mint`,
  `-p zns-keygen` or `-p zns-migrate`, against one `Cargo.lock`.
  Binary and feature names are unchanged. A keygen feature in a
  workspace build is written `--features zns-keygen/testnet`.
- `zns-keygen` builds only on x86_64 Linux, so a build at the root on
  another host needs `-p`.
- The integration harness builds the mint from this checkout.
  `ZNS_MINT_DIR` is no longer read; `ZNS_MINT_BIN` still is.

An image build that pinned four repositories pins this one, at one
commit. Because the tools now share a lock file, an image built from
this commit differs from one built from the separate repositories.

## List, auction and delist codes are random (#447)

2026-11-09

The code in a list, auction or delist challenge is random, like the
code for an update or a release. Before, it was derived from the
access-code key, so whoever issues pre-sale access codes could compute
it and list a name they do not own.

- An answer is accepted only after the mint has sent the challenge.
  A wrong code counts only against challenges that were sent.
- A list or delist challenge is dropped when any change to the name is
  queued or a buy opens on it, and on a reorg. The owner then sends the
  request again.
- A code that clashes with an open one is drawn again. The log lines
  `list fee kept: that code is already open` and
  `delist fee kept: that code is already open` are gone.
- `zns_mint_request_state` covers list and delist challenges.

The memo formats, the fees and the refunds are unchanged.

## Auction log lines say "auction" (#443)

2026-11-09

Three log lines from #423 are reworded. The memo formats and the codes
are unchanged.

- `list fee kept: the clock does not fall` is
  `list fee kept: bad auction terms`.
- `list fee kept: the clock has ended` is
  `list fee kept: the auction has ended`.
- `buy returned: the clock has not started` is
  `buy returned: the auction has not started`.

## A backlog of tip announcements costs one pass (#441)

2026-11-09

When several tip announcements from Zebra are waiting, the mint takes
the newest and runs one pass. Before, it ran a full pass for each,
with a price round and a pre-sale read every time.

`FATAL: Zebra returned an invalid canonical tip` now reads
`FATAL: Zebra could not answer its tip`.

## OTP challenges are sent as soon as a request reaches the mempool (#418)

2026-11-08

The mint sends the challenge for an update or a release when the
request enters Zebra's mempool. Before, it waited for the request to be
mined, at least one block.

A request is challenged from the mempool when:

- its transaction has no transparent inputs;
- its payment covers the challenge fee;
- no challenge for the same request is already open;
- no buy is open on the name;
- the registry allows the request: the name is live, no Name Note is
  pending, and the request satisfies the controller and term rules.

A request with transparent inputs waits until it is mined. Underpaid
or unauthorized requests do not receive a challenge. A transaction
gets at most one challenge from the mempool.

- A response counts only once its request is mined. A response mined
  before its request is refunded, less the refund fee, and the code
  stays valid; the controller sends the response again.
- A repeat of the same request (name, verb, address, term) takes over
  the open code. It does not get a new one.
- The mint reads Zebra's `MempoolChange` stream and calls
  `getrawtransaction`. If the stream task ends, the mint stops with
  `FATAL: mempool watcher ended`.

This delivers the code sooner. A change to a name is still authorized
only by confirmed transactions. A wallet should wait for the request to
be mined before sending the response.

## Unprotected names can be claimed without an access code (#375)

2026-11-07

A claim needs an access code only when its name is protected in the
pre-sale table at the tip's median time. Before, every claim needed a
code and a name on the list.

- Unprotected name: the claim goes ahead as
  `ZNS:claim:<term>:<name>:<ua>`. A code on such a claim is ignored.
- Protected name with the right code: unchanged.
- Protected name with no code: refunded, less the refund fee.

The memo grammar is unchanged. Protection depends on the last
successful read of the table, so a name listed after that read is open
until the next read succeeds.

## A failed submission is retried and no longer stops the mint (#433)

2026-11-07

- An error while sending a transaction is logged and the send is
  retried after a pause. Before, some errors stopped the mint with
  `FATAL: <label> submission failed`.
- The mint reads block times from the raw form of `getblockheader`.
  The verbose form could fail with `missing Sapling tree` if a reorg
  landed during the call, which stopped the mint.

## A resent transaction the node already holds counts as accepted (#430)

2026-11-07

When the mint sends a transaction Zebra already has in its mempool,
Zebra answers `transaction already exists in mempool`. The mint now
reads that as accepted. Before, it looked for wording Zebra 7.0.0 never
sends and treated the resend as rejected, so the order, refund or
challenge behind it was built again.

The special case for error code `-27` is removed; Zebra 7.0.0 never
returns it.

## The pinned block and the host-clock check are removed (#427)

2026-11-07

This reverses two requirements added in #379.

- Boot no longer asks Zebra for a pinned historical block (mainnet
  3,353,606, testnet 4,238,000). The log line `pinned block present`
  and the two `FATAL` lines about the pinned block are gone.
- A block's time is no longer compared with the mint host's clock. A
  wrong host clock does not stop the mint.
- Every applied block must still be after the median time of the 11
  blocks before it and at most 90 minutes past it. That rule now
  applies from the first block; before, it applied once 11 block times
  had been recorded.

## Two birthday checks leave the reorg path (#424)

2026-11-06

The mint no longer stops with
`FATAL: canonical fork crossed the mint birthday` or
`FATAL: wallet rewind crossed the mint birthday`. A rewind is bounded
by the wallet's retained checkpoints, which can include history before
the birthday. The walk still stops the mint if it reaches a height
the wallet holds no block for.

## Marketplace: Dutch auctions (#423)

2026-11-06

A name can be listed on a falling price in place of a fixed one.

**Listing.** The owner sends
`ZNS:auction:<name>:<ua>:<t1>:<start>:<min>:<start-block>:<end-block>`,
with the start price above the minimum and the end block after the
start block. The fee, the `<t1>` rule and the challenge step are those
of `ZNS:list`; the challenge is
`ZNS:otp:<code>:<name>:auction:<ua>:<t1>:<start>:<min>:<start-block>:<end-block>`.
A name has one listing, fixed or auction.

**Price.** The price falls in a straight line, in whole zatoshis, from
the start price at the start block to the minimum at the end block. The
end block is the last one that sells; the listing is removed on the
block after it.

**Buying.** The buyer sends `ZNS:buy:<name>:<ua>` as for a fixed
listing.

- The first buy in a block wins. The mint replies
  `ZNS:dutch:<code>:<name>:<ua>:<price>:<until>`, with the price of the
  block the buy was mined in and a deadline 10 minutes after that
  block's median time.
- The buyer pays the seller's `<t1>` the price plus the code before the
  deadline, and the mint writes the same `ZNS:sale` note as for a fixed
  listing.
- A buy that arrives while another holds the name is refunded, less the
  refund fee, with the memo `ZNS:held:<name>:<until>`.
- A buy before the start block is refunded the same way with
  `ZNS:wait:<name>:<start-block>`.

These are the first refunds that carry a memo. A buy on a fixed listing
that does not open still keeps its fee.

A wallet that supports buying must read `ZNS:dutch`, and should
recognise `ZNS:held` and `ZNS:wait` on a refund from the Treasury.

## Marketplace: a name can be listed, delisted and bought (#413)

2026-11-03

A name can change hands on chain. The buyer pays the seller directly;
the mint never holds the sale price.

**Listing.** The owner sends the Treasury
`ZNS:list:<name>:<ua>:<t1>:<price>`, or `ZNS:delist:<name>:<ua>` to
take a listing down.

- `<ua>` is the address the name points at. `<t1>` is a transparent
  P2PKH address and must be the transparent receiver of that address.
  `<price>` is in ZEC with at most eight decimals.
- The mint answers with a challenge sent to the owner,
  `ZNS:otp:<code>:<name>:list:<ua>:<t1>:<price>` or
  `ZNS:otp:<code>:<name>:delist:<ua>`. The listing changes when the
  owner sends that memo back within 30 minutes. The payment carrying
  the reply is refunded, less the refund fee.

**Buying.** The buyer sends `ZNS:buy:<name>:<ua>`, where `<ua>` is the
address the name will point at.

- The mint replies to that address with `ZNS:buyotp:<code>:<name>:<ua>`.
- The buyer pays the listed `<t1>` one transparent output of the price
  plus the code in zatoshis. Code `123456` adds 0.00123456 ZEC.
- When that payment is mined within 30 minutes, the mint writes a new
  kind of Name Note, `ZNS:sale:<name>:<ua>:<expiry>:<prev>`. It spends
  the seller's note and binds the name to the buyer for the rest of the
  term. The name stays live throughout.

**Fees.** A list, a delist and a buy each cost the challenge fee, 100
actions at the node's rate. The fee is kept, also when the request is
refused.

**While a buy is open** on a name, it cannot be updated, released,
listed or delisted, and the mint does not release it at the end of its
term. Open update and release challenges on it are dropped.

A listing ends when its owner no longer holds the name.

A resolver must accept `ZNS:sale` notes: the name has a new holder and
the same expiry. The verb is `sale` so that a new holder can be told
from an address change.

## A gauge tells a finished scan from a serving mint (#409)

2026-11-01

`/metrics` gains `zns_mint_serving`, with no labels. It is `0` once
boot's wallet scan has finished and `1` once the tip stream is open. A
mint still booting does not export it. A migration uses it to see that
a new guest has finished scanning before it takes over.

## One less node call per block (#408)

2026-10-31

The mint applies each block onto the commitment trees its wallet
already holds. Before, it fetched the tree state from Zebra
(`z_gettreestate`) before every block, at boot and live.

The log lines `previous chain state unavailable; retrying` and
`the chain moved under the tree-state fetch; re-converging` are gone.
An unexpected block height stops the mint with
`FATAL: block height does not follow the applied cursor`. A wrong
parent hash stops it with
`FATAL: fetched block does not continue the applied cursor`.

## Sapling payments, and names at any shielded address (#366)

2026-10-30

**Payments.** The mint reads requests paid to the Treasury's Sapling
receiver as well as its Ironwood receiver. Before, a request paid in
Sapling was kept and never read.

**Addresses.** A name can point at a Unified Address with an Orchard or
a Sapling receiver. Before, the address needed an Orchard receiver, and
a claim naming a Sapling-only address was dropped with its payment
kept. A resolver will now see Name Notes whose address has no Orchard
receiver.

**Treasury address.** The Treasury's published address always carries
both an Orchard and a Sapling receiver. On mainnet the address string
changes, and with it the identity document and the attestation report
data; anyone pinning the old report data must update. Payments to the
earlier address are still read.

**Pools.**

- An OTP challenge to a Sapling-only controller is funded from the
  Treasury's Sapling notes, with no fallback to Ironwood. It waits
  while the Treasury has no spendable Sapling funds.
- A refund may spend either pool.
- The vault sweep spends Ironwood only. Sapling funds stay in the
  Treasury.

## The challenge fee and the refund fee are a hundred actions (#405)

2026-10-29

**Challenge fee.** Starting an update or a release costs 100 times the
node's fee per action: 500,000 zatoshis at 5,000 per action, and
100,000 zatoshis at 1,000 per action, which Zebra reports on mainnet
from height 3,590,000. Before, it cost 1 USD at the daily ZEC rate,
rounded up to the next 100,000 zatoshis. The fee follows the node's
rate on each tip and no longer depends on the price of ZEC.

**Refund fee.** A refund withholds the same 100 actions. Before, it
withheld 10. A payment of 100 actions or less is kept with no refund.

A wallet that computed the challenge fee from the USD price must pay
the new amount. A request that pays less is kept, not refunded.

## Payment decisions are logged (#404)

2026-10-28

Five outcomes that used to be silent are logged at INFO with the
payment's `txid` and `name`. All except `wrong access code` also
include the amount:

- `quote above the money supply; payment kept`
- `wrong access code`
- `claim not authorized; payment kept`
- `challenge not authorized`
- `below the challenge fee`

At this point, a wrong access code still refunds the payment less the
1% penalty and the refund fee (#372). It does not keep the whole
payment; that changes in #508.

Access codes and OTP codes are never logged. Repeated `wrong access
code` lines for one name suggest someone is guessing its code.

## The Zcash crates move to their stable NU7 releases (#390)

2026-10-26

The mint builds on the stable NU7 releases of the Zcash crates
(`zcash_primitives` 0.31, `zcash_client_backend` 0.25, `zcash_keys`
0.17, `zcash_protocol` 0.11) and on `zns-orchard-v0.16.0`. Name Notes
are byte-identical.

- From NU7 a transaction expires 120 blocks after its target, not 40.
  A broadcast Name Note waits for the expiry its own transaction
  carries.
- The rule that refuses a claim built before a release follows the same
  number: the window after a release is 40 blocks, and 120 from NU7.
  In `canon-vectors-v1.json`, one `expiry_height` changes from 240 to
  220. A resolver applying this rule must use the height-dependent
  window.
- The minimum Rust version is 1.89.

## One OTP challenge per term; a payment keeps its rate (#381)

2026-10-26

**Challenges.** A challenge is identified by its whole request: name,
verb, address and term. Before, the term was left out, so a second
update request for the same name and address joined the first
challenge, and the term applied was the one from whichever request
arrived first. A stranger's term-less update request could absorb an
owner's paid renewal.

- Two update requests with different terms are two challenges with two
  codes. The controller answers the code for the term they want and
  pays that term's price.
- The response memo is unchanged and carries no term; the code selects
  the challenge. A wrong code counts against every relayed challenge
  the response names.
- A response to a challenge with a term keeps the whole payment once it
  covers the price. A response to a term-less update or a release gets
  its payment back, less the refund fee.
- A right code that arrives while a Name Note is already queued for the
  name is refunded, less the refund fee.

**Pricing.** A claim or a challenge fee is priced at the ZEC rate read
before the pass's price round, the same rate an OTP response is priced
at. Before, a payment seen just before the daily rate was published
could be repriced at the new rate and refused.

## An OTP response is decided at the block that carries it (#384)

2026-10-26

The mint rules on an OTP response when it applies the response's block,
using that block's median time. Before, it held the response until the
next tip pass and used the tip's time.

- The right code always spends its challenge. If the response is then
  refused (a renewal that pays too little, or a name now due for
  release), the payment is refunded less the refund fee and the
  controller requests a new OTP. Before, the same OTP could be sent
  again within its 30 minutes.
- A challenge expires at the first block whose median time reaches or
  passes its 30-minute deadline, before that block's responses are read.
- A response counts only against challenges relayed before its block. A
  response mined before its challenge was relayed is refunded and is not
  counted as a wrong code.

A wallet should not resend an OTP after a refused response.

## The keygen report must cover the capsule file on disk (#387)

2026-10-26

On an attested build, boot always verifies `keys/zns_attestation.bin`
against the seed capsule file on disk. A missing or unreadable report
stops boot with `FATAL: cannot read keys/zns_attestation.bin: …`. A
readable report made for a different capsule file stops boot with
`FATAL: keygen attestation report failed verification`.

Before, a capsule whose hash differed from the one recorded in
`keys/zns_custody_manifest.toml` skipped this check, so any changed
capsule file bypassed attestation.

A capsule resealed by a migration needs a matching report beside it.
`zns-migrate target` writes one from zcashme/zns-migrate#29.

## Refused payments are refunded (#372)

2026-10-26

The mint sends a refused payment back to the Unified Address written in
its memo, less a refund fee. Before, every refused payment was kept.

A claim is refunded when:

- it carries no access code, or names a name that is not on the pre-sale
  list;
- it pays less than the price;
- it pays the price with a wrong access code, in which case 1% of the
  price is also withheld;
- the name is already registered, or an earlier payment is queued for it.

The amount is judged before the access code, so the refund does not
reveal whether a cheap guess at a code was right.

An OTP response is refunded when no live challenge matches its code,
when a renewal or upgrade pays less than its price, or when the name
became due for release after the challenge was issued.

- The refund fee is 10 actions at the node's rate: 50,000 zatoshis at
  5,000 per action. A payment no larger than the fee is kept.
- A payment whose memo does not parse is kept.
- A refund is built on the tip after its payment's block and retried
  each tip until the node accepts it. It carries no memo.
- Queued refunds are held in memory. A restart loses them, and a refund
  whose payment block is orphaned is dropped.
- The daily sweep waits while any refund is queued.

Operators can follow refunds in the log lines `payment refund`,
`payment kept`, `refund built` and `refund not built`.

## One bad row no longer blocks the protected-names table (#386)

2026-10-26

A row of `zn_names` whose name is not a valid name, or whose `expiry_at`
does not decode, is skipped with a warning and the other rows load.
Before, one such row failed the whole read, which at boot meant the mint
did not start.

- A skipped row does not protect its name. Watch for
  `pre-sale name does not parse; skipping it` and
  `pre-sale row did not decode; skipping it`.
- A failed read, a short read, a missing row count, or a body that is
  not a JSON array still refuses the table.

## Several claims can be in flight at once (#385)

2026-10-26

A claim spends the first claim anchor the wallet can still spend.
Before, every claim took the first anchor in the pool, so one claim
waiting to be mined held up all the others until it confirmed or
expired.

The log line `no claim anchor in the pool` is now
`no spendable claim anchor`, with the pool size in `anchors`.

## A name's open challenges end when a Name Note is queued for it (#374)

2026-10-26

When the mint queues a Name Note for a name (a claim, an authorized
update or release, or a release at the end of a term), every open OTP
challenge on that name is dropped at once. Before, a competing challenge
stayed in the queue, unanswerable, until its 30 minutes ran out.

- An OTP for a name stops working as soon as another change to that name
  is queued, not when that change confirms.
- `zns_mint_request_state` no longer reads `2` for such a challenge.
- The OTP memo format, the 30-minute window and the limit of six wrong
  codes are unchanged.

## Block header times are checked, and the node must serve a pinned block (#379)

2026-10-24

The mint takes its clocks (terms, OTP expiry, the chain day) from block
header times its node supplies. It now bounds those times and checks the
node is on the expected chain.

- At boot on mainnet and testnet, Zebra must serve one pinned block over
  `getblockheader`: mainnet height 3,353,606, testnet height 4,238,000.
  The mint hashes the header itself. A missing or different block stops
  boot with `FATAL: pinned block <h> unavailable` or
  `FATAL: block <h> is not the pinned block`.
- Every header read must be at most 2 hours ahead of the mint's own
  clock. Once the tracker holds the full 11-header window, the next
  block's time must also be after its preceding median and at most
  90 minutes past it. The initial backfill headers are checked against
  the host clock while that window fills. A failed check stops the mint.

The host clock has to be roughly right: a clock more than 2 hours behind
the chain stops the mint.

## Transactions pay the fee rate the node reports (#380)

2026-10-24

Every transaction the mint builds (OTP challenges, Name Notes, the vault
sweep) pays the per-action rate from Zebra's `getstandardfee`, under
ZIP 317 accounting. Before, it paid a fixed 5,000 zatoshis per action,
five times what Zebra recommends from mainnet height 3,590,000.

- Zebra must serve `getstandardfee` with estimator `version` 0. Boot
  reads it once and stops with `FATAL: fee rate unavailable from Zebra`
  if the read fails. There is no fallback rate.
- The rate is read again on every tip pass. A change is logged as
  `fee rate changed`; a failed read keeps the last rate.
- Notes worth 5,000 zatoshis or less are still treated as dust, whatever
  the rate. If dust followed the rate, anyone could stall relays and
  sweeps by sending the Treasury one tiny note.

This is the fee the mint pays, not a fee users pay.

## A confirmed update always renews the name (#377)

2026-10-23

An update Name Note that spends the name's current note renews the name,
whatever the median time of the block that confirms it. Before, an
update that confirmed after the term or the liveness deadline had passed
released the name, so an owner could pay for an update and lose the name
to a slow confirmation.

- The mint still refuses to sign an update once the tip's median time
  has reached the term or the deadline. A queued update that reaches
  that point unsigned is dropped, with the log line
  `update dropped: the tip median would release the name`.
- A broadcast Name Note enters a waiting state and keeps its name
  reserved between broadcasts. This first version allows signing again
  one block before the transaction's expiry; #574 corrects that boundary.
- `zns_mint_request_state` reads `1` for a name whose Name Note is
  broadcast and not yet confirmed.

A resolver must apply the same rule: a confirmed update that spends the
current note is a renewal, even past the old deadline.

## The protected-names table is read on every tip pass (#373)

2026-10-23

The mint reads the pre-sale table `zn_names` on every tip pass. Before,
it read it at boot and then once per chain day, so a name protected
during the day stayed open to anyone until the next day.

- The read is one request, `?select=name,expiry_at` with
  `prefer: count=exact`. The paged read and the `id` column are gone.
- The timeout is 3 seconds for the request and the body, and the body
  may be up to 4 MiB. A slow table host can delay a tip pass by what is
  left of those 3 seconds.
- A failed read keeps the last table and logs
  `pre-sale read failed; the last table stands`.
- `pre-sale fetch: table loaded` is logged at DEBUG, not INFO.

The Supabase project's "Max Rows" setting must be at least the size of
the table. Below that the server truncates the reply, the count check
fails, and every read is refused.

## The vault sweep pays a real vault address on each network (#354)

2026-10-15

The daily Treasury sweep pays a Unified Address chosen by network.
Before, it paid a placeholder transparent address on every network.

- Mainnet:
  `u1eqcql0r460xjqk49maglfxa02mfuetaed4h0nkf0lum4m6ay6t9gjpuxhuuygfeuz3d9sfgcjpz7uev2gsk5nnpf6g0uh0rn2uq0gz44`
- Testnet and regtest:
  `utest1v5p9lqxsshgrhdcj3gsg60vglxlkhwmhpvhtv3884pgwxktas9s95ws5qvypv4qyxadd5gjhzp4vczpd95flh307x42ssrynp9az3j4fyhz8knacwkzf8xk2f9726480ym2ntmv3ftk9z7gy5a8tarndrm0p992dx7gsczewsglqnpxg`
- The sweep still leaves 0.01 ZEC in the Treasury.
- `treasury::VAULT_ADDRESS` is removed. The address is compiled in, so
  it changes only with a new build.

## The metrics page shows which names have a request in flight (#343)

2026-10-15

`/metrics` gains `zns_mint_request_state{name="<name>"}`, one sample for
each name the mint has something open for.

- `1`: the mint holds the next move. A request awaits its decision, a
  challenge awaits relay, or a Name Note is not yet seen on chain.
- `2`: an OTP challenge was relayed and awaits the controller's response,
  and nothing else holds the name.
- A name with nothing open has no sample. There is no `0`. The chain is
  the record of what became of the request.
- `name` is the only label. The value is refreshed once per tip pass.

The mint now serves `/metrics` and `/health` itself, on `0.0.0.0:9464`
as before. A frontend can poll this metric to tell a user whose move it
is; a name that goes absent has either landed or been refused, so read
the outcome from the resolver.

## First production release (2026-10-15)

2026-10-15

The mint went live on mainnet for early access. This entry records how
it behaved on that day; every later entry is a change from here.

**Requests.** A request is a shielded payment to the Treasury address
with a memo.

- Claim: `ZNS:claim:<code>:<term>:<name>:<ua>`. Every claim needs the
  name's six-digit access code and the name listed in the pre-sale
  table. The first payment in block order that covers the price gets
  the name.
- Update: `ZNS:update:<term|none>:<name>:<ua>` changes the address a
  name points at, adds years, or converts it to forever.
- Release: `ZNS:release:<name>:<ua>` gives a name up.
- An update or release is answered with a challenge,
  `ZNS:otp:<code>:<name>:<action>:<ua>`, sent to the address the name
  already points at. The controller sends that memo back to authorize
  the change.
- A name is 1 to 63 lowercase letters and digits. A term is `forever`
  or `1y` to `99y`.

**Prices.** Per year, in USD: 10,000, 2,500, 800, 400 and 100 for names
of 1 to 5 characters, and 20 for 6 or more. Forever costs three yearly
prices. Prices convert to ZEC at a daily rate taken from several
exchanges. Starting an update or release costs 1 USD, rounded up to the
next 100,000 zatoshis. There are no refunds: a refused or late payment
stays in the Treasury.

**OTP.** A code is six random digits, valid for 30 minutes. Six wrong
codes retire the challenge. Challenges are issued only for requests in
confirmed blocks.

**Release.** The mint releases a name itself when its term ends, or
when a year passes with no update.

**Sweep.** Once per chain day the Treasury's funds move to the vault,
if at least 1 ZEC moves, leaving 0.01 ZEC behind.

**Boot.** The mint runs in an AMD SEV-SNP guest beside its Zebra node.
At boot it reads `keys/zns_custody_manifest.toml`, verifies the keygen
attestation report, unseals the seed capsule, checks the ceremony's
anchor transaction on chain, scans from its birthday to the tip, and
writes an identity document with its own attestation report. Any
failed check stops it.

**Zebra.** The mint needs Zebra's Indexer gRPC (port 8230, testnet
18230) for blocks and the tip stream, and JSON-RPC for
`getblockchaininfo`, `z_gettreestate`, `z_getsubtreesbyindex`,
`getblockheader` and `sendrawtransaction`.

**State.** Requests, challenges and queued Name Notes are held in
memory. A restart rebuilds names and balances from the chain, and loses
whatever was pending.
