# Sale module changelog

## 2026-11-13 — The market drops checks that cannot fail (#497)

- `observe` keeps no `used` list: `open_buy` already refuses a second
  buy with the same address and total (`PaymentTaken`).
  `one_output_settles_one_sale` is gone; its buys had different totals.
- The buy law moves to `Registry::authorize_buy`, which returns the
  `BuyTerms` a sale takes from the chain. `open_buy(name, bob, ruling,
  code, mtp)` keeps only the market's part: a sale already on the name
  refuses first, then the ruling, then `PaymentTaken`. It takes no
  `registry`, `owner`, `term`, `held`, `release_due`, `note_pending`,
  or `height`; `admit` turns a pending note into `InFlight`. The
  refusal order is unchanged.
- `owner` and its `NotOwner` check are gone: a listed name's record UA
  is the listing's UA, so the check compared a value with itself. The
  stranger half of the unlisted-name test is gone with it.
- `open` and `dutch_hold` fold into `open_buy`.
- The test that `open_buy` echoes its `release_due` and `note_pending`
  flags is gone with the flags. Tests open buys on the registry's
  ruling, so a sale holds the real commitment; the fake `held()` is gone.
- The `zats` test helper is gone; the tests call upstream's
  `Zatoshis::const_from_u64` directly.
- `Phase::Paying.expires_at` is gone; `Sale.until` held the same time.
- `admit` returns `Option<ReturnedIntent>`; `Admission` and its unread
  `opened` are gone.
- `admit` no longer checks the delister's ownership before
  `propose_delist` checks it.

## 2026-11-13 — A sale is signed on the tip after its payment (#434)

- `Phase::Paid` holds the payment's height. `observe` takes the
  block's height, and `poll` takes the tip and signs a paid sale only
  once the tip is past that height, as `RefundQueue::due` does for
  refunds. A reorg that drops the payment's block replaces the market
  before the sale note is built.

## 2026-11-12 — A list pays the t1 the owner names

- A listing pays the t1 in the list memo, which the owner repeats in
  her OTP response. The controller's transparent receiver, if any,
  plays no part, so a shielded-only controller can list.
- `is_owner_listing` is gone: `propose_list` and a buy check only that
  the listing's UA is the owner's.

## 2026-11-12 — The market keeps no history, and is one type (#477)

- `SaleQueue` is gone: `Market` holds the open buys itself. Its
  forwarding methods are gone, `is_open` is private (callers ask
  `allows_transition`), and `is_paid` is test-only. `AuctionTerms`,
  `Ask`, `Listing`, and `MarketRefusal` move above `Market`, so it has
  one `impl` block.

- `MarketEvent`, `Stamped`, `Market.events`, `Market::record`, and
  `Market::truncate_to` are gone. A reorg drops the open buys instead
  of replaying a log of every buy. `SaleQueue::restore`, `mark_paid`,
  and `close` served only that replay.
- `observe`, `expire`, `reconcile`, and `poll` take no height and
  return no names: both only stamped log entries. `poll` still returns
  the sale notes to submit.
- The rollback tests are gone with the rollback. The expiry test keeps
  its expire, re-open, and pay steps.

## 2026-11-12 — Boot does not replay buys; a buy's code is random (#475)

- `Market::seal_replayed_buys` and `SaleQueue::seal_relayed` are gone.
  They marked buys rebuilt from history as already relayed, and boot
  no longer rebuilds buys.
- `Market::admit` draws a buy's code with `OtpCode::generate()` and no
  longer takes the access-code key.
- The list and delist challenge tests answer with the code the queue
  generated and relayed.

## 2026-11-11 — The market holds buys; the chain holds listings (#465)

- `Market::answer`, `Market::list`, `Market::delist`, and the
  `MarketEvent::List` and `Delist` events are gone. A completed list or
  delist challenge authorizes a Name Note in the scan loop.
- `Market::expire` and `reconcile` no longer touch listings, and
  `truncate_to` rebuilds only the buys.
- `decode_terms` and `encode_terms` read and write a listing's terms
  for requests, challenges, and Name Notes. `listable` is
  `pub(crate)`, and `Ask::action` names the verb.

## 2026-11-09 — List, delist, and buy are `Request` variants (#446)

- `MarketRequest` is gone. `Market::admit` takes a `Request`; a claim,
  update, or release changes nothing.
- A list or delist challenge is an `OtpChallenge` in `OtpQueue`.
  `MarketChallenge`, `ChallengeKind`, `Market.challenges`, the
  `Challenge` and `ChallengeClosed` marketplace events,
  `unrelayed_challenges`, and `challenge_relayed` are gone.
  `Market::truncate_to` no longer rebuilds challenges.
- `propose_list` and `propose_delist` take the request's txid and admit
  it to the `OtpQueue`; `answer` completes it there. `CodeTaken` is
  gone: a random code is drawn again instead.
- A buy that opens drops the name's challenges in `admit`.

## 2026-11-09 — An auction's terms are `AuctionTerms`

- `Clock` is `AuctionTerms`: the four values a `ZNS:auction` memo
  carries. "Clock" now means only time and the §4.5 clocks.
- `BadClock` is `BadTerms`, `clock_ready` is `listable`, and
  `Registry::finish_clocks` is `delist_ended_auctions`.
- An auction listing hands its `AuctionTerms` to `auction_otp`
  instead of converting them to integers.
- Log lines: "list fee kept: bad auction terms", "list fee kept: the
  auction has ended", "buy returned: the auction has not started".

## 2026-11-06 — A late clock reply leaves the book, and a paid hold still returns

- A reply after the end block does not install the clock. The end
  block itself still lists. A flat listing already there stays.
- After the clock payment matches, the name stays reserved until the
  sale note is signed. A later intent is returned with that deadline.

## 2026-11-05 — A listing can be a dutch clock

- `ZNS:auction` names the start price, the minimum, and the start and
  end blocks. The price falls in whole zatoshis. The end block is the
  last that sells, and the next block takes the listing down.
- The first buy in a block wins and is told
  `ZNS:dutch:<code>:<name>:<ua>:<price>:<until>`. That price stays for
  ten minutes. He pays it plus the code.
- A later intent while the name is held comes back, less the refund
  fee, with `ZNS:held`. An intent before the clock starts comes back
  with `ZNS:wait`.

## 2026-11-03 — Name requests and market requests

- `MarketRequest` replaces `ListRequest`, `DelistRequest`, and
  `BuyRequest`. `list` and `propose_list` take a `Listing`, and
  `open_buy` takes the name and the buyer. `admit` derives the list,
  delist, and buy codes from the access-code key.
- `unrelayed_challenges` returns the memo for each challenge whose
  owner still holds the name on its terms. That check was the
  Registry's.

## 2026-11-02 — Listings and sales are read again from the chain

- A list or a delist waits until the controller returns the challenge.
  The list sentence names her t1 and her price. When that code is
  already open, a second challenge does not start. The payment that
  returns her code is refunded, and the list fee stays. The listing
  leaves the book when she no longer holds the
  name.
- One transparent output settles one sale. A buy stays closed when an
  open buy already pays that address the same total. The buy code is
  derived from the access-code key, the buy transaction, and the name.
- Startup and a rollback replay listings, payments, and expiries in
  block order. A buy read from the chain stays payable, and its code
  stays unsent through a later rollback. A rollback sends a code that
  this process opened and has not yet marked sent. The sale note is
  signed only while the note captured at open is still live. A
  finished sale leaves before the next block's memos are read.

## 2026-11-01 — A buy OTP, then a sale note

- Alice lists with `ZNS:list:<name>:<ua>:<t1>:<price>` and delists
  with `ZNS:delist:<name>:<ua>`. The UA must own the name, and the t1
  must be the transparent receiver on that UA. The price has at most
  eight decimal places. A list or a delist waits while a buy is open.
- Bob's memo is `ZNS:buy:<name>:<ua>`. The reply is `ZNS:buyotp`.
  Code `123456` is `0.00123456` ZEC. A transparent output to the
  listed address counts when the amount minus the listed price
  equals that OTP.
- The mint then signs `ZNS:sale` for Bob. Her note is spent and the
  name stays live, bound to him for the term the sale captured.
