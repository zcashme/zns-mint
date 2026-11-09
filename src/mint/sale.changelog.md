# Sale module changelog

## 2026-11-09 — List, delist, and buy are `Request` variants (#446)

- `MarketRequest` is gone. `Market::admit` takes a `Request`; a claim,
  update, or release changes nothing.

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
