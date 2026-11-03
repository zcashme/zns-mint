# Sale module changelog

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
