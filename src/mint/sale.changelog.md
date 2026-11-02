# Sale module changelog

## 2026-11-02 — Listings and sales are read again from the chain

- A list or a delist waits for a controller challenge. The reply is
  `ZNS:otp` with verb `list` or `delist`. The code is derived from the
  request, so a rescan matches her reply. The reply payment is refunded.
- A buy code comes from the access-code key, the buy transaction, and
  the name. One transparent output settles one sale.
- Startup and a rollback apply answered listings, payments, and expiries
  in block order. A sale signs only while the note it captured is still
  live. A finished sale leaves before the next block's memos.

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
