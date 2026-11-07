# Zcash Name Service

The mint sells names on Zcash. A name is a short word that points at a Zcash address. You pay the mint, and the mint writes that binding into a shielded note on the chain. Anyone can then look the name up.

The mint runs inside a hardware trusted execution environment, in the same guest as a Zebra full node. Zebra is the mint's view of the chain. The mint asks Zebra for each new block, reads the payments inside it, and hands Zebra the transactions that record a name. The seed that spends those notes is sealed to that guest.

## Two addresses

One seed derives two accounts.

The **treasury** receives payment. A name request is a shielded payment to the treasury address, and the memo on that payment is the instruction.

The **registry** holds the name record. When the mint accepts a request, it writes a shielded note to the registry. The text of that note is the binding: which name, which address, and until when. The registry spending key stays inside the guest. The registry viewing key is public. That is what a resolver uses.

## Names

A name is one to sixty-three characters, lowercase letters and digits. It points at a unified address that can receive shielded notes.

A registration lasts a number of years, or it is **forever**. Forever still has to be touched about once a year. If a year passes with no update, or if a paid term runs out, the mint releases the name itself and the word is free again.

## Memos

A shielded payment can carry a short text memo. The mint treats that text as the whole instruction. The amount is the payment. The memo says what the payment is for.

You write one of these to the treasury:

```text
ZNS:claim:forever:alice:u1...
ZNS:claim:004206:5y:alice:u1...
ZNS:update:none:alice:u1...
ZNS:update:5y:alice:u1...
ZNS:release:alice:u1...
```

`claim` asks for a new name. The term is `forever` or a number of years such as `5y` (one to ninety-nine). A protected name takes a six-digit code in front of the term.

`update` changes the address a name points at, extends its term, or both. `none` keeps the current expiry. `5y` adds five years. `forever` removes the fixed expiry.

`release` gives the name up.

The mint answers an update or a release by paying the current controller a note whose memo is a one-time code:

```text
ZNS:otp:417293:alice:update:u1...
```

The controller sends that same sentence back to the treasury. That return memo is the proof they can read the address the name already points at.

When the mint accepts a request, the record it writes uses a second memo, on a note paid to the registry:

```text
ZNS:claim:alice:u1...:none:0000...
ZNS:update:alice:u1...:1893456000:abcd...
ZNS:release:alice:u1...:none:abcd...
```

That sentence is the binding. It names the action, the word, the address, the expiry (`none` when there is no fixed date), and the previous record. A claim has no previous record.

## Claim

A claim is a purchase.

1. You pay the treasury at least the posted price for that name and term.
2. The memo is `ZNS:claim:<term>:<name>:<address>`.
3. If the name is free and the payment covers the price, the mint writes a claim note to the registry.

There is no confirmation code. The payment is the request. The first sufficient payment owns the name. A second payment for the same word does not start a second record.

A name on the pre-sale list also needs its six-digit code in the memo. The mint checks the code before it looks at the price.

## Update

An update changes a name you already hold: a new address, more years, or a conversion to forever.

1. You pay the treasury the challenge fee with `ZNS:update:<term>:<name>:<address>`.
2. The mint sends a one-time code to the address the name points at now.
3. You send that code back to the treasury.
4. If the update adds years or converts the name to forever, that return payment covers the price of the new term. An address-only update (`none`) has no second price.
5. The mint spends the current registry note and writes a new one.

The code is how the mint knows the request came from the current controller. A stranger can pay the challenge fee, and the code still arrives only at the address already on the record.

## Release

A release ends a registration before its term is up. The address in the memo is the one the name already points at.

1. You pay the challenge fee with `ZNS:release:<name>:<address>`.
2. The mint sends a one-time code to the current controller.
3. You send the code back.
4. The mint spends the current registry note and writes a release note.

The name is free again. The release note keeps the address that let go of it, so the chain still shows who released it.

The mint also releases a name on its own when the paid term ends, or when about a year has passed since the last claim or update. Those releases are the same kind of registry note. They do not wait for a code.

## Payment

Shorter names cost more per year. The price is in dollars, then converted to ZEC at the mint's daily rate.

| Length        | One year   | Forever |
| ------------- | ---------- | ------- |
| 1 character   | $10,000    | $30,000 |
| 2 characters  | $2,500     | $7,500  |
| 3 characters  | $800       | $2,400  |
| 4 characters  | $400       | $1,200  |
| 5 characters  | $100       | $300    |
| 6 or more     | $20        | $60     |

Forever is three years' price, paid once. A term of several years is the yearly price times the number of years.

The mint publishes a daily ZEC price from public exchanges and quotes every name in zatoshis from that rate. The quote you meet is the one in force when the mint first sees the payment.

An update or a release starts with a challenge fee of a hundred times the node's fee per logical action: 500,000 zatoshis at 5,000 per action, and 100,000 zatoshis at 1,000 per action from height 3,590,000. That fee opens the confirmation. It is not the price of the name. Extra years are paid when you send the confirmation code back.

A payment changes a name only when the memo is one of the sentences above and the amount covers the price that sentence requires. Any other payment to the treasury stays there.

## The resolver

The mint's memory is not the lookup table. The lookup table is the chain.

Each accepted claim, update, and release is a shielded note on the registry account. The note's memo is the binding, and spending the previous note is what retires the old one. A resolver is a reader of that account. It scans the chain with the public registry viewing key, the same way a wallet scans for notes it can read, and shows the live binding for each name.

The viewing key is published by the mint. It reveals the registry log and nothing the treasury was paid. The spending key that can replace a record stays in the guest.
