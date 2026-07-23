# Treasury assembly changelog

## 2026-07-23 — Typed Treasury signer route

- Refund assembly supplies `TreasuryKeys` only for its Orchard payment spend.
- Its output-only Ironwood refund bundle supplies no Registry key; dummy spends
  are authorized internally by the Orchard builder.
- Refund witnesses use an explicit fully-applied anchor height, while branch,
  fee, and expiry policy use a separate next-mineable target height.

Tracks design-relevant changes to `src/treasury/assemble.rs`.

## 2026-07-23 — Treasury signer capability

- Treasury assembly accepts `TreasuryKeys` rather than a role-neutral account
  key container. Registry authority cannot be passed to this boundary.

## 2026-07-22 — Claim refund transaction and defensive value-flow checks

- Added the approved mixed-pool V6 refund shape: one Treasury Orchard payment
  spend, one Treasury Orchard internal change output, and one Ironwood refund
  output to the Orchard receiver in the claimant's unified address.
- The Ironwood output is always present, including at value zero. ZIP-317
  therefore sees two Orchard actions and two padded Ironwood actions, for a
  20,000-zatoshi network fee under the standard rule.
- Defined the gross Treasury surcharge as `10 * network_fee`. The refund is
  `payment - price - surcharge`; Treasury change is
  `price + surcharge - network_fee`.
- Derived action counts through `BundleType::num_actions`, and added an
  independent aggregate bundle-value-balance check before signing.
- Bound assembly to a Treasury-account payment note whose memo exactly matches
  the supplied claim request.
- Required NU6.3 activation, the target-height Orchard witness, the newest
  retained Ironwood checkpoint root, and an Orchard receiver in the claimant's
  unified address. The Ironwood bundle is output-only, so it does not require
  an exact-height spend witness; using the newest checkpoint also works when
  the target block contained no Ironwood commitments.
- Encoded both change and refund outputs with the canonical ZIP-302 no-memo
  value (`MemoBytes::empty`) instead of an all-zero empty-string memo.
- Added unit cases for the action shape, threshold and overpayment arithmetic,
  underpayment, wrong-account and wrong-memo rejection, pre-NU6.3 rejection,
  and missing-anchor rejection. These tests are written but were not executed
  in this bounded hardening pass.

## Deliberately out of scope

- Sapling and transparent refund fallbacks.
- Claim observation, exact reserved-note retrieval, broadcast, retry,
  confirmation, partial settlement, expiry, and reorg behavior.
- Relocating the assembly boundary out of the `treasury` namespace. The current
  placement remains a documented architecture contradiction to resolve before
  runtime integration.
