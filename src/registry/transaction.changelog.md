# Registry transaction changelog

Tracks design-relevant changes to `src/registry/transaction.rs`.

## 2026-07-23 — Caller-owned fee-input exclusions

- Registry fee-note selection now accepts an explicit read-only
  `BTreeSet<NoteLocator>` exclusion set instead of reading operational
  reservations from canonical Wallet state.
- The opaque exact locator plan remains unchanged; assembly still cannot
  substitute or reselect inputs.

## 2026-07-23 — Exact Registry fee-input plan

- Fee-note selection is a separate read-only phase that excludes every wallet
  reservation and returns opaque exact locators.
- Assembly resolves only those locators and rejects disappearance, wrong
  account/class, or insufficient value; it never reruns selection.
- Anchor height and next-mineable target height are separate inputs. Witnesses
  bind to the accepted cursor while ZIP-317 and expiry bind to the target.

## 2026-07-23 — Exact validated predecessor spend

- Update and release no longer search ordinary wallet notes by reparsing memos.
- Assembly reads the exact validated Name Note retained by the current Registry
  tip, obtains the witness for that note's recorded best-chain position, and
  passes the opaque wrapper to `Builder::add_validated_zns_spend`.
- The request's predecessor commitment must equal the current Registry tip
  before builder mutation.
- Ordinary Registry notes remain eligible only for fee funding and cannot be
  selected as Name Note predecessors.
- The builder accepts `RegistryKeys`, not a role-neutral raw Orchard spending
  key, so Treasury authority cannot satisfy its capability boundary.

## 2026-07-22 — ZIP-317 fee cross-check

- Replaced hand-rolled `MARGINAL_FEE` and `GRACE_ACTIONS` constants and the
  `fee = MARGINAL_FEE * max(GRACE_ACTIONS, logical_actions)` calculation with
  `zcash_primitives::transaction::fees::zip317::FeeRule::standard().fee_required(...)`.
- Kept the iterative funding-note selection loop: the fee still depends on
  the number of funding spends, so the loop converges in at most two steps.
- Replaced the manual `max(num_spends, num_outputs)` Ironwood action-count estimate with
  `builder.bundle_type().num_actions(flags, num_spends, num_outputs)` from the upstream
  Orchard builder. This pins the action count to the exact flags and bundle type used by
  the builder, instead of duplicating the cross-address-enabled arithmetic.
