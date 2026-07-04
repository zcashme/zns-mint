# 05 - Lifecycle

## Actions

ZNS v1 has three actions:

- `claim`: create a live binding from a free name to a UA;
- `update`: change a live binding to a new UA;
- `release`: terminate a live binding.

There is no `transfer` action in v1. Ownership is represented by control of the
current UA and by the Registry's ability to extend the Name Note chain under the
authorization policy.

## Chain State

For each name, the mint tracks the latest confirmed Name Note:

```text
Tip {
  action,
  rcm
}
```

The name is live if the tip action is not `release`.

## Chain Rule

The transition rule is:

- `claim` is allowed when the name has no tip;
- `claim` is allowed when the current tip is `release`;
- `update` is allowed only when the current tip is live;
- `release` is allowed only when the current tip is live.

The required `prev_rcm` is:

- all-zero 32 bytes for a valid `claim`;
- the live tip's `rcm` for `update` or `release`.

## Rebuild From Chain

The Registry database is not authoritative. On restart or reorg, the Registry
must be able to rebuild name state by replaying confirmed Name Notes in chain
order.

If two candidate Name Notes conflict, the best-chain order and Orchard spend
validity decide which one exists. A spent prior Name Note cannot be extended
twice on the same valid chain.

## Release Semantics

A release is terminal for the current chain, not permanent for the name. After a
release is confirmed, the name can be claimed again using genesis
`ZERO_PREV_RCM`.
