# Context for src/metrics.rs (zns-mint)

This file holds the small Prometheus-facing metrics surface for the daemon.

## Current State
- `set_boot_success(success: bool)` records boot status in a Prometheus integer gauge.
- Metric name: `zns_mint_boot_success`
- Semantics:
  - `1` = boot succeeded
  - `0` = boot failed
- The helper registers the gauge on demand and sets it immediately.

## Purpose
The metrics module is intentionally tiny and is meant to stay that way until the daemon needs more operational observability.

The current job is to provide one clear boot outcome signal without pulling metrics concerns into `main.rs` or the key/boot code.

## Constraints
- Keep the module minimal unless the user asks for more metrics.
- Do not introduce config parsing or env-var driven metric behavior.
- Keep metric names stable unless a deliberate compatibility change is made.

## Related Files
- `src/boot.rs.context.md` - boot flow that should drive this metric
- `src/main.rs.context.md` - overall daemon behavior and constraints

