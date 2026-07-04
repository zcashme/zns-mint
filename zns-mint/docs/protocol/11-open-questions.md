# 11 - Open Questions

These are protocol or implementation decisions that are not fully fixed.

## Broadcast Interface

The mint should use Zebra as its chain interface. The current code already uses
Zebra gRPC for tips and full blocks. The exact Zebra transaction submission RPC
surface still needs to be wired into code.

## Restart Cost

The mint is in-memory only; on every boot it replays from the static birthday
checkpoint. As the chain grows since the birthday, restart cost grows with it.
Whether the mint should ever hold durable state (and under what trust model)
is an open question. Today there is none.
