# Use upstream `MINIMUM_FEE` constant instead of hand-rolled fee calculation

## Problem

`otp.rs` contains `required_relay_value()`, which reimplements what upstream already provides as a constant:

```rust
use zcash_primitives::transaction::fees::zip317::zip317::MINIMUM_FEE; // 10_000 zats
```

The function computes the ZIP-317 fee for 2 Ironwood actions by calling `StandardFeeRule::fee_required(...)` with zeros and empty iterators, which is equivalent to `MINIMUM_FEE`.

## Proposed fix

1. Import `MINIMUM_FEE` at call sites in `main.rs`
2. Replace `required_relay_value(&network, target_height)` with `MINIMUM_FEE`
3. Delete `required_relay_value()` from `otp.rs`
4. Remove unused `use zcash_client_backend::fees::StandardFeeRule` from `otp.rs`

## Note

If challenges ever need more than 2 actions, we should call `FeeRule::standard().fee_required()` with the actual action counts instead.
