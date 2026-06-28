### Title
Decimal-Normalization Dust Permanently Locked When `fee = 0` — (`near/omni-bridge/src/lib.rs`)

### Summary
When a user initiates a NEAR → foreign-chain transfer with `fee = 0`, the floor-division in `normalize_amount` silently truncates a sub-unit remainder ("dust"). Because the full pre-truncation amount is locked/burned on NEAR, and the transfer message is deleted immediately after MPC signing when the fee is zero, the dust has no recipient and no recovery path — it is permanently frozen inside the bridge escrow.

### Finding Description
`normalize_amount` performs integer floor division to convert a NEAR-native token amount to the destination chain's lower precision:

```rust
// near/omni-bridge/src/lib.rs  L2784-2786
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

The code's own comment acknowledges the two outcomes:

```
/// When fee > 0, dust is absorbed into the fee via `claim_fee`.
/// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
``` [2](#0-1) 

**Fee > 0 path (safe):** `claim_fee_callback` computes `fee = transfer_message.amount.0 - denormalized_amount`, which naturally captures the dust and pays it to the relayer: [3](#0-2) 

**Fee = 0 path (vulnerable):** `sign_transfer_callback` removes the transfer message immediately after MPC signing:

```rust
// near/omni-bridge/src/lib.rs  L656-658
if fee.is_zero() {
    self.remove_transfer_message(message_payload.transfer_id);
}
``` [4](#0-3) 

After removal there is no pending `claim_fee` call and no other code path that can recover the dust. Meanwhile, `init_transfer_internal` has already locked or burned the **full** pre-normalization amount:

```rust
// near/omni-bridge/src/lib.rs  L1850-1857
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,
);
``` [5](#0-4) 

The destination chain receives only `normalize_amount(X)` tokens; the remainder `X − denormalize(normalize(X))` is permanently frozen in the NEAR bridge escrow.

### Impact Explanation
For any token whose NEAR decimals exceed the destination-chain decimals (e.g., 18 NEAR decimals vs. 6 EVM decimals, a common configuration for USDC-like assets), the maximum dust per transfer is `10^(origin_decimals − decimals) − 1` base units. With a 12-decimal gap that is up to `10^12 − 1` base units per transfer. Every user who sends a non-divisible amount with `fee = 0` permanently loses that dust — it is locked in the NEAR bridge contract with no withdrawal, refund, or sweep function available.

This constitutes **permanent freezing of bridged user funds**, matching the Critical impact tier.

### Likelihood Explanation
The `fee` field is user-supplied and zero is a natural default for self-relayed or protocol-subsidised transfers. Any unprivileged token holder who calls `ft_transfer_call` (the public `ft_on_transfer` entry point) with a non-round amount and `fee = 0` triggers the loss. No special role, no admin key, and no race condition is required.

### Recommendation
Before locking/burning tokens in `init_transfer_internal`, round the transfer amount down to the nearest multiple of `10^(origin_decimals − decimals)` and return the dust to the sender immediately (or reject amounts that are not already aligned). This mirrors the fix implied by the external report: account for every sub-unit before committing the escrow, so that `locked_amount == denormalize(normalize(locked_amount))` is always an invariant.

Alternatively, if rounding at entry is undesirable, store the dust alongside the transfer record and release it to the sender when the transfer message is removed in `sign_transfer_callback` for the `fee = 0` case.

### Proof of Concept
1. Token `T` is registered with `origin_decimals = 18`, `decimals = 6` (12-decimal gap; scale factor = `10^12`).
2. User calls `ft_transfer_call` on the NEAR token contract, sending `amount = 1_000_000_000_001` (1 unit + 1 base unit) to the bridge with `fee = 0`.
3. `init_transfer_internal` locks `1_000_000_000_001` base units on NEAR.
4. MPC signs the transfer; `sign_transfer_callback` sees `fee.is_zero()` and calls `remove_transfer_message` — the record is gone.
5. The destination chain receives `normalize_amount(1_000_000_000_001, {18,6}) = 1` unit (i.e., `1_000_000` in 6-decimal representation).
6. The `1` base-unit dust (`1_000_000_000_001 − denormalize(1) = 1`) remains locked in the NEAR bridge escrow forever; no function exists to recover it.

### Citations

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```

**File:** near/omni-bridge/src/lib.rs (L1128-1131)
```rust
        // Fee includes both the user-specified fee and any dust lost during decimal
        // normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
        // due to floor division, the difference naturally captures the normalization remainder.
        let fee = transfer_message.amount.0 - denormalized_amount;
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```

**File:** near/omni-bridge/src/lib.rs (L2781-2783)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
