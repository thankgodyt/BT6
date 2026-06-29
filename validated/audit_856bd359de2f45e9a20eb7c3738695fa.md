### Title
Rounding to Zero in `normalize_amount` Permanently Freezes User Funds - (`near/omni-bridge/src/lib.rs`)

### Summary

The `normalize_amount` function uses floor (integer) division to scale token amounts from the origin chain's decimal precision to the destination chain's decimal precision. When a user initiates a transfer with an `amount_without_fee` smaller than the decimal divisor (`10^(origin_decimals - decimals)`), the result rounds to zero. Because tokens are locked/burned in `init_transfer_internal` **before** this zero-check is ever evaluated in `sign_transfer`, the transfer becomes permanently stuck and the user's funds are irrecoverable.

### Finding Description

`normalize_amount` performs floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

When a user calls `ft_transfer_call` → `init_transfer`, the only validation on the amount is that `fee.fee < transfer_message.amount`: [2](#0-1) 

There is no check that `amount_without_fee >= 10^(origin_decimals - decimals)`. Execution then proceeds to `init_transfer_internal`, which **locks or burns the tokens** before returning: [3](#0-2) 

Later, when a trusted relayer calls `sign_transfer`, `normalize_amount` is applied to `amount_without_fee`: [4](#0-3) 

If the result is zero, `sign_transfer` panics with `InvalidAmountToTransfer`. Since the tokens are already locked and there is no cancel/refund path for this failure mode, the transfer remains in `pending_transfers` indefinitely and the user's funds are permanently frozen.

### Impact Explanation

This is a **permanent freezing of bridged funds**. The user's tokens are locked on the NEAR side (or burned if it is a deployed bridge token) and can never be released because `sign_transfer` will always revert for that transfer. There is no cancel or timeout mechanism visible in the contract that would allow recovery.

### Likelihood Explanation

The likelihood depends on the decimal difference between origin and destination chains. For any token pair where `origin_decimals > decimals`, the divisor is `10^(origin_decimals - decimals)`. Concrete examples:

- **NEAR (24 decimals) → Ethereum (18 decimals):** divisor = 10^6. Any transfer of fewer than 1,000,000 yoctoNEAR (≈ 0 NEAR in practice) is affected. Low value, but the mechanism is real.
- **wBTC (8 decimals) → a 6-decimal destination:** divisor = 100. Any transfer of 1–99 satoshis (up to ~$0.06 at current prices) is permanently frozen.
- **Any token with a large decimal gap:** the threshold rises, making accidental loss more likely for users unfamiliar with the decimal normalization.

A user who sends a small "test" amount or whose wallet rounds down to a sub-divisor value will permanently lose those funds with no error at deposit time.

### Recommendation

Add a validation in `init_transfer` (before tokens are locked) that ensures `amount_without_fee` is at least `10^(origin_decimals - decimals)` for the destination chain's registered decimals. Alternatively, reject the transfer at `init_transfer` time if `normalize_amount(amount_without_fee, decimals) == 0`, so the user's tokens are never locked in the first place.

### Proof of Concept

1. Register a token with `origin_decimals = 8`, `decimals = 6` (diff = 2, divisor = 100).
2. User calls `ft_transfer_call` with `amount = 99`, `fee = 0`, destination = Ethereum.
3. `init_transfer` passes the `fee < amount` check (0 < 99 ✓).
4. `init_transfer_internal` locks 99 units of the token in the bridge.
5. Relayer calls `sign_transfer`.
6. `normalize_amount(99, {origin_decimals: 8, decimals: 6}) = 99 / 100 = 0`.
7. `require!(amount_to_transfer > 0, ...)` panics — `sign_transfer` reverts.
8. The 99 token units remain locked in `pending_transfers` with no recovery path. [5](#0-4) [4](#0-3) [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L475-485)
```rust
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L554-557)
```rust
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1850-1864)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
```

**File:** near/omni-bridge/src/lib.rs (L2781-2787)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
