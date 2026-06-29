### Title
Floor Division in `normalize_amount` Permanently Freezes Bridged Funds When Transfer Amount Is Below Decimal Normalization Unit — (`near/omni-bridge/src/lib.rs`)

---

### Summary

When a user initiates a NEAR→EVM transfer for a token whose NEAR decimals exceed its EVM decimals (e.g., 24 vs 18), any transfer amount (after fee) smaller than `10^(origin_decimals − dest_decimals)` normalizes to zero via floor division. `sign_transfer` then permanently rejects the transfer with `ERR_INVALID_AMOUNT_TO_TRANSFER`, while the user's tokens are already burned or locked from the earlier `init_transfer_internal` call. There is no cancel or refund path for pending NEAR-originated transfers, so the funds are permanently lost.

---

### Finding Description

`init_transfer` accepts any amount satisfying `fee < amount` and immediately burns or locks the full token amount in `init_transfer_internal`: [1](#0-0) [2](#0-1) 

Later, when a trusted relayer calls `sign_transfer`, the bridge computes the destination-chain amount via `normalize_amount`: [3](#0-2) 

`normalize_amount` uses floor division: [4](#0-3) 

If `amount_without_fee < 10^(origin_decimals − decimals)`, the result is `0` and `sign_transfer` panics. The transfer message remains in `pending_transfers` indefinitely. `sign_transfer_callback` — the only place that calls `remove_transfer_message` for zero-fee transfers — is never reached: [5](#0-4) 

There is no public cancel or user-initiated refund function for NEAR-originated pending transfers. The tokens are permanently burned (bridge tokens) or locked (native tokens).

The code comment on `normalize_amount` acknowledges dust being locked when `fee = 0`, but only in the context of sub-unit remainders, not the case where the **entire** `amount_without_fee` normalizes to zero: [6](#0-5) 

---

### Impact Explanation

**Permanent freezing and burning of bridged funds.** For any token with `origin_decimals > dest_decimals` (e.g., a NEAR-native token with 24 decimals bridging to an EVM chain where it is registered with 18 decimals, giving `diff = 6`), any user who calls `ft_transfer_call` with `amount_without_fee < 10^6` (i.e., less than 1,000,000 yoctoNEAR ≈ 0.000001 NEAR) will have their tokens permanently burned or locked with no recovery path. The `sign_transfer` call will always revert for that transfer ID, and no mechanism exists to cancel it.

---

### Likelihood Explanation

**Medium.** The condition is triggered whenever a user submits a transfer whose net amount (after fee) falls below the decimal normalization unit. The `init_transfer` validation only checks `fee < amount`; it does not check that `normalize_amount(amount − fee) > 0`. A user who is unaware of the decimal difference, or who sets a fee close to the transfer amount, can easily trigger this. The decimal difference of 6 (24 → 18) is the standard NEAR-to-EVM configuration, making this a realistic scenario.

---

### Recommendation

Add a pre-flight check in `init_transfer` (or in `init_transfer_internal`) that validates the normalized amount is non-zero before burning or locking tokens. Specifically, look up the destination token's `Decimals` at transfer initiation time and assert:

```rust
require!(
    Self::normalize_amount(amount_without_fee, decimals) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the check already present in `sign_transfer` but must be enforced **before** tokens are burned or locked.

---

### Proof of Concept

1. A NEAR token is registered with `origin_decimals = 24`, `decimals = 18` (diff = 6, divisor = 1,000,000).
2. User calls `ft_transfer_call` transferring `amount = 500_000` yoctoNEAR with `fee = 0`.
3. `init_transfer` passes: `fee (0) < amount (500_000)`. ✓
4. `init_transfer_internal` burns 500,000 yoctoNEAR and stores the transfer message. Tokens are gone.
5. Relayer calls `sign_transfer(transfer_id, ...)`.
6. `normalize_amount(500_000, {24, 18}) = 500_000 / 1_000_000 = 0`.
7. `require!(amount_to_transfer > 0, ...)` panics → `ERR_INVALID_AMOUNT_TO_TRANSFER`.
8. Transfer message stays in `pending_transfers`. No callback fires. No refund path exists.
9. User's 500,000 yoctoNEAR are permanently burned. [3](#0-2) [4](#0-3) [1](#0-0) [2](#0-1)

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

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
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
