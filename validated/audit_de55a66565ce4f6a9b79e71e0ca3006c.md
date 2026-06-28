### Title
User Funds Permanently Locked When `normalize_amount` Rounds Net Transfer Amount to Zero — (`File: near/omni-bridge/src/lib.rs`)

---

### Summary
A user who initiates a NEAR-outbound bridge transfer with a net amount (amount minus fee) smaller than the decimal-normalization divisor will have their tokens permanently locked or burned. The zero-amount guard fires only inside `sign_transfer`, which is called after `init_transfer_internal` has already locked/burned the tokens. No cancellation path exists, so the funds are irrecoverable.

---

### Finding Description

`init_transfer` (called from `ft_on_transfer`) validates only that `fee < amount`: [1](#0-0) 

It then immediately locks or burns the full token amount in `init_transfer_internal`: [2](#0-1) 

The decimal-normalization check is deferred to `sign_transfer`, which is called later by a relayer: [3](#0-2) 

`normalize_amount` performs floor division: [4](#0-3) 

If `(amount - fee) < 10^(origin_decimals - decimals)`, the result is `0`, `sign_transfer` panics with `InvalidAmountToTransfer`, and the transfer message remains in `pending_transfers` forever — with the tokens already locked or burned and no recovery function available.

The codebase comment acknowledges the dust-loss design but only for the sub-unit remainder case: [5](#0-4) 

The unhandled case is when the **entire** net amount rounds to zero, not just a dust remainder.

---

### Impact Explanation

Any user who sends a token amount whose net value (after fee) is below the normalization threshold loses those tokens permanently. For a token registered with `origin_decimals = 24` (NEAR native precision) and `decimals = 6` (EVM representation), the divisor is `10^18`. Any transfer where `amount - fee < 10^18` base units will trigger this path. The tokens are locked/burned on NEAR, the transfer can never be signed, and there is no cancel or refund function.

This constitutes permanent freezing of bridged funds — a Critical impact under the allowed scope.

---

### Likelihood Explanation

The condition is reachable by any unprivileged user calling `ft_on_transfer` with a sufficiently small amount. Tokens with large decimal differences (e.g., 24 vs 6, common for NEAR-native tokens bridged to EVM chains) have an 18-decimal gap, meaning any transfer below 1 EVM-unit of the token triggers the bug. Users unfamiliar with decimal precision differences will naturally hit this.

---

### Recommendation

Add a normalization check inside `init_transfer`, before tokens are locked or burned, to reject transfers whose net amount normalizes to zero:

```rust
// After computing transfer_message, before init_transfer_internal:
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
);
if let Some(addr) = token_address {
    if let Some(decimals) = self.token_decimals.get(&addr) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee().unwrap_or(0),
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```

This mirrors the fix described in the referenced audit (disallow transfers that result in a withdrawable amount of less than one destination-chain unit) and ensures tokens are never locked/burned for a transfer that can never be finalized.

---

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `decimals = 6` (divisor = `10^18`).
2. Alice calls `ft_on_transfer` transferring `500_000_000_000_000_000` base units (0.5 × 10^18) with `fee = 0` to an EVM recipient.
3. `init_transfer` passes the `fee < amount` check and calls `init_transfer_internal`.
4. `init_transfer_internal` locks `500_000_000_000_000_000` units in `locked_tokens` (or burns them if a deployed token).
5. The relayer calls `sign_transfer`. `normalize_amount(500_000_000_000_000_000, {24, 6})` = `500_000_000_000_000_000 / 10^18` = `0`.
6. `require!(amount_to_transfer > 0, ...)` panics — `sign_transfer` reverts.
7. The transfer message stays in `pending_transfers` indefinitely; Alice's tokens are permanently locked/burned with no recovery path. [3](#0-2) [6](#0-5) [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

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
    }
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
