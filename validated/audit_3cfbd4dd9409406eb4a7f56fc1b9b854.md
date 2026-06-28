### Title
Decimal Normalization Floor Division Permanently Freezes User Funds When `normalize_amount` Returns Zero - (`near/omni-bridge/src/lib.rs`)

### Summary

`sign_transfer` applies `normalize_amount` (floor division) to `amount_without_fee` before signing. If the user's net transfer amount is smaller than `10^(origin_decimals − decimals)`, the result is 0 and the function panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`. Because tokens are already burned or locked inside `init_transfer_internal` before `sign_transfer` is ever called, and no cancellation path exists, those tokens are permanently frozen.

### Finding Description

`normalize_amount` performs integer floor division: [1](#0-0) 

In `sign_transfer`, this is applied to `amount_without_fee()`: [2](#0-1) [3](#0-2) 

`amount_without_fee()` is simply `amount - fee`: [4](#0-3) 

The only guard at `init_transfer` time is `fee < amount`, which does **not** ensure `normalize_amount(amount - fee) > 0`: [5](#0-4) 

By the time `sign_transfer` is called, `init_transfer_internal` has already burned (for deployed/bridged tokens) or locked (for native tokens) the full user amount: [6](#0-5) 

The panic in `sign_transfer` does not remove the transfer message from `pending_transfers` and does not trigger any refund. There is no `cancel_transfer` function. `update_transfer_fee` can only raise the fee (never below the current value), so it cannot rescue a transfer whose `amount_without_fee` is already below the normalization threshold: [7](#0-6) 

### Impact Explanation

Tokens are permanently frozen. For a token registered with `origin_decimals = 24` (NEAR) and `decimals = 6` (a 6-decimal EVM token), the normalization divisor is `10^18`. Any user who initiates a transfer with `amount_without_fee < 10^18` (i.e., less than 1 full NEAR-side unit) will have their tokens burned or locked with no recovery path. The transfer message remains in `pending_transfers` indefinitely, and `sign_transfer` will panic on every call. This constitutes permanent loss of bridged funds.

### Likelihood Explanation

The condition is reachable by any unprivileged user who calls `ft_transfer_call` with a small amount. The `init_transfer` validation only checks `fee < amount`; it does not validate that `normalize_amount(amount - fee) > 0`. Tokens with large decimal gaps (e.g., 24 vs 6) make the threshold large enough to trap ordinary user amounts. A user sending a "dust" amount, or a user who misunderstands the decimal scaling, triggers this silently.

### Recommendation

Add a normalization check at `init_transfer` time, before tokens are burned or locked, to reject transfers whose net amount would normalize to zero:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This requires looking up the token's `Decimals` during `init_transfer`, mirroring the lookup already performed in `sign_transfer`. [8](#0-7) 

### Proof of Concept

1. DAO registers a token with `origin_decimals = 24`, `decimals = 6` (normalization divisor = `10^18`).
2. User calls `ft_transfer_call` with `amount = 500_000_000_000_000_000` (0.5 NEAR-side units, below the threshold).
3. `init_transfer` passes: `fee (0) < amount (5×10^17)` ✓.
4. `init_transfer_internal` burns/locks the 500,000,000,000,000,000 tokens and stores the transfer message.
5. Relayer calls `sign_transfer`. `normalize_amount(5×10^17, {24, 6}) = 5×10^17 / 10^18 = 0`.
6. `require!(0 > 0, ...)` panics → `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. No state is rolled back. Tokens are permanently frozen. [9](#0-8) [3](#0-2)

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-401)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
```

**File:** near/omni-bridge/src/lib.rs (L471-485)
```rust
        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
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

**File:** near/omni-types/src/lib.rs (L593-595)
```rust
    pub fn amount_without_fee(&self) -> Option<u128> {
        self.amount.0.checked_sub(self.fee.fee.0)
    }
```
