### Title
Permanent Locking of User Funds via Zero-Normalized Amount Check in `sign_transfer` — (`near/omni-bridge/src/lib.rs`)

### Summary

In `sign_transfer`, the net transfer amount (`amount - fee`) is normalized to the destination chain's decimal precision before a `require!(amount_to_transfer > 0, ...)` guard. When a user sets a fee such that `amount - fee` is a positive integer but smaller than the decimal-scaling factor (`10^(origin_decimals - decimals)`), floor division produces zero, the guard panics, and the transfer is permanently stuck. No cancel or refund path exists for pending transfers, so the locked tokens are irrecoverable without admin intervention.

---

### Finding Description

`sign_transfer` in `near/omni-bridge/src/lib.rs` computes the amount to deliver on the destination chain by:

1. Subtracting the fee: `amount_without_fee = amount - fee.fee`
2. Normalizing to destination precision: `amount_to_transfer = amount_without_fee / 10^(origin_decimals - decimals)`
3. Asserting the result is positive:

```rust
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [1](#0-0) 

The normalization uses integer floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [2](#0-1) 

The only guard at `init_transfer` time is `fee.fee < amount`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [3](#0-2) 

This permits any `fee` in `[0, amount-1]`, including values where `amount - fee < 10^diff_decimals`. There is no minimum-net-amount check at deposit time.

`amount_without_fee` is defined as:

```rust
pub fn amount_without_fee(&self) -> Option<u128> {
    self.amount.0.checked_sub(self.fee.fee.0)
}
``` [4](#0-3) 

Once the transfer message is stored in `pending_transfers`, the only completion path is `sign_transfer`. The `update_transfer_fee` function only allows the fee to be **increased**, not decreased:

```rust
require!(
    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [5](#0-4) 

Increasing the fee makes `amount - fee` even smaller, keeping `amount_to_transfer` at zero. There is no cancel or refund entrypoint for pending transfers.

---

### Impact Explanation

**Permanent freezing of bridged funds.** A user who initiates a NEAR→EVM transfer with a fee satisfying `0 < amount - fee < 10^(origin_decimals - decimals)` will have their tokens locked in the bridge contract indefinitely. `sign_transfer` will always panic at the `require!(amount_to_transfer > 0, ...)` guard, and no other code path can remove the transfer message or return the tokens.

**Concrete example** (NEAR token with 24 origin decimals bridged to an EVM chain where it is registered with 18 decimals, `diff_decimals = 6`):

| Field | Value |
|---|---|
| `amount` | `2_000_000` (NEAR units) |
| `fee.fee` | `1_999_999` |
| `amount_without_fee` | `1` |
| `normalize_amount(1, diff=6)` | `0` |
| Result | `sign_transfer` panics; tokens locked forever |

---

### Likelihood Explanation

Any user transferring a token whose NEAR decimals exceed the destination chain's registered decimals (a common configuration — e.g., 24 NEAR decimals → 18 EVM decimals) can trigger this by setting a fee that leaves a sub-unit remainder. This can happen accidentally (user unaware of decimal scaling) or deliberately (self-griefing or griefing via a contract that initiates transfers on behalf of others). The `init_transfer` validation does not prevent it.

---

### Recommendation

Add a minimum net-amount check at `init_transfer` time, after computing the normalized amount:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the existing check in `sign_transfer` but fires before tokens are locked, allowing the transaction to revert cleanly. Alternatively, add a cancel/refund entrypoint for pending transfers so that stuck transfers can be unwound.

---

### Proof of Concept

1. Register a NEAR token on an EVM chain with `origin_decimals = 24`, `decimals = 18` (`diff_decimals = 6`).
2. Call `ft_transfer_call` → `init_transfer` with `amount = 2_000_000`, `fee = 1_999_999`. The check `fee < amount` passes; tokens are locked; transfer message is stored.
3. Call `sign_transfer` for this transfer. Inside:
   - `amount_without_fee() = 1`
   - `normalize_amount(1, diff=6) = 1 / 1_000_000 = 0`
   - `require!(0 > 0, ...)` → **panic: `ERR_INVALID_AMOUNT_TO_TRANSFER`**
4. Call `update_transfer_fee` with any higher fee — still `amount_without_fee < 10^6`, still normalizes to 0.
5. No other entrypoint can remove the transfer message or return the tokens. Funds are permanently locked. [6](#0-5) [2](#0-1) [3](#0-2) [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-402)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
                );
```

**File:** near/omni-bridge/src/lib.rs (L447-485)
```rust
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
        let transfer_message = self.get_transfer_message(transfer_id);

        if let Some(fee) = &fee {
            require!(
                &transfer_message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
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
