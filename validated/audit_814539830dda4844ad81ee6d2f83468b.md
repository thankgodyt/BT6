### Title
Transfers with sub-unit amounts permanently lock user funds due to missing normalization pre-check in `sign_transfer` - (File: near/omni-bridge/src/lib.rs)

### Summary

When a user initiates a NEAR → Foreign chain transfer with an `amount_without_fee` smaller than the decimal scaling factor (`10^(origin_decimals - decimals)`), `normalize_amount` returns 0 via floor division. The `require!(amount_to_transfer > 0)` guard in `sign_transfer()` then permanently blocks the MPC signing step. Because `init_transfer_internal` already burned/locked the user's tokens before this check is ever reached, and no cancel or refund path exists for pending transfers, the funds are irrecoverably lost.

### Finding Description

`sign_transfer()` normalizes the transfer amount before requesting an MPC signature:

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
``` [1](#0-0) 

`normalize_amount` uses floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [2](#0-1) 

If `amount_without_fee < 10^(origin_decimals - decimals)`, the result is `0` and `sign_transfer()` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER` every time it is called for that transfer.

`amount_without_fee()` is a simple checked subtraction:

```rust
pub fn amount_without_fee(&self) -> Option<u128> {
    self.amount.0.checked_sub(self.fee.fee.0)
}
``` [3](#0-2) 

The critical gap is in `init_transfer_internal`, which accepts the transfer, burns or locks the user's tokens, and emits the `InitTransferEvent` — all **before** any normalization check:

```rust
fn init_transfer_internal(
    &mut self,
    transfer_message: TransferMessage,
    storage_owner: AccountId,
) -> U128 {
    ...
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(...);
    ...
    env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
    U128(0)
}
``` [4](#0-3) 

There is no public `cancel_transfer` or refund function. `remove_transfer_message` is only called on successful `sign_transfer_callback` or `claim_fee_callback` completion — neither of which can be reached when `sign_transfer()` always panics. [5](#0-4) 

The `update_transfer_fee` function cannot rescue the transfer: it only allows increasing the fee (not decreasing the amount), and even setting `fee = amount - 1` leaves `amount_without_fee = 1`, which still normalizes to `0` for large decimal gaps. [6](#0-5) 

The codebase documents that "dust stays locked/burned" when `fee = 0`, but this refers to the sub-unit *remainder* after normalization of a valid transfer — not to the case where the *entire* `amount_without_fee` is below the scaling threshold and the transfer can never be signed. [7](#0-6) 

### Impact Explanation

**Critical — permanent freezing of bridged funds.** Any user who initiates a NEAR → Foreign transfer where `amount_without_fee < 10^(origin_decimals - decimals)` will have their tokens permanently burned or locked inside the bridge with no recovery path. The transfer entry remains in `pending_transfers` indefinitely, and `sign_transfer()` will revert on every call.

### Likelihood Explanation

**Moderate.** The decimal gap is largest for tokens with high NEAR-side precision bridging to low-precision destination chains. For example, a token registered with `origin_decimals = 24` and `decimals = 6` (a common USDC-like configuration) has a scaling factor of `10^18`. Any transfer of less than one full destination-chain unit (e.g., less than 1 USDC-equivalent) triggers the bug. Users unfamiliar with decimal normalization — or those who set a fee close to their transfer amount — can easily fall into this trap. The entry point (`ft_transfer_call` → `ft_on_transfer`) is fully public and requires no special role.

### Recommendation

Add a normalization pre-check inside `init_transfer_internal` (or in the `init_transfer` wrapper before calling it). If the normalized `amount_without_fee` is zero, return the full token amount as a refund instead of burning/locking:

```rust
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
if normalized == 0 {
    return transfer_message.amount; // refund to sender
}
```

This mirrors the existing pattern used when storage balance is insufficient in `init_transfer_internal`. [8](#0-7) 

### Proof of Concept

1. Token is registered with `origin_decimals = 24`, `decimals = 6`; scaling factor = `10^18`.
2. User calls `ft_transfer_call` on the token contract, sending `amount = 5 × 10^17` to the bridge with `fee = 0`.
3. `init_transfer_internal` stores the transfer in `pending_transfers`, burns `5 × 10^17` tokens, and emits `InitTransferEvent`. [9](#0-8) 
4. A trusted relayer calls `sign_transfer()`:
   - `amount_without_fee() = 5 × 10^17`
   - `normalize_amount(5 × 10^17, {decimals: 6, origin_decimals: 24}) = 5 × 10^17 / 10^18 = 0`
   - `require!(0 > 0, ERR_INVALID_AMOUNT_TO_TRANSFER)` → **panics** [10](#0-9) 
5. Every subsequent call to `sign_transfer()` for this transfer ID panics identically.
6. The user's `5 × 10^17` tokens are permanently burned; the transfer entry is permanently stuck in `pending_transfers` with no refund path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-402)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
                );
```

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

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
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
