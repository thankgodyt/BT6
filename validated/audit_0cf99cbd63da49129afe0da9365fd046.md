### Title
Permanently Frozen User Funds Due to Missing Pre-Validation of `normalize_amount` at Transfer Initiation — (`File: near/omni-bridge/src/lib.rs`)

### Summary

`init_transfer` accepts and locks user tokens without verifying that `normalize_amount(amount_without_fee)` will be non-zero. When a user bridges a token whose on-chain decimals differ from the destination decimals, any transfer whose net amount (after fee) is smaller than `10^(origin_decimals − decimals)` will normalize to zero. The subsequent `sign_transfer` call then permanently reverts with `ERR_INVALID_AMOUNT_TO_TRANSFER`, and because no cancel/refund path exists for pending transfers, the user's tokens are frozen in the bridge forever.

### Finding Description

`normalize_amount` performs integer floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

`sign_transfer` calls this on `amount_without_fee()` and hard-reverts if the result is zero:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [2](#0-1) 

`init_transfer`, however, only checks `fee < amount`; it does **not** verify that the normalized net amount will be positive:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [3](#0-2) 

After this check passes, `init_transfer_internal` immediately locks or burns the tokens and inserts the transfer into `pending_transfers`: [4](#0-3) 

There is no public cancel or refund entry point for pending transfers. `remove_transfer_message` is only called internally from `sign_transfer_callback` (on successful MPC signing with zero fee) and `claim_fee_callback` (which itself requires a destination-chain proof that can never be produced if the transfer was never signed): [5](#0-4) 

### Impact Explanation

A user who initiates a NEAR→EVM transfer for a token with `origin_decimals > decimals` (e.g., a token stored with 24 decimals on NEAR but bridged to an 18-decimal EVM representation, giving `diff_decimals = 6`) and whose `amount_without_fee < 10^6` (i.e., less than 1 full destination-chain unit) will have their tokens permanently locked in the bridge. `sign_transfer` will always revert for that `transfer_id`, no MPC signature is ever produced, no destination-chain event is ever emitted, and therefore `claim_fee` cannot be invoked either. The funds are irrecoverable without a DAO-level contract upgrade.

This constitutes **permanent freezing of bridged funds**, which is within the Critical allowed impact scope.

### Likelihood Explanation

Tokens with a decimal gap between origin and destination chains are a normal, expected configuration (e.g., a NEAR-native token with 24 decimals bridged to an EVM chain that uses 18 decimals). Any user who transfers fewer than `10^diff_decimals` base units net of fee triggers the freeze. For a 6-decimal gap this threshold is 1,000,000 base units — a plausible "dust" or test transfer amount. The entry path is the fully public `ft_on_transfer` NEP-141 callback, requiring no special role.

### Recommendation

Add the normalization check at initiation time, before tokens are locked:

```rust
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
require!(
    Self::normalize_amount(
        transfer_message.amount_without_fee()
            .near_expect(BridgeError::InvalidFee),
        decimals,
    ) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the existing guard in `sign_transfer` but places it before any state mutation, so the NEP-141 transfer is simply refunded rather than locked.

### Proof of Concept

1. Deploy a token with `origin_decimals = 24`; register it in the bridge with `decimals = 18` (`diff_decimals = 6`).
2. Call `ft_transfer_call` on the token contract with `amount = 500_000` (< 10^6) and `msg` encoding an `InitTransfer` to an EVM recipient with `fee = 0`.
3. `init_transfer` passes the `fee < amount` check; `init_transfer_internal` locks the 500,000 tokens and inserts the transfer into `pending_transfers`.
4. A trusted relayer calls `sign_transfer` for the resulting `transfer_id`.
5. `normalize_amount(500_000, {origin_decimals:24, decimals:18}) = 500_000 / 1_000_000 = 0`.
6. `require!(amount_to_transfer > 0, ...)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. The transfer remains in `pending_transfers` indefinitely; the 500,000 tokens are permanently locked in the bridge with no user-accessible recovery path.

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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
