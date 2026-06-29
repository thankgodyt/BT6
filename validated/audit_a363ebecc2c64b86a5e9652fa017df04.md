Audit Report

## Title
Missing Pre-Validation of `normalize_amount` in `init_transfer` Permanently Freezes User Funds — (`File: near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` locks or burns user tokens and inserts the transfer into `pending_transfers` without verifying that `normalize_amount(amount_without_fee)` is non-zero. When the net transfer amount is smaller than `10^(origin_decimals − decimals)`, `sign_transfer` will always revert with `ERR_INVALID_AMOUNT_TO_TRANSFER`. Because no public cancel or refund entry point exists for pending transfers, the user's tokens are permanently frozen in the bridge.

## Finding Description

`normalize_amount` performs integer floor division: [1](#0-0) 

`sign_transfer` calls this on `amount_without_fee()` and hard-reverts if the result is zero: [2](#0-1) 

`init_transfer`, however, only validates `fee < amount` — it does not verify that the normalized net amount will be positive: [3](#0-2) 

After this check passes, `init_transfer_internal` immediately inserts the transfer into `pending_transfers` via `add_transfer_message`, then burns or locks the tokens: [4](#0-3) 

`remove_transfer_message` is a private helper with no public-facing wrapper. Grep across the entire contract confirms there is no `pub fn cancel`, `pub fn refund`, or `pub fn withdraw` entry point for pending transfers. The only callers of `remove_transfer_message` / `remove_transfer_message_without_refund` are internal paths that are unreachable when `sign_transfer` permanently reverts: [5](#0-4) 

## Impact Explanation

This constitutes **permanent freezing of bridged funds**, which is explicitly within the Critical allowed impact scope. Once `init_transfer` succeeds, the tokens are burned or locked on NEAR. Because `sign_transfer` will always revert for that `transfer_id` (normalized amount is always zero), no MPC signature is ever produced, no destination-chain event is ever emitted, and `claim_fee` cannot be invoked. The funds are irrecoverable without a DAO-level contract upgrade.

## Likelihood Explanation

Tokens with a decimal gap between origin and destination chains are a normal, expected configuration (e.g., a NEAR-native token with 24 decimals bridged to an 18-decimal EVM chain, giving `diff_decimals = 6`). Any user who transfers fewer than `10^diff_decimals` base units net of fee triggers the freeze — for a 6-decimal gap this threshold is 1,000,000 base units, a plausible dust or test transfer amount. The entry path is the fully public `ft_transfer_call` → `ft_on_transfer` NEP-141 callback, requiring no special role.

## Recommendation

Add the normalization check inside `init_transfer`, before `init_transfer_internal` is called, mirroring the existing guard in `sign_transfer`:

```rust
let token_address = self.get_token_address(
    init_transfer_msg.get_destination_chain(),
    self.get_token_id(&OmniAddress::Near(token_id.clone())),
).near_expect(BridgeError::FailedToGetTokenAddress);

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

Placing this check before any state mutation ensures the NEP-141 transfer is simply refunded rather than locked.

## Proof of Concept

1. Deploy a token with `origin_decimals = 24`; register it in the bridge with `decimals = 18` (`diff_decimals = 6`).
2. Call `ft_transfer_call` on the token contract with `amount = 500_000` (< 10^6) and `msg` encoding an `InitTransfer` to an EVM recipient with `fee = 0`.
3. `init_transfer` passes the `fee < amount` check; `init_transfer_internal` inserts the transfer into `pending_transfers` and locks the 500,000 tokens.
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

**File:** near/omni-bridge/src/lib.rs (L1834-1857)
```rust
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
