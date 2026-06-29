Audit Report

## Title
Dust Transfer Permanently Locks/Burns User Tokens When Normalized Amount Rounds to Zero - (File: near/omni-bridge/src/lib.rs)

## Summary

`init_transfer` burns or locks user tokens and stores a pending transfer record without verifying that the fee-adjusted amount, after decimal normalization, is non-zero. When `sign_transfer` is later called, it rejects the transfer because the normalized amount is zero. No public cancellation or refund path exists for stuck pending transfers, making the loss permanent.

## Finding Description

`normalize_amount` applies floor division to convert NEAR-denominated amounts to the destination chain's denomination: [1](#0-0) 

The function's own doc-comment acknowledges that when `fee = 0`, dust "stays locked/burned." However, the critical case is when the *entire* amount normalizes to zero (e.g., `amount = 500_000` with `origin_decimals=24`, `decimals=18`, `diff=6` → `500_000 / 10^6 = 0`).

`init_transfer` only validates `fee < amount`: [2](#0-1) 

It does **not** check that `normalize_amount(amount - fee) > 0`. After this check passes, `init_transfer_internal` immediately burns or locks the full amount: [3](#0-2) 

The normalization guard exists only in `sign_transfer`, after the MPC call setup: [4](#0-3) 

When `sign_transfer` panics at this `require!`, the MPC call is never issued. `remove_transfer_message` (the internal helper that removes the pending record and refunds storage) is only reachable via `sign_transfer_callback` and `claim_fee_callback` — neither of which is ever invoked because `sign_transfer` panics before scheduling any callback. The transfer record remains in `pending_transfers` indefinitely with no public function to cancel it. [5](#0-4) 

## Impact Explanation

This is a **Critical** impact: permanent, irreversible loss of bridged funds. Tokens are burned or locked on NEAR, the transfer can never be signed or finalized, and no recovery mechanism exists. This matches the allowed impact class "permanent freezing of bridged funds" and "decimal/normalization abuse that changes user or protocol balances."

## Likelihood Explanation

**Medium.** The condition requires a token registered with `origin_decimals > decimals` (e.g., a NEAR-native token with 24 decimals bridged to an EVM chain with 18 decimals, a common configuration). Any user sending an amount below the normalization threshold (e.g., less than `10^6` raw units for a diff-of-6 token) triggers the loss. No special privileges are required — the attack path is through the standard `ft_transfer_call` → `ft_on_transfer` → `init_transfer` flow available to any token holder.

## Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) **before** burning or locking tokens. After computing the fee-adjusted amount, look up the token's decimals and verify `normalize_amount(amount - fee, decimals) > 0`; if not, return the full amount as a NEP-141 refund (i.e., return `amount` rather than `U128(0)`). The token address and decimals lookup already performed in `sign_transfer` should be replicated at `init_transfer` time.

As defense-in-depth, add a public `cancel_transfer` function callable by the transfer owner that removes the pending transfer record and unlocks or re-mints the tokens, to handle any future stuck-transfer scenarios.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (normalization factor = `10^6`).
2. User calls `ft_transfer_call` on the NEAR token contract with `amount = 500_000`, `fee = 0`, routing to the bridge's `ft_on_transfer`.
3. `init_transfer` passes the `fee < amount` check (`0 < 500_000`). `init_transfer_internal` burns/locks `500_000` tokens and stores the pending transfer. Returns `U128(0)` — tokens consumed.
4. Relayer calls `sign_transfer` for this transfer ID.
5. `normalize_amount(500_000, Decimals { origin_decimals: 24, decimals: 18 })` = `500_000 / 1_000_000` = `0`.
6. `require!(0 > 0, BridgeError::InvalidAmountToTransfer)` panics. No MPC call is scheduled, no callback fires.
7. The `500_000` tokens are permanently burned/locked. No public function can recover them.

A local unit test can reproduce this by: (a) registering a token with the above decimals, (b) calling `init_transfer` with `amount = 500_000`, (c) asserting the transfer is stored in `pending_transfers`, (d) calling `sign_transfer` and asserting it panics with `InvalidAmountToTransfer`, and (e) confirming no public function removes the record or restores the tokens.

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
