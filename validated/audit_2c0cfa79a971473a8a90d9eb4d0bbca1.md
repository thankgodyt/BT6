Audit Report

## Title
Net Transfer Amount Normalization Check Deferred Past Token Lock/Burn — (`File: near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` validates only that `fee < amount` before calling `init_transfer_internal`, which immediately locks or burns the full token amount on NEAR. The check that the normalized net amount is greater than zero is deferred to `sign_transfer`, which is called later by a relayer. If `normalize_amount(amount - fee, decimals)` returns `0`, `sign_transfer` panics and the transfer can never be finalized, leaving the user's tokens permanently locked or burned with no recovery path.

## Finding Description
The exploit path is as follows:

**Step 1 — Validation in `init_transfer`** only checks `fee < amount`: [1](#0-0) 

**Step 2 — `init_transfer_internal` locks or burns the full `transfer_message.amount`** before any normalization check: [2](#0-1) 

The function returns `U128(0)` on success, meaning the tokens are consumed and no refund is issued to the caller. [3](#0-2) 

**Step 3 — The normalization check lives in `sign_transfer`**, called later by a relayer: [4](#0-3) 

**Step 4 — `normalize_amount` uses floor division**: [5](#0-4) 

For a token with `origin_decimals = 24` and `decimals = 6`, the divisor is `10^18`. Any `amount - fee < 10^18` base units produces `normalize_amount(...) = 0`, causing `sign_transfer` to panic with `InvalidAmountToTransfer`. The transfer message remains in `pending_transfers` indefinitely, and the tokens are already gone.

There is no cancel or refund function reachable by the user after `init_transfer_internal` succeeds. The only internal removal path (`remove_transfer_message_without_refund`) is called only in the storage-failure branch, which executes before tokens are locked/burned. [6](#0-5) 

## Impact Explanation
This is a permanent freezing of bridged funds. Tokens are locked or burned on NEAR, the corresponding `sign_transfer` call will always revert for this transfer ID, and no admin or user function can recover them. This matches the Critical impact class: *permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows*.

## Likelihood Explanation
Any unprivileged user can trigger this via `ft_on_transfer` (the standard NEP-141 token callback). No special role or leaked key is required. Tokens with large decimal gaps — such as NEAR-native tokens (24 decimals) bridged to EVM chains (6 decimals) — have an 18-decimal divisor, meaning any transfer below 1 EVM-unit of the token triggers the bug. This is a realistic and common scenario for users unfamiliar with decimal precision differences.

## Recommendation
Add a normalization check inside `init_transfer`, after constructing `transfer_message` but before calling `init_transfer_internal`. Retrieve the token address and decimals for the destination chain and require that `normalize_amount(amount - fee, decimals) > 0`. This mirrors the existing guard in `sign_transfer` and ensures tokens are never locked or burned for a transfer that can never be finalized. [7](#0-6) 

## Proof of Concept
1. Register a token with `origin_decimals = 24`, `decimals = 6` (divisor = `10^18`).
2. Alice calls `ft_on_transfer` transferring `500_000_000_000_000_000` base units (`0.5 × 10^18`) with `fee = 0` to an EVM recipient.
3. `init_transfer` passes the `fee < amount` check.
4. `init_transfer_internal` locks `500_000_000_000_000_000` units in `locked_tokens` (or burns them) and returns `U128(0)`.
5. A relayer calls `sign_transfer`. `normalize_amount(500_000_000_000_000_000, {24, 6})` = `500_000_000_000_000_000 / 10^18` = `0`.
6. `require!(amount_to_transfer > 0, ...)` panics — `sign_transfer` reverts.
7. The transfer message stays in `pending_transfers` forever; Alice's tokens are permanently locked/burned.

A local unit test can reproduce this by constructing a `TransferMessage` with the above parameters, calling `init_transfer_internal` directly, asserting it returns `U128(0)` (tokens consumed), then calling `sign_transfer` and asserting it panics with `InvalidAmountToTransfer`.

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

**File:** near/omni-bridge/src/lib.rs (L554-584)
```rust
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );

        let required_storage_balance =
            self.required_balance_for_init_transfer_message(transfer_message.clone());

        let message_storage_account_id = transfer_message
            .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));

        // Choose storage payer or whether to yield execution until storage is available
        if self
            .try_to_transfer_balance_from_message_account(
                &message_storage_account_id,
                NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
                &signer_id,
                required_storage_balance,
            )
            .is_ok()
            || (self.has_storage_balance(
                &signer_id,
                required_storage_balance.saturating_add(NearToken::from_yoctonear(
                    init_transfer_msg.native_token_fee.0,
                )),
            ) && (init_transfer_msg.native_token_fee.0 == 0
                || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
        {
            PromiseOrPromiseIndexOrValue::Value(
                self.init_transfer_internal(transfer_message, signer_id),
            )
```

**File:** near/omni-bridge/src/lib.rs (L1838-1848)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1863-1865)
```rust
        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
    }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
