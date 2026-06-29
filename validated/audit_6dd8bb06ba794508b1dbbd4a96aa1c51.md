Audit Report

## Title
Missing Pre-Validation of Normalized Transfer Amount Permanently Freezes Funds — (`near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` burns/locks user tokens and stores a pending transfer after checking only that `fee < amount`, without verifying that `normalize_amount(amount - fee, decimals) > 0`. When a relayer later calls `sign_transfer` for such a transfer, the contract panics with `InvalidAmountToTransfer`. No cancellation or refund path exists for the resulting stuck pending transfer, making the user's tokens permanently irrecoverable.

## Finding Description

**Root cause — `init_transfer` missing normalization pre-check:**

`init_transfer` enforces only `fee.fee < transfer_message.amount`: [1](#0-0) 

It then calls `init_transfer_internal`, which stores the transfer via `add_transfer_message` and immediately burns/locks the tokens: [2](#0-1) 

No check is made that `normalize_amount(amount - fee, decimals) > 0` before committing.

**Where the revert occurs — `sign_transfer`:**

The normalization check only happens later when a trusted relayer calls `sign_transfer`: [3](#0-2) 

`normalize_amount` uses floor division: [4](#0-3) 

For any token whose NEAR-side decimals exceed the destination-chain decimals (e.g., NEAR native token: 24 vs 6 decimals, normalization factor = 10¹⁸), any transfer amount strictly below the normalization factor produces `normalize_amount(...) == 0`, causing `sign_transfer` to always panic.

**No recovery path exists:**

`remove_transfer_message` (the refunding path) is only called inside `claim_fee_callback`, which requires a successful on-chain finalization proof from the destination chain — impossible for a transfer that can never be signed: [5](#0-4) 

`remove_transfer_message_without_refund` is only reachable during the storage-check failure path (before tokens are burned/locked) or when the token is not a NEAR-origin token — neither applies after a transfer is committed: [6](#0-5) [7](#0-6) 

There is no admin cancel, no user-initiated refund, and no timeout mechanism.

## Impact Explanation

This constitutes **permanent freezing of bridged funds**, which is explicitly within the Critical impact scope. Any user who transfers an amount below the decimal normalization threshold has their tokens burned/locked on NEAR with no finalization possible on the destination chain and no refund path. The protocol's own comment acknowledges the dust-locking behavior but treats it as a minor remainder issue, not a full-amount freeze: [8](#0-7) 

## Likelihood Explanation

The vulnerability is reachable by any unprivileged bridge user via the standard `ft_transfer_call` → `init_transfer` path. For the NEAR native token bridged to a 6-decimal EVM chain, any transfer under 1 NEAR (i.e., less than 10¹⁸ yoctoNEAR) triggers the freeze. This is a realistic user mistake — testing with a small amount or a UI that does not enforce a minimum. No special privileges, leaked keys, or external collusion are required.

## Recommendation

Add a pre-validation step in `init_transfer` (before burning/locking tokens) that reads the token's registered `Decimals` and asserts `normalize_amount(amount - fee, decimals) > 0`. This mirrors the existing check already present in `sign_transfer` at lines 475–485 and should be applied symmetrically at the point of token commitment. The same guard should be applied in the EVM `initTransfer`.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 6` (normalization factor = 10¹⁸).
2. Call `ft_transfer_call` on the NEAR token contract with `amount = 10¹⁸ - 1` and `fee = 0`.
3. `init_transfer` passes the `fee < amount` check (0 < 10¹⁸ - 1), burns the tokens, and stores the transfer in `pending_transfers`.
4. A trusted relayer calls `sign_transfer` for the resulting `TransferId`.
5. `normalize_amount(10¹⁸ - 1, {decimals: 6, origin_decimals: 24})` = `(10¹⁸ - 1) / 10¹⁸` = `0`.
6. The `require!(amount_to_transfer > 0, ...)` check at line 482–485 panics — `sign_transfer` always reverts for this transfer.
7. The `10¹⁸ - 1` yoctoNEAR worth of tokens remain burned/locked with no recovery path.

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

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
```

**File:** near/omni-bridge/src/lib.rs (L1835-1857)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1859-1860)
```rust
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
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
