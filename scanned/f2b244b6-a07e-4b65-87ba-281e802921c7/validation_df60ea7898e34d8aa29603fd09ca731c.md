### Title
No Minimum Transfer Amount Validation Allows Permanently Unprocessable Pending Transfers — (`near/omni-bridge/src/lib.rs`)

---

### Summary

The NEAR-side `init_transfer` function burns/locks user tokens and stores a pending transfer without verifying that the transfer amount, after decimal normalization, will be greater than zero. When a relayer later calls `sign_transfer` for such a transfer, the contract panics with `InvalidAmountToTransfer`. Because no cancellation or refund path exists for stuck pending transfers, the user's tokens are permanently frozen.

---

### Finding Description

**Root cause — missing pre-validation in `init_transfer`:**

`init_transfer` enforces only that `fee.fee < amount`: [1](#0-0) 

It then immediately burns/locks the tokens and stores the transfer in `pending_transfers`: [2](#0-1) 

No check is made that `normalize_amount(amount - fee, decimals) > 0`.

**Where the revert occurs — `sign_transfer`:**

The normalization check only happens later, when a trusted relayer calls `sign_transfer`: [3](#0-2) 

`normalize_amount` uses floor division: [4](#0-3) 

For any token whose NEAR-side decimals exceed the destination-chain decimals (e.g., NEAR native token: 24 decimals on NEAR, 6 decimals on EVM — normalization factor = 10¹⁸), any transfer amount strictly below the normalization factor produces `normalize_amount(...) == 0`, causing `sign_transfer` to always panic.

**No recovery path exists:**

`remove_transfer_message` is only called inside `claim_fee_callback`, which requires a successful on-chain finalization proof from the destination chain — impossible for a transfer that can never be signed: [5](#0-4) 

`remove_transfer_message_without_refund` is only reachable during the initialization storage-check failure path, not after a transfer is committed: [6](#0-5) 

There is no admin cancel, no user-initiated refund, and no timeout mechanism. The pending transfer entry and the locked/burned tokens are permanently irrecoverable.

The protocol's own comment acknowledges the dust-locking behavior but treats it as a known minor remainder issue, not as a full-amount freeze: [7](#0-6) 

---

### Impact Explanation

A user who transfers any amount strictly below the decimal normalization threshold (e.g., less than 1 NEAR = 10¹⁸ yoctoNEAR for a NEAR→EVM-6-decimal route) will have their tokens permanently burned/locked on NEAR with no finalization possible on the destination chain and no refund path. This constitutes **permanent freezing of bridged funds**, which is within the critical impact scope.

---

### Likelihood Explanation

The vulnerability is reachable by any unprivileged bridge user via the standard `ft_transfer_call` → `init_transfer` path. It is triggered whenever:

1. The token has a larger decimal count on NEAR than on the destination chain (e.g., NEAR native token: 24 vs 6 = factor of 10¹⁸), and
2. The user transfers an amount below the normalization threshold.

For the NEAR native token bridged to a 6-decimal EVM chain, any transfer under 1 NEAR triggers the freeze. This is a realistic user mistake (e.g., testing with a small amount, or a UI that does not enforce a minimum). The EVM-side `initTransfer` has the same gap — no minimum amount check — making the same class of mistake possible from EVM: [8](#0-7) 

---

### Recommendation

Add a pre-validation step in `init_transfer` (NEAR side) that reads the token's registered `Decimals` and asserts `normalize_amount(amount - fee, decimals) > 0` before burning/locking tokens and storing the pending transfer. Equivalently, enforce a protocol-level minimum transfer amount per token that accounts for the decimal normalization factor. The same guard should be applied in the EVM `initTransfer` if a minimum is desired there.

---

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 6` (normalization factor = 10¹⁸).
2. Call `ft_transfer_call` on the NEAR token contract with `amount = 10¹⁸ - 1` (just below 1 NEAR), passing an `InitTransferMsg` with `fee = 0`.
3. `init_transfer` passes the `fee < amount` check, burns the tokens, and stores the transfer in `pending_transfers`.
4. A trusted relayer calls `sign_transfer` for the resulting `TransferId`.
5. `normalize_amount(10¹⁸ - 1, {decimals: 6, origin_decimals: 24})` = `(10¹⁸ - 1) / 10¹⁸` = `0`.
6. The `require!(amount_to_transfer > 0, ...)` check panics — `sign_transfer` always reverts for this transfer.
7. The `10¹⁸ - 1` yoctoNEAR worth of tokens remain burned/locked with no recovery path. [1](#0-0) [3](#0-2) [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L1846-1848)
```rust
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L381-384)
```text
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }
```
