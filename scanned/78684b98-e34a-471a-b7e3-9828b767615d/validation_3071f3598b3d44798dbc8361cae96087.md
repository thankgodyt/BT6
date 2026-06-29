### Title
Permanent Freezing of Bridged Funds Due to Missing Decimal Normalization Guard in `init_transfer` — (`near/omni-bridge/src/lib.rs`)

---

### Summary

The NEAR Omni Bridge's outbound transfer flow (`init_transfer` → `sign_transfer`) contains a decimal normalization precision flaw. Tokens are locked/burned in `init_transfer` before any check that the post-fee amount survives decimal normalization. When `normalize_amount(amount_without_fee, decimals)` floors to zero due to integer division, `sign_transfer` panics with `InvalidAmountToTransfer`, leaving the transfer message permanently in storage and the user's tokens permanently locked or burned with no recovery path.

---

### Finding Description

**Step 1 — Tokens are locked/burned in `init_transfer`:**

`init_transfer` validates only that `fee.fee < amount`, then immediately locks or burns the full `amount` and stores the `TransferMessage`. [1](#0-0) [2](#0-1) 

There is no check that `amount_without_fee` is large enough to survive normalization to the destination chain's decimal precision.

**Step 2 — `normalize_amount` uses floor division:**

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [3](#0-2) 

For a token with 24 origin decimals (NEAR) and 6 destination decimals (EVM), `diff_decimals = 18`. Any `amount_without_fee < 10^18` normalizes to **zero**.

**Step 3 — `sign_transfer` panics, leaving tokens permanently frozen:**

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [4](#0-3) 

When this panics, the NEAR runtime reverts only the state changes of `sign_transfer`. The `TransferMessage` stored in `init_transfer` (a prior transaction) remains in storage. No MPC signature is produced, so no `fin_transfer` event is emitted on the destination chain, so no proof can ever be submitted to `claim_fee`. The transfer message is never removed.

**Step 4 — No recovery path exists:**

`sign_transfer_callback` only removes the transfer message when `fee.is_zero()`: [5](#0-4) 

`claim_fee_callback` requires a proof from the destination chain, which can never exist because no signature was produced. There is no `cancel_transfer` or user-accessible refund function. The user's tokens are permanently frozen.

---

### Impact Explanation

A user who initiates a NEAR→EVM transfer where `amount_without_fee < 10^(origin_decimals - dest_decimals)` will have their tokens permanently locked (for native tokens) or burned (for bridged tokens) with no recovery mechanism. This constitutes permanent freezing of bridged funds.

The `amount_without_fee` is `amount - fee.fee`. Both are in NEAR's 24-decimal representation. The only guard in `init_transfer` is `fee.fee < amount`, which does not prevent `amount_without_fee` from being below the normalization threshold. [6](#0-5) 

---

### Likelihood Explanation

For any token registered with `origin_decimals = 24` and `decimals = 6` (a 10^18 scaling factor, common for USDC-like tokens bridged to EVM), a user who sets a fee such that `amount - fee < 10^18` triggers this path. For example: transfer `2 * 10^18` units with `fee = 1.5 * 10^18` units leaves `amount_without_fee = 5 * 10^17`, which normalizes to zero. The user has no on-chain signal before `sign_transfer` is called that their transfer will fail. The `init_transfer` validation does not surface this condition. [7](#0-6) 

---

### Recommendation

Add a normalization guard in `init_transfer` (or `init_transfer_internal`) before locking/burning tokens. After computing the `TransferMessage`, look up the destination token's `Decimals` and require:

```rust
require!(
    Self::normalize_amount(
        transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
        decimals
    ) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the existing check in `sign_transfer` but fires before tokens are committed, allowing the `ft_on_transfer` callback to return the full amount to the sender rather than locking it. [8](#0-7) 

---

### Proof of Concept

1. Token is registered with `origin_decimals = 24`, `decimals = 6` (diff = 18).
2. User calls `ft_on_transfer` transferring `amount = 2_000_000_000_000_000_000` (2 × 10^18) with `fee = 1_500_000_000_000_000_000` (1.5 × 10^18).
3. `init_transfer` passes the `fee < amount` check. Tokens are burned/locked. `TransferMessage` is stored.
4. Relayer calls `sign_transfer`.
5. `amount_without_fee() = 5 * 10^17`.
6. `normalize_amount(5 * 10^17, {origin: 24, decimals: 6}) = 5 * 10^17 / 10^18 = 0`.
7. `require!(amount_to_transfer > 0, ...)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
8. `TransferMessage` remains in storage. No MPC signature is produced. No destination-chain proof can ever be generated. `claim_fee` cannot be called. User's `2 * 10^18` units are permanently frozen. [4](#0-3) [1](#0-0)

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

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
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
