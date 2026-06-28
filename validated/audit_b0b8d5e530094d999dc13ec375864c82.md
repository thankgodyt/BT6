### Title
`normalize_amount` Floor-Division to Zero Causes Permanent Fund Lock in `sign_transfer` - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`init_transfer` accepts any `amount` satisfying `fee < amount` without verifying that the normalized transfer amount (after decimal scaling) is non-zero. When a user bridges a token whose NEAR-side decimals differ from the destination-chain decimals, a small `amount_without_fee()` value undergoes floor division in `normalize_amount` and silently becomes `0`. The subsequent `require!(amount_to_transfer > 0, ...)` guard in `sign_transfer` then permanently rejects every signing attempt for that transfer. Because no public cancel or refund path exists for pending transfers, the user's tokens are locked in the bridge forever.

---

### Finding Description

**Step 1 — Permissive validation in `init_transfer`**

`init_transfer` stores the transfer and locks/burns the full `amount` of tokens after only one fee check:

```rust
// near/omni-bridge/src/lib.rs  line 554-557
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [1](#0-0) 

This allows `amount = 999_999, fee = 0` to pass for a token whose normalization divisor is `10^6`.

**Step 2 — Full amount is burned/locked immediately**

Inside `init_transfer_internal`, the entire `amount` is burned or locked before any normalization check:

```rust
// near/omni-bridge/src/lib.rs  line 1850-1857
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
}
``` [2](#0-1) 

**Step 3 — `normalize_amount` uses floor division**

```rust
// near/omni-bridge/src/lib.rs  line 2784-2787
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [3](#0-2) 

For a NEAR token with `origin_decimals = 24` bridging to an EVM chain with `decimals = 18`, the divisor is `10^6`. Any `amount_without_fee() < 1_000_000` normalizes to `0`.

**Step 4 — `sign_transfer` permanently rejects the transfer**

```rust
// near/omni-bridge/src/lib.rs  line 475-485
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
``` [4](#0-3) 

Every call to `sign_transfer` for this transfer ID will panic with `ERR_INVALID_AMOUNT_TO_TRANSFER`. The transfer record stays in `pending_transfers` indefinitely.

**Step 5 — No public cancel/refund path**

`remove_transfer_message` is only called internally from `claim_fee_callback`. There is no public `cancel_transfer` or equivalent function that would allow the user to recover their locked tokens. [5](#0-4) 

---

### Impact Explanation

For any token where `origin_decimals > decimals` (e.g., a NEAR-native token with 24 decimals bridging to an EVM chain with 18 decimals, giving a divisor of `10^6`), any user who initiates a transfer with `amount_without_fee() < divisor` will have their tokens permanently burned or locked in the bridge with no recovery path. This is a direct, permanent loss of bridged funds triggered by a normal user action.

---

### Likelihood Explanation

The condition is reachable by any unprivileged user calling `ft_transfer_call` into the bridge. A user sending a "dust" amount — or any amount below `10^(origin_decimals − decimals)` base units — triggers the bug. For a 24-vs-18 decimal token pair the threshold is 1,000,000 base units (1 token at 6 decimals of precision), which is a realistic transfer size. No special permissions, front-running, or external dependencies are required.

---

### Recommendation

Add a normalization check inside `init_transfer` (before locking/burning tokens) to reject transfers whose net amount normalizes to zero:

```rust
// After computing transfer_message, before locking tokens:
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
);
if let Some(addr) = token_address {
    if let Some(decimals) = self.token_decimals.get(&addr) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```

This mirrors the fix in the referenced report (adding a minimum threshold check before the value is committed).

---

### Proof of Concept

1. Register a NEAR-native token with `origin_decimals = 24`, `decimals = 18` (divisor = `10^6`).
2. Call `ft_transfer_call` on the token contract with `amount = 500_000` (below `10^6`) and `msg` encoding an `InitTransferMsg` with `fee = 0` and any non-NEAR recipient.
3. `init_transfer` passes the `fee < amount` check (`0 < 500_000`). `init_transfer_internal` burns/locks `500_000` tokens. The transfer is stored in `pending_transfers`.
4. Call `sign_transfer` with the resulting `transfer_id`.
5. `normalize_amount(500_000, {decimals:18, origin_decimals:24})` = `500_000 / 1_000_000` = `0`.
6. `require!(0 > 0, ...)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. Repeat step 4 indefinitely — it always panics. The `500_000` tokens are permanently lost with no cancel path available. [1](#0-0) [4](#0-3) [3](#0-2)

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
