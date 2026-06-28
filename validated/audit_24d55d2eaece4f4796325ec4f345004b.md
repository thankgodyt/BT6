### Title
Fee Validity Check Before Decimal Normalization Causes Permanent Token Lock - (`near/omni-bridge/src/lib.rs`)

### Summary

In the NEAR omni-bridge, the `init_transfer` function validates `fee < amount` using raw NEAR-native token amounts before decimal normalization occurs. When `sign_transfer` is later called, it normalizes `amount - fee` to the destination chain's decimal precision via floor division. If `amount - fee` is smaller than the normalization divisor, the normalized result is zero, causing `sign_transfer` to permanently revert — but the user's tokens have already been irreversibly locked or burned.

### Finding Description

The outbound transfer flow (NEAR → Foreign chain) proceeds in two steps:

**Step 1 — `init_transfer` / `init_transfer_internal`** (`near/omni-bridge/src/lib.rs`):

The fee validity check is performed against the raw NEAR-native amount:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [1](#0-0) 

Immediately after, `init_transfer_internal` burns or locks the full `amount` of tokens:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(..., transfer_message.amount.0);
``` [2](#0-1) 

**Step 2 — `sign_transfer`** (called later by a relayer):

The net amount is normalized to the destination chain's decimal precision using floor division:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
``` [3](#0-2) 

`normalize_amount` applies floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [4](#0-3) 

`amount_without_fee` is simply `amount - fee`: [5](#0-4) 

**The gap:** The `fee < amount` check at Step 1 passes in NEAR-native decimals (e.g., 24 for yoctoNEAR), but the zero-amount guard at Step 2 fires only after tokens are already locked. There is no user-accessible cancel or refund path — `update_transfer_fee` only allows increasing the fee, not decreasing it, and there is no public `cancel_transfer` function. [6](#0-5) 

### Impact Explanation

A user whose transfer satisfies `fee < amount` but `(amount - fee) < 10^(origin_decimals - destination_decimals)` will have their tokens permanently locked or burned. `sign_transfer` will always revert with `InvalidAmountToTransfer`, and no recovery path exists. This constitutes a **permanent, irrecoverable loss of bridged funds** for the affected user.

### Likelihood Explanation

This is realistic for tokens with large decimal differences. For example, a NEAR-native token with 24 decimals bridging to an EVM chain where the token has 6 decimals creates a normalization divisor of `10^18`. Any transfer where `amount - fee < 10^18` (i.e., less than 1 full token unit on the destination chain) will produce a zero normalized amount. A user who sets `amount = 2` and `fee = 1` in yoctoNEAR units would trigger this. The check `fee < amount` passes (1 < 2), tokens are burned, and the transfer is permanently stuck.

### Recommendation

Enforce the minimum net-amount check **before** locking or burning tokens. Specifically, compute `normalize_amount(amount - fee, decimals)` inside `init_transfer` (after resolving the destination token's decimals) and revert immediately if the result is zero — before any token movement occurs. This mirrors the fix recommended in the referenced report: validate the post-reduction amount before committing irreversible state changes.

### Proof of Concept

1. Token `T` is registered with `origin_decimals = 24`, `decimals = 6` (divisor = `10^18`).
2. User calls `ft_transfer_call` with `amount = 2` (yoctoNEAR units) and `InitTransferMsg { fee: 1, ... }`.
3. `init_transfer` checks `1 < 2` → passes. [1](#0-0) 
4. `init_transfer_internal` burns 2 units of `T` from the user. [7](#0-6) 
5. Transfer is stored in `pending_transfers`.
6. Relayer calls `sign_transfer`. `normalize_amount(2 - 1, {24, 6}) = 1 / 10^18 = 0`. [4](#0-3) 
7. `require!(amount_to_transfer > 0, ...)` reverts. [8](#0-7) 
8. The transfer is permanently stuck. The user's 2 units of `T` are burned with no recovery path. `update_transfer_fee` cannot help because it only allows increasing the fee. [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L398-402)
```rust
                let current_fee = transfer.message.fee;
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
