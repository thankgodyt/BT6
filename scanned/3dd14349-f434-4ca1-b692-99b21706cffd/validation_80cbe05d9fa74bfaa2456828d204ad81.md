### Title
Dust-Amount Transfer Permanently Freezes Bridged Tokens Due to Missing Pre-Normalization Validation — (`near/omni-bridge/src/lib.rs`)

---

### Summary

The NEAR bridge contract accepts a `ft_transfer_call`-initiated transfer whose `amount` passes the `fee < amount` guard in `init_transfer`, locks or burns the tokens, and stores the pending transfer — but later permanently rejects every `sign_transfer` call for that transfer because `normalize_amount(amount - fee, decimals)` floors to zero. No cancel or refund path exists, so the user's tokens are frozen forever.

---

### Finding Description

**Entry point — `ft_on_transfer` → `init_transfer`**

A user calls `ft_transfer_call` on a NEP-141 token, which triggers `ft_on_transfer` on the bridge. The bridge dispatches to `init_transfer`, which applies only one amount-level guard: [1](#0-0) 

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

A transfer with `amount = 1` and `fee = 0` satisfies `0 < 1` and proceeds. The tokens are immediately locked or burned: [2](#0-1) 

and the `TransferMessage` is inserted into `pending_transfers`: [3](#0-2) 

**Failure point — `sign_transfer`**

When a relayer later calls `sign_transfer`, the bridge normalises the net amount for the destination chain: [4](#0-3) 

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

`normalize_amount` uses floor division: [5](#0-4) 

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

For any token where `origin_decimals > decimals` (e.g., a NEAR-side token with 24 decimals bridging to an EVM chain with 18 decimals, giving `diff = 6`), any `amount < 10^6` normalises to `0`. The `require!` macro panics, reverting `sign_transfer`. Because the panic happens before the MPC call, `sign_transfer_callback` — the only place that removes a zero-fee transfer — is never reached: [6](#0-5) 

**No recovery path**

There is no public `cancel_transfer` or user-accessible refund function. `remove_transfer_message` is only called from internal callbacks. The transfer entry stays in `pending_transfers` indefinitely, and the locked/burned tokens are unrecoverable.

---

### Impact Explanation

Any user who sends a "dust" amount (one that passes `fee < amount` but normalises to zero on the destination chain) permanently loses their tokens. The tokens are either burned (for deployed bridge tokens) or locked inside the bridge contract with no mechanism to release them. This constitutes **permanent freezing of bridged funds**, matching the Critical impact tier.

**Impact: High** — permanent, irreversible token loss for the affected user.

---

### Likelihood Explanation

The condition requires a token registered with `origin_decimals > decimals` (common for EVM tokens with 18 decimals mapped to a lower-precision NEAR representation) and a user submitting an amount below the normalisation threshold. This can occur through user error (e.g., sending `1` raw unit instead of `1` whole token) or through a UI that does not enforce a minimum. The likelihood is low but non-zero.

**Likelihood: Low** — requires a specific decimal configuration and a small-amount user mistake, but no privileged access is needed.

---

### Recommendation

Add a pre-normalization check inside `init_transfer` (or `init_transfer_internal`) that rejects any transfer whose net amount would normalize to zero on the destination chain. Concretely, after computing `required_storage_balance` and before locking/burning tokens, verify:

```rust
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

This mirrors the guard already present in `sign_transfer` and prevents tokens from being locked before the unsignable state is detected.

---

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `decimals = 18` (diff = 6; threshold = 1 000 000 raw units).
2. Alice calls `ft_transfer_call` with `amount = 500 000` (below threshold) and `fee = 0`.
3. `init_transfer` checks `0 < 500 000` → passes. Tokens are burned/locked. Transfer stored in `pending_transfers`.
4. Relayer calls `sign_transfer` for Alice's transfer.
5. `normalize_amount(500 000, {origin=24, dest=18}) = 500 000 / 10^6 = 0`.
6. `require!(0 > 0, ...)` panics → transaction reverts.
7. Steps 4–6 repeat forever. Alice's 500 000 raw units are permanently frozen.

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

**File:** near/omni-bridge/src/lib.rs (L2180-2191)
```rust
    fn add_transfer_message(
        &mut self,
        transfer_message: TransferMessage,
        message_owner: AccountId,
    ) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.insert_raw_transfer(transfer_message, message_owner,)
                .is_none(),
            BridgeError::KeyExists.as_ref()
        );
        env::storage_byte_cost().saturating_mul((env::storage_usage() - storage_usage).into())
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
