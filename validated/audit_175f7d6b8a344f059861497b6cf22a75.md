### Title
Permanent Fund Loss When `normalize_amount` Returns Zero in `sign_transfer` After Tokens Are Already Burned/Locked — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

In the NEAR Omni Bridge, a user initiating a NEAR-to-foreign-chain transfer can permanently lose their tokens if the transfer amount (minus fee) is smaller than the decimal normalization divisor. Tokens are burned or locked during `init_transfer_internal`, but the zero-amount check only occurs later in `sign_transfer`, which panics and leaves the transfer permanently stuck with no recovery path.

---

### Finding Description

The bridge normalizes token amounts when bridging from NEAR to a foreign chain, because the token may have more decimals on the origin chain than on the destination. The normalization is performed by `normalize_amount`: [1](#0-0) 

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

This uses **floor division**. If `amount < 10^(origin_decimals - decimals)`, the result is `0`.

The check for a zero normalized amount only occurs inside `sign_transfer`: [2](#0-1) 

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

However, by the time `sign_transfer` is called, the user's tokens have **already been burned or locked** inside `init_transfer_internal`: [3](#0-2) 

```rust
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
}
```

The `init_transfer` function only validates that `fee < amount`: [4](#0-3) 

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

There is no check that `normalize_amount(amount - fee, decimals) > 0` before tokens are consumed. When `sign_transfer` subsequently panics with `InvalidAmountToTransfer`, the transfer message remains in `pending_transfers` indefinitely, and there is no cancel or refund mechanism visible in the contract.

---

### Impact Explanation

A user who initiates a transfer with an amount below the normalization threshold (e.g., sending fewer than `10^(origin_decimals - decimals)` base units) will have their tokens permanently burned or locked on NEAR with no ability to complete the transfer or recover the funds. This constitutes **permanent freezing of bridged funds** — a critical impact under the allowed scope.

Concrete example: a token registered with `origin_decimals = 24` and `decimals = 18` has a divisor of `10^6`. A user sending `999,999` base units has those tokens burned/locked, but `normalize_amount` returns `0`, causing `sign_transfer` to always panic. The transfer is permanently stuck.

---

### Likelihood Explanation

Any token bridged from a chain with higher native decimals than NEAR's representation (a common configuration, e.g., Ethereum tokens with 18 decimals mapped to 6 on NEAR, or NEAR tokens with 24 decimals mapped to 18 on EVM) creates this condition. A user sending a "dust" amount — or a user unfamiliar with the decimal normalization — can trigger this without any privileged access. The entry path is the standard public `ft_transfer_call` → `init_transfer` flow available to any token holder.

---

### Recommendation

Add a validation in `init_transfer` (before burning/locking tokens) that the normalized amount after fee deduction is strictly greater than zero:

```rust
let token_address = self.get_token_address(
    init_transfer_msg.get_destination_chain(),
    token_id.clone(),
).near_expect(BridgeError::FailedToGetTokenAddress);

let decimals = self.token_decimals
    .get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);

let normalized = Self::normalize_amount(
    amount.0 - init_transfer_msg.fee.0,
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the guard already present in `sign_transfer` but places it **before** the irreversible token burn/lock step.

---

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `decimals = 18` (divisor = `10^6`).
2. User calls `ft_transfer_call` with `amount = 500_000` (below `10^6`) and `fee = 0`.
3. `init_transfer_internal` is reached: `burn_tokens_if_needed` burns `500_000` units from the user.
4. Transfer message is stored in `pending_transfers`.
5. Trusted relayer calls `sign_transfer` for this transfer.
6. `normalize_amount(500_000, Decimals { decimals: 18, origin_decimals: 24 })` → `500_000 / 1_000_000 = 0`.
7. `require!(amount_to_transfer > 0, ...)` panics — transaction aborted.
8. Transfer message remains in `pending_transfers` forever; user's `500_000` units are permanently burned with no recovery path. [5](#0-4) [2](#0-1) [3](#0-2) [4](#0-3)

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
