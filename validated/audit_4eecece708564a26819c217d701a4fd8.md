### Title
Rounding in `normalize_amount` Permanently Locks/Burns User Tokens When Transfer Amount Rounds to Zero - (File: `near/omni-bridge/src/lib.rs`)

### Summary
`normalize_amount` uses floor division to scale a NEAR-native token amount down to the destination chain's decimal precision. When a user initiates a transfer whose `amount_without_fee` is smaller than the normalization factor (`10^(origin_decimals - dest_decimals)`), the result is zero. The tokens are burned or locked in `init_transfer_internal` before this check is ever applied. `sign_transfer` then permanently rejects the transfer with `InvalidAmountToTransfer`, and no cancel/refund path exists, causing permanent loss of the user's bridged funds.

### Finding Description

`normalize_amount` performs integer floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

For a token with `origin_decimals = 24` (NEAR) and `decimals = 6` (EVM), the normalization factor is `10^18`. Any `amount_without_fee < 10^18` normalizes to zero.

The user-facing entry point is `ft_on_transfer`, which calls the private `init_transfer`:

```rust
pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
    ...
    BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
        self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
    }
``` [2](#0-1) 

`init_transfer` only validates `fee < amount`, with no check that the normalized net amount is non-zero:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [3](#0-2) 

It then calls `init_transfer_internal`, which **immediately burns or locks the full token amount** before any normalization check:

```rust
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
}
``` [4](#0-3) 

Only later, when a relayer calls `sign_transfer`, is `normalize_amount` applied and the zero-amount guard enforced:

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
``` [5](#0-4) 

`sign_transfer` panics, the transfer remains in `pending_transfers` indefinitely, and there is no public cancel or refund function anywhere in the contract. The burned/locked tokens are permanently unrecoverable.

### Impact Explanation

A user who sends a NEAR-side token amount smaller than `10^(origin_decimals - dest_decimals)` to a foreign chain with fewer decimals will have their tokens permanently burned (for deployed bridge tokens) or permanently locked (for native tokens), with no mechanism to recover them. This constitutes a permanent, irreversible loss of bridged funds triggered by a normal, unprivileged user action.

### Likelihood Explanation

For any token pair where `origin_decimals > dest_decimals` (e.g., a 24-decimal NEAR token bridged to a 6-decimal EVM token, normalization factor = `10^18` = 1 NEAR), any user sending less than 1 NEAR-equivalent of that token triggers the bug. This is a realistic and likely accidental scenario for users unfamiliar with decimal normalization. No special privileges or coordination are required.

### Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) **before** burning or locking tokens. Look up the destination token's `Decimals` and assert that `normalize_amount(amount_without_fee, decimals) > 0`. If the decimals are not yet registered (token not yet deployed on destination), reject the transfer early. Alternatively, implement a public `cancel_transfer` function that allows the original sender to reclaim stuck funds, as defense-in-depth.

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `dest_decimals = 6` (normalization factor = `10^18`).
2. User calls `ft_transfer_call` on the NEAR token contract with `amount = 5 * 10^17` (0.5 NEAR-equivalent) and `fee = 0`, targeting an EVM recipient.
3. `ft_on_transfer` → `init_transfer` passes the only guard (`fee < amount` → `0 < 5*10^17` ✓).
4. `init_transfer_internal` burns `5 * 10^17` tokens (deployed token) or locks them.
5. Relayer calls `sign_transfer`.
6. `normalize_amount(5 * 10^17, {24, 6}) = 5 * 10^17 / 10^18 = 0`.
7. `require!(amount_to_transfer > 0, ...)` panics — `sign_transfer` reverts.
8. The transfer stays in `pending_transfers` forever; the `5 * 10^17` tokens are permanently lost.

### Citations

**File:** near/omni-bridge/src/lib.rs (L253-263)
```rust
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
        let token_id = env::predecessor_account_id();
        let parsed_msg: BridgeOnTransferMsg = serde_json::from_str(&msg)
            .or_else(|_| serde_json::from_str(&msg).map(BridgeOnTransferMsg::InitTransfer))
            .near_expect(BridgeError::ParseMsg);

        // We can't trust sender_id to pay for storage as it can be spoofed.
        let signer_id = env::signer_account_id();
        let promise_or_promise_index_or_value = match parsed_msg {
            BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
                self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
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
