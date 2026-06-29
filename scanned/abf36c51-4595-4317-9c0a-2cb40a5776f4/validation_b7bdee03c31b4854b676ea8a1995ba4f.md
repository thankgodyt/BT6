### Title
Missing Minimum Normalized-Amount Guard in `init_transfer` Causes Permanent Freezing of Bridged Funds — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`init_transfer_internal` burns or locks user tokens before any check that the amount will survive decimal normalization. `sign_transfer`, called later by a relayer, enforces `normalize_amount(amount_without_fee) > 0`. When the deposited amount is below the normalization divisor, `sign_transfer` always panics, the pending transfer can never be completed, and the already-burned/locked tokens are permanently unrecoverable.

---

### Finding Description

**Step 1 – User deposits tokens via `ft_transfer_call`.**

`ft_on_transfer` dispatches to `init_transfer`, which builds a `TransferMessage` and validates only that `fee < amount`:

```rust
// near/omni-bridge/src/lib.rs:554-557
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [1](#0-0) 

There is no check that `normalize_amount(amount - fee) > 0`.

**Step 2 – `init_transfer_internal` burns/locks tokens.**

If the storage-balance check passes, tokens are irreversibly burned (for deployed tokens) or locked:

```rust
// near/omni-bridge/src/lib.rs:1850-1857
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
}
``` [2](#0-1) 

**Step 3 – `sign_transfer` enforces the normalization guard — too late.**

```rust
// near/omni-bridge/src/lib.rs:475-485
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee()
        .near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [3](#0-2) 

`normalize_amount` performs floor division by `10^(origin_decimals − decimals)`:

```rust
// near/omni-bridge/src/lib.rs:2784-2787
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [4](#0-3) 

If `amount_without_fee < 10^(origin_decimals − decimals)`, the result is `0`, and every future call to `sign_transfer` panics with `InvalidAmountToTransfer`. The transfer is stuck in `pending_transfers` forever.

**Step 4 – No recovery path exists.**

- `remove_transfer_message` is only called inside `claim_fee_callback`, which requires a proof of finalization on the destination chain — impossible if `sign_transfer` never succeeds.
- There is no public `cancel_transfer` or user-accessible refund function.
- The DAO has no dedicated rescue path for this state. [5](#0-4) 

---

### Impact Explanation

Tokens are permanently burned (for bridge-deployed tokens) or permanently locked (for native tokens) with zero possibility of recovery. This constitutes **permanent freezing of bridged funds**, which is within the critical impact scope.

---

### Likelihood Explanation

Any token registered with `origin_decimals > decimals` (the normal case for tokens bridged from high-precision chains, e.g., NEAR's 24-decimal yoctoNEAR representation bridged to an 18-decimal EVM token) is affected. A user who deposits an amount smaller than `10^(origin_decimals − decimals)` — whether by mistake or due to rounding in a DApp — triggers the freeze. No special privileges are required; any token holder can reach this path via the public `ft_transfer_call` interface.

---

### Recommendation

Add the normalization guard inside `init_transfer`, before tokens are burned or locked:

```rust
// in init_transfer, after building transfer_message
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
).near_expect(BridgeError::FailedToGetTokenAddress);

let decimals = self.token_decimals
    .get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);

let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee()
        .near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the fix recommended in the external report: enforce the threshold at the entry point so that tokens are never burned/locked for an amount that cannot be transferred.

---

### Proof of Concept

Assume a token registered with `origin_decimals = 24`, `decimals = 18` (divisor = 1 000 000).

1. User calls `ft_transfer_call` with `amount = 500_000`, `fee = 0`.
2. `init_transfer` passes: `fee (0) < amount (500_000)` ✓
3. `init_transfer_internal` burns 500 000 tokens and stores the pending transfer.
4. Relayer calls `sign_transfer`.
5. `normalize_amount(500_000, {origin_decimals:24, decimals:18}) = 500_000 / 1_000_000 = 0`.
6. `require!(0 > 0, ...)` → panic: `InvalidAmountToTransfer`.
7. The 500 000 tokens are permanently burned; the pending transfer entry remains in `pending_transfers` indefinitely with no recovery path.

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
