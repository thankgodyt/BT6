### Title
Missing Minimum Amount Sanity Check in `init_transfer` Causes Permanent Loss of Bridged Tokens When Amount Normalizes to Zero - (`near/omni-bridge/src/lib.rs`)

---

### Summary

When a user initiates a NEAR→foreign transfer with an amount smaller than the decimal normalization factor (`10^(origin_decimals - decimals)`), the `normalize_amount` function silently returns 0 via floor division. Tokens are burned or locked during `init_transfer_internal` before this is detected. The subsequent `sign_transfer` call always reverts with `InvalidAmountToTransfer`, and no cancel or refund path exists for the pending transfer, resulting in permanent loss of the user's bridged tokens.

---

### Finding Description

`normalize_amount` performs floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

For any `amount < 10^(origin_decimals - decimals)`, this returns 0. The `init_transfer` function only validates `fee < amount`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [2](#0-1) 

There is no check that `normalize_amount(amount_without_fee, decimals) > 0` at this stage. Execution then proceeds to `init_transfer_internal`, which irreversibly burns deployed tokens or locks native tokens:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(...);
``` [3](#0-2) 

The `ft_on_transfer` return value is `U128(0)`, signaling to the NEP-141 token contract that all tokens were consumed — no refund is issued. The transfer message is stored in `pending_transfers`.

Later, when a trusted relayer calls `sign_transfer`, the zero-amount check fires:

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

`sign_transfer` always reverts for this transfer. No public cancel or refund function exists for pending transfers. The tokens are permanently lost.

---

### Impact Explanation

For deployed (bridged) tokens: they are burned and cannot be recovered. For native tokens: they are locked in the bridge contract with no recovery path. The transfer message remains in `pending_transfers` indefinitely. This constitutes permanent freezing/loss of bridged funds, matching the Critical impact scope.

---

### Likelihood Explanation

Low-to-medium. The condition requires a user to send an amount below the normalization threshold. For a token with `origin_decimals=24` normalized to `decimals=18`, the threshold is `10^6` base units — a very small but non-zero amount. Users unfamiliar with decimal normalization (analogous to the "forgot to include decimals" scenario in the reference report) can trigger this. The CLAUDE.md false-positive list explicitly covers only the `origin_decimals < decimals` underflow case, not the floor-division-to-zero case. [5](#0-4) 

---

### Recommendation

Add a sanity check in `init_transfer` (before burning/locking tokens) that validates the net amount survives normalization:

```rust
let token_address = self.get_token_address(destination_chain, token_id.clone())
    .near_expect(BridgeError::TokenNotFound);
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
require!(
    Self::normalize_amount(
        transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
        decimals
    ) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the existing guard in `sign_transfer` but places it before the irreversible burn/lock step.

---

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `decimals = 18` (normalization factor = `10^6`).
2. User calls `ft_transfer_call` with `amount = 5` (5 base units, fee = 0).
3. `init_transfer` passes the `fee < amount` check (0 < 5).
4. `init_transfer_internal` burns 5 base units of the deployed token (or locks them). `ft_on_transfer` returns `U128(0)` — no refund.
5. Relayer calls `sign_transfer`.
6. `normalize_amount(5, Decimals{decimals:18, origin_decimals:24})` = `5 / 1_000_000` = `0`.
7. `require!(0 > 0, ...)` panics with `InvalidAmountToTransfer`.
8. The transfer message remains in `pending_transfers` forever. The 5 base units are permanently lost.

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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** near/CLAUDE.md (L192-195)
```markdown
**2. Decimal Arithmetic Underflow (NOT a vulnerability)**
- Design expects `origin_decimals >= decimals` (normalization to lower precision)
- Workspace has `overflow-checks = true` in Cargo.toml
- Misconfiguration causes panic (correct fail-safe), not silent corruption
```
