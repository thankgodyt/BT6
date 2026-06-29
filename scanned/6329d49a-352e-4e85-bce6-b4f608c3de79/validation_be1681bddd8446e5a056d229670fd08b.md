### Title
Transfer Funds Permanently Locked When `normalize_amount(amount - fee)` Rounds to Zero — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `init_transfer` function validates only that `fee < amount` before locking user tokens in the bridge. The `sign_transfer` function later additionally requires `normalize_amount(amount - fee) > 0`. When `amount - fee` is a small positive value below the decimal-normalization divisor, `init_transfer` accepts and locks the funds while `sign_transfer` will always revert. Because fees can only be increased (never decreased), the transfer is permanently unresolvable and the user's bridged tokens are frozen.

---

### Finding Description

Two constraints interact across two separate functions, creating a deadlock analogous to the reported vault-capacity/minimum-supply interaction.

**Constraint 1 — checked at initiation, in `init_transfer`:**

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

This only ensures `fee < amount`. Any positive `amount − fee` is accepted and the user's tokens are immediately locked in the bridge. [1](#0-0) 

**Constraint 2 — checked at signing time, in `sign_transfer`:**

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

`normalize_amount` converts from the NEAR-side token representation to the destination chain's decimal precision. For tokens with more decimals on NEAR than on the destination (e.g., 24 vs 6 for USDC on Ethereum), the divisor is `10^(24−6) = 10^18`. If `amount − fee < 10^18`, integer division yields `0` and `sign_transfer` always panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`. [2](#0-1) 

**No recovery path exists.** `update_transfer_fee` enforces `fee.fee >= current_fee.fee`, meaning fees can only be increased, which makes `amount − fee` even smaller. There is no cancel or refund function. [3](#0-2) 

The `Decimals` struct confirms the bridge tracks both origin and destination decimal precisions, making cross-chain normalization an active code path. [4](#0-3) 

---

### Impact Explanation

The user's tokens are transferred to the bridge contract during `ft_on_transfer` before `sign_transfer` is ever called. If `sign_transfer` permanently reverts, those tokens are frozen in the bridge with no recovery path. This constitutes **permanent freezing of bridged funds** — matching the critical impact scope.

---

### Likelihood Explanation

This is reachable whenever a token has more decimals on NEAR than on the destination chain — a common configuration (e.g., 24 NEAR decimals vs 6 for USDC on Ethereum, giving a divisor of `10^18`). A user who sets a fee such that `amount − fee` is a small positive number below the divisor — plausible when trying to maximize the relayer incentive — will inadvertently trigger this state. No special privilege is required; any bridge user initiating an outbound transfer can reach this code path.

---

### Recommendation

Add the normalization check at `init_transfer` time, before funds are locked, mirroring the check already present in `sign_transfer`:

```rust
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This ensures that any transfer whose net amount would normalize to zero is rejected before tokens are locked, eliminating the deadlock.

---

### Proof of Concept

1. Token has 24 decimals on NEAR, 6 decimals on Ethereum → normalization divisor = `10^18`.
2. User calls `ft_transfer_call` with `amount = 2 × 10^18`, `fee = 10^18 + 1`.
3. `init_transfer` check: `10^18 + 1 < 2 × 10^18` → **passes**. Tokens are locked in the bridge.
4. Relayer calls `sign_transfer`.
5. `amount_without_fee() = 2 × 10^18 − (10^18 + 1) = 10^18 − 1`.
6. `normalize_amount(10^18 − 1)` = `(10^18 − 1) / 10^18` = **0** (integer division).
7. `require!(0 > 0)` → panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
8. The user's `2 × 10^18` tokens are permanently frozen in the bridge contract with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-401)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
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

**File:** near/omni-bridge/src/storage.rs (L131-136)
```rust
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
```
