### Title
Fee Validation Uses Raw Amount While `sign_transfer` Enforces Normalized-Amount Floor, Enabling Permanent Fund Freezing — (File: `near/omni-bridge/src/lib.rs`)

### Summary

The NEAR `omni-bridge` contract validates the user-supplied fee against the raw token amount at `init_transfer` time, but later enforces a stricter implicit minimum — the decimal-normalization floor — at `sign_transfer` time. For any token whose on-chain NEAR decimals differ from its origin-chain decimals, a user can submit a transfer that passes the fee guard yet produces a normalized net amount of zero, permanently locking their tokens with no recovery path.

### Finding Description

**Check 1 — `init_transfer` fee guard (raw amounts):** [1](#0-0) 

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

The guard only requires `fee < amount` in raw (unnormalized) units. It does not account for the decimal-normalization step that will be applied later.

**Check 2 — `sign_transfer` normalized-amount floor:** [2](#0-1) 

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

**Normalization uses floor division:** [3](#0-2) 

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

**`amount_without_fee` is a simple subtraction:** [4](#0-3) 

```rust
pub fn amount_without_fee(&self) -> Option<u128> {
    self.amount.0.checked_sub(self.fee.fee.0)
}
```

**Concrete example:**

Consider a token registered with `origin_decimals = 24` and `decimals = 18` (normalization factor = 10^6). A user sends `amount = 5` raw units with `fee = 4`:

- Check 1 passes: `4 < 5` ✓
- `amount_without_fee = 5 - 4 = 1`
- `normalize_amount(1) = 1 / 10^6 = 0` (floor division)
- Check 2 fails: `0 > 0` ✗ → `sign_transfer` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`

The same conflict is reachable via `update_transfer_fee`, which also validates only against the raw amount: [5](#0-4) 

```rust
require!(
    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

A user can raise their fee to `amount - 1` (passes the raw check), reducing the net amount below the normalization floor, after which `sign_transfer` will always revert.

**No recovery path exists.** There is no public `cancel_transfer` function. `remove_transfer_message` is only called internally during successful finalization or fee-claim flows. The tokens locked/burned in `ft_on_transfer` are permanently inaccessible.

### Impact Explanation

Any bridge user who initiates a NEAR → Foreign transfer with a fee that satisfies `fee < amount` but violates `normalize(amount - fee) > 0` will have their tokens permanently frozen in the bridge contract. The tokens are consumed by `ft_on_transfer` (locked for native tokens, burned for deployed tokens), but the corresponding `sign_transfer` call will always revert, and no on-chain escape hatch exists. This constitutes permanent freezing of bridged funds.

### Likelihood Explanation

The condition requires a token with `origin_decimals > decimals` (any token whose NEAR representation uses fewer decimals than its origin chain — common for tokens bridged from chains with 18+ decimals) and a net amount after fee that falls below the normalization factor. A user who sets a fee close to the transfer amount, or who later raises the fee via `update_transfer_fee` to near the amount, can inadvertently or deliberately trigger this. The `update_transfer_fee` path makes it reachable even for transfers that were initially valid.

### Recommendation

Add a normalized-amount check at both `init_transfer` and `update_transfer_fee` time. Before storing the transfer message, verify that `normalize_amount(amount - fee, decimals) > 0`. This mirrors the fix applied in the Argo analog: use the effective constrained value (here, the normalized net amount) in the validation rather than the raw value.

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (factor = 10^6).
2. Call `ft_transfer_call` on that token with `amount = 5`, passing `InitTransferMsg { fee: 4, ... }`.
3. `init_transfer` stores the transfer: `fee (4) < amount (5)` passes.
4. Tokens are locked/burned.
5. Call `sign_transfer` for the resulting `transfer_id`.
6. `normalize_amount(5 - 4) = normalize_amount(1) = 0` → panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. Repeat step 5 indefinitely — it always fails. Tokens are permanently frozen.

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-402)
```rust
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
