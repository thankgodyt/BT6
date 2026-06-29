### Title
Unnecessary `amount_to_transfer > 0` Guard in `sign_transfer` Permanently Locks User Funds When Decimal Normalization Rounds to Zero — (`File: near/omni-bridge/src/lib.rs`)

### Summary

The `sign_transfer` function in the NEAR omni-bridge contract contains a guard `require!(amount_to_transfer > 0, ...)` that fires after decimal normalization. Because `normalize_amount` uses floor (integer) division, a legitimately initiated transfer whose post-fee amount is smaller than the decimal-scaling factor will always produce `amount_to_transfer == 0`, causing `sign_transfer` to revert unconditionally. The user's tokens are already locked inside the bridge at this point and there is no refund path, so the funds are permanently frozen.

---

### Finding Description

**Root cause — `sign_transfer` (lines 475–485):**

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
``` [1](#0-0) 

`normalize_amount` converts the NEAR-side amount (stored in NEAR token decimals) to the destination-chain decimals using floor division. The bridge's own comment in `claim_fee_callback` explicitly documents this:

> "Since `denormalize(normalize(x)) <= x` due to floor division, the difference naturally captures the normalization remainder." [2](#0-1) 

**Locking path — `init_transfer` (lines 531–619):**

When a user calls `ft_transfer_call` with an `InitTransfer` message, `ft_on_transfer` → `init_transfer` is invoked. The tokens are immediately debited from the user and the transfer record is stored in `pending_transfers`. The only validity check on the amount at this stage is:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [3](#0-2) 

This check does **not** verify that `normalize_amount(amount - fee) > 0`. A transfer with `amount = 999` and `fee = 0` passes this check, but if the token has 18 NEAR-side decimals and 6 destination-chain decimals, `normalize_amount(999)` = `999 / 10^12` = **0** (integer division).

**No refund path exists.** Once the transfer is stored in `pending_transfers`, the only way to release the locked tokens is through a successful `sign_transfer` → MPC signature → `fin_transfer` cycle. Because `sign_transfer` will always revert for this transfer, the tokens are permanently frozen.

---

### Impact Explanation

A user who initiates a cross-chain transfer with an amount smaller than the decimal-scaling factor (e.g., transferring fewer than `10^(near_decimals − dest_decimals)` raw units of a token) will have their tokens permanently locked in the NEAR bridge contract with no recovery mechanism. This constitutes a **critical permanent loss of bridged funds**.

---

### Likelihood Explanation

Any unprivileged bridge user can trigger this by calling `ft_transfer_call` with a small token amount. The condition is reachable whenever the destination chain uses fewer decimals than the NEAR-side representation (a common configuration, e.g., NEAR 18 decimals → EVM 6 decimals). No special role or admin action is required. The user is the sole attacker-controlled entry point.

---

### Recommendation

Remove or relocate the `require!(amount_to_transfer > 0, ...)` guard. Instead, enforce the minimum-amount constraint at `init_transfer` time (before tokens are locked), so that a transfer that would normalize to zero is rejected immediately and the user's tokens are never debited. Alternatively, add a refund path that returns the locked tokens to the sender when `sign_transfer` detects a zero normalized amount.

---

### Proof of Concept

1. A token is registered with 18 NEAR-side decimals and 6 destination-chain decimals (`decimals.decimals = 6`, `decimals.origin_decimals = 18`).
2. User calls `ft_transfer_call` with `amount = 500` (raw units) and `fee = 0`. The check `fee < amount` passes. The 500 raw units are locked; the transfer is stored in `pending_transfers`.
3. A relayer calls `sign_transfer` for this transfer.
4. `normalize_amount(500, decimals)` = `500 / 10^(18−6)` = `500 / 10^12` = **0**.
5. `require!(0 > 0, ...)` panics with `InvalidAmountToTransfer`.
6. The transfer record remains in `pending_transfers` forever; the 500 raw units are permanently locked. [4](#0-3) [3](#0-2)

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

**File:** near/omni-bridge/src/lib.rs (L1128-1131)
```rust
        // Fee includes both the user-specified fee and any dust lost during decimal
        // normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
        // due to floor division, the difference naturally captures the normalization remainder.
        let fee = transfer_message.amount.0 - denormalized_amount;
```
