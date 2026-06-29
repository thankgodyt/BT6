### Title
Weaker Validation at `init_transfer` vs. `sign_transfer` Allows Permanent Freezing of Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`init_transfer` only checks `fee < amount` when accepting a user's locked tokens, but `sign_transfer` additionally requires `normalize_amount(amount - fee) > 0`. For tokens whose NEAR-side decimals exceed the destination chain's decimals, any `amount - fee` below the decimal-scaling divisor normalizes to zero, causing `sign_transfer` to permanently panic. Because no cancel/refund path exists, the user's tokens are frozen in the bridge forever.

---

### Finding Description

The NEAR omni-bridge contract enforces two different safety conditions at two different stages of the NEAR → EVM transfer lifecycle:

**Stage 1 — `init_transfer`** accepts the user's tokens and stores the transfer message. Its only fee/amount guard is:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [1](#0-0) 

**Stage 2 — `sign_transfer`** is called later (by a trusted relayer) to produce the MPC signature that releases funds on the destination chain. It applies an additional, stricter check:

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
``` [2](#0-1) 

`normalize_amount` performs **floor division** by `10^(origin_decimals − dest_decimals)`:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [3](#0-2) 

For any token where `origin_decimals > dest_decimals` (e.g., a token registered with 24 decimals on NEAR and 6 decimals on EVM, giving a divisor of `10^18`), any `amount − fee < 10^18` normalizes to **zero**. The `init_transfer` check (`fee < amount`) does not account for this normalization at all.

`update_transfer_fee` cannot rescue a stuck transfer because it only allows the fee to be **increased**, never decreased:

```rust
require!(
    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [4](#0-3) 

There is no cancel or refund entrypoint in the contract. The transfer message persists in storage indefinitely, and the locked tokens can never be recovered.

---

### Impact Explanation

**Critical — Permanent freezing of bridged funds.**

Any user who calls `ft_transfer_call` → `init_transfer` with an `amount − fee` value that is smaller than the decimal-scaling divisor for the destination chain will have their tokens permanently locked. The `sign_transfer` call will always revert with `ERR_INVALID_AMOUNT_TO_TRANSFER`, and no recovery path exists. This satisfies the "permanent freezing of bridged funds" criterion.

---

### Likelihood Explanation

**Medium.** The condition is triggered whenever:
- A token has more decimals on NEAR than on the destination EVM chain (a common configuration — e.g., 24 vs. 6 or 24 vs. 8), **and**
- The user submits `amount − fee < 10^(origin_decimals − dest_decimals)`.

This can happen accidentally (a user sending a small "dust" amount) or deliberately (a griefing attacker targeting another user's funds by front-running or social engineering). The decimal-difference scenario is a standard bridge configuration, not an edge case.

---

### Recommendation

Add the same normalization check inside `init_transfer` (or `init_transfer_internal`) before accepting the user's tokens:

```rust
let token_address = self.get_token_address(destination_chain, token_id.clone())
    .near_expect(BridgeError::FailedToGetTokenAddress);
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the fix analogous to the IonPool report: apply the stricter check at creation time so that no transfer can be stored that is guaranteed to fail at signing time.

---

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `decimals = 6` (divisor = `10^18`).
2. User calls `ft_transfer_call` with `amount = 500` (500 yocto-units) and `fee = 0`.
3. `init_transfer` check: `0 < 500` → **passes**. Tokens are transferred to the bridge locker.
4. A trusted relayer calls `sign_transfer` for this transfer.
5. `normalize_amount(500 − 0, {origin:24, dest:6}) = 500 / 10^18 = 0`.
6. `require!(0 > 0, ...)` → **panics** with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. The transfer message remains in storage. The user's 500 yocto-units are permanently locked.
8. `update_transfer_fee` cannot help: increasing the fee only makes `amount − fee` smaller, worsening the normalization result.
9. No cancel or refund function exists in the contract. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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
