### Title
Precision Loss in `normalize_amount` Permanently Freezes Small-Amount NEAR-Outbound Transfers — (`near/omni-bridge/src/lib.rs`)

---

### Summary

The `normalize_amount` function uses integer floor division to scale token amounts from NEAR's higher-precision representation to a lower-precision destination chain representation. For tokens where `origin_decimals > decimals`, any transfer amount smaller than `10^(origin_decimals - decimals)` silently truncates to zero. The `sign_transfer` function then rejects the transfer with `InvalidAmountToTransfer`, permanently locking the user's tokens in the NEAR bridge contract with no recovery path.

---

### Finding Description

`normalize_amount` is defined as:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

This is called inside `sign_transfer` to compute the amount that will be authorized on the destination chain:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [2](#0-1) 

When `amount_without_fee < 10^diff_decimals`, the division truncates to zero and `sign_transfer` panics. The transfer message remains in storage, the tokens remain locked in the bridge, and there is no cancel or refund function anywhere in the contract.

The EVM `initTransfer` enforces only `fee < amount` — it has no minimum amount floor:

```solidity
if (fee >= amount) {
    revert InvalidFee();
}
``` [3](#0-2) 

So a user can lock tokens on NEAR (or burn bridge tokens on EVM) with an amount that will always fail normalization, and those tokens can never be recovered.

**Concrete example:**
- Token: NEAR-native token with `origin_decimals = 24`, mapped to an EVM token with `decimals = 18` → `diff_decimals = 6`
- User sends `500,000` yocto-units via `ft_transfer_call`
- `normalize_amount(500_000, {origin: 24, dest: 18}) = 500_000 / 1_000_000 = 0`
- Every subsequent `sign_transfer` call panics; tokens are permanently locked

The code comment on `normalize_amount` acknowledges dust loss but frames it as a sub-unit remainder:

> *"When fee = 0, dust stays locked/burned."* [4](#0-3) 

However, this scenario is not "dust" — it is the **entire transfer principal** being silently discarded, with no user-facing warning and no recovery path.

---

### Impact Explanation

A user who initiates a NEAR-outbound transfer with an amount below the normalization threshold loses their entire bridged principal permanently. The tokens are locked in the NEAR bridge contract (or burned if a bridge token), `sign_transfer` will always revert for that transfer ID, and no cancel/refund function exists. This constitutes **permanent freezing of bridged funds**, which is in the critical impact scope.

---

### Likelihood Explanation

Any token pair where `origin_decimals > decimals` is affected. NEAR-native tokens use 24 decimals; EVM tokens commonly use 6 or 18. A user sending a "small" amount (e.g., less than 1 unit in EVM terms) triggers the bug. No special privileges are required — any unprivileged bridge user calling `ft_transfer_call` with a small amount is sufficient. The EVM side has no guard against this either.

---

### Recommendation

Add a minimum-amount check **before** locking/burning tokens on the source side, or enforce it at the `ft_on_transfer` / `init_transfer` entry point by pre-computing `normalize_amount` and rejecting the call if the result is zero. This mirrors the fix suggested in the reference report: validate the post-normalization value before committing any state change.

---

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (`diff_decimals = 6`).
2. Call `ft_transfer_call` on the NEAR token contract with `amount = 999_999` (less than `10^6`), targeting the bridge with a valid `InitTransferMsg`.
3. Bridge stores the `TransferMessage`; tokens are locked.
4. Relayer calls `sign_transfer` for the resulting `TransferId`.
5. `normalize_amount(999_999, {origin_decimals: 24, decimals: 18})` → `999_999 / 1_000_000 = 0`.
6. `require!(amount_to_transfer > 0)` panics with `InvalidAmountToTransfer`.
7. Repeat step 4 indefinitely — the result is always the same panic.
8. The `999_999` units are permanently locked in the bridge contract with no recovery path. [2](#0-1) [1](#0-0)

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

**File:** near/omni-bridge/src/lib.rs (L2781-2783)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L382-384)
```text
        if (fee >= amount) {
            revert InvalidFee();
        }
```
