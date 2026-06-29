### Title
Tokens Permanently Locked When `normalize_amount` Returns Zero Due to Decimal Truncation — (`near/omni-bridge/src/lib.rs`)

---

### Summary

When a user initiates a NEAR→EVM transfer for a token whose origin decimals exceed the EVM token's decimals, and the transferred amount (minus fee) is smaller than `10^(origin_decimals − decimals)`, the `normalize_amount` helper truncates the result to **0**. The `sign_transfer` function then panics and refuses to produce an MPC signature, but the user's tokens were already locked during `init_transfer`. No cancel or refund path exists, so the funds are permanently frozen.

---

### Finding Description

`normalize_amount` performs integer floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

For any token where `origin_decimals > decimals` (e.g., a 24-decimal NEAR token bridged to an 18-decimal EVM token, giving `diff_decimals = 6`), any `amount_without_fee` smaller than `10^6` normalizes to **0**.

`sign_transfer` calls `normalize_amount` and then guards against a zero result:

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

The guard correctly prevents signing, but the tokens were already locked during `init_transfer` / `ft_transfer_call`. The only check at lock time is that `fee < amount`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [3](#0-2) 

There is no corresponding check that `normalize_amount(amount_without_fee) > 0` at lock time, and no cancel/refund function is present in the contract. The EVM side has the same gap — `initTransfer` only rejects `fee >= amount`:

```solidity
if (fee >= amount) {
    revert InvalidFee();
}
``` [4](#0-3) 

The EVM `deployToken` path caps token decimals at 18 via `_normalizeDecimals`, making the decimal gap concrete for any NEAR token with more than 18 decimals:

```solidity
function _normalizeDecimals(uint8 decimals) internal pure returns (uint8) {
    uint8 maxAllowedDecimals = 18;
    if (decimals > maxAllowedDecimals) {
        return maxAllowedDecimals;
    }
    return decimals;
}
``` [5](#0-4) 

The existing code comment acknowledges dust loss but only for sub-unit remainders, not for the case where the **entire** transferred amount normalizes to zero:

> Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`. When fee = 0, dust stays locked/burned. [6](#0-5) 

---

### Impact Explanation

A user who locks tokens whose `amount_without_fee` is below the decimal-scaling threshold loses the entire locked amount permanently. `sign_transfer` will always revert for that transfer ID, and no refund or cancel path exists. This constitutes **permanent freezing of bridged funds**, matching the Critical impact tier.

---

### Likelihood Explanation

Any NEAR-native token registered with `origin_decimals > 18` (e.g., 24-decimal tokens common in the NEAR ecosystem) creates a `diff_decimals ≥ 6` gap. A user transferring fewer than `10^6` base units of such a token triggers the bug. This is a realistic user action (small-value transfers, dust sweeps, or simple mistakes), reachable by any unprivileged bridge user with no special privileges required.

---

### Recommendation

Add a pre-lock validation in `init_transfer` (or in `ft_on_transfer` before tokens are accepted) that computes `normalize_amount(amount_without_fee)` for the target chain's decimals and rejects the transfer if the result is zero. This mirrors the guard already present in `sign_transfer` but moves it to before funds are locked:

```rust
// In init_transfer, after computing the transfer_message:
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

Alternatively, implement a cancel/refund function that allows the original sender to reclaim locked tokens for transfers that can never be signed.

---

### Proof of Concept

1. A NEAR token `foo.near` is registered with `origin_decimals = 24`; its EVM counterpart is deployed with `decimals = 18` (capped by `_normalizeDecimals`), giving `diff_decimals = 6`.
2. Alice calls `ft_transfer_call` transferring `500_000` base units (< `10^6`) with `fee = 0`. `init_transfer` accepts the transfer because `fee (0) < amount (500_000)`. Tokens are locked.
3. A relayer calls `sign_transfer`. `normalize_amount(500_000, diff_decimals=6)` = `500_000 / 1_000_000` = **0**. The `require!(amount_to_transfer > 0, ...)` guard fires and the call panics.
4. Step 3 can be repeated indefinitely — it always panics. Alice's `500_000` base units are permanently locked with no refund path. [2](#0-1) [1](#0-0)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L382-384)
```text
        if (fee >= amount) {
            revert InvalidFee();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L586-592)
```text
    function _normalizeDecimals(uint8 decimals) internal pure returns (uint8) {
        uint8 maxAllowedDecimals = 18;
        if (decimals > maxAllowedDecimals) {
            return maxAllowedDecimals;
        }
        return decimals;
    }
```
