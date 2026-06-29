### Title
Entire Transfer Amount Permanently Locked When Below Decimal Normalization Threshold — (`near/omni-bridge/src/lib.rs`)

---

### Summary

The `normalize_amount` function in the NEAR omni-bridge contract uses integer floor division to convert token amounts between decimal precisions. When a user initiates a transfer with an amount smaller than `10^(origin_decimals − decimals)`, the normalized result is `0`. The user's tokens are locked or burned on NEAR, but the amount recorded for the destination chain is zero — permanently trapping the funds with no recovery path when `fee = 0`.

---

### Finding Description

`normalize_amount` is defined as:

```rust
/// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
/// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
/// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

The protocol comment acknowledges that sub-unit *remainders* ("dust") are truncated. However, the same floor division causes the **entire transfer amount** to become `0` when the amount is smaller than `10^diff_decimals`. This is not a dust remainder — it is the complete loss of the user's deposit.

The `Decimals` struct stores both `decimals` (bridge-side precision) and `origin_decimals` (source-chain precision): [2](#0-1) 

For a token with `origin_decimals = 18` and `decimals = 6` (e.g., a USDC-like token bridged from NEAR to Ethereum), `diff_decimals = 12`. Any transfer amount below `10^12` (i.e., less than `0.000001` of the token's base unit on the destination chain) normalizes to `0`. The user's tokens are locked or burned on NEAR, but the bridge records an amount of `0` for the destination chain. No corresponding unlock or mint occurs on the destination. There is no minimum-amount guard visible in the code, and no revert when the normalized result is `0`.

The `claim_fee` path that absorbs dust into the relayer fee only applies when `fee > 0`. When `fee = 0`, the comment explicitly states the dust "stays locked/burned" — confirming the funds are irrecoverable. [3](#0-2) 

---

### Impact Explanation

A user who sends a transfer amount below the decimal normalization threshold with `fee = 0` permanently loses their tokens. The tokens are locked or burned on the NEAR side, the normalized amount is `0`, and no corresponding release or mint is triggered on the destination chain. This constitutes **permanent freezing/loss of bridged funds** — a Critical impact per the allowed scope ("escrow mis-accounting, decimal/normalization abuse … that changes user or protocol balances").

---

### Likelihood Explanation

The condition is reachable by any unprivileged bridge user. It requires only that the user submit a transfer amount below `10^diff_decimals` with `fee = 0`. For tokens with a large decimal gap (e.g., 18 on NEAR, 6 on Ethereum, diff = 12), any amount below `1,000,000,000,000` raw units triggers the bug. A user unfamiliar with the decimal normalization behavior — or one using a UI that does not enforce a minimum — can trigger this silently. No special role, key, or privileged access is required.

---

### Recommendation

Add an explicit check after calling `normalize_amount` that reverts the transaction if the normalized amount is `0`:

```rust
let normalized = Self::normalize_amount(amount, decimals);
require!(normalized > 0, BridgeError::AmountTooSmallToNormalize.as_ref());
```

This mirrors the standard mitigation for this class of bug: establish a minimum deposit requirement so that no transfer can proceed with a normalized amount of zero.

---

### Proof of Concept

Consider a token registered with `origin_decimals = 18`, `decimals = 6` (diff = 12).

1. User calls `ft_transfer_call` on the NEAR token contract, sending `999_999_999_999` raw units to the bridge with `fee = 0` and a destination on Ethereum.
2. The bridge calls `normalize_amount(999_999_999_999, Decimals { origin_decimals: 18, decimals: 6 })`.
3. `diff_decimals = 12`; `10_u128.pow(12) = 1_000_000_000_000`.
4. `999_999_999_999 / 1_000_000_000_000 = 0` (integer floor division).
5. The normalized amount is `0`. The user's `999_999_999_999` tokens are locked/burned on NEAR.
6. The bridge records amount `0` for the destination chain. No unlock or mint is ever triggered on Ethereum.
7. With `fee = 0`, there is no `claim_fee` path to recover the dust. The funds are permanently lost. [4](#0-3)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1128-1131)
```rust
        // Fee includes both the user-specified fee and any dust lost during decimal
        // normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
        // due to floor division, the difference naturally captures the normalization remainder.
        let fee = transfer_message.amount.0 - denormalized_amount;
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

**File:** near/omni-bridge/src/storage.rs (L131-136)
```rust
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
```
