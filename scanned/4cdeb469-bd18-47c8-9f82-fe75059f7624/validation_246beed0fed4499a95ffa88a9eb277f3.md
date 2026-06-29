### Title
Unchecked Arithmetic Overflow in `denormalize_amount` Produces Incorrect Token Amount — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`denormalize_amount` multiplies a `u128` amount by `10_u128.pow(diff_decimals)` with no upper-bound guard. In a Rust release build compiled without `overflow-checks = true`, this multiplication silently wraps, producing a drastically incorrect (much smaller) token amount. The Solana workspace explicitly opts into overflow checks; no equivalent setting was found for the NEAR contract workspace. A user who initiates a cross-chain transfer with a sufficiently large amount on the source chain can trigger this path.

---

### Finding Description

`denormalize_amount` is defined as:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

`Decimals` stores two `u8` fields:

```rust
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
``` [2](#0-1) 

`diff_decimals = origin_decimals − decimals` can be up to 255. `u128::MAX ≈ 3.4 × 10^38`, so `10_u128.pow(39)` already overflows `u128`. Even for realistic `diff_decimals` values (e.g., 6 for a 24-decimal EVM token capped to 18 on NEAR), any `amount > u128::MAX / 10^6 ≈ 3.4 × 10^32` raw units causes the multiplication to wrap.

There is **no upper-bound check** on `amount` before the multiplication, mirroring exactly the pattern in the external report (`wExp(x)` accepted values that caused overflow because the bound was not tight enough).

The Solana workspace explicitly enables overflow protection:

```toml
[profile.release]
overflow-checks = true
``` [3](#0-2) 

No equivalent setting was found for the NEAR contract workspace. Without `overflow-checks = true`, Rust release builds silently wrap on overflow.

---

### Impact Explanation

`denormalize_amount` is called in `fin_transfer_callback` to compute the NEAR-side token amount from the cross-chain proof:

```rust
amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
``` [4](#0-3) 

It is also called in `fast_fin_transfer` and `claim_fee_callback`: [5](#0-4) [6](#0-5) 

If the multiplication wraps, `transfer_message.amount` is set to a small (or zero) incorrect value. The source-chain tokens are already burned or locked, but the NEAR recipient receives a drastically reduced amount. This is an irreversible **balance manipulation / fund loss** for the recipient.

`denormalize_fee` delegates to the same function, so fee accounting is equally affected:

```rust
fn denormalize_fee(fee: &Fee, decimals: Decimals) -> Fee {
    Fee {
        fee: U128(Self::denormalize_amount(fee.fee.0, decimals)),
        ...
    }
}
``` [7](#0-6) 

---

### Likelihood Explanation

The attacker controls the `amount` field in the source-chain `InitTransfer` event (EVM `uint128`, Starknet `u128`, Solana `u128`). For a token with `diff_decimals = 6` (e.g., 24-decimal EVM token capped to 18 on NEAR), the overflow threshold is `~3.4 × 10^32` raw units (`~3.4 × 10^8` human-readable tokens). For tokens with `diff_decimals ≥ 39`, even `amount = 1` overflows. Likelihood is low for typical token supplies but non-zero for high-supply or high-decimal tokens, and the attacker needs only to hold and transfer the threshold amount on the source chain.

---

### Recommendation

Add an explicit upper-bound check before the multiplication, analogous to the fix recommended in the external report:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    let multiplier = 10_u128
        .checked_pow(diff_decimals)
        .expect("decimal exponent overflows u128");
    amount
        .checked_mul(multiplier)
        .expect("denormalize_amount overflow")
}
```

Additionally, add `overflow-checks = true` to the NEAR contract's `[profile.release]` in its `Cargo.toml`, mirroring the Solana workspace setting.

---

### Proof of Concept

```rust
// diff_decimals = 39 (e.g., origin_decimals = 57, decimals = 18)
// 10_u128.pow(39) overflows u128 (u128::MAX ≈ 3.4e38)
let result = Contract::denormalize_amount(
    1_u128,
    Decimals { decimals: 18, origin_decimals: 57 },
);
// In release mode without overflow-checks: result wraps to an incorrect value
// instead of panicking, producing a wrong NEAR-side amount.

// For realistic diff_decimals = 6:
let threshold = u128::MAX / 1_000_000 + 1; // ~3.4e32
let result = Contract::denormalize_amount(
    threshold,
    Decimals { decimals: 18, origin_decimals: 24 },
);
// Wraps: source-chain tokens are burned, recipient receives wrong amount on NEAR.
```

### Citations

**File:** near/omni-bridge/src/lib.rs (L725-725)
```rust
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
```

**File:** near/omni-bridge/src/lib.rs (L770-771)
```rust
        let denormalized_amount =
            Self::denormalize_amount(fast_fin_transfer_msg.amount.0, decimals);
```

**File:** near/omni-bridge/src/lib.rs (L1122-1127)
```rust
        let denormalized_amount = Self::denormalize_amount(
            fin_transfer.amount.0,
            self.token_decimals
                .get(&token_address)
                .near_expect(BridgeError::TokenDecimalsNotFound),
        );
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-bridge/src/lib.rs (L2790-2795)
```rust
    fn denormalize_fee(fee: &Fee, decimals: Decimals) -> Fee {
        Fee {
            fee: U128(Self::denormalize_amount(fee.fee.0, decimals)),
            native_fee: fee.native_fee,
        }
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

**File:** solana/Cargo.toml (L6-6)
```text
overflow-checks = true
```
