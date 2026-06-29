### Title
Unchecked `u128` Multiplication Overflow in `denormalize_amount` Permanently Freezes Bridged Funds — (`near/omni-bridge/src/lib.rs`)

### Summary

`denormalize_amount` multiplies a `u128` amount by `10^(origin_decimals − decimals)` with no overflow guard. Because the NEAR workspace compiles with `overflow-checks = true`, the multiplication panics at runtime. When triggered inside `fin_transfer_callback`, the callback aborts, the transfer is never finalised on NEAR, and the user's tokens — already locked or burned on the EVM side — are permanently frozen.

### Finding Description

`denormalize_amount` is defined as:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))   // ← no checked_mul / saturating_mul
}
``` [1](#0-0) 

The workspace `Cargo.toml` enables `overflow-checks = true` for the release profile: [2](#0-1) 

This means any `amount * 10^diff_decimals` that exceeds `u128::MAX` causes an immediate panic/abort rather than silent truncation.

`denormalize_amount` is called unconditionally inside `fin_transfer_callback` to reconstruct the NEAR-side amount from the EVM-side proof:

```rust
amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
``` [3](#0-2) 

It is also called in `fast_fin_transfer` and `claim_fee_callback`: [4](#0-3) [5](#0-4) 

The `Decimals` struct stores `decimals` (EVM-side, capped at 18) and `origin_decimals` (NEAR-side, e.g. 24 for NEAR's native token): [6](#0-5) 

These values are populated from the on-chain `DeployToken` proof during `bind_token_callback`: [7](#0-6) 

On the EVM side, `initTransfer` accepts `uint128 amount` with no upper-bound check beyond `fee >= amount`: [8](#0-7) 

### Impact Explanation

For a token with `origin_decimals = 24` and `decimals = 18` (`diff_decimals = 6`), the overflow threshold is `u128::MAX / 10^6 ≈ 3.4 × 10^32`. Any EVM `uint128` amount above this value causes `denormalize_amount` to panic. With `overflow-checks = true`, the NEAR runtime aborts the callback. Because the EVM side has already locked or burned the tokens before the proof is submitted, and because the NEAR nonce is never marked (the callback never completes), the transfer is permanently unfinalisable. The user's funds are frozen with no recovery path.

For tokens with larger decimal gaps (e.g., `diff_decimals = 18`), the overflow threshold drops to `u128::MAX / 10^18 ≈ 3.4 × 10^20`, making the attack trivially reachable with moderate token amounts.

### Likelihood Explanation

Any unprivileged bridge user can trigger this by calling `initTransfer` on the EVM contract with a `uint128` amount above the overflow threshold for the specific token's decimal configuration. No special role, key, or collusion is required. The EVM contract imposes no upper-bound on `amount` beyond the `fee < amount` check. Tokens bridging between chains with large decimal differences (e.g., NEAR native token: 24 origin decimals, 18 EVM decimals) are directly affected.

### Recommendation

Replace the bare multiplication in `denormalize_amount` with a checked variant that returns an error on overflow, and propagate that error to the caller:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> Option<u128> {
    let diff_decimals: u32 = decimals.origin_decimals.checked_sub(decimals.decimals)?.into();
    amount.checked_mul(10_u128.checked_pow(diff_decimals)?)
}
```

All call sites (`fin_transfer_callback`, `fast_fin_transfer`, `claim_fee_callback`) should handle `None` by panicking with a descriptive `BridgeError` rather than letting an arithmetic abort propagate. Additionally, consider enforcing an upper-bound check on the EVM `initTransfer` amount relative to the token's decimal configuration so that overflowing amounts are rejected at the source before tokens are locked or burned.

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `decimals = 18` (`diff_decimals = 6`).
2. Attacker calls `initTransfer` on EVM with `amount = u128::MAX / 10^6 + 1` (a valid `uint128`). EVM locks/burns the tokens.
3. Relayer submits the EVM proof to NEAR `fin_transfer` → `fin_transfer_callback`.
4. Inside the callback: `denormalize_amount(amount, decimals)` computes `(u128::MAX / 10^6 + 1) * 10^6`, which exceeds `u128::MAX`. With `overflow-checks = true`, the NEAR runtime panics.
5. The callback aborts; no state is written; the destination nonce is never marked used.
6. Every subsequent retry by any relayer produces the same panic.
7. The attacker's (or victim's) tokens are permanently frozen on EVM with no NEAR-side release possible.

### Citations

**File:** near/omni-bridge/src/lib.rs (L722-726)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
```

**File:** near/omni-bridge/src/lib.rs (L770-772)
```rust
        let denormalized_amount =
            Self::denormalize_amount(fast_fin_transfer_msg.amount.0, decimals);
        let denormalized_fee = Self::denormalize_fee(&fast_fin_transfer_msg.fee, decimals);
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

**File:** near/omni-bridge/src/lib.rs (L1262-1267)
```rust
        self.add_token(
            &deploy_token.token,
            &deploy_token.token_address,
            deploy_token.decimals,
            deploy_token.origin_decimals,
        );
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** near/Cargo.toml (L31-31)
```text
overflow-checks = true
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-384)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }
```
