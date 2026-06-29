### Title
Unchecked u8 Underflow in `normalize_amount` Causes Division-by-Zero Panic, Permanently Locking Bridged Funds — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`Contract::normalize_amount` performs an unchecked `u8` subtraction `origin_decimals - decimals`. When `origin_decimals < decimals` (e.g., a NEAR token with 6 decimals whose EVM counterpart has 18 decimals), the subtraction wraps to a large `u8` value in release mode. The resulting exponent causes `10_u128.pow(large)` to overflow and wrap to `0`, after which `amount / 0` unconditionally panics. Because `sign_transfer` calls `normalize_amount` before removing the transfer from `pending_transfers`, any transfer involving such a token is permanently stuck and the user's funds are irrecoverably locked.

---

### Finding Description

**Root cause — `normalize_amount` (lines 2784–2787):**

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

`Decimals::decimals` and `Decimals::origin_decimals` are both `u8`. In Rust release mode, integer arithmetic wraps on overflow. If `origin_decimals < decimals`:

| Step | Value |
|---|---|
| `6u8 - 18u8` (wrapping) | `244u8` |
| `244u32` as exponent | `244` |
| `10_u128.pow(244)` (wrapping) | `0` — because `10^128 ≡ 0 (mod 2^128)`, so any power ≥ 128 wraps to 0 |
| `amount / 0u128` | **unconditional panic** — Rust always panics on integer division by zero, even in release mode |

**How the state is reached — `bind_token_callback` (lines 1262–1267):**

```rust
self.add_token(
    &deploy_token.token,
    &deploy_token.token_address,
    deploy_token.decimals,
    deploy_token.origin_decimals,
);
```

`add_token` stores `Decimals { decimals: deploy_token.decimals, origin_decimals: deploy_token.origin_decimals }` keyed by the foreign-chain token address. When a NEAR-native token with fewer decimals than its EVM counterpart (e.g., 6 vs. 18) is registered via a valid `bind_token` proof, the stored `Decimals` struct will have `origin_decimals (6) < decimals (18)`.

**Where the panic fires — `sign_transfer` (lines 471–485):**

```rust
let decimals = self
    .token_decimals
    .get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
let amount_to_transfer = Self::normalize_amount(
    transfer_message
        .amount_without_fee()
        .near_expect(BridgeError::InvalidFee),
    decimals,
);
```

`sign_transfer` is called by the relayer *after* the transfer is already stored in `pending_transfers`. The panic occurs inside the callback, leaving the transfer record in place with no recovery path. There is no admin function to forcibly remove a stuck `pending_transfers` entry.

---

### Impact Explanation

Any user who initiates a NEAR-to-foreign-chain transfer of a token whose stored `Decimals` struct has `origin_decimals < decimals` will have their funds permanently locked. `sign_transfer` will panic on every invocation for that transfer, and the transfer can never be completed or cancelled. This constitutes **permanent freezing of bridged funds**, which is in the critical impact scope.

---

### Likelihood Explanation

The condition is reachable whenever a token is registered via `bind_token_callback` with `deploy_token.origin_decimals < deploy_token.decimals`. This occurs for any NEAR-native token that has fewer decimals than its EVM representation (e.g., a 6-decimal NEAR stablecoin whose EVM mirror uses 18 decimals, a common EVM convention). No privileged access is required to trigger the panic — any user who calls `ft_on_transfer` with such a token initiates the transfer, and the relayer's subsequent `sign_transfer` call panics. The user has no recourse.

---

### Recommendation

1. **Validate the invariant at registration time.** In `add_token` (or `bind_token_callback`), assert `origin_decimals >= decimals` before inserting into `token_decimals`. This mirrors the recommendation in the external report to assert the invariant at the setter.

2. **Use checked arithmetic in `normalize_amount` and `denormalize_amount`.** Replace the bare `u8` subtraction with `checked_sub`, and handle the case where `decimals > origin_decimals` by multiplying instead of dividing:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    match decimals.origin_decimals.checked_sub(decimals.decimals) {
        Some(diff) => amount / 10_u128.pow(diff.into()),
        None => {
            let diff = decimals.decimals - decimals.origin_decimals;
            amount * 10_u128.pow(diff.into())
        }
    }
}
```

3. Apply the same fix to `denormalize_amount` to prevent silent balance corruption (wrapping multiplication to 0) in the reverse direction.

---

### Proof of Concept

1. A NEAR token `usdc.near` with 6 decimals is bridged to EVM. The EVM contract deploys a mirror token with 18 decimals and emits a `DeployToken` event with `decimals = 18`, `origin_decimals = 6`.

2. A relayer submits the proof to `bind_token`. `bind_token_callback` calls `add_token("usdc.near", EVM_addr, 18, 6)`, storing `Decimals { decimals: 18, origin_decimals: 6 }` for `EVM_addr`.

3. Alice calls `ft_transfer_call` on `usdc.near` with a `BridgeOnTransferMsg::InitTransfer` targeting an EVM recipient. `init_transfer` stores the transfer in `pending_transfers` and returns `U128(0)` (success).

4. The relayer calls `sign_transfer(transfer_id, ...)`. Inside:
   - `token_address` = `EVM_addr`
   - `decimals` = `Decimals { decimals: 18, origin_decimals: 6 }`
   - `normalize_amount(amount, decimals)`:
     - `diff_decimals = 6u8 - 18u8 = 244u8` (wrapping)
     - `10_u128.pow(244) = 0` (wrapping overflow)
     - `amount / 0` → **panic**

5. Alice's funds remain in `pending_transfers` indefinitely. There is no escape hatch. Funds are permanently frozen. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L471-485)
```rust
        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
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

**File:** near/omni-bridge/src/lib.rs (L1262-1267)
```rust
        self.add_token(
            &deploy_token.token,
            &deploy_token.token_address,
            deploy_token.decimals,
            deploy_token.origin_decimals,
        );
```

**File:** near/omni-bridge/src/lib.rs (L2704-2735)
```rust
    fn add_token(
        &mut self,
        token_id: &AccountId,
        token_address: &OmniAddress,
        decimals: u8,
        origin_decimals: u8,
    ) {
        let chain_kind = token_address.get_chain();
        require!(
            self.token_id_to_address
                .insert(&(chain_kind, token_id.clone()), token_address)
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );
        require!(
            self.token_address_to_id
                .insert(token_address, token_id)
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );
        require!(
            self.token_decimals
                .insert(
                    token_address,
                    &Decimals {
                        decimals,
                        origin_decimals,
                    }
                )
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-bridge/src/storage.rs (L132-136)
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
```
