### Title
Unchecked Multiplication Overflow in `denormalize_amount` Permanently Freezes Bridged Funds — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `denormalize_amount` helper performs a bare `u128` multiplication without overflow protection. When a user deposits a sufficiently large token amount on a foreign-chain bridge (EVM, Solana, Starknet), the NEAR-side `fin_transfer_callback` calls `denormalize_amount` on the event-supplied amount. Because `overflow-checks = true` is set in the release profile, the multiplication panics (aborts) rather than wrapping. The callback transaction fails, the transfer is never marked finalised, and the user's tokens — already locked or burned on the foreign chain — are permanently frozen with no recovery path.

---

### Finding Description

`denormalize_amount` is defined as:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))   // ← unchecked multiplication
}
``` [1](#0-0) 

The release profile explicitly enables overflow trapping:

```toml
[profile.release]
overflow-checks = true
panic = "abort"
``` [2](#0-1) 

`denormalize_amount` is called unconditionally inside `fin_transfer_callback` on the amount and fee fields parsed directly from the prover result (i.e., from the foreign-chain event):

```rust
amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
...
fee: Self::denormalize_fee(&init_transfer.fee, decimals),
``` [3](#0-2) 

`denormalize_fee` delegates to the same function:

```rust
fn denormalize_fee(fee: &Fee, decimals: Decimals) -> Fee {
    Fee {
        fee: U128(Self::denormalize_amount(fee.fee.0, decimals)),
        ...
    }
}
``` [4](#0-3) 

The same unchecked call appears in `fast_fin_transfer` and `claim_fee_callback`: [5](#0-4) [6](#0-5) 

**Overflow threshold.** For a token pair where `origin_decimals = 24` (NEAR) and `decimals = 18` (EVM), `diff_decimals = 6`. The multiplication overflows `u128` when:

```
amount > u128::MAX / 10^6  ≈  3.4 × 10^32  (in 18-decimal EVM units)
```

Expressed in whole tokens (dividing by 10^18), the threshold is **≈ 340 trillion tokens**. Real tokens with supplies above this threshold exist (e.g., SHIB ≈ 589 trillion, PEPE ≈ 420 trillion). The EVM bridge accepts `uint128 amount` with no upper-bound check:

```solidity
function initTransfer(
    address tokenAddress,
    uint128 amount,
    ...
) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    ...
    if (fee >= amount) { revert InvalidFee(); }
``` [7](#0-6) 

There is no maximum-amount guard anywhere between the EVM deposit and the NEAR callback.

---

### Impact Explanation

When the multiplication overflows, the NEAR runtime aborts the `fin_transfer_callback` transaction. Because NEAR's async model consumes the promise result on each attempt, the relayer can re-submit `fin_transfer` with the same proof, but every attempt will abort identically — the amount encoded in the foreign-chain event is immutable. The transfer is never recorded in `finalised_transfers`, yet the tokens are already locked or burned on the foreign chain. There is no refund or rescue path in the EVM bridge for a NEAR-side failure. The result is **permanent, irrecoverable freezing of the deposited tokens**.

The same abort path exists in `fast_fin_transfer` (relayer-fronted fast path) and `claim_fee_callback` (fee-claim path), broadening the attack surface.

---

### Likelihood Explanation

Any unprivileged user who holds a large position in a high-supply token (SHIB, PEPE, or any future token with supply > ~340 trillion units at 18 decimals) and bridges it through Omni Bridge can trigger this. No special role, key, or collusion is required. The EVM `initTransfer` function is publicly callable and imposes no upper-bound on `amount`. The attacker need only deposit an amount above the overflow threshold; the loss is their own funds, making this a self-inflicted but irreversible outcome rather than a profitable attack — yet it still constitutes permanent freezing of bridged funds within the allowed impact scope.

---

### Recommendation

Replace the bare multiplication in `denormalize_amount` with a checked variant and propagate the error:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> Option<u128> {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount.checked_mul(10_u128.pow(diff_decimals))
}
```

In `fin_transfer_callback` (and every other call site), reject the transfer with a descriptive error if `None` is returned, rather than aborting. Additionally, add a maximum-amount guard in the EVM `initTransfer` function so that amounts that cannot be safely denormalized on NEAR are rejected at deposit time.

---

### Proof of Concept

1. Register a token pair: EVM token with 18 decimals, NEAR token with 24 decimals (`diff_decimals = 6`).
2. Call `OmniBridge.initTransfer` on EVM with `amount = 3.4 × 10^32 + 1` (a valid `uint128` value, above the overflow threshold). Tokens are locked/burned on EVM; an `InitTransfer` event is emitted.
3. A relayer submits the proof to NEAR via `fin_transfer`.
4. `fin_transfer_callback` executes `denormalize_amount(3.4 × 10^32 + 1, {decimals: 18, origin_decimals: 24})`.
5. The multiplication `(3.4 × 10^32 + 1) × 10^6` exceeds `u128::MAX`; with `overflow-checks = true` and `panic = "abort"`, the NEAR transaction aborts.
6. The transfer is never finalised. Every subsequent retry with the same proof aborts identically.
7. The user's tokens on EVM are permanently frozen.

### Citations

**File:** near/omni-bridge/src/lib.rs (L722-732)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };
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

**File:** near/Cargo.toml (L24-31)
```text
[profile.release]
codegen-units = 1
# Tell `rustc` to optimize for small code size.
opt-level = "z"
lto = true
debug = false
panic = "abort"
overflow-checks = true
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
