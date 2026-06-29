### Title
`update_transfer_fee` Allows Fee Increase That Permanently Blocks `sign_transfer` for Tokens With Decimal Mismatch, Causing Irreversible Fund Freezing — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`update_transfer_fee` permits the sender to raise the token fee up to `amount - 1` with no lower bound on the remaining transferable amount. `sign_transfer` independently enforces that `normalize_amount(amount - fee, decimals) > 0`. For any token where `origin_decimals > destination_decimals` (e.g., a 24-decimal NEAR token bridging to an 18-decimal EVM token), setting `fee = amount - 1` leaves `amount_without_fee = 1`, which normalizes to `0`, causing `sign_transfer` to permanently panic with `InvalidAmountToTransfer`. Because the fee is monotonically increasing (cannot be decreased) and no cancel/refund path exists, the sender's locked tokens are frozen forever.

---

### Finding Description

**Step 1 — `update_transfer_fee` upper bound** [1](#0-0) 

The only constraint on the new token fee is `fee.fee >= current_fee.fee && fee.fee < transfer.message.amount`. This allows `fee.fee = amount - 1`, leaving `amount_without_fee = 1`. The function can be called repeatedly; each call can only raise the fee, never lower it.

**Step 2 — `sign_transfer` normalization guard** [2](#0-1) 

`sign_transfer` computes `amount_to_transfer = normalize_amount(amount_without_fee(), decimals)` and panics if the result is `0`.

**Step 3 — `normalize_amount` uses floor division** [3](#0-2) 

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

For a token with `origin_decimals = 24` and `destination_decimals = 18`, `diff_decimals = 6`. Any `amount_without_fee < 1_000_000` normalizes to `0`.

**Step 4 — No recovery path**

`sign_transfer_callback` only removes the transfer from `pending_transfers` when `fee.is_zero()`. [4](#0-3) 

There is no `cancel_transfer`, `admin_remove_transfer`, or refund function anywhere in the contract. Once the fee is set to `amount - 1`, the transfer is permanently unprocessable and the tokens are permanently locked.

**The inconsistency (direct analog to tBTC):**

| | tBTC | NEAR Omni Bridge |
|---|---|---|
| Fee-update function | `increaseRedemptionFee` — no call-count limit | `update_transfer_fee` — no lower bound on remaining amount |
| Finalization function | `provideRedemptionProof` — hardcoded `fee ≤ initialFee × 5` | `sign_transfer` — requires `normalize_amount(amount − fee) > 0` |
| Inconsistency | >5 increases → proof always fails | `fee = amount − 1` with decimal mismatch → sign always fails |
| Outcome | Deposit liquidated, signers punished | Tokens permanently frozen, no recovery |

---

### Impact Explanation

A sender who calls `update_transfer_fee` with `fee = amount - 1` on a token with `origin_decimals > destination_decimals` causes every subsequent `sign_transfer` call to panic. The transfer record remains in `pending_transfers` indefinitely. The sender's bridged tokens — already burned or locked at `ft_transfer_call` time — are permanently unrecoverable. This constitutes permanent freezing of bridged funds.

---

### Likelihood Explanation

- NEAR native tokens use 24 decimals; EVM tokens commonly use 18. Any NEAR-originated transfer of a 24-decimal token to an EVM chain has a 6-decimal normalization gap.
- The sender only needs `amount - fee < 10^(origin_decimals - destination_decimals)` to trigger the zero-normalization. For the 24→18 case, any `amount_without_fee < 1_000_000` suffices.
- A sender who misunderstands the decimal normalization and sets the fee to maximize relayer incentive (e.g., `fee = amount - 1`) will permanently lose their funds with no warning from the protocol.
- The fee is monotonically increasing; there is no undo.

Likelihood: **Medium-Low** (requires decimal mismatch, which is the normal case for NEAR→EVM, and a sender setting the fee near the maximum).

---

### Recommendation

Add a normalization check inside `update_transfer_fee` before accepting the new fee:

```rust
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
let remaining = transfer.message.amount.0
    .checked_sub(fee.fee.0)
    .near_expect(BridgeError::InvalidFee);
require!(
    Self::normalize_amount(remaining, decimals) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

Alternatively, add a `cancel_transfer` function that allows the sender to reclaim locked tokens when no signature has yet been produced, mirroring the tBTC recommendation to provide a safe exit path.

---

### Proof of Concept

1. Token is registered with `origin_decimals = 24`, `destination_decimals = 18` (standard NEAR→EVM path).
2. Sender calls `ft_transfer_call` with `amount = 2_000_000` and `fee = 0`. Tokens are locked.
3. Sender calls `update_transfer_fee` with `fee = { fee: 1_999_999, native_fee: 0 }`. Accepted because `1_999_999 < 2_000_000`. [1](#0-0) 
4. `amount_without_fee() = 2_000_000 − 1_999_999 = 1`.
5. Relayer calls `sign_transfer`. `normalize_amount(1, Decimals { origin_decimals: 24, decimals: 18 }) = 1 / 10^6 = 0`. [3](#0-2) 
6. `require!(amount_to_transfer > 0, ...)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`. [5](#0-4) 
7. The fee cannot be decreased. No cancel path exists. The 2_000_000 tokens are permanently frozen.

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

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
