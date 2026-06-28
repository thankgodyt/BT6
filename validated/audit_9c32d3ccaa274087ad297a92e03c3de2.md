### Title
No Minimum Transfer Amount Validation Causes Permanent Token Lock for Sub-Unit Transfers — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `init_transfer` function accepts and stores outbound transfers whose net amount (after fee) is too small to survive decimal normalization to the destination chain. Once stored, the transfer can never be signed or finalized — `sign_transfer` always panics — and no cancellation path exists. The user's tokens are permanently locked in the bridge contract.

---

### Finding Description

The bridge supports tokens whose NEAR-side decimal precision differs from the destination chain. For example, a token with `origin_decimals = 24` and `decimals = 18` (a 6-decimal difference) requires a divisor of `10^6 = 1,000,000` during normalization.

`init_transfer` validates only that `fee.fee < amount`: [1](#0-0) 

It does **not** validate that `normalize_amount(amount - fee) > 0`. The transfer is accepted, stored in `pending_transfers`, and the user's tokens are locked.

Later, when a relayer calls `sign_transfer`, the normalization is applied: [2](#0-1) 

`normalize_amount` uses floor division: [3](#0-2) 

If `amount - fee < 10^(origin_decimals - decimals)`, the result is `0`, and `sign_transfer` panics. The MPC signer is never called, `sign_transfer_callback` is never reached, and the transfer is never removed from `pending_transfers`.

The only removal paths for an outbound transfer are:

1. `sign_transfer_callback` with `fee.is_zero()` — unreachable because `sign_transfer` panics before calling the signer.
2. `claim_fee_callback` — requires a proof from the destination chain that the transfer was finalized, which never happens. [4](#0-3) 

There is no `cancel_transfer` or admin-rescue function. `update_transfer_fee` cannot help: it only allows increasing the fee up to `amount - 1` (strict less-than), so `amount_without_fee` can be reduced to `1` but never to `0`, and `normalize_amount(1) = 0` still panics. [5](#0-4) 

---

### Impact Explanation

Any user who initiates an outbound transfer where `(amount - fee) < 10^(origin_decimals - decimals)` permanently loses their tokens. The tokens are locked in the bridge contract with no recovery path. This is a **permanent freezing of bridged funds**, matching the critical impact scope.

---

### Likelihood Explanation

Tokens with a large decimal gap are common (e.g., NEAR-native tokens with 24 decimals bridged to EVM chains with 18 decimals, giving a divisor of `1,000,000`). A user sending fewer than `1,000,000` base units (e.g., `0.000001` of such a token) triggers the bug. This is a realistic user error, especially for low-value or dust transfers. No special privileges are required — any unprivileged bridge user can trigger this via `ft_transfer_call`.

---

### Recommendation

Add a normalization check inside `init_transfer` before storing the transfer:

```rust
require!(
    Self::normalize_amount(
        transfer_message.amount.0.checked_sub(transfer_message.fee.fee.0)
            .near_expect(BridgeError::InvalidFee),
        decimals
    ) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This requires looking up the token decimals at `init_transfer` time (as `sign_transfer` already does). Alternatively, add a `cancel_transfer` function that allows the original sender to reclaim tokens from a transfer that has never been signed.

---

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `decimals = 18` (divisor = `1,000,000`).
2. User calls `ft_transfer_call` with `amount = 500_000`, `fee = 0`.
3. `init_transfer` passes the only check: `0 < 500_000` ✓. Transfer is stored; 500,000 tokens are locked.
4. Relayer calls `sign_transfer(transfer_id, None, None)`.
5. `normalize_amount(500_000, {origin: 24, decimals: 18}) = 500_000 / 1_000_000 = 0`.
6. `require!(0 > 0, ...)` panics. [6](#0-5) 
7. No MPC call is made. `sign_transfer_callback` is never reached. The transfer remains in `pending_transfers` indefinitely.
8. `claim_fee` cannot be called (no destination-chain finalization proof exists).
9. User's 500,000 tokens are permanently locked with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-401)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
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

**File:** near/omni-bridge/src/lib.rs (L649-668)
```rust
    pub fn sign_transfer_callback(
        &mut self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] message_payload: TransferMessagePayload,
        #[serializer(borsh)] fee: &Fee,
    ) {
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }

            env::log_str(
                &OmniBridgeEvent::SignTransferEvent {
                    signature,
                    message_payload,
                }
                .to_log_string(),
            );
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
