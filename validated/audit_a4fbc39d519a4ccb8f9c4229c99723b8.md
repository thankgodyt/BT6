### Title
Integer Division in `normalize_amount` Permanently Locks User Funds When Transfer Amount Is Below Decimal Precision Threshold — (`File: near/omni-bridge/src/lib.rs`)

---

### Summary

`normalize_amount` uses floor integer division to scale a token amount from its origin-chain precision to its destination-chain precision. When a user initiates a transfer with an amount smaller than `10^(origin_decimals - decimals)`, the normalized result is `0`. The `sign_transfer` function then panics with `InvalidAmountToTransfer` — but the user's tokens are already locked in the bridge with no recovery path.

---

### Finding Description

`normalize_amount` performs floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

This is called inside `sign_transfer` to compute the amount that will be sent to the destination chain:

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

The `require!` guard correctly rejects a zero normalized amount — but by this point the user's tokens have already been transferred into the bridge during `init_transfer` (via `ft_transfer_call` → `ft_on_transfer`): [3](#0-2) 

`init_transfer` only validates that `fee < amount`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [4](#0-3) 

There is no check that `amount` (or `amount - fee`) is at least `10^(origin_decimals - decimals)`. The transfer message is stored in `pending_transfers` and the tokens are held by the bridge. Every subsequent call to `sign_transfer` for this transfer will always panic at the same guard, and there is no `cancel_transfer` or emergency-refund function in the contract.

The `sign_transfer_callback` only removes the transfer message when MPC signing succeeds and `fee.is_zero()`:

```rust
if let Ok(signature) = call_result {
    if fee.is_zero() {
        self.remove_transfer_message(message_payload.transfer_id);
    }
``` [5](#0-4) 

Because `sign_transfer` panics before the MPC call is ever made, this callback is never reached, so the transfer message and the locked tokens are never freed.

The codebase's own comment acknowledges the floor-division behavior but only addresses the "dust" (sub-unit remainder) case:

> "When fee = 0, dust stays locked/burned." [6](#0-5) 

The unaddressed case is when the **entire** transfer amount normalizes to zero — not just a dust remainder.

---

### Impact Explanation

Any user who initiates a NEAR → foreign-chain transfer with an amount below the minimum representable unit on the destination chain permanently loses their tokens. The tokens are locked in the bridge contract with no mechanism to recover them. This constitutes **permanent freezing of bridged funds**.

Concrete example:
- Token registered with `origin_decimals = 24`, `decimals = 18` (diff = 6, divisor = 1,000,000).
- User sends `amount = 500,000` (with `fee = 0`).
- `normalize_amount(500_000, diff=6) = 500_000 / 1_000_000 = 0`.
- `sign_transfer` panics with `InvalidAmountToTransfer`.
- All 500,000 units are permanently locked.

Even with a non-zero fee, `update_transfer_fee` can only increase the fee (never decrease it below the original), so the user cannot reduce `fee` to zero to recover dust, and increasing the fee only makes `amount_without_fee` smaller, keeping the normalized result at zero.

---

### Likelihood Explanation

The condition is reachable by any unprivileged user who calls `ft_transfer_call` with a small amount. No special role or permission is required. Tokens with a large decimal difference between origin and destination chains (e.g., NEAR's 24-decimal tokens bridged to chains that register them at 18 decimals) have a minimum transferable unit of `10^6` base units. A user who sends any amount below this threshold triggers the permanent lock. This is a realistic user mistake, especially for tokens with high decimal differences.

---

### Recommendation

Add a validation in `init_transfer` (before tokens are accepted) that the `amount - fee` is at least `10^(origin_decimals - decimals)` for the destination chain, i.e., that `normalize_amount(amount - fee, decimals) > 0`. This mirrors the recommendation in the external report to enforce a minimum amount / precision multiple at the point of entry, not at the point of execution.

```rust
// Pseudocode for the guard to add in init_transfer:
let decimals = self.token_decimals.get(&token_address)...;
require!(
    Self::normalize_amount(amount.0 - fee.fee.0, decimals) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This check must be placed **before** the tokens are accepted into the bridge (i.e., before `init_transfer_internal` stores the transfer message), so that `ft_on_transfer` returns the full amount to the sender on failure.

---

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (6-decimal difference, divisor = 1,000,000).
2. Call `ft_transfer_call` on the token contract with `amount = 500_000` and `msg` encoding an `InitTransferMsg` with `fee = 0` and a valid EVM recipient.
3. `init_transfer` accepts the tokens (500,000 < 1,000,000 but fee=0 < amount=500,000 passes the only guard).
4. Tokens are locked in the bridge; transfer message stored in `pending_transfers`.
5. Trusted relayer calls `sign_transfer` for this `transfer_id`.
6. `normalize_amount(500_000, diff=6) = 0` → `require!(0 > 0, ...)` panics with `InvalidAmountToTransfer`.
7. No MPC call is made; `sign_transfer_callback` is never reached; transfer message stays in `pending_transfers`.
8. Repeat step 5 indefinitely — always panics. Tokens are permanently locked with no recovery path.

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

**File:** near/omni-bridge/src/lib.rs (L523-557)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
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
