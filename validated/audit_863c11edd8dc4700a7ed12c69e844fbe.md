### Title
Missing Pre-Validation of Normalized Transfer Amount in `init_transfer` Permanently Locks User Tokens - (File: `near/omni-bridge/src/lib.rs`)

### Summary
The NEAR bridge's `init_transfer` function accepts and locks user tokens without verifying that the post-decimal-normalization net amount is non-zero. When a user sends an amount (minus fee) smaller than the decimal scaling factor, `sign_transfer` will always revert with `ERR_INVALID_AMOUNT_TO_TRANSFER`. Because no cancel or refund path exists for pending transfers, the tokens are permanently frozen in the bridge.

### Finding Description
The bridge stores two decimal values per token: `origin_decimals` (the token's native precision on NEAR) and `decimals` (the precision on the destination chain). `normalize_amount` performs floor division: [1](#0-0) 

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

`init_transfer`, called via `ft_on_transfer`, accepts the user's tokens and stores the `TransferMessage` in `pending_transfers` with only a fee-vs-amount check: [2](#0-1) 

There is **no check** that `normalize_amount(amount - fee) > 0` before the tokens are accepted.

Later, when a trusted relayer calls `sign_transfer`, it computes the normalized amount and enforces: [3](#0-2) 

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee()...,
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

If the normalized amount is 0, `sign_transfer` panics. Because `sign_transfer` is the **only** mechanism to produce the MPC signature needed to finalize a NEAR→foreign transfer, and no user-accessible cancel or refund function exists for pending transfers, the user's tokens remain locked in the bridge indefinitely.

The `remove_transfer_message` call in `sign_transfer_callback` is only reached if MPC signing succeeds: [4](#0-3) 

Since `sign_transfer` panics before the MPC call is ever made, `sign_transfer_callback` is never invoked and the transfer message is never removed.

### Impact Explanation
**Permanent freezing of bridged funds.** Any user who initiates a transfer where `amount - fee < 10^(origin_decimals - decimals)` will have their tokens permanently locked in the bridge contract with no recovery path. For a common NEAR→EVM pairing (`origin_decimals = 24`, `decimals = 18`, scaling factor = 10^6), any net transfer amount below 1,000,000 base units triggers the lock.

### Likelihood Explanation
Any unprivileged user can trigger this condition directly via `ft_transfer_call`. A user who sets a fee close to their transfer amount (e.g., `amount = 1,000,001`, `fee = 1,000,000`) would trigger this, as `amount - fee = 1` normalizes to 0. Users unfamiliar with the decimal normalization mechanics are likely to encounter this accidentally.

### Recommendation
In `init_transfer` (before accepting tokens), add a pre-validation check:

```rust
if let Some(token_address) = self.get_token_address(destination_chain, &token_id) {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        require!(
            Self::normalize_amount(
                amount.0.saturating_sub(init_transfer_msg.fee.0),
                decimals
            ) > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
    }
}
```

If the check fails, `ft_on_transfer` should return the full `amount` to refund the user's tokens before any state is mutated.

### Proof of Concept
1. Token `token.near` is registered with `origin_decimals = 24`, `decimals = 18` (scaling factor = 10^6).
2. User calls `ft_transfer_call` on `token.near` with `amount = 500_000`, `fee = 0`.
3. Bridge's `ft_on_transfer` calls `init_transfer`, which stores the `TransferMessage` and returns `U128(0)` — bridge keeps all 500,000 tokens.
4. Trusted relayer calls `sign_transfer` for this transfer.
5. `normalize_amount(500_000, Decimals { origin_decimals: 24, decimals: 18 }) = 500_000 / 1_000_000 = 0`.
6. `require!(0 > 0, ...)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. The `TransferMessage` remains in `pending_transfers` forever.
8. The user's 500,000 tokens are permanently locked in the bridge with no recovery mechanism. [5](#0-4) [6](#0-5) [1](#0-0)

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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
