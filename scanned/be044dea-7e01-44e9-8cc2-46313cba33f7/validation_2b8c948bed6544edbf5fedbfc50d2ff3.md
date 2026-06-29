### Title
Tokens Permanently Locked When Transfer Amount Normalizes to Zero in `sign_transfer` - (File: `near/omni-bridge/src/lib.rs`)

### Summary
`init_transfer` accepts and locks user tokens for any amount where `fee < amount`, but does not validate that the decimal-normalized net amount is non-zero. When `sign_transfer` is later called for such a transfer, it panics with `InvalidAmountToTransfer`, leaving the tokens permanently locked in the bridge with no recovery path.

### Finding Description
The NEAR bridge contract has two separate validation points for transfer amounts:

**`init_transfer` (entry point):** Only checks that `fee < amount`. [1](#0-0) 

**`sign_transfer` (completion point):** Normalizes the net amount to the destination chain's decimal precision and rejects if the result is zero. [2](#0-1) 

The normalization function uses floor division: [3](#0-2) 

For a token registered with `origin_decimals=24` and `decimals=18`, any net amount below `10^6` (i.e., below 1,000,000 base units) normalizes to zero. A user who sends, say, 500,000 units with zero fee passes `init_transfer`'s `fee < amount` check, but `sign_transfer` will always panic for that transfer ID.

In `init_transfer_internal`, tokens are burned or locked before the transfer message is stored: [4](#0-3) 

Once `sign_transfer` panics, the transfer message remains in `pending_transfers` indefinitely. The `sign_transfer_callback` is never reached, so no cleanup occurs: [5](#0-4) 

`update_transfer_fee` cannot rescue the transfer because it only allows increasing the fee (not decreasing it to make `amount - fee` larger), and the amount itself is immutable: [6](#0-5) 

There is no admin cancel or rescue function in the contract.

### Impact Explanation
User tokens are permanently locked (for native tokens) or burned (for deployed bridge tokens) with no recovery path. The transfer can never be completed or refunded. This constitutes permanent freezing of bridged funds.

### Likelihood Explanation
Any user bridging a token whose `origin_decimals > decimals` (e.g., a 24-decimal NEAR token bridging to an 18-decimal EVM representation) can trigger this by sending a sub-threshold amount. The threshold is `10^(origin_decimals - decimals)` base units. This is a realistic scenario for tokens with high decimal precision. The user may not be aware of the normalization threshold, making accidental loss likely. A malicious actor could also deliberately trigger this to grief other users or test the bridge.

### Recommendation
Add a validation in `init_transfer` (or `init_transfer_internal`) that checks the normalized net amount is greater than zero before locking/burning tokens:

```rust
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
);
if let Some(token_address) = token_address {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee().unwrap_or(0),
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```

This mirrors the existing check in `sign_transfer` and ensures the transfer is rejected at the entry point before any tokens are locked.

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (divisor = `10^6`).
2. Call `ft_transfer_call` on the token contract with `amount = 500_000` (below the `10^6` threshold) and `fee = 0`, targeting the bridge with an `InitTransfer` message to an EVM recipient.
3. `init_transfer` passes: `fee (0) < amount (500_000)` ✓. Tokens are locked. Transfer message stored with nonce N.
4. Trusted relayer calls `sign_transfer` for nonce N.
5. `normalize_amount(500_000, {decimals:18, origin_decimals:24})` = `500_000 / 1_000_000` = `0`.
6. `require!(amount_to_transfer > 0, ...)` panics. Transaction reverts.
7. Transfer message for nonce N remains in `pending_transfers`. Tokens remain locked. No recovery is possible. [2](#0-1) [3](#0-2) [1](#0-0) [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L554-557)
```rust
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L649-667)
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
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
