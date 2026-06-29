Audit Report

## Title
Tokens Permanently Locked When Transfer Amount Normalizes to Zero in `sign_transfer` - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` accepts and locks user tokens for any amount where `fee < amount`, but does not validate that the decimal-normalized net amount is non-zero. When `sign_transfer` is later called for such a transfer, it panics with `InvalidAmountToTransfer`, leaving the tokens permanently locked in the bridge with no recovery path.

## Finding Description
The contract has two separate validation points that are inconsistent:

**`init_transfer_internal` (entry point):** Only checks `fee.fee < transfer_message.amount` at [1](#0-0)  before burning/locking tokens at [2](#0-1) . No normalization check is performed.

**`sign_transfer` (completion point):** Normalizes the net amount via floor division at [3](#0-2)  and panics if the result is zero at [4](#0-3) .

Because `init_transfer` and `sign_transfer` are separate NEAR transactions, the token lock/burn from `init_transfer` is already committed on-chain before `sign_transfer` is ever called. When `sign_transfer` panics, only its own transaction reverts — the tokens remain locked. The `sign_transfer_callback` is never reached, so no cleanup occurs. [5](#0-4) 

`update_transfer_fee` enforces `fee.fee >= current_fee.fee`, meaning fees can only increase, not decrease to make the net amount larger. The transfer amount itself is immutable. [6](#0-5)  No cancel, rescue, or refund function exists in the contract.

Notably, the code comment at `normalize_amount` acknowledges this behavior: *"When fee = 0, dust stays locked/burned."* [7](#0-6)  However, this documents only dust (small remainders), not the case where the entire amount normalizes to zero — a materially more severe outcome.

## Impact Explanation
This constitutes permanent freezing of bridged funds, matching the Critical impact scope. For native NEAR tokens, funds are locked in the bridge contract forever. For deployed bridge tokens, they are burned with no corresponding release on the destination chain. The transfer can never be completed or refunded.

## Likelihood Explanation
Any unprivileged user bridging a token where `origin_decimals > decimals` (e.g., a 24-decimal NEAR-side token bridging to an 18-decimal EVM representation) can trigger this by sending any amount below `10^(origin_decimals - decimals)` base units. This threshold is `10^6` for the 24→18 decimal case. The user need not be malicious — accidental loss is realistic given that sub-threshold amounts are not rejected at the entry point and the normalization behavior is not surfaced to users. The condition is repeatable and requires no special privileges.

## Recommendation
Add a normalization check in `init_transfer_internal` (before tokens are locked/burned) that mirrors the existing check in `sign_transfer`:

```rust
if let Some(token_address) = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
) {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee().unwrap_or(0),
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```

This ensures the transfer is rejected before any tokens are locked or burned.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (divisor = `10^6`).
2. Call `ft_transfer_call` on the token contract with `amount = 500_000`, `fee = 0`, targeting the bridge with an `InitTransfer` message to an EVM recipient.
3. `init_transfer` passes: `0 < 500_000` ✓. Tokens are burned/locked. Transfer message stored with nonce N. [1](#0-0) 
4. Trusted relayer calls `sign_transfer` for nonce N.
5. `normalize_amount(500_000, {decimals:18, origin_decimals:24})` = `500_000 / 1_000_000` = `0`. [3](#0-2) 
6. `require!(amount_to_transfer > 0, ...)` panics. Transaction reverts. [4](#0-3) 
7. Transfer message for nonce N remains in `pending_transfers`. Tokens remain locked/burned. No recovery is possible.

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-402)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
                );
```

**File:** near/omni-bridge/src/lib.rs (L482-485)
```rust
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
