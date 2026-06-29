### Title
Missing Transfer Removal After Signing Allows Fee Recipient Manipulation and Repeated MPC Signing — (`File: near/omni-bridge/src/lib.rs`)

### Summary

In `sign_transfer_callback`, the pending transfer is only removed from state when the fee is zero. When a non-zero fee is present, the transfer message remains in `pending_transfers` indefinitely after a successful MPC signing. Because `fee_recipient` is a caller-supplied parameter (not stored in the transfer message), any active relayer can call `sign_transfer` again for the same `transfer_id` with an arbitrary `fee_recipient`, obtaining a second valid MPC signature. The relayer submits the signature naming themselves as fee recipient to the destination chain, stealing the fee from the legitimate recipient.

### Finding Description

`sign_transfer` (line 447) accepts a caller-supplied `fee_recipient: Option<AccountId>` that is embedded directly into the signed `TransferMessagePayload` without being validated against any stored value: [1](#0-0) 

The resulting payload is sent to the MPC signer and the callback is `sign_transfer_callback`: [2](#0-1) 

The critical branch is:

```rust
if fee.is_zero() {
    self.remove_transfer_message(message_payload.transfer_id);
}
```

When `fee` is non-zero, `remove_transfer_message` is **never called**. The transfer stays in `pending_transfers` after a successful signing. Because `fee_recipient` is not stored in the `TransferMessage` struct and is not validated on entry, any relayer can immediately call `sign_transfer` again for the same `transfer_id` with a different `fee_recipient` (e.g., their own account), obtaining a second valid MPC signature over a payload that names them as fee recipient. [3](#0-2) 

The `TransferMessage` stored in `pending_transfers` contains no `fee_recipient` field, so there is no on-chain record of which recipient was already signed for: [4](#0-3) 

### Impact Explanation

A malicious relayer submits the signature that names themselves as `fee_recipient` to the destination chain. The destination chain pays the fee to the attacker. The attacker then calls `claim_fee` on NEAR with the resulting proof. `claim_fee_callback` checks `fee_recipient == predecessor_account_id` (line 1083–1086), which passes because the attacker is the fee recipient in the proof. The attacker receives the fee on NEAR as well. [5](#0-4) 

This constitutes direct theft of bridge fees from the legitimate fee recipient — a balance manipulation / fee mis-accounting impact.

### Likelihood Explanation

Any active trusted relayer (a "custom relayer" explicitly listed as an in-scope attacker) can execute this with no preconditions beyond being registered. The transfer message remains in `pending_transfers` for the entire lifetime of a fee-bearing transfer, so the window of exploitation is unbounded. No special timing or front-running is required.

### Recommendation

After a successful MPC signing, record the `fee_recipient` inside the stored `TransferMessage` (or in a separate map keyed by `transfer_id`). On subsequent calls to `sign_transfer` for the same `transfer_id`, require that the supplied `fee_recipient` matches the stored value. Alternatively, mark the transfer as "signing in progress" or remove it immediately and re-insert it with the locked `fee_recipient` so that no second signing with a different recipient is possible.

### Proof of Concept

1. User initiates a transfer with `fee = 100` tokens via `ft_on_transfer → init_transfer`. Transfer is stored in `pending_transfers` with `transfer_id = T`.
2. Legitimate relayer calls `sign_transfer(T, fee_recipient = legitimate_relayer, fee = Some(100))`. MPC produces `sig_A`. Transfer remains in `pending_transfers` (fee is non-zero, so `remove_transfer_message` is skipped).
3. Malicious relayer calls `sign_transfer(T, fee_recipient = attacker, fee = Some(100))`. MPC produces `sig_B`. Transfer still remains in `pending_transfers`.
4. Malicious relayer submits `sig_B` to the destination chain. The destination chain finalizes the transfer and records `fee_recipient = attacker`.
5. Malicious relayer calls `claim_fee` on NEAR with the proof of step 4. `claim_fee_callback` verifies `fee_recipient == predecessor_account_id` (attacker == attacker ✓), removes the transfer, and sends the fee to the attacker.
6. The legitimate relayer's `sig_A` is now useless (destination nonce already consumed). The fee is fully stolen. [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L447-452)
```rust
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
```

**File:** near/omni-bridge/src/lib.rs (L491-500)
```rust
        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };
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

**File:** near/omni-bridge/src/lib.rs (L1083-1086)
```rust
        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
```

**File:** near/omni-bridge/src/storage.rs (L55-60)
```rust
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct TransferMessageStorageValue {
    pub message: TransferMessage,
    pub owner: AccountId,
}
```
