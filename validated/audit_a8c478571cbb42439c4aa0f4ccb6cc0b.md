Audit Report

## Title
Non-Zero-Fee Transfer Remains in `pending_transfers` After MPC Signing, Enabling Fee Recipient Manipulation — (File: near/omni-bridge/src/lib.rs)

## Summary

`sign_transfer` accepts a caller-supplied `fee_recipient` that is embedded into the signed payload but never stored on-chain. In `sign_transfer_callback`, the transfer is only removed from `pending_transfers` when the fee is zero; for non-zero fees the entry persists indefinitely. Any registered trusted relayer can therefore call `sign_transfer` again for the same `transfer_id` with an arbitrary `fee_recipient`, obtain a second valid MPC signature, submit it to the destination chain, and then successfully call `claim_fee` on NEAR — stealing the fee from the legitimate recipient.

## Finding Description

`sign_transfer` (L447–521) takes `fee_recipient: Option<AccountId>` directly from the caller and places it into `TransferMessagePayload` without any validation against a stored value:

```rust
let transfer_payload = TransferMessagePayload {
    ...
    fee_recipient,   // caller-supplied, never checked against storage
    ...
};
```

The callback `sign_transfer_callback` (L649–668) contains the critical branch:

```rust
if fee.is_zero() {
    self.remove_transfer_message(message_payload.transfer_id);
}
```

When `fee` is non-zero, `remove_transfer_message` is never called, so the transfer remains in `pending_transfers` after a successful MPC signing. `TransferMessageStorageValue` (storage.rs L55–60) stores only `message: TransferMessage` and `owner: AccountId` — no `fee_recipient` field — so there is no on-chain record of which recipient was already signed for. A second call to `sign_transfer` for the same `transfer_id` with a different `fee_recipient` passes all existing checks (the fee amount equality check at L456–459 is satisfied by supplying the same fee value) and triggers a second MPC signing.

`claim_fee_callback` (L1083–1086) derives `fee_recipient` from the submitted proof (the destination-chain finalization event) and checks only that it equals `predecessor_account_id`. It does not compare against any NEAR-stored expected recipient. At L1094 it calls `remove_transfer_message`, consuming the entry — but only after the attacker's proof is accepted.

## Impact Explanation

A malicious trusted relayer obtains a valid MPC signature over a payload naming themselves as `fee_recipient`, submits it to the destination chain, and then calls `claim_fee` on NEAR with the resulting proof. `claim_fee_callback` passes the `fee_recipient == predecessor_account_id` check (attacker == attacker), removes the transfer, and disburses the fee to the attacker. This is direct, concrete theft of bridge fees — fee mis-accounting / balance manipulation — matching the Critical allowed impact scope.

## Likelihood Explanation

The attacker must be a registered trusted relayer, which the HackenProof program explicitly lists as an in-scope attacker class ("custom relayer"). No special timing, front-running, or external collusion is required. The vulnerable window is the entire lifetime of any fee-bearing transfer, since the entry is never removed until `claim_fee` is called. The attack is repeatable for every non-zero-fee transfer.

## Recommendation

After a successful MPC signing for a non-zero-fee transfer, record the `fee_recipient` in the stored `TransferMessage` (or in a separate map keyed by `transfer_id`). On any subsequent call to `sign_transfer` for the same `transfer_id`, require that the supplied `fee_recipient` matches the stored value. Alternatively, mark the transfer as "signing committed" immediately upon the first successful signing and reject further signing attempts for the same `transfer_id`.

## Proof of Concept

1. User initiates a transfer with `fee = 100` via `ft_on_transfer → init_transfer`. Transfer stored in `pending_transfers` with `transfer_id = T`.
2. Legitimate relayer calls `sign_transfer(T, fee_recipient = legitimate_relayer, fee = Some(100))`. MPC produces `sig_A`. `sign_transfer_callback` skips `remove_transfer_message` (fee is non-zero). Transfer remains in `pending_transfers`.
3. Malicious relayer calls `sign_transfer(T, fee_recipient = attacker, fee = Some(100))`. Fee equality check passes. MPC produces `sig_B`. Transfer still remains in `pending_transfers`.
4. Malicious relayer submits `sig_B` to the destination chain. Destination chain finalizes the transfer recording `fee_recipient = attacker` and consumes the destination nonce.
5. Malicious relayer calls `claim_fee` on NEAR with the proof from step 4. `claim_fee_callback` reads `fee_recipient = attacker` from the proof, checks `attacker == predecessor_account_id` (✓), calls `remove_transfer_message`, and sends the fee to the attacker.
6. Legitimate relayer's `sig_A` is now unusable (destination nonce consumed). Fee is fully stolen. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** near/omni-bridge/src/lib.rs (L1083-1094)
```rust
        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
        require!(
            self.factories
                .get(&fin_transfer.emitter_address.get_chain())
                == Some(fin_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

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
