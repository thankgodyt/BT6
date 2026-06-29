### Title
`sign_transfer_callback` Silently Swallows MPC Signing Failures, Permanently Freezing User Bridged Funds — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

When the MPC signing cross-contract call inside `sign_transfer` fails, `sign_transfer_callback` silently discards the error via an `if let Ok` guard. No event is emitted, no log is written, and the pending transfer message is never removed. Because `sign_transfer` is restricted to trusted relayers, the user has no independent path to retry or cancel, leaving their burned/locked tokens permanently frozen on NEAR.

---

### Finding Description

`sign_transfer` builds a `TransferMessagePayload`, calls the MPC signer contract, and chains `sign_transfer_callback` as the result handler: [1](#0-0) 

The callback is:

```rust
pub fn sign_transfer_callback(
    &mut self,
    #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
    #[serializer(borsh)] message_payload: TransferMessagePayload,
    #[serializer(borsh)] fee: &Fee,
) {
    if let Ok(signature) = call_result {          // ← Err branch is a no-op
        if fee.is_zero() {
            self.remove_transfer_message(message_payload.transfer_id);
        }
        env::log_str(
            &OmniBridgeEvent::SignTransferEvent { signature, message_payload }
                .to_log_string(),
        );
    }
}
``` [2](#0-1) 

When `call_result` is `Err` (MPC call panics, runs out of gas, or the MPC network rejects the request):

1. The `if let Ok` arm is skipped entirely.
2. **No `SignTransferEvent` is emitted** — the relayer receives no on-chain signal that signing occurred or failed.
3. **No error log is written** — there is no observable difference between a successful signing and a failed one from the relayer's perspective.
4. The transfer message **remains in `pending_transfers`** indefinitely.
5. The user's tokens were already burned or locked during `init_transfer_internal` and cannot be recovered. [3](#0-2) 

Because `sign_transfer` is gated by `#[trusted_relayer]`, the user cannot call it themselves to retry: [4](#0-3) 

There is no cancel or timeout mechanism visible in the contract. The only paths that remove a pending transfer message are a successful `sign_transfer_callback` (when `fee.is_zero()`) and `claim_fee_callback` — neither of which is reachable if signing never succeeds.

The same silent-failure pattern exists in `sign_log_metadata_callback` (lower impact — no funds at risk): [5](#0-4) 

---

### Impact Explanation

A user who initiates a NEAR-to-foreign transfer has their tokens burned/locked at `init_transfer` time. If the subsequent `sign_transfer` MPC call fails and the relayer does not independently detect and retry (which they cannot do reliably because no failure event or log is produced), the transfer is stuck: the nonce is consumed, the transfer message occupies storage, and the tokens are gone from the user's balance with no path to recovery. This constitutes **permanent freezing of bridged funds**.

---

### Likelihood Explanation

MPC signing calls can fail due to:
- Transient gas exhaustion (the `SIGN_TRANSFER_CALLBACK_GAS` is only 5 TGas, while the callback itself is lightweight, but the MPC call itself uses 250 TGas and can be rejected under load).
- The MPC network returning an error for a specific payload (e.g., key version mismatch, quota exceeded).
- Any panic inside the MPC signer contract. [6](#0-5) 

Because no failure signal is produced, a relayer operating at scale would have no automated way to detect which `sign_transfer` calls failed and need retrying. A single missed retry permanently freezes the user's funds.

---

### Recommendation

**Short term:** Emit a `SignTransferErrorEvent` (or at minimum `env::log_str`) in the `Err` branch of `sign_transfer_callback` so relayers can detect and retry failed signing attempts.

**Long term:** Implement a user-accessible cancel/reclaim path (analogous to the Sherlock recommendation to revert on failure) so that if signing permanently fails, the user can recover their tokens without depending on relayer liveness.

---

### Proof of Concept

1. Alice calls `ft_transfer_call` on her token contract, routing through `omni-bridge` to initiate a NEAR → EVM transfer. Her tokens are burned; a `TransferMessage` is stored in `pending_transfers`.
2. A trusted relayer calls `sign_transfer(transfer_id, fee_recipient, fee)`.
3. The MPC signer contract panics (e.g., gas exhaustion, quota exceeded). The promise result delivered to `sign_transfer_callback` is `Err(PromiseError::Failed)`.
4. `sign_transfer_callback` enters the `if let Ok` guard — the `Err` arm is a no-op. No event is emitted, no log is written.
5. The relayer's event listener sees no `SignTransferEvent` and no error event. It has no signal to retry.
6. Alice's tokens remain burned. The transfer message sits in `pending_transfers` forever. Alice cannot call `sign_transfer` herself (not a trusted relayer) and has no cancel path.
7. Alice's bridged funds are permanently frozen on NEAR.

### Citations

**File:** near/omni-bridge/src/lib.rs (L55-56)
```rust
const MPC_SIGNING_GAS: Gas = Gas::from_tgas(250);
const SIGN_TRANSFER_CALLBACK_GAS: Gas = Gas::from_tgas(5);
```

**File:** near/omni-bridge/src/lib.rs (L370-384)
```rust
    pub fn sign_log_metadata_callback(
        &self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] metadata_payload: MetadataPayload,
    ) {
        if let Ok(signature) = call_result {
            env::log_str(
                &OmniBridgeEvent::LogMetadataEvent {
                    signature,
                    metadata_payload,
                }
                .to_log_string(),
            );
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L444-452)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
```

**File:** near/omni-bridge/src/lib.rs (L508-520)
```rust
        ext_signer::ext(self.mpc_signer.clone())
            .with_static_gas(MPC_SIGNING_GAS)
            .with_attached_deposit(env::attached_deposit())
            .sign(SignRequest {
                payload,
                path: SIGN_PATH.to_owned(),
                key_version: 0,
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SIGN_TRANSFER_CALLBACK_GAS)
                    .sign_transfer_callback(transfer_payload, &transfer_message.fee),
            )
```

**File:** near/omni-bridge/src/lib.rs (L648-668)
```rust
    #[private]
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

**File:** near/omni-bridge/src/lib.rs (L1850-1864)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
```
