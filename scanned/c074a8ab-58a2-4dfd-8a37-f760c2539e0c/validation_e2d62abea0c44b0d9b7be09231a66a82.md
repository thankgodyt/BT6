### Title
Attached NEAR Deposit Permanently Locked in `omni-bridge` When MPC Signing Fails in `sign_transfer` - (File: near/omni-bridge/src/lib.rs)

### Summary
The `sign_transfer` function is `#[payable]` and forwards the caller's entire attached NEAR deposit to the external MPC signer contract. If the MPC signing call fails, NEAR's runtime automatically refunds the deposit to the `omni-bridge` contract, but `sign_transfer_callback` does not forward this refund to the original caller. The deposit is permanently locked in the `omni-bridge` contract with no recovery path.

### Finding Description
`sign_transfer` is marked `#[payable]` and unconditionally forwards `env::attached_deposit()` to the external MPC signer:

```rust
ext_signer::ext(self.mpc_signer.clone())
    .with_static_gas(MPC_SIGNING_GAS)
    .with_attached_deposit(env::attached_deposit())
    .sign(SignRequest { payload, path: SIGN_PATH.to_owned(), key_version: 0 })
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(SIGN_TRANSFER_CALLBACK_GAS)
            .sign_transfer_callback(transfer_payload, &transfer_message.fee),
    )
``` [1](#0-0) 

The subsequent callback only handles the success branch:

```rust
pub fn sign_transfer_callback(
    &mut self,
    #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
    ...
) {
    if let Ok(signature) = call_result {
        // success path only
    }
    // Err branch: silent return, no refund
}
``` [2](#0-1) 

When the MPC signing call fails (panics or returns an error), NEAR's runtime automatically refunds the forwarded deposit back to the `omni-bridge` contract. However, `sign_transfer_callback` silently ignores the `Err` case and returns without transferring the refunded NEAR back to the original caller (`predecessor_account_id`). The deposit is then permanently locked in the `omni-bridge` contract.

This contrasts sharply with `bind_token`, which correctly handles this pattern by chaining a dedicated `bind_token_refund` step that always runs and explicitly refunds the caller on failure:

```rust
.then(
    Self::ext(env::current_account_id())
        .with_attached_deposit(env::attached_deposit())
        .with_static_gas(BIND_TOKEN_REFUND_GAS)
        .bind_token_refund(near_sdk::env::predecessor_account_id()),
)
``` [3](#0-2) 

```rust
pub fn bind_token_refund(
    &mut self,
    predecessor_account_id: AccountId,
    #[callback_result] call_result: Result<NearToken, PromiseError>,
) {
    let refund_amount = call_result.unwrap_or_else(|_| env::attached_deposit());
    Self::refund(predecessor_account_id, refund_amount);
}
``` [4](#0-3) 

The `refund` helper itself is correct — it transfers NEAR back to the account — but it is simply never called in the `sign_transfer` failure path. [5](#0-4) 

### Impact Explanation
Any account holding the `TrustedRelayer` role that calls `sign_transfer` with a non-zero attached deposit loses that deposit whenever the MPC signing call fails. The `omni-bridge` contract has no administrative withdrawal function for stuck deposits, making the loss permanent. This directly and irreversibly reduces the caller's NEAR balance.

### Likelihood Explanation
MPC signing failures are operationally realistic: the MPC network can be congested, the signing request can be rejected due to quota limits, or the call can run out of gas. Trusted relayers are expected to attach NEAR to cover the MPC signer's fee on every `sign_transfer` call — this is a normal, high-frequency operational flow. Any failure in this path silently drains the relayer's deposit.

### Recommendation
Mirror the `bind_token` pattern: pass the `predecessor_account_id` into `sign_transfer_callback` and add an explicit refund in the `Err` branch:

```rust
pub fn sign_transfer_callback(
    &mut self,
    #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
    #[serializer(borsh)] message_payload: TransferMessagePayload,
    #[serializer(borsh)] fee: &Fee,
    #[serializer(borsh)] caller: AccountId,
) {
    if let Ok(signature) = call_result {
        // existing success logic
    } else {
        // Refund the deposit returned from the failed MPC call
        Self::refund(caller, env::attached_deposit());
    }
}
```

Alternatively, chain a dedicated refund callback (as done in `bind_token_refund`) that always executes after `sign_transfer_callback` and refunds any remaining deposit to the caller.

### Proof of Concept
1. Trusted relayer calls `sign_transfer` with attached deposit D yoctoNEAR (required by the MPC signer).
2. `sign_transfer` forwards D to `ext_signer.sign(...)`. [6](#0-5) 
3. The MPC signer call fails (network congestion, gas exhaustion, quota exceeded, etc.).
4. NEAR runtime automatically refunds D to the `omni-bridge` contract.
5. `sign_transfer_callback` runs with `call_result = Err(...)` and returns without refunding D. [7](#0-6) 
6. D is permanently locked in the `omni-bridge` contract; the relayer's balance is reduced by D with no recovery path.

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L1233-1238)
```rust
            .then(
                Self::ext(env::current_account_id())
                    .with_attached_deposit(env::attached_deposit())
                    .with_static_gas(BIND_TOKEN_REFUND_GAS)
                    .bind_token_refund(near_sdk::env::predecessor_account_id()),
            )
```

**File:** near/omni-bridge/src/lib.rs (L1303-1312)
```rust
    #[private]
    #[payable]
    pub fn bind_token_refund(
        &mut self,
        predecessor_account_id: AccountId,
        #[callback_result] call_result: Result<NearToken, PromiseError>,
    ) {
        let refund_amount = call_result.unwrap_or_else(|_| env::attached_deposit());
        Self::refund(predecessor_account_id, refund_amount);
    }
```

**File:** near/omni-bridge/src/lib.rs (L2770-2774)
```rust
    fn refund(account_id: AccountId, amount: NearToken) {
        if !amount.is_zero() {
            Promise::new(account_id).transfer(amount).detach();
        }
    }
```
