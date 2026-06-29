### Title
No User-Callable Cancel/Refund for Pending Transfers After Token Burn — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

When a user initiates an outbound transfer on the NEAR Omni Bridge, their tokens are **burned or locked** inside `init_transfer_internal` before any MPC signing occurs. If the MPC signer is unavailable or a trusted relayer never calls `sign_transfer`, the `sign_transfer_callback` silently does nothing on failure — no refund, no cancellation. There is no user-callable function to cancel a pending transfer and recover funds. Funds are permanently frozen in the bridge with no recovery path available to the user.

---

### Finding Description

The outbound transfer flow is:

1. User calls `ft_transfer_call` → `ft_on_transfer` → `init_transfer` → `init_transfer_internal`
2. Inside `init_transfer_internal`, tokens are **immediately burned** (for deployed/bridged tokens) or **locked** (for native NEAR tokens) before any MPC signing: [1](#0-0) 

3. The transfer is stored in `pending_transfers` and an `InitTransferEvent` is emitted.
4. A **trusted relayer** (only) calls `sign_transfer`, which requests an MPC signature.
5. In `sign_transfer_callback`, if MPC signing **fails**, the callback does nothing — no refund, no removal of the transfer record: [2](#0-1) 

The `if let Ok(signature) = call_result` branch is never entered on failure, so the burned tokens are gone and the transfer record stays in `pending_transfers` indefinitely.

There is no public, user-callable cancel or refund function anywhere in the contract. The only admin escape hatch is `transfer_token_as_dao`, which is restricted to the `DAO` role: [3](#0-2) 

Additionally, `sign_transfer` itself is gated by `#[trusted_relayer]`, meaning the user cannot even retry signing themselves: [4](#0-3) 

---

### Impact Explanation

- For **deployed (bridged) tokens**: tokens are burned in `burn_tokens_if_needed` at the moment of transfer initiation. If the transfer never completes, those tokens are permanently destroyed and the user receives nothing on the destination chain — a direct, irreversible loss of funds.
- For **native NEAR tokens**: tokens are locked via `lock_tokens_if_needed`. They remain in the bridge contract with no user-accessible recovery path.

In both cases, the user's funds are permanently frozen with no on-chain mechanism to reclaim them. [5](#0-4) 

---

### Likelihood Explanation

The MPC signer is a single registered account (`self.mpc_signer`). If it is temporarily or permanently unavailable, all pending transfers are stuck. Trusted relayers are a small set; if they go offline or selectively censor a transfer, the user has no recourse. These are realistic operational failure modes, not theoretical ones. [6](#0-5) 

---

### Recommendation

Add a user-callable `cancel_transfer` function that:
1. Verifies the caller is the original sender of the pending transfer.
2. Optionally enforces a timeout (e.g., transfer must be older than N blocks).
3. Removes the transfer from `pending_transfers`.
4. For burned tokens: mints them back to the sender.
5. For locked tokens: unlocks and returns them to the sender.

At minimum, provide an admin-callable refund path that does not require DAO governance delay.

---

### Proof of Concept

1. User holds 100 units of a bridged token (e.g., `eth.token.near`) and calls `ft_transfer_call` to the bridge with an `InitTransfer` message targeting Ethereum.
2. `init_transfer_internal` is reached; `burn_tokens_if_needed` burns all 100 tokens immediately.
3. The transfer is stored in `pending_transfers` with a valid `TransferId`.
4. The MPC signer account goes offline (or the single active trusted relayer stops processing this user's transfer).
5. `sign_transfer` is never successfully called (or always returns an MPC error).
6. `sign_transfer_callback` receives `Err(PromiseError)` and exits without any state change or refund.
7. The user's 100 tokens are permanently burned. The transfer record sits in `pending_transfers` forever. The user has no callable function to cancel or recover funds. [2](#0-1) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L232-232)
```rust
    pub mpc_signer: AccountId,
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

**File:** near/omni-bridge/src/lib.rs (L1511-1530)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn transfer_token_as_dao(
        &mut self,
        token: AccountId,
        amount: U128,
        recipient: AccountId,
        msg: Option<String>,
    ) -> Promise {
        if let Some(msg) = msg {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_CALL_GAS)
                .ft_transfer_call(recipient, amount, None, msg)
        } else {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1806-1813)
```rust
    fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
        if self.is_deployed_token(&token) {
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
                .detach();
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

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
    }
```
