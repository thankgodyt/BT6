### Title
Pause Bypass via `init_transfer_resume` and `fin_transfer_callback` Lacking Pause Checks - (`near/omni-bridge/src/lib.rs`)

### Summary

The NEAR `omni-bridge` contract enforces pause checks on public entry points (`ft_on_transfer`, `fin_transfer`) but omits those checks from their respective async continuations (`init_transfer_resume`, `fin_transfer_callback`). Because NEAR callbacks are independent function calls, a pause set between the entry-point call and the callback execution is silently bypassed, allowing transfers to be initiated or finalized during a pause period.

### Finding Description

`ft_on_transfer` is decorated with `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]`, which enforces the pause at the entry point. [1](#0-0) 

When storage is insufficient, `ft_on_transfer` creates a NEAR yield promise and returns, suspending execution until someone deposits storage: [2](#0-1) 

The yield resumes via `init_transfer_resume`, which is marked only `#[private]` — **no pause check**: [3](#0-2) 

`init_transfer_resume` unconditionally calls `init_transfer_internal`, which burns/locks tokens and emits the `InitTransferEvent`: [4](#0-3) 

The same pattern applies to `fin_transfer`. The entry point has `#[pause(except(roles(Role::DAO)))]`: [5](#0-4) 

But `fin_transfer_callback`, which actually mints/transfers tokens to the recipient, has **no pause check**: [6](#0-5) 

### Impact Explanation

**`init_transfer_resume` bypass (higher severity):** A yield can remain pending for an extended period. If the bridge is paused after the yield is created (e.g., due to a security incident), any party can deposit storage to trigger `init_transfer_resume`, which will burn/lock the user's tokens on NEAR and emit an `InitTransferEvent`. A relayer can then finalize the transfer on the destination chain, moving funds across the bridge despite the NEAR-side pause. This is a **pause bypass enabling unauthorized cross-chain fund movement**.

**`fin_transfer_callback` bypass:** A relayer submits `fin_transfer` just before a pause. The proof verification and callback execute after the pause, minting tokens on NEAR despite the bridge being paused. If the pause was triggered due to a compromised prover or discovered exploit, fraudulent proofs submitted just before the pause can still be finalized.

### Likelihood Explanation

For `init_transfer_resume`: Likelihood is **medium-high**. Yields can remain pending for hours or days. Any actor (including the original user) can deposit storage to trigger the resume. The attacker does not need to race against the pause — they simply wait for the pause and then deposit storage.

For `fin_transfer_callback`: Likelihood is **low-medium**. The window between `fin_transfer` and its callback is only a few NEAR blocks (~1–2 seconds), requiring the admin to pause in that exact window.

### Recommendation

Add a pause check inside `init_transfer_resume` and `fin_transfer_callback`:

```rust
// In init_transfer_resume:
#[private]
pub fn init_transfer_resume(...) -> U128 {
    self.assert_not_paused(); // add this
    ...
}

// In fin_transfer_callback:
#[private]
#[payable]
pub fn fin_transfer_callback(...) -> PromiseOrValue<Nonce> {
    self.assert_not_paused(); // add this
    ...
}
```

Alternatively, apply the `#[pause]` macro (with the same role exceptions as the entry point) to both callback functions so that in-flight transactions are blocked when the bridge is paused.

### Proof of Concept

**`init_transfer_resume` scenario:**

1. Alice calls `ft_transfer_call` → `ft_on_transfer` → `init_transfer` on the NEAR bridge with insufficient storage. A yield is created and stored in `init_transfer_promises`.
2. Admin pauses the bridge (e.g., `acl_grant_role(Role::PauseManager)` + pause).
3. Alice (or any actor) calls `storage_deposit` for the virtual message-storage account ID, which triggers `env::promise_yield_resume`.
4. `init_transfer_resume` executes at line 623 — **no pause check** — and calls `init_transfer_internal` at line 645.
5. Alice's tokens are burned/locked and `InitTransferEvent` is emitted despite the bridge being paused.
6. A relayer picks up the event and finalizes on the destination chain, completing the cross-chain transfer during a pause. [3](#0-2) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L252-253)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
```

**File:** near/omni-bridge/src/lib.rs (L585-617)
```rust
        } else {
            let promise_index = env::promise_yield_create(
                "init_transfer_resume",
                json!({
                    "transfer_message": transfer_message,
                    "message_storage_account_id": message_storage_account_id,
                    "storage_owner": signer_id,
                })
                .to_string()
                .as_bytes(),
                INIT_TRANSFER_RESUME_GAS,
                GasWeight(0),
                PROMISE_REGISTER_ID,
            );

            let yield_id: CryptoHash = env::read_register(PROMISE_REGISTER_ID)
                .near_expect(BridgeError::ReadPromiseRegister)
                .try_into()
                .near_expect(BridgeError::ReadPromiseYieldId);

            let required_storage_balance = self.add_promise(&message_storage_account_id, &yield_id);

            self.update_storage_balance(
                env::current_account_id(),
                required_storage_balance,
                NearToken::from_yoctonear(0),
            );

            env::log_str(&format!(
                "Yield init transfer until storage is available at {message_storage_account_id}"
            ));

            PromiseOrPromiseIndexOrValue::PromiseIndex(promise_index)
```

**File:** near/omni-bridge/src/lib.rs (L621-646)
```rust
    #[private]
    #[allow(clippy::needless_pass_by_value)]
    pub fn init_transfer_resume(
        &mut self,
        transfer_message: TransferMessage,
        message_storage_account_id: AccountId,
        storage_owner: AccountId,
        #[callback_result] response: Result<(), PromiseError>,
    ) -> U128 {
        self.remove_promise(&message_storage_account_id);
        if response.is_err() {
            env::log_str("Init transfer resume timeout");
        }

        if let Err(err) = self.try_to_transfer_balance_from_message_account(
            &message_storage_account_id,
            NearToken::from_yoctonear(transfer_message.fee.native_fee.0),
            &storage_owner,
            self.required_balance_for_init_transfer_message(transfer_message.clone()),
        ) {
            env::log_str(&format!("Error paying native fee and storage: {err}"));
            return transfer_message.amount;
        }

        self.init_transfer_internal(transfer_message, storage_owner)
    }
```

**File:** near/omni-bridge/src/lib.rs (L670-696)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise {
        require!(
            args.storage_deposit_actions.len() <= 3,
            BridgeError::InvalidStorageAccountsLen.as_ref()
        );
        let mut main_promise = self.verify_proof(args.chain_kind, args.prover_args);

        let mut attached_deposit = env::attached_deposit();

        for action in &args.storage_deposit_actions {
            main_promise =
                main_promise.and(Self::check_or_pay_ft_storage(action, &mut attached_deposit));
        }

        main_promise.then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(attached_deposit)
                .with_static_gas(FIN_TRANSFER_CALLBACK_GAS)
                .fin_transfer_callback(
                    &args.storage_deposit_actions,
                    env::predecessor_account_id(),
                ),
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L698-746)
```rust
    #[private]
    #[payable]
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };

        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
        } else {
            self.process_fin_transfer_to_other_chain(predecessor_account_id, transfer_message);
            PromiseOrValue::Value(destination_nonce)
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
