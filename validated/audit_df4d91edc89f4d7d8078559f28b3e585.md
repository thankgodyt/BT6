Audit Report

## Title
Pause Bypass via `init_transfer_resume` and `fin_transfer_callback` Lacking Pause Checks - (File: `near/omni-bridge/src/lib.rs`)

## Summary

The NEAR `omni-bridge` contract enforces pause checks on `ft_on_transfer` and `fin_transfer` but omits those checks from their async continuations `init_transfer_resume` and `fin_transfer_callback`. Because NEAR callbacks are independent function calls, a pause set between the entry-point call and the callback execution is silently bypassed. For `init_transfer_resume`, the bypass is particularly severe: yields can remain pending for an extended period, and any unprivileged actor can trigger the resume by calling the public `storage_deposit` function after the bridge is paused, causing tokens to be burned/locked and an `InitTransferEvent` to be emitted despite the pause.

## Finding Description

`ft_on_transfer` is decorated with `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]` at L252, enforcing the pause at the entry point. [1](#0-0) 

When storage is insufficient, `ft_on_transfer` → `init_transfer` creates a NEAR yield promise via `env::promise_yield_create("init_transfer_resume", ...)` at L586–617, suspending execution until someone deposits storage. [2](#0-1) 

The yield resumes via `init_transfer_resume`, which is marked only `#[private]` — no pause check — and unconditionally calls `init_transfer_internal` (which burns/locks tokens and emits `InitTransferEvent`) if storage is available. [3](#0-2) 

The resume is triggered by the public `storage_deposit` function, which has no pause check and calls `self.resume_promise(&account_id).detach()` at L166, which in turn calls `env::promise_yield_resume` at L174. [4](#0-3) [5](#0-4) 

The same pattern applies to `fin_transfer`. The entry point has `#[pause(except(roles(Role::DAO)))]` at L672, but `fin_transfer_callback` at L698–746 has only `#[private]` and `#[payable]` — no pause check — and proceeds to mint/transfer tokens to the recipient. [6](#0-5) [7](#0-6) 

## Impact Explanation

This is a **pause bypass enabling unauthorized cross-chain fund movement**, matching the allowed critical impact class: "pause bypass that lets an attacker execute bridge actions." For `init_transfer_resume`: tokens are burned/locked on NEAR and an `InitTransferEvent` is emitted despite the bridge being paused, allowing a relayer to finalize the transfer on the destination chain. If the pause was triggered due to a security incident (e.g., a compromised prover or discovered exploit), in-flight yields can still be resolved by any actor depositing storage, completing cross-chain transfers that the pause was intended to block. For `fin_transfer_callback`: fraudulent proofs submitted just before a pause can still be finalized, minting tokens on NEAR despite the bridge being paused.

## Likelihood Explanation

For `init_transfer_resume`: **Medium-high**. Yields can remain pending for hours or days. Any actor — including the original user or a third party — can call the public `storage_deposit` function for the virtual message-storage account ID to trigger the resume. The attacker does not need to race against the pause; they simply wait for the pause to be set and then deposit storage. No special privileges are required.

For `fin_transfer_callback`: **Low-medium**. The window between `fin_transfer` and its callback is only a few NEAR blocks (~1–2 seconds), requiring the admin to pause in that exact window. This is a narrow race condition.

## Recommendation

Add a pause check inside both callback functions:

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

Alternatively, apply the `#[pause]` macro with the same role exceptions as the corresponding entry point to both callback functions. For `init_transfer_resume`, also consider whether a paused resume should refund the user's tokens rather than silently failing.

## Proof of Concept

**`init_transfer_resume` scenario (sandbox-reproducible):**

1. Alice calls `ft_transfer_call` → `ft_on_transfer` → `init_transfer` on the NEAR bridge with insufficient storage. A yield is created and stored in `init_transfer_promises`.
2. Admin pauses the bridge (e.g., via `acl_grant_role(Role::PauseManager)` + pause call).
3. Any actor calls `storage_deposit` on the bridge contract for the virtual `message_storage_account_id` with sufficient NEAR. This triggers `resume_promise` → `env::promise_yield_resume` → `init_transfer_resume`.
4. `init_transfer_resume` executes at L621 with no pause check, passes the storage balance check, and calls `init_transfer_internal` at L645.
5. Alice's tokens are burned/locked and `InitTransferEvent` is emitted despite the bridge being paused.
6. A relayer picks up the event and finalizes on the destination chain, completing the cross-chain transfer during a pause.

This path is directly demonstrated by the existing integration test `test_init_transfer_with_external_id` in `near/omni-tests/src/init_transfer.rs` (L566–745), which shows that `storage_deposit` by any account (including `relayer_account`) successfully resumes a pending yield and completes the transfer. Extending that test to pause the bridge between steps 2 and 3 would confirm the bypass. [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L252-253)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
```

**File:** near/omni-bridge/src/lib.rs (L586-617)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L621-645)
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
```

**File:** near/omni-bridge/src/lib.rs (L670-672)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
```

**File:** near/omni-bridge/src/lib.rs (L698-704)
```rust
    #[private]
    #[payable]
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
```

**File:** near/omni-bridge/src/storage.rs (L140-166)
```rust
    #[payable]
    pub fn storage_deposit(&mut self, account_id: Option<AccountId>) -> StorageBalance {
        let account_id = account_id.unwrap_or_else(env::predecessor_account_id);
        let amount = env::attached_deposit();
        let storage = self.accounts_balances.get(&account_id).map_or_else(
            || {
                let min_required_storage_balance = self.required_balance_for_account();
                let available = amount
                    .checked_sub(min_required_storage_balance)
                    .near_expect(StorageError::NotEnoughStorageBalanceAttached {
                        required: min_required_storage_balance,
                        attached: amount,
                    });
                StorageBalance {
                    total: amount,
                    available,
                }
            },
            |mut storage| {
                storage.total = storage.total.saturating_add(amount);
                storage.available = storage.available.saturating_add(amount);
                storage
            },
        );
        self.accounts_balances.insert(&account_id, &storage);

        self.resume_promise(&account_id).detach();
```

**File:** near/omni-bridge/src/storage.rs (L171-184)
```rust
    #[private]
    pub fn resume_promise(&self, account_id: &AccountId) -> PromiseOrValue<()> {
        if let Some(promise_id) = &self.init_transfer_promises.get(account_id) {
            let result = env::promise_yield_resume(promise_id, []);
            env::log_str(&format!("Resume promise. Result: {result}"));

            if !result {
                return Self::ext(env::current_account_id())
                    .resume_promise(account_id)
                    .into();
            }
        }
        PromiseOrValue::Value(())
    }
```

**File:** near/omni-tests/src/init_transfer.rs (L566-678)
```rust
    async fn test_init_transfer_with_external_id(
        build_artifacts: &BuildArtifacts,
    ) -> anyhow::Result<()> {
        let sender_balance_token = 1_000_000;
        let transfer_amount = 5000;
        let fee = U128(1000);

        let env = TestEnv::new(sender_balance_token, false, build_artifacts).await?;

        // Register the sender with the bare-minimum bridge storage. This is enough to
        // identify the signer during resume, but not enough to fund the transfer — so
        // `init_transfer` must take the yield branch.
        let required_balance_for_account: NearToken = env
            .locker_contract
            .view("required_balance_for_account")
            .await?
            .json()?;
        env.sender_account
            .call(env.locker_contract.id(), "storage_deposit")
            .args_json(json!({ "account_id": env.sender_account.id() }))
            .deposit(required_balance_for_account)
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        // The yield branch charges the bridge contract's own storage balance (for the
        // init_transfer_promises entry). Fund it so `init_transfer` can register the yield.
        env.sender_account
            .call(env.locker_contract.id(), "storage_deposit")
            .args_json(json!({ "account_id": env.locker_contract.id() }))
            .deposit(NearToken::from_millinear(100))
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        // Build two InitTransferMsgs that differ only by external_id.
        let msg_a = InitTransferMsg {
            native_token_fee: U128(0),
            fee,
            recipient: eth_eoa_address(),
            msg: None,
            external_id: Some(BoundedString::new("external-id-a").unwrap()),
        };
        let msg_b = InitTransferMsg {
            external_id: Some(BoundedString::new("external-id-b").unwrap()),
            ..msg_a.clone()
        };

        // Predict the virtual storage account each transfer will yield on. All the fields
        // consumed by the hash are known in advance: the chain-side `TransferMessage` only
        // adds nonces to this struct, and nonces are not part of the storage-account hash.
        let storage_account = TransferMessageStorageAccount {
            token: OmniAddress::Near(env.token_contract.id().clone()),
            amount: U128(transfer_amount),
            recipient: msg_a.recipient.clone(),
            fee: Fee {
                fee: msg_a.fee,
                native_fee: msg_a.native_token_fee,
            },
            sender: OmniAddress::Near(env.sender_account.id().clone()),
            msg: String::new(),
        };
        let virtual_a = storage_account.id(Some("external-id-a".to_string()));
        let virtual_b = storage_account.id(Some("external-id-b".to_string()));
        assert_ne!(
            virtual_a, virtual_b,
            "Different external_ids must yield different virtual storage accounts"
        );

        // Fire both ft_transfer_calls without awaiting final execution — each one yields
        // inside ft_on_transfer, so the tx stays in "Started" state until resumed.
        let submit_ft_transfer_call = |msg: InitTransferMsg| {
            env.sender_account
                .call(env.token_contract.id(), "ft_transfer_call")
                .args_json(json!({
                    "receiver_id": env.locker_contract.id(),
                    "amount": U128(transfer_amount),
                    "memo": None::<String>,
                    "msg": serde_json::to_string(&BridgeOnTransferMsg::InitTransfer(msg))
                        .unwrap(),
                }))
                .deposit(NearToken::from_yoctonear(1))
                .max_gas()
                .transact_async()
        };
        let status_a = submit_ft_transfer_call(msg_a.clone()).await?;
        let status_b = submit_ft_transfer_call(msg_b.clone()).await?;

        // Fast-forward a few blocks so both yield/resume callbacks are processed.
        env.worker.fast_forward(5).await?;

        let required_balance_init_transfer: NearToken = env
            .locker_contract
            .view("required_balance_for_init_transfer")
            .args_json(json!({}))
            .await?
            .json()?;

        // Depositing storage on each virtual account resumes its yielded transfer. The
        // yield callback (`init_transfer_resume`) runs as part of the original
        // ft_transfer_call's receipt chain, so the `InitTransferEvent` shows up there.
        for virtual_id in [&virtual_a, &virtual_b] {
            env.relayer_account
                .call(env.locker_contract.id(), "storage_deposit")
                .args_json(json!({ "account_id": virtual_id }))
                .deposit(required_balance_init_transfer)
                .max_gas()
                .transact()
                .await?
                .into_result()?;
        }
```
