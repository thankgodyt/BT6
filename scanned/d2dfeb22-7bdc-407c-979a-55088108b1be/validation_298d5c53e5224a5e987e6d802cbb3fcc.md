### Title
Partial Token State Written Before Deployer Call Completes Enables Permanent Transfer Finalization With No Token Minting — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

In `deploy_token_internal`, all token registration state (`token_id_to_address`, `token_address_to_id`, `token_decimals`, `deployed_tokens`) is written and a `DeployTokenEvent` is emitted **before** the external call to the deployer contract completes. During the async window between the state write and the deployer callback, the token appears fully registered in the bridge but the token contract does not yet exist on NEAR. A relayer that observes the `DeployTokenEvent` and submits a `fin_transfer` proof during this window will cause the transfer to be permanently finalized with no tokens minted, resulting in permanent loss of bridged funds.

---

### Finding Description

In `deploy_token_internal` (`near/omni-bridge/src/lib.rs`, lines 2397–2454), the execution order is:

1. `add_token` writes to `token_id_to_address`, `token_address_to_id`, and `token_decimals` (line 2414).
2. `deployed_tokens.insert` marks the token as deployed (line 2422).
3. `deployed_tokens_v2.insert` is written (line 2425).
4. `DeployTokenEvent` is emitted via `env::log_str` (line 2437).
5. **Only then** is the external call to `ext_deployer::ext(deployer).deploy_token(...)` dispatched (line 2446), with `deploy_token_by_deployer_callback` as the continuation. [1](#0-0) 

The cleanup in `deploy_token_by_deployer_callback` only runs if the deployer call **fails**: [2](#0-1) 

Because NEAR's execution model processes cross-contract calls in separate receipts, there is a multi-block async window between step 4 (state written, event emitted) and the deployer receipt completing. During this window, the token is fully registered in the bridge's storage maps but the token contract account does not yet exist on NEAR.

When `fin_transfer_callback` processes a transfer for this token during the window:

1. `token_decimals.get(&init_transfer.token)` succeeds — token is registered (line 716).
2. `add_fin_transfer` **permanently** inserts the transfer ID into `finalised_transfers` (line 1875 / 2226–2234).
3. `send_tokens` calls `mint` on the non-existent token contract (line 2094–2101).
4. `mint` fails — the account does not exist.
5. `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = false` (for a plain transfer with no `msg`).
6. `is_refund_required(false)` unconditionally returns `false` — the promise result of `mint` is **never checked**.
7. The success path executes: `FinTransferEvent` is emitted, the transfer is permanently finalized, and no tokens are minted. [3](#0-2) [4](#0-3) [5](#0-4) 

---

### Impact Explanation

The user's tokens are locked or burned on the source chain (EVM, Solana, etc.) and the corresponding `fin_transfer` proof is consumed. The transfer ID is permanently recorded in `finalised_transfers`, preventing any retry. No tokens are ever minted on NEAR. This constitutes **permanent, irrecoverable loss of bridged funds** for the user.

---

### Likelihood Explanation

The `DeployTokenEvent` is emitted in the same receipt as the state writes, **before** the deployer receipt executes. A relayer monitoring NEAR logs will observe this event and may immediately submit `fin_transfer` for a pending transfer of the newly-registered token, not knowing the token contract does not yet exist. This is a realistic scenario during first-time bridging of a new token, where `deploy_

### Citations

**File:** near/omni-bridge/src/lib.rs (L1177-1198)
```rust
    #[private]
    pub fn deploy_token_by_deployer_callback(
        &mut self,
        token_address: &OmniAddress,
        token_id: AccountId,
    ) -> PromiseOrValue<()> {
        if env::promise_result_checked(0, usize::MAX).is_ok() {
            ext_token::ext(token_id)
                .with_static_gas(STORAGE_DEPOSIT_GAS)
                .with_attached_deposit(NEP141_DEPOSIT)
                .storage_deposit(&env::current_account_id(), Some(true))
                .into()
        } else {
            self.deployed_tokens.remove(&token_id);
            self.deployed_tokens_v2.remove(&token_id);
            self.token_id_to_address
                .remove(&(token_address.get_chain(), token_id));
            self.token_address_to_id.remove(token_address);
            self.token_decimals.remove(token_address);
            PromiseOrValue::Value(())
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1692-1746)
```rust
    pub fn fin_transfer_send_tokens_callback(
        &mut self,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] fee_recipient: &AccountId,
        #[serializer(borsh)] is_ft_transfer_call: bool,
        #[serializer(borsh)] storage_owner: &AccountId,
        #[serializer(borsh)] lock_actions: Vec<LockAction>,
    ) {
        let token = self.get_token_id(&transfer_message.token);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.burn_tokens_if_needed(
                token.clone(),
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
            );

            self.revert_lock_actions(&lock_actions);

            self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);

            env::log_str(
                &OmniBridgeEvent::FailedFinTransferEvent { transfer_message }.to_log_string(),
            );
        } else {
            // Send fee to the fee recipient
            if transfer_message.fee.fee.0 > 0 {
                if self.is_deployed_token(&token) {
                    ext_token::ext(token)
                        .with_static_gas(MINT_TOKEN_GAS)
                        .mint(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                } else {
                    ext_token::ext(token)
                        .with_attached_deposit(ONE_YOCTO)
                        .with_static_gas(FT_TRANSFER_GAS)
                        .ft_transfer(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                }
            }

            if transfer_message.fee.native_fee.0 > 0 {
                let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

                ext_token::ext(native_token_id)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }

            env::log_str(&OmniBridgeEvent::FinTransferEvent { transfer_message }.to_log_string());
        }
```

**File:** near/omni-bridge/src/lib.rs (L1783-1803)
```rust
impl Contract {
    fn is_refund_required(is_ft_transfer_call: bool) -> bool {
        if is_ft_transfer_call {
            match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
                Ok(value) => {
                    if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                        // Normal case: refund if the used token amount is zero
                        // The amount can be zero if the `ft_on_transfer` in the receiver contract returns an amount instead of `0`, or if it panics.
                        amount.0 == 0
                    } else {
                        // Unexpected case: don't refund
                        false
                    }
                }
                // Unexpected case: don't refund
                Err(_) => false,
            }
        } else {
            // Not ft_transfer_call: don't refund
            false
        }
```

**File:** near/omni-bridge/src/lib.rs (L2226-2234)
```rust
    fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
        env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
    }
```

**File:** near/omni-bridge/src/lib.rs (L2413-2453)
```rust
        let storage_usage = env::storage_usage();
        self.add_token(
            &token_id,
            token_address,
            metadata.decimals,
            metadata.decimals,
        );

        require!(
            self.deployed_tokens.insert(&token_id),
            BridgeError::TokenExists.as_ref()
        );
        self.deployed_tokens_v2
            .insert(&token_id, &token_address.get_chain());

        let required_deposit = env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
            .saturating_add(NEP141_DEPOSIT);

        require!(
            attached_deposit >= required_deposit,
            BridgeError::InsufficientStorageDeposit.as_ref()
        );

        env::log_str(
            &OmniBridgeEvent::DeployTokenEvent {
                token_id: token_id.clone(),
                token_address: token_address.clone(),
                metadata: metadata.clone(),
            }
            .to_log_string(),
        );

        ext_deployer::ext(deployer)
            .with_static_gas(DEPLOY_TOKEN_GAS)
            .with_attached_deposit(attached_deposit.saturating_sub(required_deposit))
            .deploy_token(token_id.clone(), metadata)
            .then(
                Self::ext(env::current_account_id())
                    .deploy_token_by_deployer_callback(token_address, token_id),
            )
```
