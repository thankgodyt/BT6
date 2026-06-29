### Title
No User-Accessible Cancellation Mechanism for Pending Outbound Transfers Permanently Locks Native Tokens Unless Admin Intervenes — (File: `near/omni-bridge/src/lib.rs`)

### Summary

When a user initiates an outbound transfer of a native NEAR-origin token (e.g., wNEAR → Ethereum), the tokens are transferred into the bridge contract and the `locked_tokens` counter is incremented. There is no public function that allows the user to cancel the pending transfer and recover their tokens. The only paths to release locked tokens are through privileged actors: a trusted relayer calling `sign_transfer` / `claim_fee`, or a DAO/`TokenLockController` calling `set_locked_tokens`. This is a direct analog to M-05: user deposits are locked in escrow with no user-accessible withdrawal path, and recovery requires admin or relayer intervention.

### Finding Description

The outbound transfer flow is:

1. User calls `ft_transfer_call` on the token contract, which triggers `ft_on_transfer` on the bridge.
2. `init_transfer` → `init_transfer_internal` is called.
3. For native NEAR-origin tokens, `burn_tokens_if_needed` is a no-op (not a deployed token), and `lock_tokens_if_needed` increments `locked_tokens[(destination_chain, token_id)]`.
4. The transfer is stored in `pending_transfers`. [1](#0-0) 

At this point the user's tokens are held by the bridge contract and the `locked_tokens` counter is incremented. The only ways to release them are:

- **`sign_transfer`** — gated by `#[trusted_relayer]`; only removes the `pending_transfers` entry when `fee.is_zero()`.
- **`claim_fee`** — gated by `#[trusted_relayer]`; removes the entry after proof verification.
- **`set_locked_tokens`** — gated by `#[access_control_any(roles(Role::DAO, Role::TokenLockController))]`. [2](#0-1) [3](#0-2) 

There is **no public `cancel_transfer` function**. The `update_transfer_fee` function allows the sender to increase the fee but not cancel the transfer. [4](#0-3) 

The `storage_withdraw` and `storage_unregister` functions only operate on the NEAR storage balance, not on locked tokens. [5](#0-4) 

### Impact Explanation

For native NEAR-origin tokens (e.g., wNEAR, any NEP-141 token whose origin chain is NEAR), once a user initiates an outbound transfer:

- Their tokens are held by the bridge contract.
- The `locked_tokens` counter is incremented.
- If no trusted relayer ever calls `sign_transfer` (e.g., fee is too low, relayer set is empty, or relayer infrastructure is down), the tokens are **permanently frozen** in the bridge with no user-accessible recovery path.
- Recovery requires DAO/`TokenLockController` to call `set_locked_tokens` to manually adjust the counter, and a separate mechanism to return the actual token balance — neither of which is automated or user-triggered.

This matches the allowed impact: **permanent freezing of bridged funds**.

### Likelihood Explanation

The scenario is realistic in several conditions:

1. A user sets a fee below the minimum relayers are willing to accept; no relayer signs the transfer.
2. The trusted relayer set is temporarily or permanently unavailable.
3. A user initiates a transfer to a destination chain for which no active relayer is registered.

In all cases, the user has no recourse. The `update_transfer_fee` function allows increasing the fee, but if no relayer is monitoring, this is also ineffective.

### Recommendation

Add a public `cancel_transfer` function that:

1. Verifies the caller is the original `sender` of the transfer (stored in `TransferMessage.sender`).
2. Removes the entry from `pending_transfers` (with storage refund).
3. Decrements `locked_tokens` for the relevant chain/token pair.
4. Returns the locked tokens to the sender via `ft_transfer`.

Optionally, enforce a minimum time-lock (e.g., the transfer must have been pending for at least N blocks) to prevent griefing of relayers who are in the process of signing.

### Proof of Concept

1. User calls `ft_transfer_call` on a native NEAR token contract, bridging 1000 tokens to Ethereum with a fee of 0 (or any amount).
2. `init_transfer_internal` runs: `locked_tokens[(Eth, token_id)]` increases by 1000; the transfer is stored in `pending_transfers`.
3. No trusted relayer calls `sign_transfer` (fee too low, or relayer offline).
4. User attempts to recover tokens — no public function exists to cancel the transfer.
5. User calls `storage_unregister(force: true)` — this removes the storage balance entry but does **not** return the locked tokens or remove the `pending_transfers` entry.
6. Tokens remain locked in the bridge contract indefinitely. Only a DAO transaction to `set_locked_tokens` and a manual token transfer can recover them. [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L386-436)
```rust
    #[payable]
    #[pause]
    pub fn update_transfer_fee(&mut self, transfer_id: TransferId, fee: UpdateFee) {
        match fee {
            UpdateFee::Fee(fee) => {
                let mut transfer = self.get_transfer_message_storage(transfer_id);

                require!(
                    transfer.message.origin_transfer_id.is_none(),
                    BridgeError::UpdateFeeNotAllowedForTransfer.as_ref()
                );

                let current_fee = transfer.message.fee;
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
                );

                require!(
                    fee.fee == current_fee.fee
                        || OmniAddress::Near(env::predecessor_account_id())
                            == transfer.message.sender,
                    BridgeError::SenderCanUpdateTokenFeeOnly.as_ref()
                );

                let diff_native_fee = fee
                    .native_fee
                    .0
                    .checked_sub(current_fee.native_fee.0)
                    .near_expect(BridgeError::LowerFee);

                require!(
                    NearToken::from_yoctonear(diff_native_fee) == env::attached_deposit(),
                    BridgeError::InvalidAttachedDeposit.as_ref()
                );

                transfer.message.fee = fee;
                self.insert_raw_transfer(transfer.message.clone(), transfer.owner);

                env::log_str(
                    &OmniBridgeEvent::UpdateFeeEvent {
                        transfer_message: transfer.message,
                    }
                    .to_log_string(),
                );
            }
            UpdateFee::Proof(_) => {
                env::panic_str(BridgeError::UnsupportedFeeUpdateProof.to_string().as_str())
            }
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L444-521)
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
        let transfer_message = self.get_transfer_message(transfer_id);

        if let Some(fee) = &fee {
            require!(
                &transfer_message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
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

        let message = DestinationChainMsg::from_json(&transfer_message.msg)
            .and_then(|s| s.destination_msg())
            .unwrap_or_default();

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

        let payload = near_sdk::env::keccak256_array(
            transfer_payload
                .encode_hashable()
                .near_expect(BridgeError::Borsh),
        );

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
    }
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

**File:** near/omni-bridge/src/token_lock.rs (L38-44)
```rust
    #[access_control_any(roles(Role::DAO, Role::TokenLockController))]
    pub fn set_locked_tokens(&mut self, args: Vec<SetLockedTokenArgs>) {
        for arg in args {
            self.locked_tokens
                .insert(&(arg.chain_kind, arg.token_id), &arg.amount.0);
        }
    }
```

**File:** near/omni-bridge/src/storage.rs (L186-237)
```rust
    #[payable]
    pub fn storage_withdraw(&mut self, amount: Option<NearToken>) -> StorageBalance {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let mut storage = self
            .storage_balance_of(&account_id)
            .near_expect(StorageError::AccountNotRegistered(account_id.clone()));
        let to_withdraw = amount.unwrap_or(storage.available);
        storage.total = storage.total.checked_sub(to_withdraw).near_expect(
            StorageError::NotEnoughStorageBalance {
                requested: to_withdraw,
                available: storage.total,
            },
        );
        storage.available = storage.available.checked_sub(to_withdraw).near_expect(
            StorageError::NotEnoughStorageBalance {
                requested: to_withdraw,
                available: storage.available,
            },
        );

        self.accounts_balances.insert(&account_id, &storage);

        Promise::new(account_id).transfer(to_withdraw).detach();

        storage
    }

    #[payable]
    pub fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let Some(storage) = self.storage_balance_of(&account_id) else {
            return false;
        };

        if !force.unwrap_or_default() {
            require!(
                storage.total.saturating_sub(storage.available)
                    == self.required_balance_for_account(),
                BridgeError::StoragePendingTransfers.as_ref()
            );
        }

        self.accounts_balances.remove(&account_id);

        let refund = self
            .required_balance_for_account()
            .saturating_add(storage.available);
        Promise::new(account_id).transfer(refund).detach();
        true
    }
```
