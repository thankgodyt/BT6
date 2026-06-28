### Title
Race Condition in `fast_fin_transfer_to_near_callback` Allows Double-Spending of Bridged Funds — (`File: near/omni-bridge/src/lib.rs`)

### Summary

The `fast_fin_transfer` function checks `is_unified_transfer_finalised` before scheduling an async callback. Because NEAR cross-contract calls execute in separate blocks, a proof-based `fin_transfer` can be submitted and finalized in the window between the initial check and the callback execution. The callback (`fast_fin_transfer_to_near_callback`) does not re-verify finalization status, causing the recipient to receive tokens twice.

### Finding Description

The fast-transfer flow for NEAR recipients is split across two transactions:

**Transaction 1** — `ft_on_transfer` → `fast_fin_transfer`: [1](#0-0) 

The check `is_unified_transfer_finalised` reads from `finalised_transfers` (the proof-based set). At this point the fast transfer has not yet been recorded in `fast_transfers`.

**Transaction 2** — `fast_fin_transfer_to_near_callback`: [2](#0-1) 

The callback contains **no re-check** of `is_unified_transfer_finalised`. It calls `add_fast_transfer`, which only checks the `fast_transfers` map: [3](#0-2) 

Between Transaction 1 and Transaction 2, a proof-based `fin_transfer` can execute. `process_fin_transfer_to_near` calls `add_fin_transfer` (adding to `finalised_transfers`) and then checks `get_fast_transfer_status`: [4](#0-3) 

Since the fast transfer is not yet in `fast_transfers`, `fast_transfer_status` is `None`, and tokens are sent to the original recipient. When the callback later runs, `add_fast_transfer` succeeds (the entry is absent from `fast_transfers`), and `send_tokens` dispatches a second payment to the same recipient.

### Impact Explanation

The recipient receives bridged tokens twice for a single origin-chain transfer:
- For **bridged tokens** (deployed by the bridge): the bridge mints tokens in `fin_transfer` and again transfers the relayer's tokens in the callback — unauthorized double issuance.
- For **native tokens**: the bridge unlocks from its locked balance in `fin_transfer` and transfers the relayer's deposited tokens in the callback — the recipient receives 2× the bridged amount.

The relayer is not reimbursed because `process_fin_transfer_to_near` found no fast-transfer record and paid the original recipient directly.

### Likelihood Explanation

The proof for a foreign-chain transfer (e.g., Ethereum light-client proof or Wormhole VAA) is available minutes before a relayer submits the fast transfer. A recipient who monitors the NEAR chain can observe the `ft_on_transfer` transaction that initiates the fast transfer and immediately submit `fin_transfer` with the pre-obtained proof. The exploitable window spans 2–3 NEAR blocks (~2–6 seconds), which is sufficient for a prepared attacker.

### Recommendation

Add a re-check of `is_unified_transfer_finalised` at the start of `fast_fin_transfer_to_near_callback`, before calling `add_fast_transfer` or `send_tokens`. If the transfer has already been proof-finalized, the callback should refund the relayer's tokens and abort:

```rust
pub fn fast_fin_transfer_to_near_callback(...) -> Promise {
    require!(Self::check_storage_balance_result(0), ...);

    // Re-check: abort if proof-based fin_transfer already ran
    if self.is_unified_transfer_finalised(&fast_transfer.transfer_id) {
        // refund relayer tokens and return
        return self.send_tokens(fast_transfer.token_id, storage_payer, amount, "");
    }

    let required_balance = self.add_fast_transfer(...);
    ...
}
```

### Proof of Concept

1. User initiates a transfer of 100 USDC from Ethereum to NEAR. Ethereum tx finalizes; proof is available.
2. Relayer calls `ft_transfer_call` on USDC with `FastFinTransferMsg` for the transfer. `fast_fin_transfer` runs: `is_unified_transfer_finalised` → `false`. `check_or_pay_ft_storage` is scheduled (Transaction 1 ends).
3. Recipient submits `fin_transfer` with the Ethereum proof. `fin_transfer_callback` → `process_fin_transfer_to_near` → `add_fin_transfer` (adds to `finalised_transfers`). `get_fast_transfer_status` → `None`. `send_tokens` → recipient receives 100 USDC (Transaction 2 ends).
4. `fast_fin_transfer_to_near_callback` runs. No `is_unified_transfer_finalised` check. `add_fast_transfer` succeeds (entry absent from `fast_transfers`). `send_tokens` → recipient receives another 100 USDC (Transaction 3 ends).

Recipient holds 200 USDC. Relayer's 100 USDC is consumed without reimbursement. [5](#0-4) [2](#0-1) [6](#0-5) [7](#0-6) [3](#0-2)

### Citations

**File:** near/omni-bridge/src/lib.rs (L748-836)
```rust
    #[allow(clippy::needless_pass_by_value)]
    fn fast_fin_transfer(
        &mut self,
        token_id: AccountId,
        amount: U128,
        signer_id: AccountId,
        fast_fin_transfer_msg: FastFinTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(self.is_trusted_relayer(&signer_id), "Relayer is not active");

        let origin_token = self
            .get_token_address(
                fast_fin_transfer_msg.transfer_id.origin_chain,
                token_id.clone(),
            )
            .near_expect(BridgeError::TokenNotFound);

        let decimals = self
            .token_decimals
            .get(&origin_token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let denormalized_amount =
            Self::denormalize_amount(fast_fin_transfer_msg.amount.0, decimals);
        let denormalized_fee = Self::denormalize_fee(&fast_fin_transfer_msg.fee, decimals);
        require!(
            denormalized_amount == amount.0 + denormalized_fee.fee.0,
            BridgeError::InvalidFastTransferAmount.as_ref()
        );

        if self.is_unified_transfer_finalised(&fast_fin_transfer_msg.transfer_id) {
            env::panic_str(BridgeError::TransferAlreadyFinalised.to_string().as_str());
        }

        let fast_transfer = FastTransfer {
            token_id: token_id.clone(),
            recipient: fast_fin_transfer_msg.recipient.clone(),
            amount: U128(denormalized_amount),
            fee: denormalized_fee,
            transfer_id: fast_fin_transfer_msg.transfer_id,
            msg: fast_fin_transfer_msg.msg,
        };

        if let OmniAddress::Near(recipient) = fast_fin_transfer_msg.recipient {
            let storage_deposit_amount = fast_fin_transfer_msg
                .storage_deposit_amount
                .map(|amount| amount.0)
                .unwrap_or_default();
            if storage_deposit_amount > 0 {
                self.update_storage_balance(
                    signer_id.clone(),
                    NearToken::from_yoctonear(storage_deposit_amount),
                    NearToken::from_yoctonear(0),
                );
            }

            let deposit_action = StorageDepositAction {
                account_id: recipient,
                token_id,
                storage_deposit_amount: fast_fin_transfer_msg
                    .storage_deposit_amount
                    .map(|amount| amount.0),
            };

            Self::check_or_pay_ft_storage(
                &deposit_action,
                &mut NearToken::from_yoctonear(storage_deposit_amount),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(
                        FAST_TRANSFER_CALLBACK_GAS.saturating_add(FT_TRANSFER_CALL_GAS),
                    )
                    .fast_fin_transfer_to_near_callback(
                        &fast_transfer,
                        signer_id,
                        fast_fin_transfer_msg.relayer,
                    ),
            )
            .into()
        } else {
            self.fast_fin_transfer_to_other_chain(
                &fast_transfer,
                signer_id,
                fast_fin_transfer_msg.relayer,
            );
            PromiseOrPromiseIndexOrValue::Value(U128(0))
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L838-893)
```rust
    #[private]
    pub fn fast_fin_transfer_to_near_callback(
        &mut self,
        #[serializer(borsh)] fast_transfer: &FastTransfer,
        #[serializer(borsh)] storage_payer: AccountId,
        #[serializer(borsh)] relayer_id: AccountId,
    ) -> Promise {
        require!(
            Self::check_storage_balance_result(0),
            BridgeError::StorageRecipientOmitted.as_ref()
        );

        let OmniAddress::Near(recipient) = fast_transfer.recipient.clone() else {
            env::panic_str(BridgeError::InvalidState.to_string().as_str())
        };

        let required_balance = self
            .add_fast_transfer(fast_transfer, relayer_id, storage_payer.clone())
            .saturating_add(ONE_YOCTO);

        self.update_storage_balance(
            storage_payer,
            required_balance,
            NearToken::from_yoctonear(0),
        );

        env::log_str(
            &OmniBridgeEvent::FastTransferEvent {
                fast_transfer: fast_transfer.clone(),
                new_transfer_id: None,
            }
            .to_log_string(),
        );

        let amount_without_fee = U128(
            fast_transfer
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
        );
        self.send_tokens(
            fast_transfer.token_id.clone(),
            recipient,
            amount_without_fee,
            &fast_transfer.msg,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(RESOLVE_FAST_TRANSFER_GAS)
                .resolve_fast_transfer(
                    &fast_transfer.token_id,
                    &fast_transfer.id(),
                    amount_without_fee,
                    !fast_transfer.msg.is_empty(),
                ),
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L1867-1902)
```rust
    #[allow(clippy::too_many_lines, clippy::ptr_arg)]
    fn process_fin_transfer_to_near(
        &mut self,
        recipient: AccountId,
        predecessor_account_id: &AccountId,
        transfer_message: TransferMessage,
        storage_deposit_actions: &Vec<StorageDepositAction>,
    ) -> Promise {
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());

        let token = self.get_token_id(&transfer_message.token);
        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let fast_transfer_status = self.get_fast_transfer_status(&fast_transfer.id());

        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];

        // If fast transfer happened, change recipient and fee recipient to the relayer that executed fast transfer
        let (recipient, msg, fee_recipient) = match fast_transfer_status {
            Some(status) => {
                require!(
                    !status.finalised,
                    BridgeError::FastTransferAlreadyFinalised.as_ref()
                );
                self.remove_fast_transfer(&fast_transfer.id());
                (status.relayer.clone(), String::new(), status.relayer)
            }
            None => (
                recipient,
                transfer_message.msg.clone(),
                predecessor_account_id.clone(),
            ),
        };
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

**File:** near/omni-bridge/src/lib.rs (L2246-2265)
```rust
    fn add_fast_transfer(
        &mut self,
        fast_transfer: &FastTransfer,
        relayer: AccountId,
        storage_owner: AccountId,
    ) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.fast_transfers
                .insert(
                    &fast_transfer.id(),
                    &FastTransferStatusStorage::V0(FastTransferStatus {
                        relayer,
                        storage_owner,
                        finalised: false,
                    }),
                )
                .is_none(),
            BridgeError::FastTransferAlreadyPerformed.as_ref()
        );
```
