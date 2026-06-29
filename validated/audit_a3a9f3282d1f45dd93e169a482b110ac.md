### Title
Native Fee Permanently Locked When Outbound Transfer Is Abandoned — (`near/omni-bridge/src/lib.rs`)

### Summary
When a user initiates an outbound transfer (NEAR → Foreign) with a non-zero `native_fee`, the fee is immediately deducted from their storage balance escrow inside the bridge contract. If the transfer is subsequently abandoned — because MPC signing fails permanently, the relayer never retries, or the destination-chain transaction fails — the native fee is permanently locked in the contract. There is no cancel mechanism and no refund path in `sign_transfer_callback` for the failure case.

### Finding Description
In `init_transfer_internal`, the `native_fee` is added to `required_storage_balance` and atomically deducted from the user's available storage balance via `try_update_storage_balance`: [1](#0-0) 

The NEAR equivalent of the native fee is now held inside the contract's own balance. It is only ever released to the fee recipient when `claim_fee` is called, which requires a cryptographic proof of a `FinTransfer` event on the destination chain: [2](#0-1) 

The `send_fee_internal` function then transfers the native fee NEAR to the fee recipient: [3](#0-2) 

The critical gap is in `sign_transfer_callback`. When the MPC signing call fails (`call_result` is `Err`), the callback silently does nothing — no refund is issued, no transfer message is removed, and no native fee is returned: [4](#0-3) 

Furthermore, when `remove_transfer_message` is eventually called (e.g., via `claim_fee`), only the storage-byte cost is refunded to the user's available balance — the `native_fee` amount is never credited back: [5](#0-4) 

There is no `cancel_transfer` or equivalent function anywhere in the contract that would allow a user to reclaim their native fee from a stuck pending transfer.

### Impact Explanation
If a transfer is permanently abandoned — because the destination-chain transaction fails and no `FinTransfer` proof can ever be produced — `claim_fee` can never be called. The user's `native_fee` NEAR is permanently frozen inside the bridge contract. Neither the user nor the fee recipient can recover it. This constitutes permanent freezing of user funds and fee mis-accounting: the contract's internal storage balance records show the native fee as consumed, but it is never disbursed.

### Likelihood Explanation
This is realistically triggered whenever a destination-chain transaction fails after MPC signing succeeds. The relayer submits the signed transaction to the destination chain; if the destination chain rejects it (e.g., gas exhaustion, recipient contract revert, nonce collision), no `FinTransfer` event is emitted, `

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L1054-1063)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args).then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(env::attached_deposit())
                .with_static_gas(CLAIM_FEE_CALLBACK_GAS)
                .claim_fee_callback(&env::predecessor_account_id()),
        )
```

**File:** near/omni-bridge/src/lib.rs (L1834-1848)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }
```

**File:** near/omni-bridge/src/lib.rs (L2664-2667)
```rust
            } else if origin_chain == ChainKind::Near {
                Promise::new(fee_recipient.clone())
                    .transfer(NearToken::from_yoctonear(transfer_message.fee.native_fee.0))
                    .detach();
```
