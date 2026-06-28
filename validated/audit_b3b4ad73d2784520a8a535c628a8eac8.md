### Title
No Cancellation Mechanism for Pending Transfers Permanently Locks User Funds - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

After a user initiates a NEAR-outbound bridge transfer via `ft_transfer_call` → `init_transfer`, their tokens are irrevocably locked inside the NEAR bridge contract. There is no `cancel_transfer`, `withdraw`, or equivalent function that allows the user to reclaim their tokens. The only path to release the funds is for a trusted relayer to call `sign_transfer`, which is access-controlled. If no relayer processes the transfer, the user's funds are permanently frozen with zero recourse.

---

### Finding Description

The NEAR → Foreign transfer lifecycle on the NEAR side is:

1. User calls `ft_transfer_call` on the token contract, transferring tokens to the bridge.
2. The bridge's `ft_on_transfer` handler calls `init_transfer`, which stores a `TransferMessage` in `pending_transfers` and emits an `InitTransferEvent`.
3. A trusted relayer must call `sign_transfer` to request an MPC signature.
4. After signing, the relayer submits the signature to the destination chain and calls `claim_fee` on NEAR to finalize.

The critical gap is between steps 2 and 3. Once the user's tokens are transferred to the bridge in step 1, the user has no function to call to cancel the transfer and recover their tokens.

`sign_transfer` is decorated with `#[trusted_relayer]`, meaning only accounts in the trusted-relayer set may invoke it: [1](#0-0) 

There is no public `cancel_transfer`, `abort_transfer`, or time-locked refund function anywhere in the contract. The only internal removal paths are `remove_transfer_message` and `remove_transfer_message_without_refund`, both of which are private helpers called only from within relayer-triggered callbacks: [2](#0-1) 

The `sign_transfer_callback` only removes the pending transfer record when `fee.is_zero()`; otherwise the record persists until `claim_fee` is called by the relayer: [3](#0-2) 

The `init_transfer` function itself confirms that tokens are consumed (transferred to the bridge) before any relayer interaction occurs, and the only return value to the token contract is the amount to refund (0 on success), meaning the bridge retains the full amount: [4](#0-3) 

The same structural gap exists on the EVM side: `initTransfer` immediately burns or locks tokens and emits an event, with no cancel path if the NEAR-side MPC never produces a signature: [5](#0-4) 

---

### Impact Explanation

If a pending transfer is never processed by a trusted relayer — due to relayer software failure, selective censorship of specific transfers, relayer set becoming temporarily empty during a transition, or any other operational condition — the user's tokens remain locked in `pending_transfers` indefinitely. There is no timeout, no self-service cancel, and no governance-triggered refund path. This constitutes **permanent freezing of bridged funds**, which is a Critical impact under the allowed scope.

---

### Likelihood Explanation

The scenario is realistic and does not require any privileged compromise:

- A relayer may crash or go offline after the user's `ft_transfer_call` is confirmed but before `sign_transfer` is called.
- A relayer may selectively ignore transfers (e.g., those with fees below a threshold, or from specific senders).
- During a relayer set rotation, there may be a window where no active relayer picks up the pending transfer.
- The `init_transfer` yield/resume path (used when storage is insufficient) can leave a transfer in a partially-initialized state that a relayer may not recognize.

In all these cases the user has no on-chain recourse.

---

### Recommendation

Add a time-locked self-cancellation function, for example:

```rust
pub fn cancel_transfer(&mut self, transfer_id: TransferId) {
    let transfer = self.get_transfer_message_storage(transfer_id);
    require!(
        OmniAddress::Near(env::predecessor_account_id()) == transfer.message.sender,
        "Only sender can cancel"
    );
    require!(
        env::block_timestamp() > transfer.created_at + CANCEL_TIMEOUT_NS,
        "Cancel timeout not elapsed"
    );
    // Return tokens to sender via ft_transfer
    let msg = self.remove_transfer_message(transfer_id);
    // refund msg.amount to msg.sender
}
```

A reasonable timeout (e.g., 24–72 hours) gives relayers time to process the transfer while ensuring users are not permanently locked out.

---

### Proof of Concept

1. User calls `ft_transfer_call` on a NEP-141 token with `msg = InitTransferMsg { recipient: <EVM address>, fee: 0, ... }`.
2. Bridge receives tokens; `init_transfer` stores the `TransferMessage` in `pending_transfers` and emits `InitTransferEvent`. Tokens are now held by the bridge.
3. The single active trusted relayer goes offline (or selectively ignores this transfer).
4. User attempts to recover funds — there is no function to call. `sign_transfer` reverts because the caller is not a trusted relayer. No other public function touches `pending_transfers`.
5. Funds remain locked indefinitely. [6](#0-5) [7](#0-6)

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L523-619)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );

        let required_storage_balance =
            self.required_balance_for_init_transfer_message(transfer_message.clone());

        let message_storage_account_id = transfer_message
            .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));

        // Choose storage payer or whether to yield execution until storage is available
        if self
            .try_to_transfer_balance_from_message_account(
                &message_storage_account_id,
                NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
                &signer_id,
                required_storage_balance,
            )
            .is_ok()
            || (self.has_storage_balance(
                &signer_id,
                required_storage_balance.saturating_add(NearToken::from_yoctonear(
                    init_transfer_msg.native_token_fee.0,
                )),
            ) && (init_transfer_msg.native_token_fee.0 == 0
                || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
        {
            PromiseOrPromiseIndexOrValue::Value(
                self.init_transfer_internal(transfer_message, signer_id),
            )
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
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L649-667)
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-437)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
        }

        initTransferExtension(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );

        emit BridgeTypes.InitTransfer(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
    }
```
