### Title
Permanent Freezing of Bridged Funds When EVM Recipient Is Blacklisted — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

When a user initiates a NEAR → EVM transfer specifying a recipient address that is blacklisted by the EVM token contract (e.g., USDC/USDT), the `finTransfer` call on EVM will always revert. Because the MPC signature is cryptographically bound to the specific recipient address and the NEAR side has no refund or recipient-update mechanism for failed EVM finalizations, the bridged funds are permanently frozen.

### Finding Description

**Outbound transfer flow (NEAR → EVM):**

1. User calls `ft_transfer_call` on the NEAR token contract, which triggers `ft_on_transfer` → `init_transfer` on the bridge. Tokens are burned (deployed tokens) or locked (native tokens) on NEAR, and a `TransferMessage` is stored in `pending_transfers`. [1](#0-0) 

2. A trusted relayer calls `sign_transfer`. The bridge reads `transfer_message.recipient` from `pending_transfers` — the recipient is fixed and cannot be changed — and requests an MPC signature over the full `TransferMessagePayload` (which includes `recipient`). If `fee.is_zero()`, the transfer is removed from `pending_transfers` immediately after signing. [2](#0-1) [3](#0-2) 

3. The relayer calls `finTransfer` on `OmniBridge.sol`. The nonce is marked used, the signature is verified, and then `safeTransfer` is called to the recipient: [4](#0-3) 

4. If `payload.recipient` is blacklisted by the token (e.g., USDC's `Blacklistable`), `safeTransfer` reverts. Because Solidity reverts roll back all state changes, `completedTransfers[payload.destinationNonce]` is also rolled back — the nonce is **not** permanently consumed.

5. However, the funds on NEAR are **already burned or locked** (step 1). The relayer can retry `finTransfer`, but the recipient is fixed in the MPC-signed payload. There is no function on NEAR to:
   - Change the recipient in a stored `TransferMessage`
   - Cancel a pending transfer and refund the sender
   - Re-sign with a different recipient [5](#0-4) 

The `update_transfer_fee` function only allows updating the fee, not the recipient. No `cancel_transfer` or `refund_transfer` function exists.

**Contrast with inbound transfers (EVM → NEAR):** The NEAR side *does* handle failed token sends via `fin_transfer_send_tokens_callback`, which burns tokens and emits `FailedFinTransferEvent` on failure. No equivalent recovery path exists for the outbound direction. [6](#0-5) 

### Impact Explanation

Bridged funds are permanently frozen: tokens are burned/locked on NEAR but can never be delivered to the EVM recipient. This matches the allowed critical impact: *"permanent freezing of bridged funds across NEAR, EVM … flows."*

### Likelihood Explanation

Realistic scenarios:
- A user initiates a transfer to a valid EVM address, but that address is subsequently blacklisted by the token issuer (e.g., OFAC-sanctioned USDC address) before the relayer finalizes on EVM. USDC has a documented history of blacklisting addresses post-issuance.
- A user mistakenly specifies a known blacklisted address (e.g., a sanctioned mixer contract) as the recipient.

No admin compromise, MPC collusion, or social engineering is required. The entry path is the standard public `ft_transfer_call` → `ft_on_transfer` → `init_transfer` flow.

### Recommendation

1. **Recipient update**: Allow the original sender to update `transfer_message.recipient` in `pending_transfers` before `sign_transfer` is called, so a valid recipient can be substituted.
2. **Refund on EVM failure**: After a configurable timeout or explicit relayer report of repeated EVM revert, allow the NEAR bridge to refund the sender by unlocking/minting back the original tokens.
3. **Pre-flight validation**: Where feasible (e.g., for known tokens with on-chain blacklist interfaces), validate the recipient is not blacklisted before burning/locking funds on NEAR.

### Proof of Concept

```
1. Alice calls ft_transfer_call on NEAR USDC wrapper:
   receiver_id = omni-bridge.near
   amount      = 1000 USDC
   msg         = InitTransferMsg {
       recipient: OmniAddress::Eth(0xE1D865c3D669dCc8c57c8D023140CB204e672ee4),  // USDC-blacklisted address
       fee: U128(0),
       ...
   }

2. Bridge burns 1000 USDC on NEAR, stores TransferMessage in pending_transfers.

3. Relayer calls sign_transfer → MPC signs payload with blacklisted recipient.
   fee.is_zero() == true → TransferMessage removed from pending_transfers.
   Alice's 1000 USDC are now burned with no pending record.

4. Relayer calls OmniBridge.finTransfer(signature, payload) on Ethereum.
   → completedTransfers[nonce] = true
   → ECDSA.recover(...) == nearBridgeDerivedAddress  ✓
   → IERC20(usdc).safeTransfer(0xE1D865..., 1000e6)
   → REVERT: "Blacklistable: account is blacklisted"
   → entire tx reverts, nonce rolled back

5. Relayer retries → same revert, indefinitely.
   Alice's 1000 USDC are permanently lost.
``` [7](#0-6) [8](#0-7)

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

**File:** near/omni-bridge/src/lib.rs (L491-520)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1700-1718)
```rust
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-355)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
            Borsh.encodeUint64(payload.destinationNonce),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
            bytes(payload.feeRecipient).length == 0 // None or Some(String) in rust
                ? bytes("\x00")
                : bytes.concat(
                    bytes("\x01"),
                    Borsh.encodeString(payload.feeRecipient)
                ),
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }

        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
        } else if (customMinters[payload.tokenAddress] != address(0)) {
            ICustomMinter(customMinters[payload.tokenAddress]).mint(
                payload.tokenAddress,
                payload.recipient,
                payload.amount
            );
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```
