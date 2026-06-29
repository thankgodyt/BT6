### Title
Blacklisted EVM Recipient Causes Permanent Freezing of Bridged Funds - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary

When a NEAR → EVM transfer is in flight and the destination EVM recipient address becomes blacklisted by the token contract (e.g., USDC, USDT), the `finTransfer` call on the EVM bridge will always revert. Because the recipient address is cryptographically bound into the MPC-signed payload and there is no mechanism to change the recipient or cancel the pending transfer on NEAR, the bridged funds are permanently frozen.

### Finding Description

The EVM `finTransfer` function in `OmniBridge.sol` marks the destination nonce as used before attempting the token transfer: [1](#0-0) 

Then it attempts to deliver tokens to `payload.recipient`: [2](#0-1) 

If `payload.recipient` is blacklisted by the token contract (e.g., USDC's `_blacklisted` mapping), `safeTransfer` reverts, rolling back the entire transaction including the nonce marking. The nonce is therefore not consumed, and the relayer can retry — but the retry will always fail because `payload.recipient` is hardcoded into the MPC-signed payload: [3](#0-2) 

The recipient is part of the Borsh-encoded message that is verified against the MPC-derived address. Any change to `payload.recipient` invalidates the signature. There is no mechanism in the bridge to:
1. Request a new MPC signature with a different recipient for the same transfer, or
2. Cancel the pending transfer on NEAR and refund the sender.

On the NEAR side, when `init_transfer` is processed, the tokens are burned or locked: [4](#0-3) 

The transfer message is stored in `pending_transfers` awaiting finalization. Since `finTransfer` on EVM can never succeed for a blacklisted recipient, and there is no cancel/refund path, the tokens are permanently frozen in the NEAR bridge contract.

A secondary analog exists on the NEAR inbound path: `fin_transfer_send_tokens_callback` only checks for refund when `is_ft_transfer_call` is `true` (i.e., `ft_transfer_call` path). For plain `ft_transfer` (empty `msg`), `is_refund_required` unconditionally returns `false`: [5](#0-4) 

So if `ft_transfer` to a NEAR recipient fails (e.g., a custom NEP-141 token with a blacklist), the callback takes the "success" path, marks the transfer finalized, and the tokens remain permanently stuck in the bridge contract with no recovery path.

### Impact Explanation

Bridged funds are permanently frozen. For the EVM outbound path: tokens burned/locked on NEAR cannot be recovered if the EVM recipient is blacklisted by the token contract. For the NEAR inbound path: tokens held by the bridge contract are permanently inaccessible if `ft_transfer` to the recipient fails silently. Both scenarios result in complete, irrecoverable loss of the user's bridged assets.

### Likelihood Explanation

USDC and USDT — two of the most commonly bridged assets — have on-chain blacklists actively used by Circle and Tether. A user whose EVM address is blacklisted after initiating a bridge transfer (or who specifies a recipient that is subsequently blacklisted during the multi-step bridge process) will have their funds permanently frozen. The probability is low but non-zero and has real-world precedent.

### Recommendation

**EVM side (`OmniBridge.sol`):** Add a `recipient` override parameter to `finTransfer` that allows the original `sender` (proven via the signed payload) to redirect funds to an alternative address. Alternatively, implement a pull-payment pattern where tokens are credited to an internal balance mapping and the recipient (or sender, if recipient is blacklisted) can withdraw to any address.

**NEAR side (`lib.rs`):** In `fin_transfer_send_tokens_callback`, check the promise result even when `is_ft_transfer_call` is `false`. If `ft_transfer` failed, revert the lock actions and remove the finalization record so the transfer can be retried or refunded:

```rust
// Check ft_transfer result regardless of is_ft_transfer_call
let transfer_failed = match env::promise_result_checked(0, ...) {
    Err(_) => true,
    _ => Self::is_refund_required(is_ft_transfer_call),
};
```

### Proof of Concept

**EVM path:**
1. Alice holds 10,000 USDC on NEAR and initiates a bridge transfer to her EVM address `0xAlice`.
2. NEAR burns Alice's USDC and stores the transfer message with `recipient = 0xAlice`.
3. MPC signs the payload binding `recipient = 0xAlice`.
4. Circle blacklists `0xAlice` (e.g., due to a regulatory action).
5. Relayer calls `finTransfer(signature, payload)` on EVM — `safeTransfer(0xAlice, 10000e6)` reverts.
6. Transaction reverts; nonce not consumed. Relayer retries — same result, indefinitely.
7. Alice's 10,000 USDC is permanently locked in the NEAR bridge contract with no refund mechanism. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L1692-1747)
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L1784-1803)
```rust
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
