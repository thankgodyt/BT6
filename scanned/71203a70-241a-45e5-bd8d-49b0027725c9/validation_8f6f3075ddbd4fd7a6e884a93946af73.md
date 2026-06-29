### Title
Missing Zero-Address Validation on `payload.recipient` in `finTransfer` Causes Permanent Loss of Bridged Funds — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The EVM `OmniBridge.finTransfer` function transfers tokens to `payload.recipient` without validating that it is non-zero. Because the NEAR-side `init_transfer` also performs no zero-address check on the recipient, a user can initiate a NEAR→EVM bridge transfer specifying `address(0)` as the EVM recipient. The MPC will sign the payload, the relayer will submit `finTransfer`, and for any ERC20 token that rejects zero-address transfers (e.g. USDC, and OmniBridge's own `BridgeToken` via OpenZeppelin's `_mint`), the token transfer reverts. Since there is no cancellation or refund path for failed EVM finalizations, the user's tokens are permanently locked in the NEAR bridge contract.

---

### Finding Description

**NEAR side — `init_transfer` accepts zero EVM recipient:** [1](#0-0) 

The only recipient validation is that the destination chain is not NEAR. There is no `require!(!recipient.is_zero())` guard. A user can supply `OmniAddress::Eth(H160::ZERO)` (i.e. `"eth:0x0000000000000000000000000000000000000000"`) as the recipient. Tokens are burned/locked on NEAR and an `InitTransferEvent` is emitted.

**NEAR side — `sign_transfer` propagates the zero recipient into the signed payload:** [2](#0-1) 

The `recipient` field is taken directly from the stored `transfer_message` with no zero-address check. The MPC signs the payload containing `recipient = address(0)`.

**EVM side — `finTransfer` performs no zero-address check on `payload.recipient`:** [3](#0-2) 

For a standard ERC20 token (non-bridge, non-ETH, non-ERC1155), the code reaches:

```solidity
IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount);
```

For a bridge token, it reaches:

```solidity
IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount);
```

Both paths revert when `payload.recipient == address(0)`:
- OpenZeppelin's `SafeERC20.safeTransfer` propagates the underlying token's revert (USDC: `require(to != address(0))`).
- OpenZeppelin's ERC20 `_mint` has `require(account != address(0), "ERC20: mint to the zero address")`.

The entire `finTransfer` transaction reverts, so `completedTransfers[destinationNonce]` is rolled back. The nonce is not consumed, meaning the relayer can retry — but the MPC-signed payload is fixed with `recipient = address(0)`, so every retry reverts identically.

**No recovery path exists:**

The NEAR bridge has no `cancel_transfer` or refund function for the NEAR→EVM direction. The `FailedFinTransferEvent` / refund path in `fin_transfer_send_tokens_callback` applies only to NEAR-destination transfers: [4](#0-3) 

For NEAR→EVM transfers, `process_fin_transfer_to_other_chain` is used and has no refund mechanism: [5](#0-4) 

The user's tokens remain burned/locked on NEAR indefinitely.

---

### Impact Explanation

A user who specifies `address(0)` as their EVM recipient (accidentally or via a malicious front-end) will have their bridged tokens permanently locked in the NEAR bridge contract. The tokens are burned/locked on NEAR at `init_transfer` time, and `finTransfer` on EVM will always revert for any ERC20 or bridge token that enforces the standard zero-address prohibition. There is no protocol-level recovery path. This constitutes **permanent freezing of bridged funds**.

---

### Likelihood Explanation

The entry path is reachable by any bridge user: `init_transfer` on NEAR is a public, unprivileged function. A user can supply any `OmniAddress` as recipient, including a zero EVM address. The NEAR bridge performs no zero-address check. The MPC signs whatever recipient is stored. The likelihood of accidental occurrence is low but non-zero (e.g. UI bugs, copy-paste errors, programmatic integrations that fail to validate the address). The impact when triggered is irreversible.

---

### Recommendation

1. **NEAR `init_transfer`**: Add a `require!(!init_transfer_msg.recipient.is_zero(), ...)` guard after the chain-kind check. [6](#0-5) 

2. **EVM `finTransfer`**: Add `require(payload.recipient != address(0), "ERR_ZERO_RECIPIENT")` before the token dispatch block. [7](#0-6) 

3. **NEAR `sign_transfer`**: As a defense-in-depth measure, validate that the stored recipient is non-zero before requesting an MPC signature.

---

### Proof of Concept

1. User calls NEAR `init_transfer` with `recipient = OmniAddress::Eth(H160::ZERO)` and a USDC-equivalent token. Tokens are burned on NEAR.
2. Relayer calls `sign_transfer` on NEAR. MPC signs `TransferMessagePayload { recipient: address(0), ... }`.
3. Relayer calls `OmniBridge.finTransfer(signature, payload)` on EVM.
4. `completedTransfers[destinationNonce] = true` executes.
5. `IERC20(usdcAddress).safeTransfer(address(0), amount)` reverts (USDC: `require(to != address(0))`).
6. Entire transaction reverts; nonce is rolled back.
7. Every subsequent retry of step 3 reverts identically (payload is MPC-signed and immutable).
8. User's tokens are permanently locked on NEAR with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L491-500)
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
```

**File:** near/omni-bridge/src/lib.rs (L531-557)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1980-2050)
```rust
    fn process_fin_transfer_to_other_chain(
        &mut self,
        predecessor_account_id: AccountId,
        transfer_message: TransferMessage,
    ) {
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
        let token = self.get_token_id(&transfer_message.token);

        if transfer_message.recipient.is_utxo_chain() {
            let btc_account_id =
                self.get_utxo_chain_token(transfer_message.get_destination_chain());
            require!(
                token == btc_account_id,
                BridgeError::NativeTokenRequiredForChain.as_ref()
            );
        }

        self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        );
        self.lock_tokens_if_needed(
            transfer_message.get_destination_chain(),
            &token,
            transfer_message.fee.fee.into(),
        );

        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let recipient = if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            require!(
                !status.finalised,
                BridgeError::FastTransferAlreadyFinalised.as_ref()
            );
            Some(status.relayer)
        } else {
            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token,
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            );

            None
        };

        // If fast transfer happened, send tokens to the relayer that executed fast transfer
        if let Some(relayer) = recipient {
            self.send_tokens(
                token,
                relayer,
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
                "",
            )
            .detach();
            self.mark_fast_transfer_as_finalised(&fast_transfer.id());
        } else {
            required_balance = self
                .add_transfer_message(transfer_message.clone(), predecessor_account_id.clone())
                .saturating_add(required_balance);
        }

        self.update_storage_balance(
            predecessor_account_id,
            required_balance,
            env::attached_deposit(),
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
