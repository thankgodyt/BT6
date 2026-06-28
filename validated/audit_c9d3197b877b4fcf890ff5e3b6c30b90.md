### Title
ERC-1155 `safeTransferFrom` in `finTransfer` Permanently Freezes Bridged Funds When Recipient Is a Non-Receiver Contract - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol::finTransfer` uses `IERC1155.safeTransferFrom` to deliver ERC-1155 tokens to the recipient. ERC-1155's safe transfer variant requires the recipient contract to implement `IERC1155Receiver.onERC1155Received()` and return the correct magic value. If the recipient is a contract that does not implement this interface, the call reverts. Because the entire transaction reverts, the destination nonce is not consumed, so the transfer can never be finalized — permanently freezing the user's tokens that were already locked or burned on NEAR.

---

### Finding Description

In `finTransfer`, after signature verification, the nonce is marked used and then the token delivery branch for ERC-1155 is:

```solidity
IERC1155(multiToken.tokenAddress).safeTransferFrom(
    address(this),
    payload.recipient,
    multiToken.tokenId,
    payload.amount,
    ""
);
``` [1](#0-0) 

The ERC-1155 standard mandates that `safeTransferFrom` calls `onERC1155Received` on any contract recipient and reverts if the return value is not the correct selector. Contracts such as multisigs, DAOs, DeFi vaults, or any contract not explicitly implementing `IERC1155Receiver` will cause this revert.

Because the revert unwinds the entire transaction, the `completedTransfers[payload.destinationNonce] = true` assignment at line 287 is also rolled back: [2](#0-1) 

The nonce is therefore never consumed. Every subsequent relay attempt for this transfer will also revert. Meanwhile, on NEAR, the user's tokens were locked or burned at `ft_on_transfer` / `init_transfer` time and are held in the bridge contract with no on-chain refund path triggered by a failed EVM finalization. [3](#0-2) 

---

### Impact Explanation

**Critical — Permanent freezing of bridged funds.**

The user's tokens on NEAR are locked inside the bridge contract. The EVM finalization can never succeed for a non-receiver contract recipient. There is no NEAR-side escape hatch that fires when EVM finalization permanently fails. The tokens are irrecoverably frozen.

---

### Likelihood Explanation

**High.** Many common contract types — Gnosis Safe multisigs, governance contracts, yield aggregators, and any contract deployed before ERC-1155 became widespread — do not implement `IERC1155Receiver`. A user who specifies such a contract as the recipient (intentionally or by mistake) will trigger this condition. No special privilege is required; any bridge user can supply an arbitrary `recipient` address in the cross-chain message.

---

### Recommendation

Replace `safeTransferFrom` with the non-safe `transferFrom` variant for ERC-1155 delivery in `finTransfer`, mirroring the recommendation in the reference report:

```solidity
// Instead of:
IERC1155(multiToken.tokenAddress).safeTransferFrom(
    address(this), payload.recipient, multiToken.tokenId, payload.amount, ""
);

// Use:
IERC1155(multiToken.tokenAddress).transferFrom(
    address(this), payload.recipient, multiToken.tokenId, payload.amount, ""
);
```

Alternatively, wrap the call in a try/catch and implement a pull-based withdrawal pattern so that a failed delivery does not permanently freeze funds.

---

### Proof of Concept

1. Register an ERC-1155 token via `multiTokens` mapping on the deployed `OmniBridge`.
2. On NEAR, call `ft_on_transfer` / `init_transfer` to lock tokens and emit an `InitTransferEvent` with `recipient` set to a contract address that does **not** implement `IERC1155Receiver` (e.g., a plain Gnosis Safe).
3. A relayer submits the proof and calls `finTransfer` on EVM with the signed payload.
4. Execution reaches line 324; `safeTransferFrom` calls `onERC1155Received` on the Safe, which returns nothing or reverts.
5. The entire `finTransfer` transaction reverts. `completedTransfers[nonce]` is rolled back.
6. Every subsequent relay attempt for this nonce also reverts.
7. The user's tokens remain locked in the NEAR bridge contract with no recovery path. [4](#0-3) [5](#0-4)

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

**File:** near/omni-bridge/src/lib.rs (L523-558)
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

```

**File:** near/omni-bridge/src/lib.rs (L2056-2117)
```rust
    fn send_tokens(
        &self,
        token: AccountId,
        recipient: AccountId,
        amount: U128,
        msg: &str,
    ) -> Promise {
        let ft_transfer_call_gas = env::prepaid_gas()
            .saturating_sub(env::used_gas())
            .saturating_sub(SEND_TOKENS_CALLBACK_GAS) // TODO: not all send_tokens callbacks has the same gas.
            .saturating_sub(MINT_TOKEN_GAS)
            .min(FT_TRANSFER_CALL_GAS);

        let is_deployed_token = self.is_deployed_token(&token);

        if token == self.wnear_account_id && msg.is_empty() {
            // Unwrap wNEAR and transfer NEAR tokens
            ext_wnear_token::ext(self.wnear_account_id.clone())
                .with_static_gas(WNEAR_WITHDRAW_GAS)
                .with_attached_deposit(ONE_YOCTO)
                .near_withdraw(amount)
                .then(
                    Self::ext(env::current_account_id())
                        .with_static_gas(NEAR_WITHDRAW_CALLBACK_GAS)
                        .near_withdraw_callback(recipient, NearToken::from_yoctonear(amount.0)),
                )
        } else if is_deployed_token {
            let deposit = if msg.is_empty() {
                NO_DEPOSIT
            } else {
                ONE_YOCTO
            };

            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );

            ext_token::ext(token)
                .with_attached_deposit(deposit)
                .with_static_gas(MINT_TOKEN_GAS.saturating_add(ft_transfer_call_gas))
                .mint(
                    recipient,
                    amount,
                    (!msg.is_empty()).then(|| msg.to_string()),
                )
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        } else {
            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );

            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(ft_transfer_call_gas)
                .ft_transfer_call(recipient, amount, None, msg.to_string())
        }
```
