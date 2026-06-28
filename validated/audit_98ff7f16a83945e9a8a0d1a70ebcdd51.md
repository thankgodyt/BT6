### Title
Blacklisted EVM Recipient Permanently Freezes Bridged Funds in `finTransfer` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.sol::finTransfer` uses a push-based token delivery to `payload.recipient`. If the recipient address is blacklisted by the token contract (e.g., USDC) between the time the user initiates the transfer on NEAR and the time a relayer calls `finTransfer` on EVM, every finalization attempt reverts. Because the NEAR side has already burned or locked the user's tokens and there is no pull-based fallback or redirect mechanism, the bridged funds are permanently frozen.

### Finding Description

In `finTransfer`, after signature verification, the contract unconditionally pushes tokens to `payload.recipient`: [1](#0-0) 

The nonce is marked consumed at line 287 (`completedTransfers[payload.destinationNonce] = true`) before the token transfer. If the `safeTransfer` / `safeTransferFrom` call at lines 324–360 reverts (because the recipient is USDC-blacklisted), the entire transaction reverts, so the nonce is not permanently consumed. However, every subsequent attempt to call `finTransfer` for this transfer will also revert for the same reason. There is no alternative code path to redirect funds to a different address, no pull-based claim function, and no mechanism to cancel the pending transfer and refund the user on NEAR.

On the NEAR side, `init_transfer` already burned (for deployed bridge tokens) or locked (for native tokens) the user's funds before the EVM finalization is attempted: [2](#0-1) 

The pending transfer record on NEAR is only removed upon successful finalization. With EVM finalization permanently blocked, the NEAR-side record and the locked/burned tokens are irrecoverable.

### Impact Explanation

A user who initiates a NEAR→EVM transfer of a blacklist-capable token (USDC, USDT, etc.) and is subsequently blacklisted before a relayer calls `finTransfer` loses their funds permanently:

- Their tokens are burned or locked on NEAR.
- `finTransfer` on EVM reverts on every attempt due to the blacklisted recipient.
- No refund, redirect, or cancellation path exists in the protocol.

This constitutes **permanent freezing of bridged funds**, which is within the critical impact scope.

### Likelihood Explanation

USDC is one of the most commonly bridged assets. USDC blacklisting is exercised regularly by Circle (e.g., in response to sanctions or law enforcement requests). The window between a user initiating a transfer and a relayer finalizing it can be minutes to hours, providing a realistic opportunity for blacklisting to occur in between. No privileged attacker action is required — the blacklisting is performed by the token issuer, not the bridge operator.

### Recommendation

Replace the push-based delivery in `finTransfer` with a pull-based pattern:

1. Instead of calling `safeTransfer` directly to `payload.recipient` inside `finTransfer`, record the claimable balance in a mapping (e.g., `claimable[recipient][token] += amount`).
2. Expose a separate `claimTokens(address token)` function that the recipient calls to withdraw their balance.
3. This isolates a single recipient's blacklist status from the finalization of the transfer, preventing any one recipient from blocking the protocol flow.

### Proof of Concept

1. Alice holds 10,000 USDC on NEAR and calls `init_transfer` targeting her EVM address. The NEAR bridge burns her USDC and records the pending transfer.
2. Before any relayer calls `finTransfer` on EVM, Circle blacklists Alice's EVM address.
3. A relayer calls `OmniBridge.finTransfer(signatureData, payload)` where `payload.recipient = Alice_EVM`.
4. Execution reaches the `safeTransfer` call at line ~331 of `OmniBridge.sol`. USDC's `transfer` reverts because Alice is blacklisted.
5. The entire `finTransfer` transaction reverts. The nonce is not consumed.
6. Every future relayer attempt to finalize this transfer also reverts.
7. Alice's 10,000 USDC on NEAR is permanently burned with no recovery path. [3](#0-2) [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-330)
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
```

**File:** near/omni-bridge/src/lib.rs (L1850-1861)
```rust
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
