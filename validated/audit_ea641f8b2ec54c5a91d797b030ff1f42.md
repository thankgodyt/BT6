### Title
Permanent Freezing of Bridged Funds When EVM Recipient Is Blacklisted on Destination Token — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

When bridging tokens from NEAR to EVM, if the destination EVM token (e.g., USDC, USDT) has a blacklist and the recipient address is blacklisted, every `finTransfer` call will revert. Because the MPC signature is cryptographically bound to the blacklisted recipient, the transfer can never be finalized, permanently freezing the funds that were already burned or locked on NEAR.

---

### Finding Description

In `OmniBridge.sol`, `finTransfer` marks the destination nonce as used before performing the token transfer:

```solidity
completedTransfers[payload.destinationNonce] = true;   // line 287
// ... signature verification ...
IERC20(payload.tokenAddress).safeTransfer(             // line 351
    payload.recipient,
    payload.amount
);
``` [1](#0-0) 

If `safeTransfer` reverts (e.g., because the recipient is blacklisted in USDC or USDT), the entire transaction reverts, including the nonce marking. The nonce is therefore never consumed. However, the MPC signature produced by `sign_transfer` on NEAR is Borsh-encoded over the exact `recipient` field: [2](#0-1) 

This means the signature cannot be reused with a different recipient. Every retry of `finTransfer` with the same payload will revert identically. There is no fallback path, no try/catch, and no mechanism to redirect funds to a safe address.

On the NEAR side, once `ft_transfer_call` is processed through `ft_on_transfer`, the tokens are burned (for deployed tokens) or locked, and the transfer message is stored in `pending_transfers`: [3](#0-2) 

There is no user-accessible cancellation function. The DAO could theoretically intervene, but no protocol-level recovery path exists for the user.

---

### Impact Explanation

**Critical — Permanent freezing of bridged funds.**

Tokens are burned or locked on NEAR and can never be released on EVM. The MPC signature is bound to the blacklisted recipient, so no valid `finTransfer` call can ever succeed. The user loses the full bridged amount with no on-chain recourse.

---

### Likelihood Explanation

**Medium.** USDC and USDT — both of which implement address blacklists — are among the most commonly bridged assets. A user's EVM address can be blacklisted by Circle or Tether after a bridge transfer is initiated on NEAR (e.g., due to regulatory action), or a user may unknowingly bridge to a blacklisted address. The source chain (NEAR) performs no blacklist check, so the transfer is accepted and tokens are burned before the incompatibility is discovered.

---

### Recommendation

Wrap the token transfer in a try/catch and redirect funds to a designated fallback address (e.g., the bridge admin) on failure, emitting a `RedistributeFunds` event. This mirrors the fix applied in `StakedUSDeOFTAdapter._credit`. For example:

```solidity
try IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount) {
    // success
} catch {
    IERC20(payload.tokenAddress).safeTransfer(fallbackAddress, payload.amount);
    emit RedistributeFunds(payload.recipient, payload.amount);
}
```

Apply the same pattern to the `IBridgeToken.mint`, `IERC1155.safeTransferFrom`, and `ICustomMinter.mint` branches.

---

### Proof of Concept

1. User holds USDC (NEP-141) on NEAR and calls `ft_transfer_call` to the bridge with recipient `0xBlacklisted` on Ethereum.
2. NEAR bridge burns the USDC and stores the transfer message in `pending_transfers`.
3. A trusted relayer calls `sign_transfer`; the MPC service signs a payload that includes `0xBlacklisted` as the recipient.
4. The relayer submits `finTransfer` on EVM with the signed payload.
5. `OmniBridge.finTransfer` reaches `IERC20(USDC).safeTransfer(0xBlacklisted, amount)`.
6. USDC's internal blacklist check causes `transfer` to revert.
7. The entire `finTransfer` transaction reverts; `completedTransfers[nonce]` is never set.
8. Every subsequent retry with the same MPC-signed payload reverts identically.
9. The NEAR-side USDC is permanently burned; the EVM-side USDC is permanently locked in the bridge contract with no user-accessible recovery path. [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-367)
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

        finTransferExtension(payload);

        emit BridgeTypes.FinTransfer(
            payload.originChain,
            payload.originNonce,
            payload.tokenAddress,
            payload.amount,
            payload.recipient,
            payload.feeRecipient
        );
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
