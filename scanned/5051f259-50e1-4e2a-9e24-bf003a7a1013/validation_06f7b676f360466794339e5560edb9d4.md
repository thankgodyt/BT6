### Title
ERC-1155 `safeTransferFrom` Recipient Hook Causes Permanent Freezing of Bridged Funds — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`finTransfer` in `OmniBridge.sol` uses `IERC1155.safeTransferFrom` to deliver ERC-1155 tokens to the recipient. The ERC-1155 standard mandates that `safeTransferFrom` calls `onERC1155Received` on any contract recipient. If the recipient contract reverts inside that hook, the entire `finTransfer` transaction reverts. Because the nonce is marked used before the external call but the revert undoes that state change, the nonce is never consumed and the transfer is permanently unfinalizable. The user's tokens on NEAR are already burned or locked with no recovery path, resulting in permanent freezing of bridged funds.

---

### Finding Description

In `finTransfer`, the nonce is marked used at line 287, then the MPC signature is verified, and then the token transfer is executed. For the ERC-1155 branch:

```solidity
// OmniBridge.sol line 287
completedTransfers[payload.destinationNonce] = true;

// ... signature verification ...

// OmniBridge.sol lines 323-330
IERC1155(multiToken.tokenAddress).safeTransferFrom(
    address(this),
    payload.recipient,
    multiToken.tokenId,
    payload.amount,
    ""
);
```

`safeTransferFrom` unconditionally calls `onERC1155Received` on `payload.recipient` if it is a contract. If that call reverts, the entire transaction reverts — including the `completedTransfers` write at line 287. The nonce is therefore never consumed.

Because the MPC signature is bound to the exact `(destinationNonce, recipient, amount, token)` tuple, no alternative payload can be signed for the same origin transfer. Every subsequent attempt to call `finTransfer` with the same signed payload will again reach `safeTransferFrom` and again revert. The transfer is permanently unfinalizable.

On the NEAR side, `init_transfer_internal` either burns deployed tokens or locks native tokens before emitting `InitTransferEvent`. There is no admin function, timeout, or cancellation path on either side that can reverse this state. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

Any user who initiates a NEAR→EVM transfer of an ERC-1155 token to a contract recipient that does not correctly implement `IERC1155Receiver` (or that deliberately reverts in `onERC1155Received`) will have their bridged funds permanently frozen. The tokens are burned or locked on NEAR at `init_transfer` time and can never be recovered because `finTransfer` on EVM will always revert. There is no admin escape hatch in `OmniBridge.sol` to force-complete or re-route the transfer.

This satisfies the allowed impact: **permanent freezing of bridged funds across NEAR and EVM**. [3](#0-2) [4](#0-3) 

---

### Likelihood Explanation

ERC-1155 tokens are explicitly supported via `logMetadata1155` / `initTransfer1155` / `finTransfer`. Many legitimate contract recipients (multisig wallets, DAO treasuries, DeFi vaults) do not implement `IERC1155Receiver`. A user bridging to any such address — even accidentally — permanently loses their funds. A malicious recipient contract can also deliberately revert in `onERC1155Received` to grief a sender. No special privilege is required; any bridge user initiating an ERC-1155 transfer is exposed. [5](#0-4) [6](#0-5) 

---

### Recommendation

Replace the push-to-recipient pattern with a **pull (claim) pattern** for ERC-1155 deliveries:

1. In `finTransfer`, when the token is ERC-1155, store the pending claim in a mapping (`pendingClaims[recipient][token][tokenId] += amount`) instead of calling `safeTransferFrom` immediately.
2. Expose a separate `claimERC1155(address token, uint256 tokenId)` function that the recipient calls to pull their tokens. The recipient's own call context handles any hook reversion without affecting the bridge's finalization state.

This ensures the nonce is consumed and the bridge state is finalized regardless of whether the recipient can accept the token, eliminating the permanent-freeze vector. [1](#0-0) 

---

### Proof of Concept

1. Deploy a malicious/non-compliant contract `BadRecipient` on EVM that either has no `onERC1155Received` implementation or reverts inside it.
2. On NEAR, call `ft_transfer_call` to the bridge with an `InitTransferMsg` specifying an ERC-1155 token and `recipient = BadRecipient_address`. The bridge burns/locks the tokens and emits `InitTransferEvent`.
3. The MPC signs a `TransferMessagePayload` with `recipient = BadRecipient_address`.
4. A relayer calls `finTransfer(signature, payload)` on `OmniBridge.sol`.
5. Execution reaches line 324: `IERC1155(...).safeTransferFrom(address(this), BadRecipient_address, ...)`.
6. `safeTransferFrom` calls `BadRecipient.onERC1155Received(...)`, which reverts.
7. The entire transaction reverts. `completedTransfers[nonce]` is reset to `false`.
8. Every subsequent `finTransfer` attempt with the same signed payload repeats steps 5–7.
9. The user's tokens on NEAR are permanently burned/locked with no recovery path. [7](#0-6) [8](#0-7)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-490)
```text
    function initTransfer1155(
        address tokenAddress,
        uint256 tokenId,
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

        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );

        uint256 extensionValue = msg.value - nativeFee;

        initTransferExtension(
            msg.sender,
            deterministicToken,
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
            deterministicToken,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L522-535)
```text
    function onERC1155Received(
        address operator,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external view override returns (bytes4) {
        // Only accept transfers that were initiated by this contract itself
        if (operator != address(this)) {
            revert ERC1155DirectSendNotAllowed();
        }

        return this.onERC1155Received.selector;
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

**File:** evm/CLAUDE.md (L32-36)
```markdown
- **No replay attacks**: Every `destinationNonce` must be checked against `completedTransfers` and marked used before any token transfer. Every `originNonce` is incremented atomically. A nonce must never be reusable
- **Event completeness**: `InitTransfer` and `FinTransfer` events must contain every field needed to reconstruct the transfer. The NEAR side relies solely on these events — any missing or ambiguous field means lost funds or spoofable transfers. Fields must not be collapsible (e.g. two different transfers must never produce the same event data)
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
- **No token release without signature**: Never mint, transfer, or unlock tokens to a recipient without first verifying a valid MPC signature. No admin function, emergency path, or refactor may bypass this — it is the only authorization gate for finTransfer
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```
