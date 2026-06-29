### Title
ERC1155 `finTransfer` Permanently Freezes Bridged Tokens When Recipient Contract Lacks `IERC1155Receiver` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.finTransfer` delivers ERC1155 tokens to `payload.recipient` via `IERC1155.safeTransferFrom`. If `payload.recipient` is a contract that does not implement `IERC1155Receiver.onERC1155Received()`, the delivery always reverts. Because the recipient address is cryptographically bound in the signed payload and the bridge has no cancel or refund path, the corresponding source-chain ERC1155 tokens locked by `initTransfer1155` are permanently frozen.

---

### Finding Description

`OmniBridge` implements `IERC1155Receiver` so it can accept ERC1155 tokens during `initTransfer1155`. On the destination side, `finTransfer` releases those tokens using:

```solidity
IERC1155(multiToken.tokenAddress).safeTransferFrom(
    address(this),
    payload.recipient,
    multiToken.tokenId,
    payload.amount,
    ""
);
``` [1](#0-0) 

`safeTransferFrom` in the ERC1155 standard mandates that if `payload.recipient` is a contract, it must return the correct selector from `onERC1155Received`; otherwise the call reverts. The bridge performs no pre-flight check (e.g., `supportsInterface(IERC1155Receiver)`) and has no try/catch around this call. [2](#0-1) 

The source-chain lock is performed in `initTransfer1155`, which calls `IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), ...)`, transferring custody of the tokens to the bridge contract before any destination-side action occurs. [3](#0-2) 

There is no `cancel`, `rescue`, `refund`, or `withdraw` function anywhere in `OmniBridge.sol` that would allow recovery of ERC1155 tokens held by the bridge. [4](#0-3) 

---

### Impact Explanation

When `payload.recipient` is a contract without `IERC1155Receiver`:

1. Every `finTransfer` attempt reverts (the whole transaction rolls back, so `completedTransfers[nonce]` is never durably set).
2. The recipient address is part of the MPC-signed payload and cannot be changed by anyone.
3. No relayer can ever successfully finalize the transfer.
4. The ERC1155 tokens locked in the source-chain bridge are permanently frozen with no recovery path.

This is **permanent freezing of bridged funds**, matching the critical impact scope.

---

### Likelihood Explanation

Contract addresses are common bridge recipients: multisig wallets (Gnosis Safe), DAO treasuries, protocol vaults, and smart-contract wallets. Many of these do not implement `IERC1155Receiver`. Any user who initiates an ERC1155 bridge transfer to such an address triggers the freeze. No special privilege or attacker cooperation is required — a regular token holder calling `initTransfer1155` with a contract recipient is sufficient.

---

### Recommendation

Replace the bare `safeTransferFrom` with a pattern that handles non-receiver contracts gracefully. Options:

1. **Pre-flight interface check**: Before calling `safeTransferFrom`, call `IERC165(payload.recipient).supportsInterface(type(IERC1155Receiver).interfaceId)` and fall back to a pull-payment escrow if it returns false.
2. **Try/catch with escrow**: Wrap the `safeTransferFrom` in a `try/catch`; on failure, store the tokens in a per-recipient claimable balance that the recipient can pull later.
3. **Use non-safe transfer**: Replace `safeTransferFrom` with a direct `transferFrom` (if the underlying ERC1155 exposes one) that skips the receiver callback, accepting the trade-off that the recipient must be aware of the incoming tokens.

---

### Proof of Concept

1. User holds ERC1155 token `(tokenAddress, tokenId=1)` on the source EVM chain.
2. User calls `initTransfer1155(tokenAddress, 1, 100, 0, 0, "RecipientContract.near", "")` where `RecipientContract` on the destination chain is a Gnosis Safe or similar contract without `onERC1155Received`.
3. Bridge emits `InitTransfer`; 100 units of token ID 1 are now held by `OmniBridge`.
4. NEAR MPC signs the transfer payload with `recipient = RecipientContract`.
5. Relayer calls `finTransfer(sig, payload)` on the destination chain.
6. `IERC1155(multiToken.tokenAddress).safeTransferFrom(address(this), RecipientContract, 1, 100, "")` is executed.
7. The ERC1155 contract calls `RecipientContract.onERC1155Received(...)` — the call reverts because `RecipientContract` has no such function.
8. The entire `finTransfer` transaction reverts; `completedTransfers[nonce]` remains `false`.
9. No alternative recipient can be substituted (payload is MPC-signed). No refund path exists.
10. The 100 ERC1155 tokens are permanently locked in the source-chain `OmniBridge`. [5](#0-4)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L458-464)
```text
        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L548-598)
```text
    function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause(flags);
    }

    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        uint256 flags = PAUSED_FIN_TRANSFER |
            PAUSED_INIT_TRANSFER |
            PAUSED_DEPLOY_TOKEN;
        _pause(flags);
    }

    function upgradeToken(
        address tokenAddress,
        address implementation
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(isBridgeToken[tokenAddress], "ERR_NOT_BRIDGE_TOKEN");
        BridgeToken proxy = BridgeToken(tokenAddress);
        proxy.upgradeToAndCall(implementation, bytes(""));
    }

    function setNearBridgeDerivedAddress(
        address nearBridgeDerivedAddress_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    }

    receive() external payable {}

    function deriveDeterministicAddress(
        address tokenAddress,
        uint256 tokenId
    ) public pure returns (address) {
        return
            address(
                bytes20(keccak256(abi.encodePacked(tokenAddress, tokenId)))
            );
    }

    function _normalizeDecimals(uint8 decimals) internal pure returns (uint8) {
        uint8 maxAllowedDecimals = 18;
        if (decimals > maxAllowedDecimals) {
            return maxAllowedDecimals;
        }
        return decimals;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    uint256[49] private __gap;
```
