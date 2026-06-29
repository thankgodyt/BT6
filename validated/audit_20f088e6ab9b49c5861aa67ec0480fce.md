### Title
`removeCustomToken()` Permanently Freezes In-Flight Bridged Funds for the Removed Token — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`removeCustomToken()` deletes the `isBridgeToken` and `customMinters` mappings for a token without verifying that no in-flight NEAR→EVM transfers exist for it. After removal, any subsequent `finTransfer()` call for that token silently falls through to a raw `IERC20.safeTransfer()` from the bridge contract's own balance — a balance that is zero for every burn/mint custom token — causing the call to revert and permanently stranding the user's already-burned NEAR-side funds.

---

### Finding Description

**`removeCustomToken()` deletes all routing state without a pending-transfer guard:** [1](#0-0) 

```solidity
function removeCustomToken(address tokenAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
    delete isBridgeToken[tokenAddress];
    delete nearToEthToken[ethToNearToken[tokenAddress]];
    delete ethToNearToken[tokenAddress];
    delete customMinters[tokenAddress];
}
```

**`finTransfer()` dispatches token delivery through a priority chain that ends in a bare `safeTransfer`:** [2](#0-1) 

```solidity
} else if (customMinters[payload.tokenAddress] != address(0)) {
    ICustomMinter(customMinters[payload.tokenAddress]).mint(...);
} else if (isBridgeToken[payload.tokenAddress]) {
    IBridgeToken(payload.tokenAddress).mint(...);
} else {
    IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount); // ← fallback
}
```

After `removeCustomToken()`:
- `customMinters[tokenAddress]` → `address(0)` → first branch skipped
- `isBridgeToken[tokenAddress]` → `false` → second branch skipped
- Execution falls to `IERC20.safeTransfer(recipient, amount)`

For every burn/mint custom token the bridge contract holds **zero** ERC20 balance, so `safeTransfer` reverts. The entire `finTransfer` transaction is atomically rolled back, including the `completedTransfers[nonce] = true` write at line 287, so the nonce is not consumed — but the user's tokens were already burned on NEAR and cannot be recovered without admin intervention to re-add the token. [3](#0-2) 

---

### Impact Explanation

Any NEAR→EVM transfer for the removed token that was initiated before (or concurrently with) the removal call becomes undeliverable on the EVM side. Because the NEAR bridge has already burned or locked the user's tokens, those funds are stranded with no escape path unless the admin explicitly re-adds the token. If the removal was intentional (e.g., decommissioning a token), re-addition may never happen, making the freeze permanent. This matches the allowed critical impact class: **permanent freezing of bridged funds across NEAR and EVM**.

---

### Likelihood Explanation

`removeCustomToken()` is a legitimate administrative operation with no guard against outstanding transfers. An admin may call it to rotate a custom minter contract, respond to a security incident, or decommission a token — all plausible, non-malicious scenarios. The window between a NEAR-side `fin_transfer` and the corresponding EVM `finTransfer` relay can span multiple blocks, making a race condition realistic.

---

### Recommendation

Before deleting the routing state, require that no in-flight transfers exist for the token, or implement a two-phase deprecation:

1. **Phase 1 – Deprecate**: mark the token as deprecated (block new `initTransfer` calls for it) while keeping `finTransfer` routing intact.
2. **Phase 2 – Remove**: allow full deletion only after a time-lock or after confirming all pending nonces have been finalized.

Alternatively, add an emergency recovery path that allows `finTransfer` to succeed for deprecated tokens by reading from a separate "deprecated minter" mapping that is not cleared on removal.

---

### Proof of Concept

1. Admin calls `addCustomToken(nearTokenId, tokenAddress, customMinter, originDecimals)` — sets `isBridgeToken[tokenAddress] = true`, `customMinters[tokenAddress] = customMinter`.
2. User initiates a NEAR→EVM transfer; NEAR bridge burns the user's tokens and emits a signed `TransferMessagePayload`.
3. Admin calls `removeCustomToken(tokenAddress)` — clears `isBridgeToken` and `customMinters`.
4. Relayer submits `finTransfer(signatureData, payload)` for the pending transfer.
5. Signature verification passes (line 311). `completedTransfers[nonce]` is set to `true` (line 287).
6. Dispatch: `customMinters[tokenAddress]` is `address(0)` → skip; `isBridgeToken[tokenAddress]` is `false` → skip; falls to `IERC20(tokenAddress).safeTransfer(recipient, amount)`.
7. Bridge holds zero balance → `safeTransfer` reverts → entire transaction rolls back.
8. Relayer retries indefinitely; every attempt reverts. User's NEAR-side tokens are burned with no EVM delivery possible. [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L120-127)
```text
    function removeCustomToken(
        address tokenAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        delete isBridgeToken[tokenAddress];
        delete nearToEthToken[ethToNearToken[tokenAddress]];
        delete ethToNearToken[tokenAddress];
        delete customMinters[tokenAddress];
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
