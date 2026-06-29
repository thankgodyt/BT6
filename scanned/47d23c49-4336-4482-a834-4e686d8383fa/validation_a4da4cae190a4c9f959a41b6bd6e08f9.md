### Title
`removeCustomToken()` Permanently Freezes In-Flight Bridged Funds Without Draining Pending Transfers — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.removeCustomToken()` deletes all routing state for a custom-minter token in a single atomic operation with no check for in-flight `initTransfer` events. Any user whose tokens were already burned on the source chain via `initTransfer` but whose corresponding `finTransfer` has not yet been executed will have their funds permanently frozen: the nonce can never be consumed because the `finTransfer` code path will always revert.

---

### Finding Description

`removeCustomToken()` performs four unconditional storage deletions:

```solidity
function removeCustomToken(
    address tokenAddress
) external onlyRole(DEFAULT_ADMIN_ROLE) {
    delete isBridgeToken[tokenAddress];
    delete nearToEthToken[ethToNearToken[tokenAddress]];
    delete ethToNearToken[tokenAddress];
    delete customMinters[tokenAddress];
}
``` [1](#0-0) 

For a custom-minter token, `initTransfer` routes the user's tokens to the custom minter and burns them:

```solidity
if (customMinters[tokenAddress] != address(0)) {
    IERC20(tokenAddress).safeTransferFrom(msg.sender, customMinters[tokenAddress], amount);
    ICustomMinter(customMinters[tokenAddress]).burn(...);
``` [2](#0-1) 

The corresponding `finTransfer` mints tokens back via the same custom minter. After `removeCustomToken()` is called, `customMinters[tokenAddress]` is `address(0)` and `isBridgeToken[tokenAddress]` is `false`, so `finTransfer` falls through to the raw `safeTransfer` branch:

```solidity
} else if (customMinters[payload.tokenAddress] != address(0)) {
    // skipped — mapping deleted
} else if (isBridgeToken[payload.tokenAddress]) {
    // skipped — mapping deleted
} else {
    IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount);
    // ↑ always reverts: contract holds zero balance of this token
}
``` [3](#0-2) 

Because `completedTransfers[payload.destinationNonce] = true` is set before the token transfer, a revert rolls back the nonce mark, so the relayer can retry — but every retry will also revert. The user's source-chain tokens are already burned; the transfer can never be finalized. [4](#0-3) 

---

### Impact Explanation

Any user who called `initTransfer` for a custom-minter token before `removeCustomToken()` was executed loses their funds permanently. The source-chain tokens are burned; the destination-chain mint path is destroyed. This is a direct, irreversible loss of bridged funds — matching the "permanent freezing of bridged funds" impact class.

---

### Likelihood Explanation

Custom tokens are registered via `addCustomToken()` for tokens with non-standard mint/burn logic (e.g., eNEAR). Operational scenarios that trigger `removeCustomToken()` include: replacing a custom minter contract, deprecating a token, or correcting a misconfigured registration. In any of these cases, in-flight transfers initiated seconds or minutes before the removal will be silently bricked. No on-chain guard prevents this. [5](#0-4) 

---

### Recommendation

Before deleting the custom token mappings, `removeCustomToken()` should:

1. Revert (or require an explicit override flag) if there are any `completedTransfers` nonces that reference this token and have not yet been finalized on the destination side. Since the contract does not track pending outbound nonces per token, the safest mitigation is to require the caller to explicitly acknowledge that in-flight transfers may exist, or to add a per-token pending-transfer counter incremented in `initTransfer` and decremented in `finTransfer`.

2. Alternatively, preserve the `customMinters` entry (or a "tombstone" flag) so that `finTransfer` can still route correctly for already-burned transfers, while blocking new `initTransfer` calls for the removed token.

---

### Proof of Concept

1. Admin calls `addCustomToken(nearTokenId, tokenAddress, customMinterAddress, decimals)`.
2. User calls `initTransfer(tokenAddress, 1000, ...)` — tokens are transferred to `customMinterAddress` and burned. `InitTransfer` event is emitted with `originNonce = N`.
3. NEAR side processes the event; MPC signs a `finTransfer` payload for `destinationNonce = M`.
4. Before the relayer submits `finTransfer`, admin calls `removeCustomToken(tokenAddress)`.
5. Relayer submits `finTransfer` with the signed payload:
   - `completedTransfers[M]` is set to `true`.
   - `customMinters[tokenAddress]` → `address(0)` → branch skipped.
   - `isBridgeToken[tokenAddress]` → `false` → branch skipped.
   - `IERC20(tokenAddress).safeTransfer(recipient, 1000)` → reverts (contract balance = 0).
   - Entire transaction reverts; nonce `M` is not consumed.
6. Every subsequent retry also reverts. User's 1000 tokens are permanently lost. [1](#0-0) [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L88-127)
```text
    function addCustomToken(
        string calldata nearTokenId,
        address tokenAddress,
        address customMinter,
        uint8 originDecimals
    ) external payable onlyRole(DEFAULT_ADMIN_ROLE) {
        isBridgeToken[tokenAddress] = true;
        ethToNearToken[tokenAddress] = nearTokenId;
        nearToEthToken[nearTokenId] = tokenAddress;
        customMinters[tokenAddress] = customMinter;

        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        deployTokenExtension(
            nearTokenId,
            tokenAddress,
            decimals,
            originDecimals
        );

        emit BridgeTypes.DeployToken(
            tokenAddress,
            nearTokenId,
            name,
            symbol,
            decimals,
            originDecimals
        );
    }

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L394-410)
```text
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
```
