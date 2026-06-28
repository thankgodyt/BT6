### Title
`initTransfer1155()` Accepts ERC-1155 Tokens Without Verifying `logMetadata1155()` Was Called First, Permanently Freezing Tokens in the Bridge - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer1155()` transfers ERC-1155 tokens from the caller into the bridge and emits an `InitTransfer` event using a deterministic pseudo-address (`deterministicToken`) as the token identifier. However, it never verifies that `logMetadata1155()` was previously called to populate `multiTokens[deterministicToken]`. When NEAR later finalizes the transfer by calling `finTransfer()` on the destination chain, the lookup `multiTokens[payload.tokenAddress]` returns a zero address, causing the function to fall through to an ERC-20 `safeTransfer` on a non-existent token address, which reverts. The source-chain ERC-1155 tokens are permanently locked in the bridge with no recovery path.

---

### Finding Description

`initTransfer1155()` performs the following steps:

1. Derives `deterministicToken = keccak256(tokenAddress, tokenId)[0:20]`
2. Calls `IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), tokenId, amount, "")` — tokens are now held by the bridge
3. Emits `InitTransfer(..., deterministicToken, ...)`

It does **not** check whether `multiTokens[deterministicToken]` has been populated.

`finTransfer()` on the destination chain resolves the token type via:

```solidity
MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress]; // deterministicToken
if (multiToken.tokenAddress != address(0)) {
    IERC1155(multiToken.tokenAddress).safeTransferFrom(...); // ERC-1155 path
} else if (...) { ... }
else {
    IERC20(payload.tokenAddress).safeTransfer(...); // falls here — deterministicToken is not a real ERC-20
}
```

If `logMetadata1155()` was never called, `multiToken.tokenAddress == address(0)`, and `finTransfer` attempts `IERC20(deterministicToken).safeTransfer(...)` on a synthetic address that has no code, causing a revert. The nonce is already marked `completedTransfers[nonce] = true` before the transfer attempt, so the finalization cannot be retried. The source-chain tokens remain locked forever.

---

### Impact Explanation

ERC-1155 tokens transferred via `initTransfer1155()` without a prior `logMetadata1155()` call are permanently frozen in the `OmniBridge` contract. There is no admin rescue function, no refund path, and no way to re-attempt finalization (nonce is consumed). This constitutes permanent loss of bridged funds.

---

### Likelihood Explanation

`logMetadata1155()` is a separate, permissionless, prerequisite transaction that is not enforced by `initTransfer1155()`. Any user who calls `initTransfer1155()` directly (e.g., via a script, block explorer, or wallet integration that omits the prerequisite step) will trigger the freeze. The ERC-20 analog `initTransfer()` has no such prerequisite, making the asymmetry non-obvious. Likelihood is low-to-medium given the protocol's user base and the absence of on-chain enforcement.

---

### Recommendation

Add a guard at the top of `initTransfer1155()` that requires the `multiTokens` mapping to already be populated for the derived deterministic address:

```solidity
function initTransfer1155(...) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);
+   if (multiTokens[deterministicToken].tokenAddress == address(0)) revert MultiTokenNotRegistered();
    ...
}
```

Alternatively, `initTransfer1155()` can call the `logMetadata1155()` logic inline so registration is atomic with the transfer.

---

### Proof of Concept

1. Alice holds ERC-1155 token at `tokenAddress`, `tokenId = 7`, `amount = 5`.
2. Alice approves `OmniBridge` and calls `initTransfer1155(tokenAddress, 7, 5, 0, 0, "alice.near", "")` **without** first calling `logMetadata1155(tokenAddress, 7)`.
3. `IERC1155(tokenAddress).safeTransferFrom(alice, bridge, 7, 5, "")` succeeds — 5 tokens are now in the bridge.
4. `InitTransfer` is emitted with `deterministicToken = keccak256(tokenAddress, 7)[0:20]`.
5. NEAR relayer picks up the event and eventually calls `finTransfer(sig, payload)` on the destination chain with `payload.tokenAddress = deterministicToken`.
6. `completedTransfers[nonce]` is set to `true` (line 287).
7. `multiTokens[deterministicToken].tokenAddress == address(0)` → falls through all branches to `IERC20(deterministicToken).safeTransfer(alice, 5)` → reverts (no code at `deterministicToken`).
8. The nonce is consumed; `finTransfer` can never succeed for this transfer. Alice's 5 ERC-1155 tokens are permanently frozen in the bridge. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L234-270)
```text
    function logMetadata1155(
        address tokenAddress,
        uint256 tokenId
    ) external payable {
        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        MultiTokenInfo storage multiToken = multiTokens[deterministicToken];

        if (multiToken.tokenAddress == address(0)) {
            multiToken.tokenAddress = tokenAddress;
            multiToken.tokenId = tokenId;
        } else {
            if (
                multiToken.tokenAddress != tokenAddress ||
                multiToken.tokenId != tokenId
            ) {
                revert ERC1155MappingMismatch();
            }
        }

        logMetadataExtension(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
        );

        emit BridgeTypes.LogMetadata(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-355)
```text
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
