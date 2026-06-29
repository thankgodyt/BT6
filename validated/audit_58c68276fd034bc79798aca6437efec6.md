Now I have a complete picture of the codebase. Let me analyze the analog.

The external report's vulnerability class is **token metadata binding confusion**: the same identifier (`nftId`) can be bound to two different type properties (`isFungible`), causing the routing logic to use the wrong code path.

In `OmniBridge.sol`, the exact analog exists between `initTransfer1155` and `finTransfer`. The `finTransfer` function routes token releases based on `multiTokens[payload.tokenAddress]` — but `initTransfer1155` locks ERC1155 tokens and emits `InitTransfer` using the `deterministicToken` address **without ever writing to `multiTokens[deterministicToken]`**. Only `logMetadata1155` sets that mapping. There is no enforcement that `logMetadata1155` must be called before `initTransfer1155`, so the same `deterministicToken` identifier can be used in `initTransfer1155` (implying ERC1155 type) while `multiTokens` remains unset (implying non-ERC1155 type), causing `finTransfer` to route through the wrong code path.

---

### Title
`initTransfer1155` Does Not Enforce `multiTokens` Registration, Causing Permanent ERC1155 Fund Lock on `finTransfer` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`initTransfer1155` locks ERC1155 tokens and emits `InitTransfer` using a `deterministicToken` address, but never writes to `multiTokens[deterministicToken]`. The `finTransfer` function exclusively relies on `multiTokens[payload.tokenAddress]` to identify and release ERC1155 tokens. If `logMetadata1155` was not called before `finTransfer` is invoked, `finTransfer` falls through to the ERC20 code path, which reverts because the deterministic address holds no contract code. Because the destination nonce is marked used **before** the token transfer, the transfer is permanently bricked and the ERC1155 tokens are frozen in the bridge.

### Finding Description

`initTransfer1155` derives `deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId)`, locks the ERC1155 tokens, and emits `InitTransfer` — but does **not** write to `multiTokens[deterministicToken]`: [1](#0-0) 

The only function that sets `multiTokens[deterministicToken]` is `logMetadata1155`: [2](#0-1) 

`finTransfer` marks the nonce used first, then branches on `multiTokens[payload.tokenAddress]`: [3](#0-2) 

If `multiTokens[deterministicToken]` is zero (not set), execution falls to the final `else` branch:

```solidity
IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount);
```

`deterministicToken` is `address(bytes20(keccak256(abi.encodePacked(tokenAddress, tokenId))))` — a hash-derived address with no deployed code. The `safeTransfer` call reverts. The nonce is already consumed, so the transfer is permanently stuck. [4](#0-3) 

### Impact Explanation

**Critical — permanent freezing of bridged ERC1155 funds.**

The attack path:
1. User calls `initTransfer1155(erc1155Addr, tokenId, amount, ...)` without first calling `logMetadata1155`. The ERC1155 tokens are locked in the bridge; `multiTokens[deterministicToken]` remains unset.
2. NEAR processes the `InitTransfer` event and mints NEAR-side tokens for the user.
3. User initiates a return transfer on NEAR; NEAR burns the user's tokens.
4. Relayer calls `finTransfer` on EVM with `payload.tokenAddress = deterministicToken`.
5. `completedTransfers[payload.destinationNonce] = true` executes first (nonce consumed).
6. `multiTokens[deterministicToken].tokenAddress == address(0)` → falls to ERC20 path → `IERC20(deterministicToken).safeTransfer(...)` → reverts (no code at that address).
7. The nonce is permanently used. The user's NEAR tokens are burned. The ERC1155 tokens are frozen in the bridge contract with no recovery path.

### Likelihood Explanation

**Medium.** `logMetadata1155` is permissionless and is the intended prerequisite, but `initTransfer1155` imposes no on-chain enforcement of this ordering. Any user who calls `initTransfer1155` without the prior `logMetadata1155` step — or any relayer that calls `finTransfer` before `logMetadata1155` is set — triggers the permanent lock. The protocol documentation does not prevent this ordering mistake, and no existing guard in `initTransfer1155` checks `multiTokens[deterministicToken]`.

### Recommendation

`initTransfer1155` should enforce that the `multiTokens` binding is already established before locking tokens. Add a check at the top of `initTransfer1155`:

```solidity
address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);
require(
    multiTokens[deterministicToken].tokenAddress != address(0),
    "ERC1155NotRegistered"
);
```

Alternatively, `initTransfer1155` can set `multiTokens[deterministicToken]` itself (mirroring `logMetadata1155`'s logic) so the mapping is always consistent with the locked tokens.

### Proof of Concept

```solidity
// 1. Deploy ERC1155 and mint tokens to attacker
TestERC1155 erc1155 = new TestERC1155();
erc1155.mint(user, tokenId, 5);
erc1155.setApprovalForAll(address(bridge), true);

// 2. Call initTransfer1155 WITHOUT calling logMetadata1155 first
//    multiTokens[deterministicToken] remains unset
bridge.initTransfer1155(address(erc1155), tokenId, 1, 0, 0, "user.near", "");
// ERC1155 tokens are now locked in bridge; NEAR mints tokens for user

// 3. User bridges back from NEAR; NEAR burns tokens; relayer calls finTransfer
address deterministicToken = bridge.deriveDeterministicAddress(address(erc1155), tokenId);
// multiTokens[deterministicToken].tokenAddress == address(0)
// finTransfer falls to: IERC20(deterministicToken).safeTransfer(...) → REVERT
// nonce is already marked used → permanent fund lock
bridge.finTransfer(signature, TransferMessagePayload({
    tokenAddress: deterministicToken,
    amount: 1,
    recipient: user,
    ...
}));
// Result: user's NEAR tokens burned, ERC1155 tokens permanently frozen
```

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L576-584)
```text
    function deriveDeterministicAddress(
        address tokenAddress,
        uint256 tokenId
    ) public pure returns (address) {
        return
            address(
                bytes20(keccak256(abi.encodePacked(tokenAddress, tokenId)))
            );
    }
```
