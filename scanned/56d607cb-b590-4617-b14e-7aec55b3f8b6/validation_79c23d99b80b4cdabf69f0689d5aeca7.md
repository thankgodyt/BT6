### Title
ERC1155 Token Freezing via `deterministicToken` Used as ERC20 Address in `finTransfer` When `logMetadata1155` Not Called First - (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`initTransfer1155` accepts ERC1155 tokens and emits an `InitTransfer` event using a synthetic `deterministicToken` address as the token identifier, but does **not** populate the `multiTokens[deterministicToken]` mapping. Only `logMetadata1155` sets that mapping. If a user calls `initTransfer1155` without a prior `logMetadata1155`, the downstream `finTransfer` call falls through to the ERC20 branch and attempts `IERC20(deterministicToken).safeTransfer(...)` on a non-contract address — directly mirroring the OCY_Convex pattern of calling `safeTransfer` on a wrapper/synthetic address instead of the real token.

### Finding Description

`deriveDeterministicAddress` produces a synthetic address from `keccak256(abi.encodePacked(tokenAddress, tokenId))`:

```solidity
address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);
```

`initTransfer1155` transfers the real ERC1155 into the bridge and emits `InitTransfer` with `deterministicToken`, but **never writes** `multiTokens[deterministicToken]`: [1](#0-0) 

Only `logMetadata1155` writes the mapping: [2](#0-1) 

When NEAR later triggers `finTransfer` with `payload.tokenAddress = deterministicToken`, the dispatch logic is:

```solidity
MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress]; // zero struct
...
} else if (multiToken.tokenAddress != address(0)) {   // FALSE — mapping empty
    IERC1155(multiToken.tokenAddress)...               // skipped
} else {
    IERC20(payload.tokenAddress).safeTransfer(         // deterministicToken is NOT a contract
        payload.recipient, payload.amount
    );
}
``` [3](#0-2) 

`deterministicToken` has no code; `safeTransfer` reverts. The entire `finTransfer` transaction rolls back, including `completedTransfers[nonce] = true`, so the nonce remains reusable — but the ERC1155 tokens are stuck in the bridge until `logMetadata1155` is separately called and `finTransfer` retried.

The test suite itself demonstrates that `initTransfer1155` succeeds without a prior `logMetadata1155`: [4](#0-3) 

### Impact Explanation

ERC1155 tokens are frozen inside the bridge contract. Because `finTransfer` reverts atomically (nonce not consumed), the transfer is not permanently lost — recovery requires someone to call the permissionless `logMetadata1155` and then retry `finTransfer`. However, until that happens, the user's bridged assets are inaccessible. In a production scenario where neither the user nor the relayer knows to call `logMetadata1155`, the freeze can persist indefinitely. This constitutes escrow mis-accounting / token metadata binding confusion causing user balance impact.

### Likelihood Explanation

`initTransfer1155` is a public, unpermissioned function callable by any token holder. There is no on-chain guard requiring `logMetadata1155` to be called first. A user following the ERC20 analogy (`initTransfer` needs no prior metadata call) will naturally omit `logMetadata1155`. The test at line 191–194 confirms the path is reachable without the prerequisite call.

### Recommendation

Add a guard in `initTransfer1155` that requires the mapping to already be set, or have `initTransfer1155` set `multiTokens[deterministicToken]` itself (mirroring what `logMetadata1155` does):

```solidity
require(
    multiTokens[deterministicToken].tokenAddress != address(0),
    "ERC1155: metadata not registered"
);
```

Alternatively, merge the mapping-write logic from `logMetadata1155` into `initTransfer1155` so the two operations are atomic.

### Proof of Concept

1. User calls `initTransfer1155(erc1155Addr, tokenId, amount, 0, 0, "alice.near", "")` — **no prior `logMetadata1155`**.
2. `IERC1155(erc1155Addr).safeTransferFrom(user, bridge, tokenId, amount, "")` succeeds; tokens are now held by the bridge.
3. `InitTransfer` is emitted with `deterministicToken = keccak256(erc1155Addr, tokenId)[0:20]`.
4. NEAR relayer picks up the event and eventually calls `finTransfer(sig, {tokenAddress: deterministicToken, amount, recipient, ...})`.
5. `multiTokens[deterministicToken].tokenAddress == address(0)` → falls through to `IERC20(deterministicToken).safeTransfer(recipient, amount)`.
6. `deterministicToken` has no bytecode → call reverts → entire `finTransfer` tx rolls back.
7. ERC1155 tokens remain locked in the bridge; `finTransfer` cannot succeed until `logMetadata1155(erc1155Addr, tokenId)` is called out-of-band.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L243-255)
```text
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L315-355)
```text
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L453-489)
```text
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
```

**File:** evm/tests/OmniBridge1155.test.ts (L191-194)
```typescript
    await bridge
      .connect(user)
      .initTransfer1155(await erc1155.getAddress(), tokenId, 1, 0, 0, "receiver.near", "")
    expect(await erc1155.balanceOf(bridgeAddress, tokenId)).to.equal(1n)
```
