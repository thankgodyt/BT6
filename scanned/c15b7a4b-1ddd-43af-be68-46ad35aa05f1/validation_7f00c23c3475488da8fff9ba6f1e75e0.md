The code confirms this is a real vulnerability. Here is the full analysis:

---

### Title
Missing `multiTokens` Registration Guard in `initTransfer1155` Allows Permanent ERC1155 Token Lock — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`initTransfer1155` accepts and escrows any ERC1155 token without verifying that `logMetadata1155` was previously called for the `(tokenAddress, tokenId)` pair. Tokens transferred without a prior `logMetadata1155` call are permanently locked: NEAR has no metadata binding to finalize the inbound transfer, and the EVM-side `finTransfer` path also fails to release them.

### Finding Description

`initTransfer1155` computes a `deterministicToken` address and immediately pulls ERC1155 tokens into the bridge: [1](#0-0) 

There is no guard checking that `multiTokens[deterministicToken]` is populated before the transfer is accepted. Compare with `logMetadata1155`, which is the only function that writes to `multiTokens`: [2](#0-1) 

`logMetadata1155` also emits the `LogMetadata` event that NEAR uses to register the token binding. Without it, NEAR has no record of `deterministicToken` and cannot finalize the inbound transfer.

On the EVM return path, `finTransfer` reads `multiTokens[payload.tokenAddress]`. If `logMetadata1155` was never called, `multiToken.tokenAddress == address(0)`, so the ERC1155 branch is skipped: [3](#0-2) 

The code falls through to `IERC20(deterministicToken).safeTransfer(...)` (line 351), which calls a non-contract address and reverts. There is no recovery path.

The existing test suite inadvertently confirms the missing guard — `initTransfer1155` is called without a prior `logMetadata1155` and succeeds: [4](#0-3) 

### Impact Explanation
Any user who calls `initTransfer1155` before `logMetadata1155` (whether by mistake or by design) permanently loses their ERC1155 tokens. The tokens are held by the bridge contract with no mechanism to release them: NEAR cannot finalize the inbound transfer, and EVM `finTransfer` reverts when attempting to return them. This is a **permanent freezing of bridged funds**.

### Likelihood Explanation
The protocol provides no on-chain enforcement of the required ordering. A user unfamiliar with the two-step flow, or a UI that omits the `logMetadata1155` step, will silently lock funds. The attack surface is every public call to `initTransfer1155`.

### Recommendation
Add a registration guard at the top of `initTransfer1155`:

```solidity
require(
    multiTokens[deterministicToken].tokenAddress != address(0),
    "ERC1155 not registered: call logMetadata1155 first"
);
```

Alternatively, auto-register inside `initTransfer1155` by inlining the `logMetadata1155` logic (populate `multiTokens` and emit `LogMetadata`) before the token transfer, ensuring atomicity.

### Proof of Concept
1. Deploy a mock ERC1155 and the bridge (no `logMetadata1155` call).
2. Call `initTransfer1155(mockERC1155, tokenId, amount, 0, 0, "victim.near", "")`.
3. Assert `erc1155.balanceOf(bridge, tokenId) == amount` — tokens are held.
4. Attempt `finTransfer` with `payload.tokenAddress = deterministicToken` — it reverts at the `IERC20.safeTransfer` fallback because `deterministicToken` is not a contract.
5. Tokens are permanently locked with no release path. [5](#0-4)

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

**File:** evm/tests/OmniBridge1155.test.ts (L191-194)
```typescript
    await bridge
      .connect(user)
      .initTransfer1155(await erc1155.getAddress(), tokenId, 1, 0, 0, "receiver.near", "")
    expect(await erc1155.balanceOf(bridgeAddress, tokenId)).to.equal(1n)
```
