Audit Report

## Title
`initTransfer1155()` Locks ERC1155 Tokens Without Validating `multiTokens` Mapping, Causing Permanent Fund Loss - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

`initTransfer1155()` accepts and locks ERC1155 tokens via `safeTransferFrom` without verifying that `multiTokens[deterministicToken]` has been populated by a prior `logMetadata1155()` call. When the mapping is absent, the NEAR-side `fin_transfer_callback` panics with `TokenDecimalsNotFound` (no wrapped tokens minted), and the EVM-side `finTransfer()` falls through to the ERC20 branch and reverts on a non-existent contract. There is no admin rescue path, making the locked tokens permanently irrecoverable.

## Finding Description

`initTransfer1155()` computes `deterministicToken`, transfers tokens into the bridge, and emits `InitTransfer` — but never reads or writes `multiTokens[deterministicToken]`: [1](#0-0) 

`multiTokens[deterministicToken]` is exclusively populated by `logMetadata1155()`: [2](#0-1) 

`finTransfer()` branches on `multiToken.tokenAddress != address(0)`. If the mapping is absent, it skips the ERC1155 release path and falls through to `IERC20(deterministicToken).safeTransfer(...)`, which reverts because `deterministicToken` is a hash-derived pseudo-address with no deployed code: [3](#0-2) 

On the NEAR side, `fin_transfer_callback` requires the token to be registered in `token_decimals` (populated by the `LogMetadata` event from `logMetadata1155()`). Without that registration, the call panics with `TokenDecimalsNotFound`, so no wrapped tokens are ever minted and no return transfer is initiated: [4](#0-3) 

The `onERC1155Received` hook does not block this path: it only rejects transfers where `operator != address(this)`. Since `initTransfer1155()` is the caller of `safeTransferFrom`, the bridge contract itself is the operator, so the hook accepts the transfer: [5](#0-4) 

The existing test suite confirms the gap: the "validates ERC1155 receiver hooks" test calls `initTransfer1155()` directly without `logMetadata1155()` and observes that tokens are locked, but does not verify recoverability: [6](#0-5) 

## Impact Explanation

ERC1155 tokens sent via `initTransfer1155()` without a prior `logMetadata1155()` call are permanently frozen in the bridge contract. This constitutes permanent, irrecoverable loss of bridged funds — matching the Critical allowed impact of "permanent freezing of bridged funds across EVM flows." There is no admin rescue path, no refund mechanism, and no way to recover the locked tokens once `safeTransferFrom` has executed.

## Likelihood Explanation

`initTransfer1155()` is a public, permissionless function. The correct two-step flow (`logMetadata1155` → `initTransfer1155`) is not enforced at the contract level and is not communicated via revert messages or function signatures. The `evm/SECURITY.md` confirms the bridge is "fully permissionless," meaning no gating prevents this call sequence. Any user who calls `initTransfer1155()` directly — a natural action given the function name — without knowing to call `logMetadata1155()` first will permanently lose their tokens. The contract silently accepts the tokens rather than reverting, giving the user no indication that the prerequisite was missed. [7](#0-6) 

## Recommendation

Add a guard in `initTransfer1155()` that requires `multiTokens[deterministicToken]` to already be populated before accepting the token lock:

```solidity
address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);

if (multiTokens[deterministicToken].tokenAddress == address(0)) {
    revert ERC1155NotRegistered();
}

IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), tokenId, amount, "");
```

Alternatively, `initTransfer1155()` can atomically invoke the registration logic (setting `multiTokens` and emitting `LogMetadata`) if the mapping is not yet set, mirroring the idempotent behavior of `logMetadata1155()`.

## Proof of Concept

1. Deploy `OmniBridge` and a `TestERC1155` token. Do **not** call `logMetadata1155()`.
2. Mint tokens to a user and approve the bridge via `setApprovalForAll`.
3. Call `initTransfer1155(erc1155, tokenId, amount, 0, 0, "victim.near", "")`.
4. Observe: `erc1155.balanceOf(bridge, tokenId) == amount` — tokens are locked.
5. Observe: `multiTokens[deterministicToken].tokenAddress == address(0)` — mapping is unset.
6. NEAR-side `fin_transfer_callback` panics with `TokenDecimalsNotFound` — no wrapped tokens minted, no return transfer created.
7. Attempt `finTransfer()` with `payload.tokenAddress = deterministicToken` — reverts at `IERC20(deterministicToken).safeTransfer(...)` because `deterministicToken` is not a deployed ERC20.
8. Tokens are permanently locked with no recovery path.

This is directly reproducible using the existing test harness (`OmniBridge1155Harness`) by extending the "validates ERC1155 receiver hooks" test to assert that `multiTokens[deterministicToken].tokenAddress == address(0)` after the `initTransfer1155()` call and that a subsequent `finTransfer()` attempt reverts. [8](#0-7)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L245-247)
```text
        if (multiToken.tokenAddress == address(0)) {
            multiToken.tokenAddress = tokenAddress;
            multiToken.tokenId = tokenId;
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L453-464)
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

**File:** near/omni-bridge/src/lib.rs (L715-718)
```rust
        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);
```

**File:** evm/tests/OmniBridge1155.test.ts (L170-195)
```typescript
  it("validates ERC1155 receiver hooks", async () => {
    const bridgeAddress = await bridge.getAddress()

    await expect(
      erc1155
        .connect(user)
        .safeTransferFrom(await user.getAddress(), bridgeAddress, tokenId, 1, "0x"),
    ).to.be.revertedWithCustomError(bridge, "ERC1155DirectSendNotAllowed")

    await expect(
      erc1155
        .connect(user)
        .safeBatchTransferFrom(
          await user.getAddress(),
          bridgeAddress,
          [tokenId, secondaryTokenId],
          [1, 1],
          "0x",
        ),
    ).to.be.revertedWithCustomError(bridge, "ERC1155BatchNotSupported")

    await bridge
      .connect(user)
      .initTransfer1155(await erc1155.getAddress(), tokenId, 1, 0, 0, "receiver.near", "")
    expect(await erc1155.balanceOf(bridgeAddress, tokenId)).to.equal(1n)
  })
```

**File:** evm/SECURITY.md (L8-8)
```markdown
- **`logMetadata` and `deployToken` are permissionless**: Anyone can call `logMetadata` for any ERC20, and anyone can submit a valid MPC signature to `deployToken`. This is by design — the bridge is fully permissionless
```
