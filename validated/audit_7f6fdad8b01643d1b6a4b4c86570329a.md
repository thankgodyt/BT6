### Title
Missing `multiTokens` Registration Check in `initTransfer1155` Allows Permanent Freezing of ERC-1155 Tokens - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary

`initTransfer1155` in `OmniBridge.sol` accepts and locks any ERC-1155 token without verifying that the `(tokenAddress, tokenId)` pair has been previously registered via `logMetadata1155`. This is the direct analog of the external report's root cause: a token-identity validation step is missing before the contract accepts custody of tokens.

### Finding Description

The ERC-1155 bridging flow requires two steps in order:

1. **`logMetadata1155(tokenAddress, tokenId)`** — registers the pair in `multiTokens[deterministicToken]` and emits a `LogMetadata` event so the NEAR side can deploy/register the corresponding token.
2. **`initTransfer1155(tokenAddress, tokenId, ...)`** — locks the ERC-1155 tokens and emits `InitTransfer` so the NEAR side can mint.

`logMetadata1155` enforces the binding: [1](#0-0) 

But `initTransfer1155` performs **no check** that `multiTokens[deterministicToken]` is populated before accepting custody: [2](#0-1) 

The deterministic address is computed and used in the event, but the contract never asserts `multiTokens[deterministicToken].tokenAddress != address(0)`.

`deriveDeterministicAddress` is: [3](#0-2) 

On the `finTransfer` path, the ERC-1155 release branch is only taken when `multiToken.tokenAddress != address(0)`: [4](#0-3) 

If `logMetadata1155` was never called, `multiTokens[deterministicToken]` is zero, so `finTransfer` cannot release the locked ERC-1155 tokens even if a valid NEAR-signed payload were produced.

### Impact Explanation

Any unprivileged user who calls `initTransfer1155` for a `(tokenAddress, tokenId)` pair that was never registered via `logMetadata1155` will have their ERC-1155 tokens permanently locked in the bridge contract. The NEAR side will receive the `InitTransfer` event referencing an unregistered deterministic address, fail to finalize the transfer, and there is no on-chain EVM recovery path — no refund function exists for ERC-1155 tokens. This constitutes **permanent freezing of bridged funds**.

### Likelihood Explanation

The `logMetadata1155` step is off-chain convention only; the contract does not enforce ordering. A user who calls `initTransfer1155` directly (e.g., following ERC-20 bridging UX patterns, or using a different `tokenId` than the one registered) will trigger the freeze with no warning. The entry path is fully permissionless and requires no special role.

### Recommendation

Add a guard at the top of `initTransfer1155` that reverts if the `multiTokens` mapping for the computed deterministic address is not yet populated:

```solidity
address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);
if (multiTokens[deterministicToken].tokenAddress == address(0)) {
    revert ERC1155NotRegistered();
}
```

This mirrors the pattern already enforced in `logMetadata1155` (collision check) and ensures the NEAR side will always have a registered token before EVM-side custody is taken.

### Proof of Concept

1. Deploy any ERC-1155 contract and mint tokens to `attacker`.
2. Call `bridge.initTransfer1155(erc1155Addr, tokenId, amount, 0, 0, "victim.near", "")` **without** first calling `bridge.logMetadata1155(erc1155Addr, tokenId)`.
3. The `safeTransferFrom` succeeds; `amount` tokens are now held by the bridge.
4. The `InitTransfer` event is emitted with `deterministicToken = keccak256(erc1155Addr || tokenId)[0:20]`.
5. The NEAR relayer processes the event but finds no registered token for that deterministic address; the NEAR-side transfer fails.
6. No `finTransfer` call on the EVM side can release the ERC-1155 tokens because `multiTokens[deterministicToken].tokenAddress == address(0)`, so the branch at line 323 is never taken.
7. Tokens are permanently locked with no recovery path. [2](#0-1) [4](#0-3)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L315-330)
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
