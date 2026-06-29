### Title
`initTransfer1155` Allows ERC1155 Transfers Without Prior `multiTokens` Mapping Registration, Permanently Freezing Bridged Funds - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.initTransfer1155` computes a deterministic virtual address for an ERC1155 `(tokenAddress, tokenId)` pair and emits an `InitTransfer` event using that address as the token identifier. However, it does **not** verify that the `multiTokens` mapping for that deterministic address has been populated by a prior call to `logMetadata1155`. When NEAR later signs a `finTransfer` payload referencing the deterministic address, the EVM-side `finTransfer` cannot resolve the ERC1155 contract from the empty mapping and falls through to an ERC20 transfer path that reverts, permanently locking the deposited ERC1155 tokens.

### Finding Description
`deriveDeterministicAddress` computes a virtual token identifier as the **first 20 bytes** of `keccak256(abi.encodePacked(tokenAddress, tokenId))`:

```solidity
function deriveDeterministicAddress(
    address tokenAddress,
    uint256 tokenId
) public pure returns (address) {
    return address(bytes20(keccak256(abi.encodePacked(tokenAddress, tokenId))));
}
``` [1](#0-0) 

This virtual address is not a deployed contract. The `multiTokens` mapping binds it to the real ERC1155 contract and token ID, and is populated **only** by `logMetadata1155`:

```solidity
MultiTokenInfo storage multiToken = multiTokens[deterministicToken];
if (multiToken.tokenAddress == address(0)) {
    multiToken.tokenAddress = tokenAddress;
    multiToken.tokenId = tokenId;
}
``` [2](#0-1) 

`initTransfer1155` computes the same deterministic address and emits `InitTransfer` with it as the token address, but **never checks** that `multiTokens[deterministicToken]` is already set:

```solidity
address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);
IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), tokenId, amount, "");
// ...
emit BridgeTypes.InitTransfer(msg.sender, deterministicToken, ...);
``` [3](#0-2) 

When NEAR processes the `InitTransfer` event and later signs a `finTransfer` payload with `tokenAddress = deterministicToken`, the EVM-side `finTransfer` dispatches on `multiTokens[payload.tokenAddress]`:

```solidity
MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];
// ...
} else if (multiToken.tokenAddress != address(0)) {
    IERC1155(multiToken.tokenAddress).safeTransferFrom(...);
} else {
    IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount);
}
``` [4](#0-3) 

Because `multiTokens[deterministicToken]` is zero (never set), the code falls through to the ERC20 path and calls `IERC20(deterministicToken).safeTransfer(...)`. Since `deterministicToken` is not a deployed contract, this call reverts. The ERC1155 tokens remain permanently locked in the bridge with no recovery path.

### Impact Explanation
Any user who calls `initTransfer1155` without a prior `logMetadata1155` for the same `(tokenAddress, tokenId)` pair will have their ERC1155 tokens permanently frozen in the bridge. The `finTransfer` call will always revert for that deterministic address, and there is no admin escape hatch to recover the locked tokens. This constitutes a **permanent, irreversible loss of bridged funds** for the affected user.

### Likelihood Explanation
`initTransfer1155` is a public, permissionless function with no prerequisite enforcement. The protocol documentation does not enforce call ordering. A user unfamiliar with the two-step flow (`logMetadata1155` → `initTransfer1155`) will naturally call `initTransfer1155` directly. The likelihood is **moderate to high** for any new ERC1155 token being bridged for the first time.

### Recommendation
Add a guard in `initTransfer1155` that requires the `multiTokens` mapping to already be populated before accepting the ERC1155 deposit:

```solidity
address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);
require(
    multiTokens[deterministicToken].tokenAddress != address(0),
    "ERR_ERC1155_NOT_REGISTERED"
);
```

Alternatively, `initTransfer1155` can call the same registration logic as `logMetadata1155` inline, atomically setting the mapping if it is not yet set.

### Proof of Concept
1. Deploy an ERC1155 token contract and mint token ID `42` to Alice.
2. Alice approves the bridge and calls `initTransfer1155(erc1155, 42, 10, 0, 0, "alice.near", "")` **without** first calling `logMetadata1155(erc1155, 42)`.
3. The bridge receives 10 units of token ID 42. `multiTokens[deterministicToken]` remains `{address(0), 0}`.
4. NEAR processes the `InitTransfer` event and records the transfer with `tokenAddress = deterministicToken`.
5. Alice initiates a return transfer on NEAR. NEAR signs a `finTransfer` payload with `tokenAddress = deterministicToken, amount = 10, recipient = Alice`.
6. Anyone calls `finTransfer(signature, payload)` on the EVM bridge.
7. `multiTokens[deterministicToken].tokenAddress == address(0)` → falls through to `IERC20(deterministicToken).safeTransfer(Alice, 10)`.
8. `deterministicToken` has no code → call reverts.
9. Alice's 10 ERC1155 tokens are permanently locked in the bridge.

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
