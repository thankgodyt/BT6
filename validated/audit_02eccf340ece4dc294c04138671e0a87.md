### Title
Missing `multiTokens` Registration Check in `initTransfer1155` Allows Permanent ERC1155 Token Loss — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`initTransfer1155` accepts and locks ERC1155 tokens into the bridge without verifying that the corresponding `multiTokens[deterministicToken]` mapping was previously populated by `logMetadata1155`. When a user initiates an ERC1155 transfer without the prerequisite metadata registration, the tokens are permanently frozen in the bridge contract with no recovery path.

### Finding Description

`initTransfer1155` computes a deterministic pseudo-address for the `(tokenAddress, tokenId)` pair and immediately pulls the ERC1155 tokens from the caller into the bridge: [1](#0-0) 

There is no check that `multiTokens[deterministicToken].tokenAddress != address(0)` before accepting the tokens. The `multiTokens` mapping is only populated by `logMetadata1155`: [2](#0-1) 

On the release side, `finTransfer` routes based on `multiTokens[payload.tokenAddress]`: [3](#0-2) 

When `multiToken.tokenAddress == address(0)` (because `logMetadata1155` was never called), `finTransfer` falls through to the ERC20 branch and attempts `IERC20(deterministicToken).transfer(...)`. Since `deterministicToken` is a hash-derived address with no ERC20 code, this call reverts. The ERC1155 tokens remain locked in the bridge with no mechanism to recover them.

### Impact Explanation

Any user who calls `initTransfer1155` before `logMetadata1155` has been called for that `(tokenAddress, tokenId)` pair will have their ERC1155 tokens permanently frozen in the bridge. The `finTransfer` call will always revert for that transfer, and there is no admin rescue or withdrawal function for locked ERC1155 tokens. This constitutes **permanent freezing of bridged funds**.

### Likelihood Explanation

`initTransfer1155` is a permissionless, payable function callable by any token holder. The bridge is described as fully permissionless by design. A user unfamiliar with the two-step flow (`logMetadata1155` → `initTransfer1155`) will naturally attempt to bridge directly, triggering the loss. No adversarial intent is required — ordinary user error is sufficient. The function provides no revert or warning when the mapping is absent. [4](#0-3) 

### Recommendation

Add an existence guard at the top of `initTransfer1155`:

```solidity
function initTransfer1155(
    address tokenAddress,
    uint256 tokenId,
    ...
) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);
    if (multiTokens[deterministicToken].tokenAddress == address(0)) {
        revert ERC1155NotRegistered();
    }
    // ... rest of function
}
```

This mirrors the fix applied to the C-01 analog: check that the relevant state entry is already live/populated before accepting assets.

### Proof of Concept

1. Deploy `OmniBridge` (no `logMetadata1155` call for token `T`, id `42`).
2. Call `initTransfer1155(T, 42, 10, 0, 0, "victim.near", "")` — succeeds, 10 units of token `T` id `42` are transferred to the bridge. `currentOriginNonce` increments and `InitTransfer` is emitted.
3. NEAR relayer observes the event and calls `fin_transfer` on NEAR side, which eventually triggers `finTransfer` on EVM with `payload.tokenAddress = deterministicAddress(T, 42)`.
4. Inside `finTransfer`: `multiTokens[deterministicAddress(T,42)]` returns `{tokenAddress: address(0), tokenId: 0}`. The ERC1155 branch is skipped. The ERC20 branch executes `IERC20(deterministicAddress(T,42)).transfer(recipient, 10)` — reverts (no code at that address).
5. The transaction reverts; the nonce is not consumed. Step 4 can be retried indefinitely but will always revert. The 10 ERC1155 tokens are permanently locked. [1](#0-0) [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L234-255)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-330)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-495)
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

    function initTransferExtension(
        address /*sender*/,
        address /*tokenAddress*/,
        uint64 /*originNonce*/,
```

**File:** evm/SECURITY.md (L8-8)
```markdown
- **`logMetadata` and `deployToken` are permissionless**: Anyone can call `logMetadata` for any ERC20, and anyone can submit a valid MPC signature to `deployToken`. This is by design — the bridge is fully permissionless
```
