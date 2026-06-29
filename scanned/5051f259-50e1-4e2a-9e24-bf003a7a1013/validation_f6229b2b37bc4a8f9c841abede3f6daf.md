### Title
Unguarded `logMetadata1155` Modifies Bridge State During Full Pause — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.sol` implements a selective pause system with three flags (`PAUSED_INIT_TRANSFER`, `PAUSED_FIN_TRANSFER`, `PAUSED_DEPLOY_TOKEN`). The core transfer functions are correctly guarded. However, `logMetadata1155` — a public, payable, state-mutating function — carries no `whenNotPaused` modifier and can be called by any unprivileged user even when all pause flags are set via `pauseAll()`.

### Finding Description
`OmniBridge.sol` defines three pause flags and applies them to the critical transfer functions: [1](#0-0) 

`initTransfer`, `initTransfer1155`, `finTransfer`, and `deployToken` are all correctly gated: [2](#0-1) [3](#0-2) 

However, `logMetadata1155` (lines 234–270) carries **no** `whenNotPaused` modifier: [4](#0-3) 

This function **writes to the `multiTokens` storage mapping** — a mapping that directly controls the token-transfer path inside `finTransfer`: [5](#0-4) 

The `multiTokens` mapping is then consumed inside `finTransfer` to decide whether to call `IERC1155.safeTransferFrom`: [6](#0-5) 

Similarly, `logMetadata` (lines 224–232) is also unguarded, though in the base contract it only emits an event. `logMetadata1155` is the more impactful case because it mutates persistent state. [7](#0-6) 

### Impact Explanation
During an emergency pause (e.g., `pauseAll()` is called), an attacker can still invoke `logMetadata1155(maliciousERC1155, tokenId)` to register a new entry in `multiTokens[deterministicToken]`. Because the mapping slot is keyed by `keccak256(abi.encodePacked(tokenAddress, tokenId))`, once written it cannot be overwritten (the function reverts on mismatch). After the pause is lifted:

1. The NEAR bridge processes the `LogMetadata` event emitted during the pause and deploys a corresponding NEP-141 token.
2. The attacker locks tokens in the malicious ERC1155 contract on the source chain and triggers a normal bridge flow.
3. The NEAR bridge signs a `finTransfer` payload for the `deterministicToken`.
4. `finTransfer` on EVM calls `IERC1155(maliciousERC1155).safeTransferFrom(address(this), recipient, tokenId, amount, "")` — invoking attacker-controlled code inside the bridge's execution context.

This enables reentrancy into `finTransfer` or other bridge functions at the point of token delivery, potentially allowing double-spend or state corruption. Beyond this specific exploit path, the broader impact is that the pause mechanism fails to freeze all state-mutating paths: administrators cannot guarantee a clean, known state when restarting the bridge after an emergency, which is the core invariant a pause is meant to provide.

### Likelihood Explanation
The entry point is fully permissionless — `logMetadata1155` is `external payable` with no role check and no pause check. Any EOA or contract can call it at any time, including during a full pause. The attacker only needs to know a valid `(tokenAddress, tokenId)` pair (or supply their own malicious ERC1155 contract) and pay the gas cost. Likelihood is high.

### Recommendation
Apply the `whenNotPaused(PAUSED_DEPLOY_TOKEN)` modifier (or a dedicated flag) to both `logMetadata` and `logMetadata1155`, consistent with how `deployToken` is guarded:

```solidity
function logMetadata1155(
    address tokenAddress,
    uint256 tokenId
) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) {
    ...
}

function logMetadata(address tokenAddress)
    external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) {
    ...
}
```

Additionally, audit all `virtual` extension hooks (`logMetadataExtension`, `deployTokenExtension`, `finTransferExtension`, `initTransferExtension`) in derived contracts to ensure they do not introduce unguarded state-mutating paths.

### Proof of Concept
1. Admin calls `pauseAll()` — all three pause flags are set.
2. Attacker deploys `MaliciousERC1155` implementing `safeTransferFrom` with a reentrant callback.
3. Attacker calls `logMetadata1155(address(MaliciousERC1155), tokenId)`.
   - No revert: no `whenNotPaused` check exists.
   - `multiTokens[deterministicToken] = {tokenAddress: MaliciousERC1155, tokenId: tokenId}` is written.
4. Admin lifts the pause.
5. Attacker initiates a bridge transfer of `(MaliciousERC1155, tokenId)` via `initTransfer1155`.
6. NEAR bridge signs a `finTransfer` payload for `deterministicToken`.
7. Attacker calls `finTransfer` with the valid MPC signature.
8. `finTransfer` reaches the `multiToken.tokenAddress != address(0)` branch and calls `MaliciousERC1155.safeTransferFrom(...)`, executing attacker-controlled code inside the bridge. [8](#0-7) [9](#0-8)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L52-55)
```text
    uint256 constant UNPAUSED_ALL = 0;
    uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;
    uint256 constant PAUSED_FIN_TRANSFER = 1 << 1;
    uint256 constant PAUSED_DEPLOY_TOKEN = 1 << 2;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-232)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }
```

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L282-283)
```text
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
        if (completedTransfers[payload.destinationNonce]) {
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L380-381)
```text
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L548-557)
```text
    function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause(flags);
    }

    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        uint256 flags = PAUSED_FIN_TRANSFER |
            PAUSED_INIT_TRANSFER |
            PAUSED_DEPLOY_TOKEN;
        _pause(flags);
    }
```

**File:** evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol (L63-66)
```text
    modifier whenNotPaused(uint256 flag) {
        _requireNotPaused(flag);
        _;
    }
```
