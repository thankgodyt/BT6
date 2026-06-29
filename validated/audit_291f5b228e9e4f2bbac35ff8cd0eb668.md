Audit Report

## Title
Reentrancy via ERC1155 Mandatory Callback in `initTransfer1155` Causes Nonce Collision and Unauthorized Minting — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

`initTransfer1155` increments `currentOriginNonce` before an external ERC1155 call but reads the storage variable again — after that call — when passing it to `initTransferExtension` and `emit`. A malicious ERC1155 token can reenter `initTransfer1155` during its mandatory `onERC1155Received` callback, causing two `InitTransfer` events to be emitted with the same nonce while one nonce is permanently skipped and no tokens are actually locked. The NEAR side mints wrapped tokens for the first event and rejects the second as a replay, resulting in unauthorized minting for zero EVM collateral.

## Finding Description

In `initTransfer1155`, `currentOriginNonce` is incremented at line 448 but then read again from storage at lines 471 and 483 — after the external `safeTransferFrom` call at line 458: [1](#0-0) 

The external call at line 458 is the reentrancy window. The `onERC1155Received` guard at lines 530–531 checks `operator != address(this)`: [2](#0-1) 

This guard does **not** block reentrancy through `initTransfer1155`. When the bridge calls `maliciousToken.safeTransferFrom(...)`, `msg.sender` inside the malicious token is the bridge itself. When the malicious token calls `bridge.onERC1155Received(msg.sender, ...)`, `operator` equals `address(this)` — the guard passes for both the inner and outer invocations.

**Exploit trace (starting with `currentOriginNonce = N-1`):**

1. Attacker calls `bridge.initTransfer1155(maliciousToken, ...)`.
2. Bridge increments `currentOriginNonce` → N, then calls `maliciousToken.safeTransferFrom(user, bridge, ...)`.
3. Malicious token reenters: calls `bridge.initTransfer1155(maliciousToken, ...)` again.
4. Inner call increments `currentOriginNonce` → N+1, calls `safeTransferFrom` again (reentrancy flag set, skips), receives `onERC1155Received` callback (operator = bridge → passes), emits `InitTransfer(nonce=N+1)`, returns.
5. Malicious token calls `bridge.onERC1155Received(bridge, ...)` for the outer call — passes.
6. Outer call reads `currentOriginNonce = N+1` (stale storage read), emits `InitTransfer(nonce=N+1)` a second time.

Result: nonce N is never emitted; nonce N+1 is emitted twice. The malicious token need not transfer any real tokens — its `safeTransferFrom` can be a no-op that only triggers the callback chain.

`logMetadata1155` is fully permissionless (no access control modifier), allowing any attacker to register a malicious ERC1155 address on NEAR before executing the attack: [3](#0-2) 

This directly violates the documented invariant in `evm/CLAUDE.md` ("State before external calls").

## Impact Explanation

The NEAR side treats any `InitTransfer` event emitted by the bridge as authoritative proof that tokens are locked on EVM. The attacker emits a valid `InitTransfer(nonce=N+1)` without locking any tokens. NEAR processes the first event and mints wrapped tokens for the attacker; the second event is rejected as a replay. The attacker receives bridged tokens for zero EVM collateral — unauthorized minting of bridged funds. This matches the critical impact class: *unauthorized minting of bridged funds* and *nonce/replay misuse that changes user or protocol balances*.

## Likelihood Explanation

Both `logMetadata1155` and `initTransfer1155` are permissionless and callable by any unprivileged user. Deploying a malicious ERC1155 token requires no special access. The ERC1155 standard mandates the `onERC1155Received` callback, making the reentrancy window structural. The attack requires no admin compromise, no front-running, and no off-chain coordination. It is repeatable for each new nonce pair.

## Recommendation

Capture `currentOriginNonce` in a local variable immediately after incrementing it, before any external call, and use only the local variable for all subsequent reads within the function:

```solidity
function initTransfer1155(...) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;
    uint64 originNonce = currentOriginNonce; // capture before external call
    ...
    IERC1155(tokenAddress).safeTransferFrom(...);
    ...
    initTransferExtension(..., originNonce, ...);
    emit BridgeTypes.InitTransfer(..., originNonce, ...);
}
```

Apply the same fix to `initTransfer` (lines 415–436) for consistency. Additionally, add `ReentrancyGuardUpgradeable` to both functions as defense-in-depth. [4](#0-3) 

## Proof of Concept

```solidity
contract MaliciousERC1155 is IERC1155 {
    address bridge;
    bool reentered;

    function safeTransferFrom(
        address from, address to, uint256 id, uint256 amount, bytes calldata
    ) external override {
        if (!reentered) {
            reentered = true;
            // Inner call: increments currentOriginNonce to N+1, emits InitTransfer(N+1)
            IOmniBridge(bridge).initTransfer1155(
                address(this), id, uint128(amount), 0, 0, "attacker.near", ""
            );
            reentered = false;
        }
        // No actual token transfer — balances unchanged
        // operator = msg.sender = bridge → onERC1155Received guard passes
        IERC1155Receiver(to).onERC1155Received(msg.sender, from, id, amount, "");
    }
}

// Attack sequence:
// 1. Deploy MaliciousERC1155, set bridge address
// 2. bridge.logMetadata1155(maliciousToken, tokenId)   ← permissionless
// 3. bridge.initTransfer1155(maliciousToken, tokenId, X, 0, 0, "attacker.near", "")
//    → emits InitTransfer(nonce=N+1) twice, nonce N skipped, 0 tokens locked
// 4. NEAR mints wrapped tokens for attacker at nonce N+1
```

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L234-237)
```text
    function logMetadata1155(
        address tokenAddress,
        uint256 tokenId
    ) external payable {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L415-436)
```text
        initTransferExtension(
            msg.sender,
            tokenAddress,
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
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L448-490)
```text
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
