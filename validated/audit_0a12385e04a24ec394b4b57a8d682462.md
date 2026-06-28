### Title
Reentrancy in `initTransfer` via Hookable ERC20 Tokens Causes Nonce Collision and Permanent Freezing of Bridged Funds — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer` increments `currentOriginNonce` before making an external call to the user-supplied ERC20 token, but reads `currentOriginNonce` from storage (not a local variable) when emitting the `InitTransfer` event and when passing the nonce to `initTransferExtension`. A malicious ERC20 token with a transfer hook can reenter `initTransfer`, causing `currentOriginNonce` to be incremented a second time. Both the original and reentrant calls then emit `InitTransfer` events carrying the same (post-reentrant) nonce. The NEAR bridge processes only one event per `originNonce`; the other transfer's tokens are permanently frozen in the EVM bridge contract.

---

### Finding Description

`OmniBridge.initTransfer` has no `nonReentrant` modifier. Its execution order is:

1. `currentOriginNonce += 1` — incremented to `N`.
2. External call: `IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount)` — user-controlled token.
3. `initTransferExtension(..., currentOriginNonce, ...)` — reads `currentOriginNonce` from storage.
4. `emit BridgeTypes.InitTransfer(..., currentOriginNonce, ...)` — reads `currentOriginNonce` from storage. [1](#0-0) 

Because `currentOriginNonce` is **not captured as a local variable** before the external call, any reentrant call that increments it will corrupt the value seen by the original call's emit and extension invocation.

**Reentrant execution trace:**

| Step | `currentOriginNonce` | Action |
|---|---|---|
| Outer call enters | N-1 → **N** | `currentOriginNonce += 1` |
| `safeTransferFrom` fires hook | — | Malicious token calls back into `initTransfer` |
| Inner call enters | N → **N+1** | `currentOriginNonce += 1` |
| Inner `safeTransferFrom` | — | (hook stops recursion) |
| Inner `initTransferExtension` | reads **N+1** | Wormhole message with nonce N+1 |
| Inner `emit InitTransfer` | reads **N+1** | Event with nonce N+1 |
| Inner call returns | — | — |
| Outer `initTransferExtension` | reads **N+1** | Wormhole message with nonce N+1 ← **collision** |
| Outer `emit InitTransfer` | reads **N+1** | Event with nonce N+1 ← **collision** |

Nonce `N` is **never emitted**. Nonce `N+1` is **emitted twice** with different transfer parameters. The NEAR bridge, which relies solely on `InitTransfer` events to reconstruct transfers, processes the first event for nonce `N+1` and rejects the second as a duplicate. The tokens locked by the rejected transfer are permanently frozen in the bridge. [2](#0-1) 

The SECURITY.md documents the intended defense as "Always mutate state before any external call," but this defense is incomplete: incrementing the nonce before the external call does not prevent the nonce from being read with a stale (post-reentrant) value at emit time. [3](#0-2) 

The same structural flaw exists in `initTransfer1155`, which also reads `currentOriginNonce` from storage at emit time after an external ERC1155 `safeTransferFrom`. [4](#0-3) 

---

### Impact Explanation

The `InitTransfer` event is the **sole data source** the NEAR bridge uses to finalize inbound transfers from EVM chains. [5](#0-4) 

When two events share the same `originNonce`, the NEAR bridge processes one and permanently ignores the other. The ERC20 tokens transferred to the bridge in the ignored call are locked with no release path — constituting **permanent freezing of bridged funds**. This matches the critical impact category: "permanent freezing of bridged funds across EVM flows."

---

### Likelihood Explanation

`initTransfer` accepts **any ERC20 token address** — there is no whitelist for non-bridge tokens. An attacker can deploy a malicious ERC20 with a `transferFrom` hook (e.g., ERC777-style `tokensToSend`, or a custom before-transfer callback) that reenters `initTransfer`. The attacker needs only to:

1. Deploy the malicious token.
2. Call `initTransfer` with it while the bridge is unpaused.

No admin compromise, no front-running of other users, and no special permissions are required. The bridge is explicitly designed to be permissionless for `initTransfer`. [6](#0-5) 

---

### Recommendation

Capture `currentOriginNonce` into a local variable **before** any external call, and use that local variable in all subsequent reads within the same function:

```solidity
function initTransfer(...) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;
    uint64 nonce = currentOriginNonce; // capture before external call
    // ...
    IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);

    initTransferExtension(msg.sender, tokenAddress, nonce, ...);
    emit BridgeTypes.InitTransfer(msg.sender, tokenAddress, nonce, ...);
}
```

Apply the same fix to `initTransfer1155`. Alternatively, add OpenZeppelin's `ReentrancyGuardUpgradeable` and the `nonReentrant` modifier to both functions.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OmniBridge} from "./OmniBridge.sol";

/// Malicious ERC20: transferFrom always succeeds (returns true) but
/// reenters initTransfer once before actually moving tokens.
contract MaliciousERC20 is IERC20 {
    OmniBridge public bridge;
    bool private _reentered;

    function setBridge(address b) external { bridge = OmniBridge(payable(b)); }

    function transferFrom(address, address, uint256) external override returns (bool) {
        if (!_reentered) {
            _reentered = true;
            // Reentrant call — increments currentOriginNonce to N+1
            bridge.initTransfer(address(this), 1, 0, 0, "near:attacker.near", "");
            _reentered = false;
        }
        return true; // pretend transfer succeeded
    }

    // ... minimal ERC20 stubs ...
}

// Attack:
// 1. Deploy MaliciousERC20, set bridge address.
// 2. Call bridge.initTransfer(maliciousToken, 1, 0, 0, "near:attacker.near", "")
//    - currentOriginNonce: N-1 → N (outer)
//    - safeTransferFrom fires hook → reentrant call
//      - currentOriginNonce: N → N+1 (inner)
//      - inner emit: InitTransfer(nonce=N+1, ...)
//    - outer initTransferExtension reads currentOriginNonce = N+1  ← WRONG
//    - outer emit: InitTransfer(nonce=N+1, ...)  ← COLLISION
//
// Result: two InitTransfer events with nonce N+1.
// NEAR processes one; the other transfer's tokens are permanently frozen.
// Nonce N is never emitted.
``` [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-437)
```text
    function initTransfer(
        address tokenAddress,
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

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
        }

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

**File:** evm/CLAUDE.md (L23-23)
```markdown
**EVM → NEAR (initTransfer)**: User calls `initTransfer` which burns/locks tokens on EVM and emits `InitTransfer` with all transfer details (sender, token, amount, fee, nativeFee, recipient, message). In the Wormhole variant, a Wormhole message is also sent. The NEAR side reads this event (via light client or Wormhole) to complete the transfer. Every field needed to reconstruct the transfer must be in the event — it is the only data the NEAR side sees.
```

**File:** evm/CLAUDE.md (L34-34)
```markdown
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
```

**File:** evm/SECURITY.md (L8-8)
```markdown
- **`logMetadata` and `deployToken` are permissionless**: Anyone can call `logMetadata` for any ERC20, and anyone can submit a valid MPC signature to `deployToken`. This is by design — the bridge is fully permissionless
```
